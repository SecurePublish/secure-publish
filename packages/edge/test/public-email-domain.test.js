/**
 * Public-email-domain rule (Marcus): company mode requires a work domain.
 * Exact list + exact domain match (case-insensitive). Do not treat subdomains.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { mintSessionCookie } from "../src/sso.js";
import {
  PUBLIC_EMAIL_DOMAINS,
  isPublicEmailDomain,
  isBlockedSignupDomain,
  normalizeEmailDomain,
  checkPanelAccess,
} from "../src/acl.js";

const SPEC_DOMAINS = [
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "outlook.com.br",
  "hotmail.com",
  "hotmail.com.br",
  "live.com",
  "msn.com",
  "yahoo.com",
  "yahoo.com.br",
  "yahoo.co.uk",
  "yahoo.co.jp",
  "yahoo.fr",
  "yahoo.de",
  "yahoo.it",
  "yahoo.es",
  "yahoo.ca",
  "yahoo.com.au",
  "yahoo.com.mx",
  "yahoo.com.ar",
  "yahoo.co.in",
  "icloud.com",
  "me.com",
  "mac.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "gmx.com",
  "gmx.net",
  "gmx.de",
  "zoho.com",
  "zohomail.com",
  "yandex.com",
  "yandex.ru",
  "mail.com",
  "uol.com.br",
  "bol.com.br",
  "terra.com.br",
  "ig.com.br",
  "users.noreply.github.com",
];

const GMAIL_COMPANY_ID = "222222222222222222222222";
const GMAIL_ALLOW_ID = "333333333333333333333333";
const WISE_COMPANY_ID = "444444444444444444444444";
const WISE_ALLOW_ID = "555555555555555555555555";
const PANEL_HTML = "<html>public-domain-acl</html>";

function memoryKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, String(value));
    },
    async delete(key) {
      store.delete(key);
    },
    async list({ prefix = "", limit = 1000 } = {}) {
      const keys = [...store.keys()]
        .filter((k) => k.startsWith(prefix))
        .sort()
        .map((name) => ({ name }));
      return { keys: keys.slice(0, limit), list_complete: true, cursor: undefined };
    },
    _store: store,
  };
}

function kvDump(kv) {
  return JSON.stringify([...kv._store.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

function oauthEnv(panels) {
  return {
    PANELS: panels,
    SESSION_SECRET: "test-session-secret-at-least-32-chars!!",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
  };
}

async function sessionCookie(env, email) {
  const setCookie = await mintSessionCookie(
    {
      email,
      provider: "google",
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    env.SESSION_SECRET,
    env,
    "https://app.securepublish.work/_auth/callback/google"
  );
  return setCookie.split(";")[0];
}

function apiHeaders(cookie, extra = {}) {
  return {
    Origin: "https://app.securepublish.work",
    Cookie: cookie,
    ...extra,
  };
}

describe("PUBLIC_EMAIL_DOMAINS", () => {
  it("includes the spec list plus vendored free-email-domains extras", () => {
    for (const d of SPEC_DOMAINS) {
      assert.equal(PUBLIC_EMAIL_DOMAINS.has(d), true, d);
    }
    for (const d of ["pm.me", "fastmail.com", "hotmail.co.uk", "live.com.br", "tutanota.com"]) {
      assert.equal(isPublicEmailDomain(`user@${d}`), true, d);
      assert.equal(isBlockedSignupDomain(`user@${d}`), true, d);
    }
    assert.ok(PUBLIC_EMAIL_DOMAINS.size > 1000);
  });

  it("matches the email domain part case-insensitively (User@GMAIL.com)", () => {
    assert.equal(isPublicEmailDomain("User@GMAIL.com"), true);
    assert.equal(isPublicEmailDomain("ANA@Outlook.COM.BR"), true);
    assert.equal(isPublicEmailDomain("x@users.noreply.github.com"), true);
  });

  it("is exact domain match: foo.gmail.com is not in the list", () => {
    assert.equal(isPublicEmailDomain("foo.gmail.com"), false);
    assert.equal(isPublicEmailDomain("user@foo.gmail.com"), false);
    assert.equal(isPublicEmailDomain("user@mail.googlemail.com"), false);
    assert.equal(isPublicEmailDomain("user@notmail.com"), false);
  });

  it("does not treat wises.com.br as public", () => {
    assert.equal(isPublicEmailDomain("ana@wises.com.br"), false);
    assert.equal(isPublicEmailDomain("wises.com.br"), false);
  });

  it("treats every listed domain as public", () => {
    for (const d of SPEC_DOMAINS) {
      assert.equal(isPublicEmailDomain(`user@${d}`), true, d);
      assert.equal(isPublicEmailDomain(d.toUpperCase()), true, d);
    }
  });
});

describe("normalizeEmailDomain / signup blocklist", () => {
  it("lowercases and trims a valid host; does not strip a trailing dot", () => {
    assert.equal(normalizeEmailDomain("  Ana@WISES.COM.BR "), "wises.com.br");
    assert.equal(normalizeEmailDomain("  Ana@WISES.COM.BR. "), "");
  });

  it("denies domains containing # / ? \\ : and never URL-repairs them", () => {
    const emails = [
      "x@wises.com.br#evil",
      "x@wises.com.br/evil",
      "x@wises.com.br?evil",
      "x@wises.com.br\\evil",
      "x@wises.com.br:8080",
    ];
    for (const email of emails) {
      assert.equal(normalizeEmailDomain(email), "", email);
      assert.equal(isBlockedSignupDomain(email), true, email);
    }
  });

  it("punycode-encodes an IDN email domain", () => {
    assert.equal(normalizeEmailDomain("user@bücher.example"), "xn--bcher-kva.example");
  });

  it("blocks signup for listed providers and their subdomains", () => {
    assert.equal(isBlockedSignupDomain("ana@gmail.com"), true);
    assert.equal(isBlockedSignupDomain("ana@mail.yahoo.com"), true);
    assert.equal(isBlockedSignupDomain("x@users.noreply.github.com"), true);
    assert.equal(isBlockedSignupDomain("x@mail.users.noreply.github.com"), true);
    assert.equal(isBlockedSignupDomain("ana@yahoo.co.uk"), true);
    assert.equal(isBlockedSignupDomain("ana@gmx.de"), true);
    assert.equal(isBlockedSignupDomain("ana@zohomail.com"), true);
  });

  it("does not block company domains (including lookalikes of public providers)", () => {
    assert.equal(isBlockedSignupDomain("clovis@furk.tech"), false);
    assert.equal(isBlockedSignupDomain("ana@wises.com.br"), false);
    assert.equal(isBlockedSignupDomain("user@notmail.com"), false);
    assert.equal(isBlockedSignupDomain("user@evilgmail.com"), false);
  });
});

describe("checkPanelAccess — old public-domain company panels", () => {
  const access = { mode: "company", domains: ["gmail.com"] };
  const publisher = "ana@gmail.com";

  it("denies same-domain viewers (including other @gmail.com)", () => {
    const r = checkPanelAccess({ email: "bob@gmail.com" }, access, {}, publisher);
    assert.equal(r.ok, false);
  });

  it("publisherEmail is the only exception", () => {
    const r = checkPanelAccess({ email: "ana@gmail.com" }, access, {}, publisher);
    assert.equal(r.ok, true);
  });

  it("publisher exception is case-insensitive", () => {
    const r = checkPanelAccess({ email: "Ana@Gmail.COM" }, access, {}, publisher);
    assert.equal(r.ok, true);
  });

  it("allowlist mode is unchanged for public-domain accounts", () => {
    const allow = { mode: "allowlist", emails: ["bob@gmail.com"] };
    assert.equal(
      checkPanelAccess({ email: "bob@gmail.com" }, allow, {}, publisher).ok,
      true
    );
    assert.equal(
      checkPanelAccess({ email: "eve@gmail.com" }, allow, {}, publisher).ok,
      false
    );
  });

  it("work-domain company panels still allow same-domain viewers", () => {
    const r = checkPanelAccess(
      { email: "bruno@wises.com.br" },
      { mode: "company", domains: ["wises.com.br"] },
      {},
      "ana@wises.com.br"
    );
    assert.equal(r.ok, true);
  });
});

describe("API — public email domain", () => {
  it("GET /api/me denies a Gmail session at the signup blocklist (stable error)", async () => {
    const env = oauthEnv(memoryKv());
    const cookie = await sessionCookie(env, "User@GMAIL.com");
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/me", {
        headers: apiHeaders(cookie),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: "company_requires_work_domain" });
  });

  it("GET /api/me returns publicDomain false for wises.com.br", async () => {
    const env = oauthEnv(memoryKv());
    const cookie = await sessionCookie(env, "ana@wises.com.br");
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/me", {
        headers: apiHeaders(cookie),
      }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.publicDomain, false);
    assert.equal(body.domain, "wises.com.br");
  });

  it("POST company from public domain is 403 at the blocklist, KV unchanged", async () => {
    const panels = memoryKv();
    const env = oauthEnv(panels);
    const cookie = await sessionCookie(env, "ana@gmail.com");
    const before = kvDump(panels);
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: apiHeaders(cookie, { "content-type": "application/json" }),
        body: JSON.stringify({ html: "<p>company</p>" }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: "company_requires_work_domain" });
    assert.equal(kvDump(panels), before);
  });

  it("POST /api/panels company mode from public domain → 403, KV unchanged", async () => {
    const panels = memoryKv({
      "tenant:user:user@gmail.com": JSON.stringify({
        email: "user@gmail.com",
        slug: "gmailpub",
        host: "gmailpub.securepublish.work",
      }),
      "host:sub:gmailpub": "user@gmail.com",
    });
    const env = oauthEnv(panels);
    const cookie = await sessionCookie(env, "User@GMAIL.com");
    const before = kvDump(panels);

    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: apiHeaders(cookie, { "content-type": "application/json" }),
        body: JSON.stringify({ html: "<p>company</p>", title: "Nope" }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: "company_requires_work_domain" });
    assert.equal(kvDump(panels), before);
  });

  it("POST /api/panels with --to allowlist is also blocked for public-domain accounts", async () => {
    const panels = memoryKv({
      "tenant:user:ana@gmail.com": JSON.stringify({
        email: "ana@gmail.com",
        slug: "gmailpub",
        host: "gmailpub.securepublish.work",
      }),
      "host:sub:gmailpub": "ana@gmail.com",
    });
    const env = oauthEnv(panels);
    const cookie = await sessionCookie(env, "ana@gmail.com");
    const before = kvDump(panels);
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: apiHeaders(cookie, { "content-type": "application/json" }),
        body: JSON.stringify({
          html: "<p>only</p>",
          to: ["bob@gmail.com", "ana@gmail.com"],
        }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: "company_requires_work_domain" });
    assert.equal(kvDump(panels), before);
  });

  it("POST company from user@foo.gmail.com (subdomain of a blocked provider) is denied", async () => {
    const panels = memoryKv({
      "tenant:user:user@foo.gmail.com": JSON.stringify({
        email: "user@foo.gmail.com",
        slug: "foogmail",
        host: "foogmail.securepublish.work",
      }),
      "host:sub:foogmail": "user@foo.gmail.com",
    });
    const env = oauthEnv(panels);
    const cookie = await sessionCookie(env, "user@foo.gmail.com");
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: apiHeaders(cookie, { "content-type": "application/json" }),
        body: JSON.stringify({ html: "<p>sub</p>" }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: "company_requires_work_domain" });
  });

  it("PATCH mode:company from public-domain publisher → 403, KV unchanged", async () => {
    const record = {
      v: 1,
      title: "Allow",
      publishedAt: "2026-10-08T00:00:00Z",
      publisherEmail: "ana@gmail.com",
      access: { mode: "allowlist", emails: ["ana@gmail.com", "bob@gmail.com"] },
      html: PANEL_HTML,
    };
    const panels = memoryKv({
      [GMAIL_ALLOW_ID]: JSON.stringify(record),
    });
    const env = oauthEnv(panels);
    const cookie = await sessionCookie(env, "ana@gmail.com");
    const before = kvDump(panels);

    const res = await worker.fetch(
      new Request(`https://app.securepublish.work/api/panels/${GMAIL_ALLOW_ID}/access`, {
        method: "PATCH",
        headers: apiHeaders(cookie, { "content-type": "application/json" }),
        body: JSON.stringify({ mode: "company" }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: "company_requires_work_domain" });
    assert.equal(kvDump(panels), before);
    const stored = JSON.parse(panels._store.get(GMAIL_ALLOW_ID));
    assert.equal(stored.access.mode, "allowlist");
  });

  it("PATCH allowlist is also blocked for public-domain publishers", async () => {
    const panels = memoryKv({
      [GMAIL_ALLOW_ID]: JSON.stringify({
        v: 1,
        title: "Allow",
        publishedAt: "2026-10-08T00:00:00Z",
        publisherEmail: "ana@gmail.com",
        access: { mode: "allowlist", emails: ["ana@gmail.com"] },
        html: PANEL_HTML,
      }),
    });
    const env = oauthEnv(panels);
    const cookie = await sessionCookie(env, "ana@gmail.com");
    const res = await worker.fetch(
      new Request(`https://app.securepublish.work/api/panels/${GMAIL_ALLOW_ID}/access`, {
        method: "PATCH",
        headers: apiHeaders(cookie, { "content-type": "application/json" }),
        body: JSON.stringify({
          mode: "allowlist",
          allowlist: ["ana@gmail.com", "cara@gmail.com"],
        }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), { error: "company_requires_work_domain" });
  });

  it("old public-domain company panel: 403 for viewer and publisher (blocklist)", async () => {
    const panels = memoryKv({
      [GMAIL_COMPANY_ID]: JSON.stringify({
        v: 1,
        title: "Old",
        publishedAt: "2026-10-01T00:00:00Z",
        publisherEmail: "ana@gmail.com",
        access: { mode: "company", domains: ["gmail.com"] },
        html: PANEL_HTML,
      }),
    });
    const env = oauthEnv(panels);

    const viewer = await worker.fetch(
      new Request(`https://edge.workers.dev/${GMAIL_COMPANY_ID}`, {
        headers: {
          Host: "edge.workers.dev",
          Cookie: await sessionCookie(env, "bob@gmail.com"),
        },
      }),
      env
    );
    assert.equal(viewer.status, 403);

    const publisher = await worker.fetch(
      new Request(`https://edge.workers.dev/${GMAIL_COMPANY_ID}`, {
        headers: {
          Host: "edge.workers.dev",
          Cookie: await sessionCookie(env, "ana@gmail.com"),
        },
      }),
      env
    );
    assert.equal(publisher.status, 403);
    assert.equal(
      await publisher.text(),
      "Acesso negado: domínio de e-mail não autorizado.\n"
    );
  });

  it("GET /api/panels with a Gmail session is denied at the blocklist", async () => {
    const panels = memoryKv({
      [GMAIL_COMPANY_ID]: JSON.stringify({
        v: 1,
        title: "Old Gmail Co",
        publishedAt: "2026-10-01T00:00:00Z",
        publisherEmail: "ana@gmail.com",
        access: { mode: "company", domains: ["gmail.com"] },
        html: PANEL_HTML,
      }),
      [GMAIL_ALLOW_ID]: JSON.stringify({
        v: 1,
        title: "Gmail Allow",
        publishedAt: "2026-10-02T00:00:00Z",
        publisherEmail: "ana@gmail.com",
        access: { mode: "allowlist", emails: ["ana@gmail.com"] },
        html: PANEL_HTML,
      }),
      "idx:domain:gmail.com": JSON.stringify([GMAIL_COMPANY_ID]),
      "idx:pub:ana@gmail.com": JSON.stringify([GMAIL_COMPANY_ID, GMAIL_ALLOW_ID]),
    });
    const env = oauthEnv(panels);

    const other = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels?scope=company", {
        headers: apiHeaders(await sessionCookie(env, "bob@gmail.com")),
      }),
      env
    );
    assert.equal(other.status, 403);
    assert.deepEqual(await other.json(), { error: "company_requires_work_domain" });

    const pubCompany = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels?scope=company", {
        headers: apiHeaders(await sessionCookie(env, "ana@gmail.com")),
      }),
      env
    );
    assert.equal(pubCompany.status, 403);

    const mine = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels?scope=mine", {
        headers: apiHeaders(await sessionCookie(env, "ana@gmail.com")),
      }),
      env
    );
    assert.equal(mine.status, 403);
  });
});

describe("API — work domain wises.com.br unchanged", () => {
  it("company publish, PATCH company, company listing, and access still work", async () => {
    const panels = memoryKv({
      "tenant:user:ana@wises.com.br": JSON.stringify({
        email: "ana@wises.com.br",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
      "host:sub:wise": "ana@wises.com.br",
      [WISE_ALLOW_ID]: JSON.stringify({
        v: 1,
        title: "Allow",
        publishedAt: "2026-10-08T00:00:00Z",
        publisherEmail: "ana@wises.com.br",
        access: { mode: "allowlist", emails: ["ana@wises.com.br"] },
        html: PANEL_HTML,
      }),
      [WISE_COMPANY_ID]: JSON.stringify({
        v: 1,
        title: "Co",
        publishedAt: "2026-10-07T00:00:00Z",
        publisherEmail: "ana@wises.com.br",
        access: { mode: "company", domains: ["wises.com.br"] },
        html: PANEL_HTML,
      }),
      "idx:domain:wises.com.br": JSON.stringify([WISE_COMPANY_ID]),
      "idx:pub:ana@wises.com.br": JSON.stringify([WISE_COMPANY_ID, WISE_ALLOW_ID]),
    });
    const env = oauthEnv(panels);
    const ana = await sessionCookie(env, "ana@wises.com.br");
    const bruno = await sessionCookie(env, "bruno@wises.com.br");

    const pub = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: apiHeaders(ana, { "content-type": "application/json" }),
        body: JSON.stringify({ html: "<p>wise</p>", title: "Horas" }),
      }),
      env
    );
    assert.equal(pub.status, 201);
    const published = await pub.json();
    assert.equal(published.mode, "company");

    const patch = await worker.fetch(
      new Request(`https://app.securepublish.work/api/panels/${WISE_ALLOW_ID}/access`, {
        method: "PATCH",
        headers: apiHeaders(ana, { "content-type": "application/json" }),
        body: JSON.stringify({ mode: "company" }),
      }),
      env
    );
    assert.equal(patch.status, 200);
    assert.equal((await patch.json()).panel.mode, "company");

    const listed = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels?scope=company", {
        headers: apiHeaders(bruno),
      }),
      env
    );
    assert.equal(listed.status, 200);
    const listBody = await listed.json();
    assert.ok(listBody.panels.find((p) => p.id === WISE_COMPANY_ID));
    assert.ok(listBody.panels.find((p) => p.id === WISE_ALLOW_ID));

    const access = await worker.fetch(
      new Request(`https://edge.workers.dev/${WISE_COMPANY_ID}`, {
        headers: { Host: "edge.workers.dev", Cookie: bruno },
      }),
      env
    );
    assert.equal(access.status, 200);
    assert.equal(await access.text(), PANEL_HTML);
  });
});
