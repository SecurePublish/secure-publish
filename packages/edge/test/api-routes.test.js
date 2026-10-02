/**
 * Route-shape / auth gate tests with a minimal in-memory KV + fetch handler.
 * SSO_DEV_BYPASS used only in these unit tests (never default on in wrangler).
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

function memoryKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, value);
    },
    async delete(key) {
      store.delete(key);
    },
    async list({ prefix = "", cursor, limit = 1000 } = {}) {
      const keys = [...store.keys()]
        .filter((k) => k.startsWith(prefix))
        .sort()
        .map((name) => ({ name }));
      return { keys: keys.slice(0, limit), list_complete: true, cursor: undefined };
    },
    _store: store,
  };
}

const PANEL_ID = "aaaaaaaaaaaaaaaaaaaaaaaa";
const PANEL_OTHER = "bbbbbbbbbbbbbbbbbbbbbbbb";

function setCookies(res) {
  if (typeof res.headers.getSetCookie === "function") {
    return res.headers.getSetCookie();
  }
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

describe("API routes — Marcus checklist", () => {
  let env;

  before(() => {
    const panels = memoryKv({
      [PANEL_ID]: JSON.stringify({
        v: 1,
        title: "Mine",
        publishedAt: "2026-10-02T03:18:00-03:00",
        publisherEmail: "dev@localhost",
        access: { mode: "company", domains: ["localhost"] },
        html: "<html>ok</html>",
      }),
      [PANEL_OTHER]: JSON.stringify({
        v: 1,
        title: "Other",
        publishedAt: "2026-10-01T00:00:00Z",
        publisherEmail: "other@acme.example",
        access: { mode: "company", domains: ["acme.example"] },
        html: "<html>x</html>",
      }),
      [`idx:pub:dev@localhost`]: JSON.stringify([PANEL_ID]),
      [`idx:domain:localhost`]: JSON.stringify([PANEL_ID]),
    });
    env = {
      PANELS: panels,
      SSO_DEV_BYPASS: "1",
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
    };
  });

  it("(1) /api/me without bypass and without cookie → 401 when SSO none", async () => {
    const locked = {
      PANELS: env.PANELS,
      CONSOLE_ORIGIN: env.CONSOLE_ORIGIN,
      // no SSO_DEV_BYPASS, no secrets → mode none
    };
    const res = await worker.fetch(
      new Request("https://worker.test/api/me", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      locked
    );
    assert.equal(res.status, 401);
  });

  it("(1) /api/me with session (dev-bypass) returns contract shape", async () => {
    const res = await worker.fetch(
      new Request("https://worker.test/api/me", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.email, "dev@localhost");
    assert.equal(body.idp, "dev-bypass");
    assert.equal(body.domain, "localhost");
    assert.ok("host" in body);
    // No subdomain claimed yet — must be null, never "" (console would show https:///{id})
    assert.equal(body.host, null);
    assert.equal(res.headers.get("Access-Control-Allow-Origin"), "https://console.pages.dev");
    assert.equal(res.headers.get("Access-Control-Allow-Credentials"), "true");
  });

  it("GET /api/panels?scope=mine returns panels array shape", async () => {
    const res = await worker.fetch(
      new Request("https://worker.test/api/panels?scope=mine", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.panels));
    assert.ok("host" in body);
    assert.equal(body.host, null); // no hosting yet — do not fabricate https:///
    const p = body.panels.find((x) => x.id === PANEL_ID);
    assert.ok(p);
    assert.equal(p.publisherEmail, "dev@localhost");
    assert.equal(p.mode, "company");
    assert.ok(Array.isArray(p.allowlist));
    assert.ok(Array.isArray(p.viewers));
    assert.equal(typeof p.views, "number");
  });

  it("(2) PATCH access forbidden for non-publisher", async () => {
    const res = await worker.fetch(
      new Request(`https://worker.test/api/panels/${PANEL_OTHER}/access`, {
        method: "PATCH",
        headers: {
          Origin: "https://console.pages.dev",
          "content-type": "application/json",
        },
        body: JSON.stringify({ mode: "allowlist", allowlist: ["dev@localhost"] }),
      }),
      env
    );
    assert.equal(res.status, 403);
  });

  it("(2) PATCH access ok for publisher", async () => {
    const res = await worker.fetch(
      new Request(`https://worker.test/api/panels/${PANEL_ID}/access`, {
        method: "PATCH",
        headers: {
          Origin: "https://console.pages.dev",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          mode: "allowlist",
          allowlist: ["dev@localhost"],
          sendInvite: true,
        }),
      }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.panel.mode, "allowlist");
    assert.deepEqual(body.panel.allowlist, ["dev@localhost"]);
    assert.equal(body.inviteStub.queued, false);
  });

  it("PUT /api/hosting/subdomain returns { host }", async () => {
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/subdomain", {
        method: "PUT",
        headers: {
          Origin: "https://console.pages.dev",
          "content-type": "application/json",
        },
        body: JSON.stringify({ slug: "wise" }),
      }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.host, "wise.securepublish.work");
  });

  it("after subdomain claim, /api/me and /api/panels emit non-empty host", async () => {
    const me = await worker.fetch(
      new Request("https://worker.test/api/me", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    const meBody = await me.json();
    assert.equal(meBody.host, "wise.securepublish.work");
    assert.notEqual(meBody.host, "");

    const panels = await worker.fetch(
      new Request("https://worker.test/api/panels?scope=mine", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    const panelsBody = await panels.json();
    assert.equal(panelsBody.host, "wise.securepublish.work");
    assert.notEqual(panelsBody.host, "");
  });

  it("empty host is never emitted (whitespace DEFAULT_PANEL_HOST → null)", async () => {
    const fresh = {
      PANELS: memoryKv(),
      SSO_DEV_BYPASS: "1",
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
      DEFAULT_PANEL_HOST: "   ",
    };
    const res = await worker.fetch(
      new Request("https://worker.test/api/me", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      fresh
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.host, null);
    assert.notEqual(body.host, "");
  });

  it("(5) PUT /api/hosting/custom claims but does not verify", async () => {
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom", {
        method: "PUT",
        headers: {
          Origin: "https://console.pages.dev",
          "content-type": "application/json",
        },
        body: JSON.stringify({ hostname: "dash.acme.example" }),
      }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.customVerified, false);
    assert.ok(body.verify);
  });

  it("(3) CORS preflight rejects unknown origin", async () => {
    const res = await worker.fetch(
      new Request("https://worker.test/api/me", {
        method: "OPTIONS",
        headers: { Origin: "https://evil.example" },
      }),
      env
    );
    assert.equal(res.status, 403);
  });

  it("(5) unverified custom Host cannot serve panels", async () => {
    const res = await worker.fetch(
      new Request(`https://dash.acme.example/${PANEL_ID}`, {
        headers: { Host: "dash.acme.example" },
      }),
      env
    );
    assert.equal(res.status, 403);
  });
});

describe("GET|POST /auth/logout", () => {
  const baseEnv = {
    PANELS: memoryKv(),
    CONSOLE_ORIGIN: "https://app.securepublish.work,https://secure-publish-app.pages.dev",
    SESSION_SECRET: "test-session-secret-at-least-32-chars",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
  };

  it("GET clears cookie (4 Set-Cookie: host-only+Domain, Lax+None) and redirects", async () => {
    const res = await worker.fetch(
      new Request("https://demo.securepublish.work/auth/logout", { redirect: "manual" }),
      baseEnv
    );
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "https://app.securepublish.work/signup/");
    const cookies = setCookies(res);
    assert.equal(cookies.length, 4, `expected 4 Set-Cookie clears, got ${cookies.length}: ${cookies.join(" || ")}`);
    for (const c of cookies) {
      assert.match(c, /secure_publish_session=/);
      assert.match(c, /Max-Age=0/);
      assert.match(c, /Secure/);
      assert.match(c, /HttpOnly/);
      assert.match(c, /Path=\//);
    }
    assert.ok(cookies.some((c) => /SameSite=Lax/i.test(c) && !/Domain=/i.test(c)), "host-only Lax");
    assert.ok(cookies.some((c) => /SameSite=Lax/i.test(c) && /Domain=\.securepublish\.work/i.test(c)), "Domain Lax");
    assert.ok(cookies.some((c) => /SameSite=None/i.test(c) && !/Domain=/i.test(c)), "host-only None");
    assert.ok(cookies.some((c) => /SameSite=None/i.test(c) && /Domain=\.securepublish\.work/i.test(c)), "Domain None");
  });


  it("POST is idempotent without prior session", async () => {
    const res = await worker.fetch(
      new Request("https://demo.securepublish.work/auth/logout", {
        method: "POST",
        redirect: "manual",
      }),
      baseEnv
    );
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "https://app.securepublish.work/signup/");
  });

  it("always uses canonical signup, ignoring caller-supplied redirects", async () => {
    const res = await worker.fetch(
      new Request(
        "https://demo.securepublish.work/auth/logout?next=" +
          encodeURIComponent("https://app.securepublish.work/app/home.html"),
        { redirect: "manual" }
      ),
      baseEnv
    );
    assert.equal(res.headers.get("location"), "https://app.securepublish.work/signup/");
  });

  it("redirect=0 and JSON Accept retain the plain 200 response", async () => {
    for (const request of [
      new Request("https://demo.securepublish.work/_auth/logout?redirect=0"),
      new Request("https://demo.securepublish.work/auth/logout", {
        headers: { Accept: "application/json" },
      }),
    ]) {
      const res = await worker.fetch(request, baseEnv);
      assert.equal(res.status, 200);
      assert.equal(await res.text(), "Sessão encerrada.\n");
      assert.ok(setCookies(res).some((c) => /Max-Age=0/.test(c)));
    }
  });

  it("clear variants cover mint attrs (host-only + Domain, Lax + None)", async () => {
    const { mintSessionCookie, clearSessionCookie, clearSessionCookieVariants } =
      await import("../src/sso.js");
    const url = "https://demo.securepublish.work/";
    const minted = await mintSessionCookie(
      { email: "a@wises.com.br", provider: "google", exp: 9999999999 },
      baseEnv.SESSION_SECRET,
      baseEnv,
      url
    );
    const cleared = clearSessionCookie(baseEnv, url);
    const attrs = (s) =>
      s
        .split(";")
        .slice(1)
        .map((p) => p.trim().toLowerCase())
        .filter((p) => p && !p.startsWith("max-age="))
        .sort();
    assert.deepEqual(attrs(cleared), attrs(minted));

    const variants = clearSessionCookieVariants(baseEnv, url);
    assert.equal(variants.length, 4);
    assert.ok(
      variants.some((v) => /Domain=\.securepublish\.work/i.test(v) && /SameSite=Lax/i.test(v)),
      "Domain+Lax clear present"
    );
    assert.ok(
      variants.some((v) => /SameSite=Lax/i.test(v) && !/Domain=/i.test(v)),
      "host-only Lax clear present"
    );
  });


  it("workers.dev logout still emits all 4 clears (incl. Domain for cross-host zombies)", async () => {
    const res = await worker.fetch(
      new Request("https://secure-publish.clovist.workers.dev/auth/logout", {
        redirect: "manual",
      }),
      baseEnv
    );
    assert.equal(res.status, 302);
    const cookies = setCookies(res);
    assert.equal(cookies.length, 4);
    assert.ok(cookies.some((c) => /SameSite=None/i.test(c) && !/Domain=/i.test(c)));
    assert.ok(cookies.some((c) => /Domain=\.securepublish\.work/i.test(c)));
  });

});
