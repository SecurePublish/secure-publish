/**
 * Route-shape / auth gate tests with a minimal in-memory KV + fetch handler.
 * SSO_DEV_BYPASS used only in these unit tests (never default on in wrangler).
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { CLAIM_RESERVED_SLUGS } from "../src/kv.js";

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
    assert.equal(body.publicDomain, false);
    assert.ok("host" in body);
    // No subdomain claimed yet — must be null, never "" (console would show https:///{id})
    assert.equal(body.host, null);
    assert.equal(body.customHostname, null);
    assert.equal(body.customVerified, false);
    assert.equal(body.verify, undefined);
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
    assert.equal(p.title, "Mine");
    assert.equal(p.publisherEmail, "dev@localhost");
    assert.equal(p.mode, "company");
    assert.ok(Array.isArray(p.allowlist));
    assert.ok(Array.isArray(p.viewers));
    assert.equal(typeof p.views, "number");
  });

  it("GET /api/panels title falls back to untitled when missing", async () => {
    const id = "cccccccccccccccccccccccc";
    await env.PANELS.put(
      id,
      JSON.stringify({
        v: 1,
        publishedAt: "2026-10-03T00:00:00Z",
        publisherEmail: "dev@localhost",
        access: { mode: "company", domains: ["localhost"] },
        html: "<html>no title</html>",
      })
    );
    const raw = await env.PANELS.get("idx:pub:dev@localhost");
    const ids = JSON.parse(raw || "[]");
    if (!ids.includes(id)) {
      ids.push(id);
      await env.PANELS.put("idx:pub:dev@localhost", JSON.stringify(ids));
    }
    const res = await worker.fetch(
      new Request("https://worker.test/api/panels?scope=mine", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    const body = await res.json();
    const p = body.panels.find((x) => x.id === id);
    assert.ok(p);
    assert.equal(p.title, "untitled");
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

  it("(5) PUT /api/hosting/custom claims but does not verify (opaque TXT token)", async () => {
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
    assert.equal(body.verify.type, "txt");
    assert.equal(body.verify.name, "_secure-publish.dash.acme.example");
    assert.match(body.verify.value, /^sp-verify=[0-9a-f]{64}$/);
    assert.ok(!body.verify.value.includes("dev@localhost"), "must not publish owner email in DNS");
  });

  it("GET /api/me returns pending custom-domain verify object", async () => {
    const res = await worker.fetch(
      new Request("https://worker.test/api/me", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.customHostname, "dash.acme.example");
    assert.equal(body.customVerified, false);
    assert.equal(body.host, "wise.securepublish.work"); // serving host unchanged
    assert.ok(body.verify);
    assert.equal(body.verify.type, "txt");
    assert.equal(body.verify.name, "_secure-publish.dash.acme.example");
    assert.match(body.verify.value, /^sp-verify=[0-9a-f]{64}$/);
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


  it("POST /api/hosting/custom/verify without claim → 400 no_custom_hostname", async () => {
    const fresh = {
      PANELS: memoryKv(),
      SSO_DEV_BYPASS: "1",
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
    };
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom/verify", {
        method: "POST",
        headers: { Origin: "https://console.pages.dev" },
      }),
      fresh
    );
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.error, "no_custom_hostname");
  });

  it("POST /api/hosting/custom/verify txt_not_found → 422, stays unverified", async () => {
    const me = await (
      await worker.fetch(
        new Request("https://worker.test/api/me", {
          headers: { Origin: "https://console.pages.dev" },
        }),
        env
      )
    ).json();
    const expected = me.verify.value;
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom/verify", {
        method: "POST",
        headers: { Origin: "https://console.pages.dev" },
      }),
      {
        ...env,
        __lookupTxt: async () => ({ ok: true, records: [] }),
      }
    );
    assert.equal(res.status, 422);
    const body = await res.json();
    assert.equal(body.error, "txt_not_found");
    assert.equal(body.verify?.name, "_secure-publish.dash.acme.example");
    assert.equal(body.verify?.value, expected);
    assert.ok(!String(body.verify?.value || "").includes("@"));
  });

  it("POST /api/hosting/custom/verify txt_mismatch → 422", async () => {
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom/verify", {
        method: "POST",
        headers: { Origin: "https://console.pages.dev" },
      }),
      {
        ...env,
        __lookupTxt: async () => ({
          ok: true,
          records: ["sp-verify=deadbeef"],
        }),
      }
    );
    assert.equal(res.status, 422);
    const body = await res.json();
    assert.equal(body.error, "txt_mismatch");
  });

  it("POST /api/hosting/custom/verify without SSO → 401", async () => {
    const locked = {
      PANELS: env.PANELS,
      CONSOLE_ORIGIN: env.CONSOLE_ORIGIN,
    };
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom/verify", {
        method: "POST",
        headers: { Origin: "https://console.pages.dev" },
      }),
      locked
    );
    assert.equal(res.status, 401);
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

  it("POST /api/hosting/custom/verify success → customVerified + host switch + serve OK", async () => {
    const meBefore = await (
      await worker.fetch(
        new Request("https://worker.test/api/me", {
          headers: { Origin: "https://console.pages.dev" },
        }),
        env
      )
    ).json();
    const tokenValue = meBefore.verify.value;

    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom/verify", {
        method: "POST",
        headers: { Origin: "https://console.pages.dev" },
      }),
      {
        ...env,
        __lookupTxt: async (name) => {
          assert.equal(name, "_secure-publish.dash.acme.example");
          return { ok: true, records: [tokenValue] };
        },
      }
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.customVerified, true);
    assert.equal(body.customHostname, "dash.acme.example");
    assert.equal(body.host, "dash.acme.example");

    const me = await worker.fetch(
      new Request("https://worker.test/api/me", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    const meBody = await me.json();
    assert.equal(meBody.host, "dash.acme.example");
    assert.equal(meBody.customHostname, "dash.acme.example");
    assert.equal(meBody.customVerified, true);
    assert.equal(meBody.verify, undefined);

    const serve = await worker.fetch(
      new Request(`https://dash.acme.example/${PANEL_ID}`, {
        headers: { Host: "dash.acme.example" },
      }),
      env
    );
    assert.equal(serve.status, 200);
  });

  it("DELETE is listed in CORS Allow-Methods", async () => {
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom", {
        method: "OPTIONS",
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(res.status, 204);
    assert.match(res.headers.get("Access-Control-Allow-Methods") || "", /DELETE/);
  });

  it("DELETE /api/hosting/custom without SSO → 401", async () => {
    const locked = {
      PANELS: env.PANELS,
      CONSOLE_ORIGIN: env.CONSOLE_ORIGIN,
    };
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom", {
        method: "DELETE",
        headers: { Origin: "https://console.pages.dev" },
      }),
      locked
    );
    assert.equal(res.status, 401);
  });

});

describe("DELETE /api/hosting/custom — pending claim rules", () => {
  function freshEnv(tenantExtra = {}) {
    const panels = memoryKv({
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        domain: "localhost",
        slug: "wise",
        host: "wise.securepublish.work",
        ...tenantExtra,
      }),
      "host:sub:wise": "dev@localhost",
    });
    return {
      PANELS: panels,
      SSO_DEV_BYPASS: "1",
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
    };
  }

  it("clears unverified pending claim; keeps subdomain host", async () => {
    const env = freshEnv({
      customHostname: "pending.acme.example",
      customVerified: false,
      customVerifyToken: "b".repeat(64),
    });
    await env.PANELS.put("host:custom:pending.acme.example", "dev@localhost");

    const del = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom", {
        method: "DELETE",
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(del.status, 200);
    assert.deepEqual(await del.json(), { ok: true });
    assert.equal(await env.PANELS.get("host:custom:pending.acme.example"), null);

    const me = await (
      await worker.fetch(
        new Request("https://worker.test/api/me", {
          headers: { Origin: "https://console.pages.dev" },
        }),
        env
      )
    ).json();
    assert.equal(me.customHostname, null);
    assert.equal(me.customVerified, false);
    assert.equal(me.verify, undefined);
    assert.equal(me.host, "wise.securepublish.work");
  });

  it("404 when none pending", async () => {
    const env = freshEnv();
    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom", {
        method: "DELETE",
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error, "no_pending_custom_hostname");
  });

  it("409 when already verified (must use host-switch, not DELETE)", async () => {
    const env = freshEnv({
      customHostname: "dash.acme.example",
      customVerified: true,
      host: "dash.acme.example",
    });
    await env.PANELS.put("host:custom:dash.acme.example", "dev@localhost");

    const res = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom", {
        method: "DELETE",
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, "custom_already_verified");
    assert.equal(await env.PANELS.get("host:custom:dash.acme.example"), "dev@localhost");
  });

  it("owner-only: session cannot clear another tenant's pending lock", async () => {
    const env = freshEnv({
      customHostname: "mine.acme.example",
      customVerified: false,
      customVerifyToken: "c".repeat(64),
    });
    await env.PANELS.put("host:custom:mine.acme.example", "dev@localhost");
    await env.PANELS.put("host:custom:other.acme.example", "other@acme.example");
    await env.PANELS.put(
      "tenant:user:other@acme.example",
      JSON.stringify({
        email: "other@acme.example",
        customHostname: "other.acme.example",
        customVerified: false,
        customVerifyToken: "d".repeat(64),
      })
    );

    const del = await worker.fetch(
      new Request("https://worker.test/api/hosting/custom", {
        method: "DELETE",
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(del.status, 200);
    assert.equal(await env.PANELS.get("host:custom:mine.acme.example"), null);
    assert.equal(await env.PANELS.get("host:custom:other.acme.example"), "other@acme.example");
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

/**
 * Claim-blocked slugs (PUT /api/hosting/subdomain). Separate from the Worker's
 * product-host list (app/www/apex only) — see kv.js vs worker.js comments.
 * `wise` and `demo` stay claimable (fixtures / interim tenant).
 */
const CLAIM_BLOCKED_SLUGS = [
  "app",
  "www",
  "cname",
  "api",
  "admin",
  "auth",
  "login",
  "mail",
  "smtp",
  "status",
  "docs",
  "static",
  "assets",
  "cdn",
];

function hostingEnv(initial = {}) {
  return {
    PANELS: memoryKv(initial),
    SSO_DEV_BYPASS: "1",
    CONSOLE_ORIGIN: "https://console.pages.dev",
    OAUTH_ALLOWED_DOMAINS: "localhost",
  };
}

function putSubdomain(env, slug) {
  return worker.fetch(
    new Request("https://worker.test/api/hosting/subdomain", {
      method: "PUT",
      headers: {
        Origin: "https://console.pages.dev",
        "content-type": "application/json",
      },
      body: JSON.stringify({ slug }),
    }),
    env
  );
}

describe("PUT /api/hosting/subdomain — reserved_slug", () => {
  it("test list matches Worker CLAIM_RESERVED_SLUGS", () => {
    assert.deepEqual(
      [...CLAIM_RESERVED_SLUGS].sort(),
      [...CLAIM_BLOCKED_SLUGS].sort()
    );
  });

  for (const slug of CLAIM_BLOCKED_SLUGS) {
    it(`rejects ${slug} with 400 {"error":"reserved_slug"} and writes nothing`, async () => {
      const env = hostingEnv();
      const res = await putSubdomain(env, slug);
      assert.equal(res.status, 400);
      assert.deepEqual(await res.json(), { error: "reserved_slug" });
      assert.equal(await env.PANELS.get(`host:sub:${slug}`), null);
      assert.equal(await env.PANELS.get("tenant:user:dev@localhost"), null);
    });
  }

  it("rejects mixed-case reserved slugs (APP, Www, API)", async () => {
    for (const slug of ["APP", "Www", "API"]) {
      const env = hostingEnv();
      const res = await putSubdomain(env, slug);
      assert.equal(res.status, 400, slug);
      assert.deepEqual(await res.json(), { error: "reserved_slug" });
      assert.equal(await env.PANELS.get(`host:sub:${slug.toLowerCase()}`), null);
      assert.equal(await env.PANELS.get("tenant:user:dev@localhost"), null);
    }
  });

  it("rejects _AUTH after sanitize (underscores stripped → auth)", async () => {
    const env = hostingEnv();
    const res = await putSubdomain(env, "_AUTH");
    assert.equal(res.status, 400);
    assert.deepEqual(await res.json(), { error: "reserved_slug" });
    assert.equal(await env.PANELS.get("host:sub:auth"), null);
    assert.equal(await env.PANELS.get("host:sub:_auth"), null);
  });

  it("still claims a normal slug (wise)", async () => {
    const env = hostingEnv();
    const res = await putSubdomain(env, "wise");
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { host: "wise.securepublish.work" });
    assert.equal(await env.PANELS.get("host:sub:wise"), "dev@localhost");
  });

  it("still claims demo (interim tenant in docs — not claim-blocked)", async () => {
    const env = hostingEnv();
    const res = await putSubdomain(env, "demo");
    assert.equal(res.status, 200);
    assert.equal((await res.json()).host, "demo.securepublish.work");
  });

  it("409 subdomain_taken when another owner holds the lock", async () => {
    const env = hostingEnv({ "host:sub:acme": "other@acme.example" });
    const res = await putSubdomain(env, "acme");
    assert.equal(res.status, 409);
    assert.deepEqual(await res.json(), { error: "subdomain_taken" });
    assert.equal(await env.PANELS.get("host:sub:acme"), "other@acme.example");
  });
});

