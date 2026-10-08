/**
 * Marcus: /api/* only on the app host; cookie mutations need Origin + JSON.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { mintSessionCookie } from "../src/sso.js";

const PANEL_404 = "Not found — invalid or unknown panel id.";
const APP = "https://app.securepublish.work";
const CONSOLE = "https://app.securepublish.work";
const PANEL_HOST = "wise.securepublish.work";
const CODE = "k7f3qx2abc";
const OWNER = "ana@wises.com.br";
const SECRET = "test-session-secret-at-least-32-chars!!";

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
    async list() {
      return {
        keys: [...store.keys()].sort().map((name) => ({ name })),
        list_complete: true,
      };
    },
    _store: store,
  };
}

function oauthEnv(panels, extra = {}) {
  return {
    PANELS: panels,
    SESSION_SECRET: SECRET,
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN: CONSOLE,
    OAUTH_ALLOWED_DOMAINS: "wises.com.br",
    ...extra,
  };
}

function tenantKv() {
  return memoryKv({
    [CODE]: JSON.stringify({
      v: 1,
      title: "Painel",
      html: "<html>ok</html>",
      publishedAt: "2026-10-08T00:00:00.000Z",
      publisherEmail: OWNER,
      name: "performance-out-26",
      access: { mode: "company", domains: ["wises.com.br"] },
    }),
    [`idx:pub:${OWNER}`]: JSON.stringify([CODE]),
    [`idx:domain:wises.com.br`]: JSON.stringify([CODE]),
    [`tenant:user:${OWNER}`]: JSON.stringify({
      email: OWNER,
      domain: "wises.com.br",
      slug: "wise",
      host: PANEL_HOST,
    }),
    "host:sub:wise": OWNER,
  });
}

async function cookieFor(env, email = OWNER) {
  const setCookie = await mintSessionCookie(
    {
      email,
      provider: "google",
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    env.SESSION_SECRET,
    env,
    `${APP}/_auth/callback/google`
  );
  return setCookie.split(";")[0];
}

function appReq(path, { method = "GET", headers = {}, body } = {}) {
  const init = { method, headers, redirect: "manual" };
  if (body !== undefined) init.body = body;
  return new Request(`${APP}${path}`, init);
}

describe("API host scoping", () => {
  it("GET /api/me on a panel host with a valid session is the same 404 as unknown paths", async () => {
    const env = oauthEnv(tenantKv());
    const cookie = await cookieFor(env);
    const api = await worker.fetch(
      new Request(`https://${PANEL_HOST}/api/me`, {
        headers: { Host: PANEL_HOST, Cookie: cookie },
        redirect: "manual",
      }),
      env
    );
    const unknown = await worker.fetch(
      new Request(`https://${PANEL_HOST}/not-a-panel`, {
        headers: { Host: PANEL_HOST, Cookie: cookie },
        redirect: "manual",
      }),
      env
    );
    assert.equal(api.status, 404);
    assert.equal(unknown.status, 404);
    assert.equal(await api.text(), PANEL_404);
    assert.equal(await unknown.text(), PANEL_404);
  });

  it("GET /api/me on apex and workers.dev is the same unknown-path 404", async () => {
    const env = oauthEnv(tenantKv());
    const cookie = await cookieFor(env);
    for (const host of ["securepublish.work", "edge.workers.dev"]) {
      const res = await worker.fetch(
        new Request(`https://${host}/api/me`, {
          headers: { Host: host, Cookie: cookie },
          redirect: "manual",
        }),
        env
      );
      assert.equal(res.status, 404, host);
      assert.equal(await res.text(), PANEL_404);
    }
  });
});

describe("CSRF for cookie-authenticated /api mutations", () => {
  it("POST /api/device/bind with a valid cookie and panel Origin is 403 csrf_origin", async () => {
    const env = oauthEnv(memoryKv());
    const cookie = await cookieFor(env);
    const started = await worker.fetch(
      appReq("/api/device/code", { method: "POST", headers: { accept: "application/json" } }),
      env
    );
    const { device_code } = await started.json();
    const res = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: {
          Origin: `https://${PANEL_HOST}`,
          Cookie: cookie,
          "content-type": "application/json",
        },
        body: JSON.stringify({ device_code }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "csrf_origin");
  });

  it("cookie POST with the console Origin but text/plain is 403 csrf_content_type", async () => {
    const env = oauthEnv(memoryKv());
    const cookie = await cookieFor(env);
    const started = await worker.fetch(
      appReq("/api/device/code", { method: "POST", headers: { accept: "application/json" } }),
      env
    );
    const { device_code } = await started.json();
    const res = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: {
          Origin: CONSOLE,
          Cookie: cookie,
          "content-type": "text/plain",
        },
        body: JSON.stringify({ device_code }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "csrf_content_type");
  });

  it("cookie POST with the console Origin and JSON (charset allowed) succeeds", async () => {
    const env = oauthEnv(memoryKv());
    const cookie = await cookieFor(env);
    const started = await worker.fetch(
      appReq("/api/device/code", { method: "POST", headers: { accept: "application/json" } }),
      env
    );
    const { device_code } = await started.json();
    const res = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: {
          Origin: CONSOLE,
          Cookie: cookie,
          "content-type": "application/json; charset=utf-8",
        },
        body: JSON.stringify({ device_code }),
      }),
      env
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).ok, true);
  });

  it("missing Origin on a cookie mutation is 403 csrf_origin", async () => {
    const env = oauthEnv(memoryKv());
    const cookie = await cookieFor(env);
    const started = await worker.fetch(
      appReq("/api/device/code", { method: "POST", headers: { accept: "application/json" } }),
      env
    );
    const { device_code } = await started.json();
    const res = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: {
          Cookie: cookie,
          "content-type": "application/json",
        },
        body: JSON.stringify({ device_code }),
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "csrf_origin");
  });

  it("Bearer POST /api/panels with no Origin still publishes", async () => {
    const panels = tenantKv();
    const env = oauthEnv(panels);
    const started = await worker.fetch(
      appReq("/api/device/code", { method: "POST", headers: { accept: "application/json" } }),
      env
    );
    const start = await started.json();
    const cookie = await cookieFor(env);
    const bound = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: {
          Origin: CONSOLE,
          Cookie: cookie,
          "content-type": "application/json",
        },
        body: JSON.stringify({ device_code: start.device_code }),
      }),
      env
    );
    assert.equal(bound.status, 200);
    const polled = await worker.fetch(
      appReq("/api/device/token", {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify({ device_code: start.device_code }),
      }),
      env
    );
    assert.equal(polled.status, 200);
    const { access_token } = await polled.json();
    const res = await worker.fetch(
      appReq("/api/panels", {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          authorization: `Bearer ${access_token}`,
        },
        body: JSON.stringify({ html: "<p>cli</p>", title: "CLI" }),
      }),
      env
    );
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.host, PANEL_HOST);
    assert.match(body.id, /^[abcdefghijklmnopqrstuvwxyz234567]{10}$/);
  });

  it("CLI device/code and device/token still work without Origin", async () => {
    const env = oauthEnv(memoryKv());
    const started = await worker.fetch(
      appReq("/api/device/code", {
        method: "POST",
        headers: { accept: "application/json" },
      }),
      env
    );
    assert.equal(started.status, 200);
    const start = await started.json();
    assert.ok(start.device_code);
    assert.ok(start.verification_url);

    const pending = await worker.fetch(
      appReq("/api/device/token", {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify({ device_code: start.device_code }),
      }),
      env
    );
    assert.equal(pending.status, 400);
    assert.equal((await pending.json()).error, "authorization_pending");
  });

  it("PATCH name and PATCH access with a bad Origin are 403 csrf_origin", async () => {
    const env = oauthEnv(tenantKv());
    const cookie = await cookieFor(env);
    const bad = { Origin: `https://${PANEL_HOST}`, Cookie: cookie, "content-type": "application/json" };

    const nameRes = await worker.fetch(
      appReq(`/api/panels/${CODE}/name`, {
        method: "PATCH",
        headers: bad,
        body: JSON.stringify({ name: "hacked" }),
      }),
      env
    );
    assert.equal(nameRes.status, 403);
    assert.equal((await nameRes.json()).error, "csrf_origin");

    const accessRes = await worker.fetch(
      appReq(`/api/panels/${CODE}/access`, {
        method: "PATCH",
        headers: bad,
        body: JSON.stringify({ mode: "allowlist", allowlist: ["eve@wises.com.br"] }),
      }),
      env
    );
    assert.equal(accessRes.status, 403);
    assert.equal((await accessRes.json()).error, "csrf_origin");
  });

  it("POST /api/hosting/custom/verify with a bad Origin is 403 csrf_origin", async () => {
    const env = oauthEnv(tenantKv(), { CUSTOM_DOMAINS_ENABLED: "true" });
    const cookie = await cookieFor(env);
    const res = await worker.fetch(
      appReq("/api/hosting/custom/verify", {
        method: "POST",
        headers: {
          Origin: `https://${PANEL_HOST}`,
          Cookie: cookie,
          "content-type": "application/json",
        },
        body: "{}",
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "csrf_origin");
  });
});
