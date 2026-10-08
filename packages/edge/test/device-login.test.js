/**
 * RFC 8628-style device login: polling secret vs user_code, no auto-approve.
 */
import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { handleAuthRoutes, mintSessionCookie, safeReturnTo } from "../src/sso.js";

const APP = "https://app.securepublish.work";
const CONSOLE = "https://app.securepublish.work";
const PANEL_HOST = "wise.securepublish.work";
const OWNER = "ana@wises.com.br";
const SECRET = "test-session-secret-at-least-32-chars!!";
const USER_CODE_RE = /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/;
const INVALID = { error: "device_code_invalid" };

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

async function startDevice(env) {
  const res = await worker.fetch(
    appReq("/api/device/code", { method: "POST", headers: { accept: "application/json" } }),
    env
  );
  assert.equal(res.status, 200);
  return res.json();
}

function bindHeaders(cookie, extra = {}) {
  return {
    Origin: CONSOLE,
    Cookie: cookie,
    "content-type": "application/json",
    ...extra,
  };
}

async function bind(env, cookie, body, extraHeaders = {}) {
  return worker.fetch(
    appReq("/api/device/bind", {
      method: "POST",
      headers: bindHeaders(cookie, extraHeaders),
      body: JSON.stringify(body),
    }),
    env
  );
}

async function poll(env, device_code) {
  return worker.fetch(
    appReq("/api/device/token", {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/json" },
      body: JSON.stringify({ device_code }),
    }),
    env
  );
}

function encodeState(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeState(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = String(s).replace(/-/g, "+").replace(/_/g, "/") + pad;
  return JSON.parse(atob(b64));
}

describe("POST /api/device/code", () => {
  it("returns user_code in XXXX-XXXX form and a verification_url with no codes", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    assert.match(start.device_code, /^[a-f0-9]{64}$/);
    assert.match(start.user_code, USER_CODE_RE);
    assert.equal(start.verification_url, `${APP}/device`);
    assert.equal(start.expires_in, 600);
    assert.equal(start.interval, 2);
    assert.equal(start.verification_url.includes(start.device_code), false);
    assert.equal(start.verification_url.includes(start.user_code), false);
    assert.equal(start.verification_url.includes(start.user_code.replace("-", "")), false);
  });
});

describe("OAuth no longer auto-approves a device", () => {
  const origFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = origFetch;
  });

  it("ignores device on /auth/google and does not put it in OAuth state", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    const res = await handleAuthRoutes(
      new Request(`${APP}/auth/google?device=${start.device_code}`, { redirect: "manual" }),
      env
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location"));
    assert.equal(loc.searchParams.get("device"), null);
    const state = decodeState(loc.searchParams.get("state"));
    assert.equal(state.device, undefined);
    assert.equal(String(res.headers.get("location")).includes(start.device_code), false);
  });

  it("/_auth/login does not forward ?device= into start links", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    const res = await handleAuthRoutes(
      new Request(`${APP}/_auth/login?device=${start.device_code}&return_to=${encodeURIComponent("/app/device")}`),
      env
    );
    const html = await res.text();
    assert.equal(html.includes(start.device_code), false);
    assert.equal(html.includes("device="), false);
    assert.match(html, /return_to=%2Fapp%2Fdevice/);
  });

  it("OAuth callback with device in state logs in normally and leaves the device pending", async () => {
    const panels = memoryKv();
    const env = oauthEnv(panels);
    const start = await startDevice(env);
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes("oauth2.googleapis.com/token")) {
        return new Response(JSON.stringify({ access_token: "tok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (u.includes("googleapis.com/oauth2/v2/userinfo")) {
        return new Response(JSON.stringify({ email: "Ana@Wises.com.br" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch ${u}`);
    };
    const state = encodeState({
      returnTo: "/app/device",
      provider: "google",
      n: "n1",
      device: start.device_code,
    });
    const res = await handleAuthRoutes(
      new Request(`${APP}/_auth/callback/google?code=abc&state=${state}`, {
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 302);
    const loc = res.headers.get("location") || "";
    assert.equal(loc, `${APP}/app/device`);
    assert.equal(loc.includes("/_auth/device/done"), false);
    assert.equal(loc.includes(start.device_code), false);
    assert.equal(loc.includes(start.user_code), false);
    const pending = await poll(env, start.device_code);
    assert.equal(pending.status, 400);
    assert.equal((await pending.json()).error, "authorization_pending");
  });
});

describe("login return_to for the console device page", () => {
  it("accepts /device and /app/device on the app host, not an external URL", async () => {
    const env = oauthEnv(memoryKv());
    assert.equal(await safeReturnTo("/device", env), `${APP}/device`);
    assert.equal(await safeReturnTo("/app/device", env), `${APP}/app/device`);
    assert.equal(await safeReturnTo("/device/", env), `${APP}/device/`);
    assert.equal(
      await safeReturnTo("https://evil.example/device", env),
      `${APP}/`
    );
  });
});

describe("POST /api/device/bind", () => {
  it("approves a dashed lowercase spaced user_code for the session email", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    const cookie = await cookieFor(env, "Ana@Wises.com.br");
    const messy = `  ${start.user_code.toLowerCase()}  `;
    const res = await bind(env, cookie, { user_code: messy });
    assert.equal(res.status, 200);
    const bound = await res.json();
    assert.equal(bound.ok, true);
    assert.equal(bound.device_code, undefined);
    const polled = await poll(env, start.device_code);
    assert.equal(polled.status, 200);
    const body = await polled.json();
    assert.equal(body.email, "ana@wises.com.br");
    assert.equal(body.token_type, "Bearer");
    assert.match(body.access_token, /^[a-f0-9]{64}$/);
  });

  it("device_code in the bind body is 404 device_code_invalid", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    const cookie = await cookieFor(env);
    const res = await bind(env, cookie, { device_code: start.device_code });
    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), INVALID);
    const pending = await poll(env, start.device_code);
    assert.equal((await pending.json()).error, "authorization_pending");
  });

  it("wrong, expired, and reused user_code return the same 404 body", async () => {
    const panels = memoryKv();
    const env = oauthEnv(panels);
    const cookie = await cookieFor(env);

    const wrong = await bind(env, cookie, { user_code: "BBBB-CCCC" });
    assert.equal(wrong.status, 404);
    const wrongBody = await wrong.json();
    assert.deepEqual(wrongBody, INVALID);

    const expiredStart = await startDevice(env);
    const rec = JSON.parse(panels._store.get(`device:${expiredStart.device_code}`));
    rec.exp = 1;
    panels._store.set(`device:${expiredStart.device_code}`, JSON.stringify(rec));
    const expired = await bind(env, cookie, { user_code: expiredStart.user_code });
    assert.equal(expired.status, 404);
    assert.deepEqual(await expired.json(), wrongBody);

    const okStart = await startDevice(env);
    const first = await bind(env, cookie, { user_code: okStart.user_code });
    assert.equal(first.status, 200);
    const reused = await bind(env, cookie, { user_code: okStart.user_code });
    assert.equal(reused.status, 404);
    assert.deepEqual(await reused.json(), wrongBody);
  });

  it("6th failed bind for the same account is 429 device_code_rate_limited", async () => {
    const env = oauthEnv(memoryKv());
    const cookie = await cookieFor(env);
    const bodies = [];
    for (let i = 0; i < 5; i++) {
      const res = await bind(env, cookie, { user_code: "BBBB-CCCC" });
      assert.equal(res.status, 404);
      bodies.push(await res.json());
    }
    for (const body of bodies) assert.deepEqual(body, INVALID);
    const sixth = await bind(env, cookie, { user_code: "BBBB-CCCC" });
    assert.equal(sixth.status, 429);
    assert.deepEqual(await sixth.json(), { error: "device_code_rate_limited" });
  });

  it("51st failed bind globally is 429 even for a fresh account", async () => {
    const panels = memoryKv();
    const env = oauthEnv(panels);
    await panels.put("devbindfail:global", "50");
    const cookie = await cookieFor(env, "bia@wises.com.br");
    const res = await bind(env, cookie, { user_code: "BBBB-CCCC" });
    assert.equal(res.status, 429);
    assert.deepEqual(await res.json(), { error: "device_code_rate_limited" });
  });

  it("bind without cookie is 401", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    const res = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: { Origin: CONSOLE, "content-type": "application/json" },
        body: JSON.stringify({ user_code: start.user_code }),
      }),
      env
    );
    assert.equal(res.status, 401);
  });

  it("bind with Bearer is 401 even with cookie + Origin/JSON", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    const cookie = await cookieFor(env);
    const res = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: {
          Origin: CONSOLE,
          Cookie: cookie,
          "content-type": "application/json",
          authorization: `Bearer ${"ab".repeat(32)}`,
        },
        body: JSON.stringify({ user_code: start.user_code }),
      }),
      env
    );
    assert.equal(res.status, 401);
  });

  it("bind with a bad Origin or non-JSON is 403 CSRF", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    const cookie = await cookieFor(env);
    const badOrigin = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: {
          Origin: `https://${PANEL_HOST}`,
          Cookie: cookie,
          "content-type": "application/json",
        },
        body: JSON.stringify({ user_code: start.user_code }),
      }),
      env
    );
    assert.equal(badOrigin.status, 403);
    assert.equal((await badOrigin.json()).error, "csrf_origin");

    const badType = await worker.fetch(
      appReq("/api/device/bind", {
        method: "POST",
        headers: {
          Origin: CONSOLE,
          Cookie: cookie,
          "content-type": "text/plain",
        },
        body: JSON.stringify({ user_code: start.user_code }),
      }),
      env
    );
    assert.equal(badType.status, 403);
    assert.equal((await badType.json()).error, "csrf_content_type");
  });
});

describe("POST /api/device/token", () => {
  it("never accepts a user_code as the polling secret", async () => {
    const env = oauthEnv(memoryKv());
    const start = await startDevice(env);
    const cookie = await cookieFor(env);
    const bound = await bind(env, cookie, { user_code: start.user_code });
    assert.equal(bound.status, 200);
    const asUser = await poll(env, start.user_code);
    assert.equal(asUser.status, 400);
    assert.equal((await asUser.json()).error, "invalid_request");
    const asPlain = await poll(env, start.user_code.replace("-", ""));
    assert.equal(asPlain.status, 400);
    assert.equal((await asPlain.json()).error, "invalid_request");
  });

  it("approved and consumed device records are written with expirationTtl", async () => {
    const puts = [];
    const inner = memoryKv();
    const panels = {
      ...inner,
      async put(key, value, opts) {
        puts.push({ key, value: String(value), opts: opts || null });
        return inner.put(key, value);
      },
    };
    const env = oauthEnv(panels);
    const start = await startDevice(env);
    const cookie = await cookieFor(env);
    const bound = await bind(env, cookie, { user_code: start.user_code });
    assert.equal(bound.status, 200);
    const polled = await poll(env, start.device_code);
    assert.equal(polled.status, 200);

    const devicePuts = puts.filter((p) => p.key === `device:${start.device_code}`);
    const approved = devicePuts.find((p) => JSON.parse(p.value).status === "approved");
    const consumed = devicePuts.find((p) => JSON.parse(p.value).status === "consumed");
    assert.ok(approved, "approved put");
    assert.ok(consumed, "consumed put");
    assert.equal(typeof approved.opts?.expirationTtl, "number");
    assert.ok(approved.opts.expirationTtl >= 60);
    assert.ok(approved.opts.expirationTtl <= 600);
    assert.equal(typeof consumed.opts?.expirationTtl, "number");
    assert.ok(consumed.opts.expirationTtl >= 60);
    assert.ok(consumed.opts.expirationTtl <= 600);
  });
});
