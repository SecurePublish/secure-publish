/**
 * GET /auth/switch — clear session like logout, validate ?return=, Google prompt=select_account.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { mintSessionCookie, validateSwitchReturn, resolvePostLoginLocation } from "../src/sso.js";

const PANEL_ID = "aaaaaaaaaaaaaaaaaaaaaaaa";
const VALID_RETURN = `https://wise.securepublish.work/${PANEL_ID}`;
const SIGNUP = "https://app.securepublish.work/signup/";

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

function oauthEnv() {
  return {
    PANELS: memoryKv(),
    SESSION_SECRET: "test-session-secret-at-least-32-chars!!",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
  };
}

function decodeState(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = String(s).replace(/-/g, "+").replace(/_/g, "/") + pad;
  return JSON.parse(atob(b64));
}

function encodeState(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function setCookies(res) {
  if (typeof res.headers.getSetCookie === "function") return res.headers.getSetCookie();
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

describe("validateSwitchReturn", () => {
  it("accepts https://wise.securepublish.work/<24hex> and drops query/hash", () => {
    assert.equal(validateSwitchReturn(VALID_RETURN), VALID_RETURN);
    assert.equal(
      validateSwitchReturn(`${VALID_RETURN}?q=1#hash`),
      VALID_RETURN
    );
  });

  it("accepts apex securepublish.work", () => {
    assert.equal(
      validateSwitchReturn("https://securepublish.work/x"),
      "https://securepublish.work/x"
    );
  });

  const rejected = [
    ["https://securepublish.work.evil.com/x", "suffix host"],
    ["https://evil-securepublish.work/x", "lookalike host"],
    ["http://wise.securepublish.work/" + PANEL_ID, "http:"],
    ["https://user:pw@wise.securepublish.work/x", "userinfo"],
    ["https://wise.securepublish.work//evil.com", "double-slash path"],
    ["https://wise.securepublish.work/foo\\bar", "backslash path"],
    ["https://wise.securepublish.work/foo/bar\\baz", "backslash anywhere"],
    ["javascript:alert(1)", "javascript:"],
    ["not a url", "garbage"],
    ["", "empty"],
  ];

  for (const [raw, label] of rejected) {
    it(`rejects ${label}`, () => {
      assert.equal(validateSwitchReturn(raw), null, raw);
    });
  }
});

describe("resolvePostLoginLocation — re-validate, do not trust state", () => {
  const env = { CONSOLE_ORIGIN: "https://app.securepublish.work" };

  it("keeps a valid panel return", () => {
    assert.equal(resolvePostLoginLocation(VALID_RETURN, env), VALID_RETURN);
  });

  it("does not honor an evil return in state", () => {
    const loc = resolvePostLoginLocation("https://evil.com/phish", env);
    assert.ok(loc);
    assert.equal(new URL(loc).hostname.includes("evil.com"), false);
    assert.notEqual(loc, "https://evil.com/phish");
  });
});

describe("GET /auth/switch", () => {
  it("clears session cookies like logout, no-store, Google prompt=select_account, return in state", async () => {
    const env = oauthEnv();
    const cookie = await mintSessionCookie(
      {
        email: "ana@wises.com.br",
        provider: "google",
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      env.SESSION_SECRET,
      env,
      "https://app.securepublish.work/_auth/callback/google"
    );
    const res = await worker.fetch(
      new Request(
        `https://app.securepublish.work/auth/switch?return=${encodeURIComponent(VALID_RETURN)}`,
        {
          headers: { Cookie: cookie.split(";")[0], Host: "app.securepublish.work" },
          redirect: "manual",
        }
      ),
      env
    );
    assert.equal(res.status, 302);
    assert.match(res.headers.get("cache-control") || "", /no-store/i);
    const cookies = setCookies(res);
    assert.ok(cookies.some((c) => /Domain=\.securepublish\.work/i.test(c) && /Max-Age=0/i.test(c)));
    assert.ok(cookies.some((c) => /SameSite=Lax/i.test(c) && /Max-Age=0/i.test(c)));
    const loc = new URL(res.headers.get("location"));
    assert.equal(loc.hostname, "accounts.google.com");
    assert.equal(loc.searchParams.get("prompt"), "select_account");
    const state = decodeState(loc.searchParams.get("state"));
    assert.equal(state.returnTo, VALID_RETURN);
  });

  it("rejected return values never survive into OAuth state", async () => {
    const env = oauthEnv();
    const evil = [
      "https://securepublish.work.evil.com/x",
      "https://evil-securepublish.work/x",
      "http://wise.securepublish.work/" + PANEL_ID,
      "https://user:pw@wise.securepublish.work/x",
      "https://wise.securepublish.work//evil.com",
      "javascript:alert(1)",
      "totally-garbage",
    ];
    for (const raw of evil) {
      const res = await worker.fetch(
        new Request(
          `https://app.securepublish.work/auth/switch?return=${encodeURIComponent(raw)}`,
          { headers: { Host: "app.securepublish.work" }, redirect: "manual" }
        ),
        env
      );
      assert.equal(res.status, 302, raw);
      const loc = new URL(res.headers.get("location"));
      const state = decodeState(loc.searchParams.get("state"));
      assert.notEqual(state.returnTo, raw, raw);
      assert.equal(state.returnTo, SIGNUP, raw);
    }
  });
});

describe("OAuth callback re-validates returnTo", () => {
  const originalFetch = globalThis.fetch;

  after(() => {
    globalThis.fetch = originalFetch;
  });

  function mockGoogleOk(email = "new@wises.com.br") {
    globalThis.fetch = async (url) => {
      const href = String(url);
      if (href.includes("oauth2.googleapis.com/token")) {
        return new Response(JSON.stringify({ access_token: "tok" }), { status: 200 });
      }
      if (href.includes("googleapis.com/oauth2/v2/userinfo")) {
        return new Response(JSON.stringify({ email }), { status: 200 });
      }
      return new Response("nope", { status: 404 });
    };
  }

  it("validated panel return from /auth/switch survives the round-trip", async () => {
    const env = oauthEnv();
    const start = await worker.fetch(
      new Request(
        `https://app.securepublish.work/auth/switch?return=${encodeURIComponent(VALID_RETURN)}`,
        { headers: { Host: "app.securepublish.work" }, redirect: "manual" }
      ),
      env
    );
    const state = new URL(start.headers.get("location")).searchParams.get("state");
    mockGoogleOk();
    const cb = await worker.fetch(
      new Request(
        `https://app.securepublish.work/_auth/callback/google?code=abc&state=${encodeURIComponent(state)}`,
        { headers: { Host: "app.securepublish.work" }, redirect: "manual" }
      ),
      env
    );
    assert.equal(cb.status, 302);
    assert.equal(cb.headers.get("location"), VALID_RETURN);
  });

  it("tampered state with an evil return does not redirect there", async () => {
    const env = oauthEnv();
    const evilState = encodeState({
      returnTo: "https://evil.com/phish",
      provider: "google",
      n: "tamper",
    });
    mockGoogleOk();
    const cb = await worker.fetch(
      new Request(
        `https://app.securepublish.work/_auth/callback/google?code=abc&state=${encodeURIComponent(evilState)}`,
        { headers: { Host: "app.securepublish.work" }, redirect: "manual" }
      ),
      env
    );
    assert.equal(cb.status, 302);
    const loc = cb.headers.get("location") || "";
    assert.equal(loc.includes("evil.com"), false);
    assert.notEqual(loc, "https://evil.com/phish");
  });
});
