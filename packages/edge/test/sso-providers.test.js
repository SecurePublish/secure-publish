/**
 * GitHub + Microsoft OAuth — configured vs absent, verified-email fail-closed,
 * same session cookie, company = email domain (not IdP org membership).
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import {
  mintSessionCookie,
  readSessionCookie,
  COOKIE_NAME,
  isProviderConfigured,
  resolveOauthEmail,
} from "../src/sso.js";

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
  };
}

const baseOauth = {
  SESSION_SECRET: "test-session-secret-32chars-min!!",
  CONSOLE_ORIGIN: "https://app.securepublish.work",
  OAUTH_ALLOWED_DOMAINS: "wises.com.br",
  GOOGLE_CLIENT_ID: "google-id",
  GOOGLE_CLIENT_SECRET: "google-secret",
};

describe("isProviderConfigured", () => {
  it("requires both client id and secret", () => {
    assert.equal(isProviderConfigured({}, "google"), false);
    assert.equal(
      isProviderConfigured({ GOOGLE_CLIENT_ID: "x" }, "google"),
      false
    );
    assert.equal(
      isProviderConfigured({ GOOGLE_CLIENT_SECRET: "y" }, "google"),
      false
    );
    assert.equal(
      isProviderConfigured(
        { GOOGLE_CLIENT_ID: "x", GOOGLE_CLIENT_SECRET: "y" },
        "google"
      ),
      true
    );
  });

  it("treats github and microsoft independently of google", () => {
    const env = { ...baseOauth };
    assert.equal(isProviderConfigured(env, "github"), false);
    assert.equal(isProviderConfigured(env, "microsoft"), false);
    assert.equal(
      isProviderConfigured(
        { ...env, GITHUB_CLIENT_ID: "g", GITHUB_CLIENT_SECRET: "s" },
        "github"
      ),
      true
    );
    assert.equal(
      isProviderConfigured(
        { ...env, MICROSOFT_CLIENT_ID: "m", MICROSOFT_CLIENT_SECRET: "s" },
        "microsoft"
      ),
      true
    );
  });
});

describe("OAuth start fail-closed when provider unconfigured", () => {
  it("GET /auth/github → 503 when secrets missing; Google still starts", async () => {
    const env = { ...baseOauth, PANELS: memoryKv() };
    const gh = await worker.fetch(
      new Request("https://demo.securepublish.work/auth/github?next=/signup/", {
        redirect: "manual",
      }),
      env
    );
    assert.equal(gh.status, 503);
    assert.match(await gh.text(), /não configurado/i);

    const google = await worker.fetch(
      new Request("https://demo.securepublish.work/auth/google?next=/signup/", {
        redirect: "manual",
      }),
      env
    );
    assert.equal(google.status, 302);
    assert.match(google.headers.get("location"), /accounts\.google\.com/);
  });

  it("GET /auth/microsoft → 503 when only client id is set (secret missing)", async () => {
    const env = {
      ...baseOauth,
      PANELS: memoryKv(),
      MICROSOFT_CLIENT_ID: "ms-id-only",
    };
    const res = await worker.fetch(
      new Request("https://demo.securepublish.work/auth/microsoft", {
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 503);
  });

  it("GET /_auth/start/github redirects when both secrets present", async () => {
    const env = {
      ...baseOauth,
      PANELS: memoryKv(),
      GITHUB_CLIENT_ID: "gh-id",
      GITHUB_CLIENT_SECRET: "gh-secret",
    };
    const res = await worker.fetch(
      new Request("https://demo.securepublish.work/_auth/start/github", {
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 302);
    const loc = res.headers.get("location");
    assert.match(loc, /github\.com\/login\/oauth\/authorize/);
    assert.match(loc, /client_id=gh-id/);
    assert.match(loc, /scope=.*user%3Aemail|user:email/);
  });

  it("Microsoft start uses /common/ (personal + work), not a single tenant", async () => {
    const env = {
      ...baseOauth,
      PANELS: memoryKv(),
      MICROSOFT_CLIENT_ID: "ms-id",
      MICROSOFT_CLIENT_SECRET: "ms-secret",
    };
    const res = await worker.fetch(
      new Request("https://demo.securepublish.work/auth/microsoft", {
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 302);
    const loc = res.headers.get("location");
    assert.match(loc, /login\.microsoftonline\.com\/common\//);
    assert.doesNotMatch(loc, /access_type=/);
  });
});

describe("Viewer login page — buttons only for configured providers", () => {
  it("Google-only: no GitHub/Microsoft buttons; tip may mention Google", async () => {
    const env = { ...baseOauth, PANELS: memoryKv() };
    const res = await worker.fetch(
      new Request("https://demo.securepublish.work/_auth/login"),
      env
    );
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /Continuar com Google|Continue with Google/);
    assert.doesNotMatch(html, /\/_auth\/start\/github/);
    assert.doesNotMatch(html, /\/_auth\/start\/microsoft/);
  });

  it("with GitHub+Microsoft configured: show all three; tip is not Google-only", async () => {
    const env = {
      ...baseOauth,
      PANELS: memoryKv(),
      GITHUB_CLIENT_ID: "gh",
      GITHUB_CLIENT_SECRET: "ghs",
      MICROSOFT_CLIENT_ID: "ms",
      MICROSOFT_CLIENT_SECRET: "mss",
    };
    const res = await worker.fetch(
      new Request("https://demo.securepublish.work/_auth/login"),
      env
    );
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /\/_auth\/start\/google/);
    assert.match(html, /\/_auth\/start\/github/);
    assert.match(html, /\/_auth\/start\/microsoft/);
    assert.match(html, /Entrar com GitHub|Continue with GitHub/);
    assert.match(html, /Entrar com Microsoft|Continue with Microsoft/);
    assert.doesNotMatch(html, /só Google|Google only|conta Google da empresa —/i);
    assert.doesNotMatch(html, /\bgate\b/i);
  });
});

describe("resolveOauthEmail — verified email fail-closed", () => {
  /** @type {typeof fetch | undefined} */
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("GitHub: accepts verified primary email", async () => {
    globalThis.fetch = async (url) => {
      if (String(url).includes("/user/emails")) {
        return new Response(
          JSON.stringify([
            { email: "other@x.com", primary: false, verified: true },
            { email: "clovis@wises.com.br", primary: true, verified: true },
          ]),
          { status: 200 }
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    };
    const email = await resolveOauthEmail("github", "tok");
    assert.equal(email, "clovis@wises.com.br");
  });

  it("GitHub: fails closed without verified primary (no noreply / unverified fallback)", async () => {
    globalThis.fetch = async (url) => {
      if (String(url).includes("/user/emails")) {
        return new Response(
          JSON.stringify([
            { email: "hide@users.noreply.github.com", primary: true, verified: false },
            { email: "ok@wises.com.br", primary: false, verified: true },
          ]),
          { status: 200 }
        );
      }
      if (String(url).includes("/user")) {
        return new Response(
          JSON.stringify({ email: "fallback@users.noreply.github.com" }),
          { status: 200 }
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    };
    assert.equal(await resolveOauthEmail("github", "tok"), null);
  });

  it("Microsoft: uses verified email claim; rejects preferred_username-only guess", async () => {
    assert.equal(
      await resolveOauthEmail("microsoft", "tok", {
        idTokenClaims: { preferred_username: "someone@contoso.com" },
      }),
      null
    );
    assert.equal(
      await resolveOauthEmail("microsoft", "tok", {
        idTokenClaims: {
          email: "ana@wises.com.br",
          email_verified: true,
        },
      }),
      "ana@wises.com.br"
    );
  });

  it("Microsoft: Graph mail works; does not use unverified UPN guest form", async () => {
    globalThis.fetch = async (url) => {
      if (String(url).includes("graph.microsoft.com")) {
        return new Response(
          JSON.stringify({
            mail: null,
            userPrincipalName: "user_gmail.com#EXT#@tenant.onmicrosoft.com",
          }),
          { status: 200 }
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    };
    assert.equal(await resolveOauthEmail("microsoft", "tok"), null);

    globalThis.fetch = async (url) => {
      if (String(url).includes("graph.microsoft.com")) {
        return new Response(
          JSON.stringify({ mail: "bob@wises.com.br", userPrincipalName: "bob@wises.com.br" }),
          { status: 200 }
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    };
    assert.equal(await resolveOauthEmail("microsoft", "tok"), "bob@wises.com.br");
  });

  it("Google: rejects unverified email", async () => {
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({ email: "x@wises.com.br", verified_email: false }),
        { status: 200 }
      );
    assert.equal(await resolveOauthEmail("google", "tok"), null);
  });
});

describe("OAuth callback — clear page on missing verified email; same cookie", () => {
  /** @type {typeof fetch | undefined} */
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function encodeState(obj) {
    return Buffer.from(JSON.stringify(obj))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  it("GitHub callback without verified primary → HTML fail-closed, no Set-Cookie", async () => {
    globalThis.fetch = async (url, init) => {
      if (String(url).includes("github.com/login/oauth/access_token")) {
        return new Response(JSON.stringify({ access_token: "gh-tok" }), { status: 200 });
      }
      if (String(url).includes("/user/emails")) {
        return new Response(
          JSON.stringify([{ email: "x@users.noreply.github.com", primary: true, verified: false }]),
          { status: 200 }
        );
      }
      if (String(url).includes("api.github.com/user")) {
        return new Response(JSON.stringify({ email: null }), { status: 200 });
      }
      throw new Error(`unexpected ${url} ${init?.method}`);
    };

    const state = encodeState({ returnTo: "/", provider: "github", n: "1" });
    const env = {
      ...baseOauth,
      PANELS: memoryKv(),
      GITHUB_CLIENT_ID: "gh",
      GITHUB_CLIENT_SECRET: "ghs",
    };
    const res = await worker.fetch(
      new Request(
        `https://demo.securepublish.work/_auth/callback/github?code=abc&state=${state}`,
        { redirect: "manual" }
      ),
      env
    );
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("set-cookie"), null);
    const body = await res.text();
    assert.match(body, /text\/html|<html|e-mail|email/i);
    assert.doesNotMatch(body, /users\.noreply\.github\.com/i);
    assert.doesNotMatch(body, /\bgate\b/i);
  });

  it("GitHub and Microsoft mint the same cookie name and session shape as Google", async () => {
    for (const provider of ["google", "github", "microsoft"]) {
      const cookie = await mintSessionCookie(
        {
          email: "clovis@wises.com.br",
          provider,
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        baseOauth.SESSION_SECRET,
        baseOauth,
        "https://demo.securepublish.work/"
      );
      assert.match(cookie, new RegExp(`^${COOKIE_NAME}=`));
      assert.match(cookie, /HttpOnly/);
      assert.match(cookie, /Secure/);
      assert.match(cookie, /SameSite=Lax/);
      assert.match(cookie, /Domain=\.securepublish\.work/);

      const session = await readSessionCookie(
        new Request("https://demo.securepublish.work/", {
          headers: { cookie: cookie.split(";")[0] },
        }),
        baseOauth.SESSION_SECRET
      );
      assert.equal(session.email, "clovis@wises.com.br");
      assert.equal(session.provider, provider);
      assert.ok(session.exp > Math.floor(Date.now() / 1000));
    }
  });
});

describe("Company access = email domain after SSO (not GitHub org)", () => {
  it("GitHub-authenticated user from another company is denied on company panel", async () => {
    const panels = memoryKv({
      aaaaaaaaaaaaaaaaaaaaaaaa: JSON.stringify({
        v: 1,
        title: "Painel",
        publisherEmail: "clovis@wises.com.br",
        access: { mode: "company", domains: ["wises.com.br"] },
        html: "<p>ok</p>",
      }),
    });
    const env = {
      ...baseOauth,
      PANELS: panels,
      GITHUB_CLIENT_ID: "gh",
      GITHUB_CLIENT_SECRET: "ghs",
    };
    const outsider = await mintSessionCookie(
      {
        email: "alice@othercorp.io",
        provider: "github",
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      env.SESSION_SECRET,
      env,
      "https://secure-publish.clovist.workers.dev/"
    );
    const denied = await worker.fetch(
      new Request("https://secure-publish.clovist.workers.dev/aaaaaaaaaaaaaaaaaaaaaaaa", {
        headers: { cookie: outsider.split(";")[0] },
      }),
      env
    );
    assert.equal(denied.status, 403);
    assert.match(await denied.text(), /domínio|domain|empresa/i);

    const insider = await mintSessionCookie(
      {
        email: "ana@wises.com.br",
        provider: "github",
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      env.SESSION_SECRET,
      env,
      "https://secure-publish.clovist.workers.dev/"
    );
    const ok = await worker.fetch(
      new Request("https://secure-publish.clovist.workers.dev/aaaaaaaaaaaaaaaaaaaaaaaa", {
        headers: { cookie: insider.split(";")[0] },
      }),
      env
    );
    assert.equal(ok.status, 200);
    assert.match(await ok.text(), /<p>ok<\/p>/);
  });
});

describe("Device-code login opens provider picker (not Google-only)", () => {
  it("verification_url points at /_auth/login?device=…", async () => {
    const env = { ...baseOauth, PANELS: memoryKv() };
    const res = await worker.fetch(
      new Request("https://demo.securepublish.work/api/device/code", { method: "POST" }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.match(body.device_code, /^[a-f0-9]{64}$/);
    assert.match(
      body.verification_url,
      /\/_auth\/login\?device=[a-f0-9]{64}$/
    );
    assert.doesNotMatch(body.verification_url, /\/auth\/google/);
  });
});
