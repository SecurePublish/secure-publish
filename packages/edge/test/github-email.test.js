/**
 * GitHub SSO: pick a verified /user/emails address whose domain is allowed,
 * not merely the primary verified email (often a personal gmail).
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import {
  handleAuthRoutes,
  selectGitHubEmail,
  readSessionCookie,
} from "../src/sso.js";

const APP = "https://app.securepublish.work";
const SECRET = "test-session-secret-at-least-32-chars!!";
const DENIED = "Acesso negado: domínio de e-mail não autorizado.";

function env(extra = {}) {
  return {
    SESSION_SECRET: SECRET,
    GITHUB_CLIENT_ID: "gh-id",
    GITHUB_CLIENT_SECRET: "gh-secret",
    CONSOLE_ORIGIN: APP,
    OAUTH_ALLOWED_DOMAINS: "wises.com.br",
    ...extra,
  };
}

function emails(list) {
  return list.map((e) => ({
    primary: false,
    verified: false,
    visibility: null,
    ...e,
  }));
}

function encodeState(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("selectGitHubEmail — verified + exact allowed domain", () => {
  it("picks the first verified allowed-domain email over a primary gmail", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@wises.com.br", verified: true },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "ana@wises.com.br");
  });

  it("falls back to primary verified gmail when the work email is unverified", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@wises.com.br", verified: false },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "ana@gmail.com");
  });

  it("never selects an entry that is not verified: true", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@wises.com.br", verified: 1 },
      { email: "other@wises.com.br" },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "ana@gmail.com");
  });

  it("picks the first allowed verified email in GitHub list order, not primary", () => {
    const list = emails([
      { email: "first@wises.com.br", verified: true },
      { email: "second@wises.com.br", primary: true, verified: true },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "first@wises.com.br");
  });

  it("matches an uppercase OAUTH_ALLOWED_DOMAINS entry (WISES.COM.BR)", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@wises.com.br", verified: true },
    ]);
    assert.equal(
      selectGitHubEmail(list, env({ OAUTH_ALLOWED_DOMAINS: "WISES.COM.BR" })),
      "ana@wises.com.br"
    );
  });

  it("matches an uppercase email domain against the allowlist", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@WISES.COM.BR", verified: true },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "ana@WISES.COM.BR");
  });

  it("does not match lookalike wises.com.br.evil.com", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@wises.com.br.evil.com", verified: true },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "ana@gmail.com");
  });

  it("does not match lookalike evilwises.com.br", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@evilwises.com.br", verified: true },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "ana@gmail.com");
  });

  it("keeps primary verified when OAUTH_ALLOWED_DOMAINS is unset", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@wises.com.br", verified: true },
    ]);
    const { OAUTH_ALLOWED_DOMAINS: _, ...noDomains } = env();
    assert.equal(selectGitHubEmail(list, noDomains), "ana@gmail.com");
  });

  it("keeps primary verified when OAUTH_ALLOWED_DOMAINS is empty", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@wises.com.br", verified: true },
    ]);
    assert.equal(
      selectGitHubEmail(list, env({ OAUTH_ALLOWED_DOMAINS: "" })),
      "ana@gmail.com"
    );
  });

  it("never treats users.noreply.github.com as an allowed match even if listed", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "12345+ana@users.noreply.github.com", verified: true },
    ]);
    assert.equal(
      selectGitHubEmail(
        list,
        env({ OAUTH_ALLOWED_DOMAINS: "users.noreply.github.com,wises.com.br" })
      ),
      "ana@gmail.com"
    );
  });

  it("never treats a subdomain of users.noreply.github.com as an allowed match", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "ana@mail.users.noreply.github.com", verified: true },
    ]);
    assert.equal(
      selectGitHubEmail(
        list,
        env({ OAUTH_ALLOWED_DOMAINS: "mail.users.noreply.github.com,wises.com.br" })
      ),
      "ana@gmail.com"
    );
  });

  it("still prefers a real work email when a GitHub noreply address is also present", () => {
    const list = emails([
      { email: "12345+ana@users.noreply.github.com", primary: true, verified: true },
      { email: "ana@wises.com.br", verified: true },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "ana@wises.com.br");
  });

  it("does not treat users.noreply.github.com in the local-part as a noreply domain", () => {
    const list = emails([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "users.noreply.github.com@wises.com.br", verified: true },
    ]);
    assert.equal(selectGitHubEmail(list, env()), "users.noreply.github.com@wises.com.br");
  });
});

describe("GitHub OAuth start scope", () => {
  it("requests user:email", async () => {
    const res = await handleAuthRoutes(
      new Request(`${APP}/auth/github`, { redirect: "manual" }),
      env()
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location"));
    assert.equal(loc.hostname, "github.com");
    const scope = loc.searchParams.get("scope") || "";
    assert.match(scope, /\buser:email\b/);
  });
});

describe("GitHub OAuth callback uses selected email", () => {
  const origFetch = globalThis.fetch;

  after(() => {
    globalThis.fetch = origFetch;
  });

  function mockGithub({ emails: emailList, userEmail = "ana@gmail.com" }) {
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes("/login/oauth/access_token")) {
        return new Response(JSON.stringify({ access_token: "tok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (u.includes("/user/emails")) {
        return new Response(JSON.stringify(emailList), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (u.endsWith("/user") || u.includes("/user?")) {
        return new Response(JSON.stringify({ email: userEmail }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch ${u}`);
    };
  }

  async function callback(testEnv) {
    const state = encodeState({ returnTo: "/", provider: "github", n: "n1" });
    return handleAuthRoutes(
      new Request(`${APP}/_auth/callback/github?code=abc&state=${state}`, {
        redirect: "manual",
      }),
      testEnv
    );
  }

  async function sessionEmail(res, testEnv) {
    const parts = [];
    if (typeof res.headers.getSetCookie === "function") {
      for (const c of res.headers.getSetCookie()) parts.push(c.split(";")[0]);
    } else {
      parts.push(String(res.headers.get("set-cookie") || "").split(";")[0]);
    }
    const req = new Request(APP + "/", { headers: { cookie: parts.join("; ") } });
    const session = await readSessionCookie(req, testEnv.SESSION_SECRET);
    return session?.email;
  }

  it("mints a session with the verified work email when primary is gmail", async () => {
    const testEnv = env();
    mockGithub({
      emails: emails([
        { email: "ana@gmail.com", primary: true, verified: true },
        { email: "ana@wises.com.br", verified: true },
      ]),
    });
    const res = await callback(testEnv);
    assert.equal(res.status, 302);
    assert.equal(await sessionEmail(res, testEnv), "ana@wises.com.br");
  });

  it("denies when primary gmail is selected because the work email is unverified", async () => {
    mockGithub({
      emails: emails([
        { email: "ana@gmail.com", primary: true, verified: true },
        { email: "ana@wises.com.br", verified: false },
      ]),
    });
    const res = await callback(env());
    assert.equal(res.status, 403);
    assert.match(await res.text(), new RegExp(DENIED));
  });

  it("denies GitHub noreply even when that domain is listed in OAUTH_ALLOWED_DOMAINS", async () => {
    mockGithub({
      emails: emails([
        { email: "12345+ana@users.noreply.github.com", primary: true, verified: true },
      ]),
    });
    const res = await callback(
      env({ OAUTH_ALLOWED_DOMAINS: "users.noreply.github.com" })
    );
    assert.equal(res.status, 403);
    assert.match(await res.text(), new RegExp(DENIED));
  });
});
