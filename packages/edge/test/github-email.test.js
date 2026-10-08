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
  COOKIE_NAME,
} from "../src/sso.js";

const APP = "https://app.securepublish.work";
const SECRET = "test-session-secret-at-least-32-chars!!";
const GOOGLE_MS_DENIED = "Acesso negado: domínio de e-mail não autorizado.\n";
const GITHUB_DENIED =
  "Não conseguimos entrar com essa conta do GitHub. Ela precisa ter o e-mail da empresa confirmado no GitHub. Confira em github.com/settings/emails ou entre com outra conta.\n" +
  "We couldn't sign you in with this GitHub account. It needs your company email confirmed on GitHub. Check github.com/settings/emails or sign in with another account.\n";

function env(extra = {}) {
  return {
    SESSION_SECRET: SECRET,
    GITHUB_CLIENT_ID: "gh-id",
    GITHUB_CLIENT_SECRET: "gh-secret",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    MICROSOFT_CLIENT_ID: "ms-id",
    MICROSOFT_CLIENT_SECRET: "ms-secret",
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
  const fetchCalls = { user: 0 };

  after(() => {
    globalThis.fetch = origFetch;
  });

  function mockGithub({
    emails: emailList,
    emailsStatus = 200,
    userEmail = "ana@wises.com.br",
  }) {
    fetchCalls.user = 0;
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes("/login/oauth/access_token")) {
        return new Response(JSON.stringify({ access_token: "tok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (u.includes("/user/emails")) {
        if (emailsStatus !== 200) {
          return new Response("upstream error", { status: emailsStatus });
        }
        return new Response(JSON.stringify(emailList), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (/\/user\/?$/.test(new URL(u).pathname)) {
        fetchCalls.user += 1;
        return new Response(JSON.stringify({ email: userEmail }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch ${u}`);
    };
  }

  function mockIdp({ tokenUrlPart, userUrlPart, profile }) {
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes(tokenUrlPart)) {
        return new Response(JSON.stringify({ access_token: "tok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (u.includes(userUrlPart)) {
        return new Response(JSON.stringify(profile), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch ${u}`);
    };
  }

  async function callback(provider, testEnv) {
    const state = encodeState({ returnTo: "/", provider, n: "n1" });
    return handleAuthRoutes(
      new Request(`${APP}/_auth/callback/${provider}?code=abc&state=${state}`, {
        redirect: "manual",
      }),
      testEnv
    );
  }

  function setCookieLines(res) {
    if (typeof res.headers.getSetCookie === "function") return res.headers.getSetCookie();
    const raw = res.headers.get("set-cookie");
    return raw ? [raw] : [];
  }

  function sessionCookieLines(res) {
    return setCookieLines(res).filter((c) => {
      const pair = String(c).split(";")[0];
      const eq = pair.indexOf("=");
      if (eq < 0) return false;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      return name === COOKIE_NAME && value.length > 0;
    });
  }

  async function sessionEmail(res, testEnv) {
    const parts = setCookieLines(res).map((c) => c.split(";")[0]);
    const req = new Request(APP + "/", { headers: { cookie: parts.join("; ") } });
    const session = await readSessionCookie(req, testEnv.SESSION_SECRET);
    return session?.email;
  }

  async function assertGithubDenied(res) {
    assert.equal(res.status, 403);
    assert.equal(res.headers.get("content-type"), "text/plain; charset=utf-8");
    assert.equal(await res.text(), GITHUB_DENIED);
    assert.equal(sessionCookieLines(res).length, 0);
    assert.equal(fetchCalls.user, 0);
  }

  it("mints a session with the verified work email when primary is gmail", async () => {
    const testEnv = env();
    mockGithub({
      emails: emails([
        { email: "ana@gmail.com", primary: true, verified: true },
        { email: "ana@wises.com.br", verified: true },
      ]),
    });
    const res = await callback("github", testEnv);
    assert.equal(res.status, 302);
    assert.equal(await sessionEmail(res, testEnv), "ana@wises.com.br");
  });

  it("lowercases a verified GitHub email before minting the session", async () => {
    const testEnv = env();
    mockGithub({
      emails: emails([{ email: "ana@WISES.COM.BR", primary: true, verified: true }]),
    });
    const res = await callback("github", testEnv);
    assert.equal(res.status, 302);
    assert.equal(await sessionEmail(res, testEnv), "ana@wises.com.br");
  });

  it("lowercases a Google email before minting the session", async () => {
    const testEnv = env();
    mockIdp({
      tokenUrlPart: "oauth2.googleapis.com/token",
      userUrlPart: "googleapis.com/oauth2/v2/userinfo",
      profile: { email: "ana@WISES.COM.BR" },
    });
    const res = await callback("google", testEnv);
    assert.equal(res.status, 302);
    assert.equal(await sessionEmail(res, testEnv), "ana@wises.com.br");
  });

  it("lowercases a Microsoft email before minting the session", async () => {
    const testEnv = env();
    mockIdp({
      tokenUrlPart: "login.microsoftonline.com",
      userUrlPart: "graph.microsoft.com/v1.0/me",
      profile: { mail: "ana@WISES.COM.BR" },
    });
    const res = await callback("microsoft", testEnv);
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
    const res = await callback("github", env());
    await assertGithubDenied(res);
  });

  it("denies GitHub noreply even when that domain is listed in OAUTH_ALLOWED_DOMAINS", async () => {
    mockGithub({
      emails: emails([
        { email: "12345+ana@users.noreply.github.com", primary: true, verified: true },
      ]),
    });
    const res = await callback(
      "github",
      env({ OAUTH_ALLOWED_DOMAINS: "users.noreply.github.com" })
    );
    await assertGithubDenied(res);
  });

  it("denies when every /user/emails entry is unverified even if /user has a work email", async () => {
    mockGithub({
      emails: emails([
        { email: "ana@gmail.com", primary: true, verified: false },
        { email: "ana@wises.com.br", verified: false },
      ]),
      userEmail: "ana@wises.com.br",
    });
    const res = await callback("github", env());
    await assertGithubDenied(res);
  });

  it("denies when /user/emails returns 500 even if /user has a work email", async () => {
    mockGithub({
      emails: emails([]),
      emailsStatus: 500,
      userEmail: "ana@wises.com.br",
    });
    const res = await callback("github", env());
    await assertGithubDenied(res);
  });

  it("uses the same GitHub denial body for domain-not-allowed and no-verified-email", async () => {
    mockGithub({
      emails: emails([{ email: "ana@gmail.com", primary: true, verified: true }]),
    });
    const domainDenied = await callback("github", env());
    const domainBody = await domainDenied.clone().text();
    assert.equal(domainDenied.status, 403);
    assert.equal(domainBody, GITHUB_DENIED);

    mockGithub({
      emails: emails([{ email: "ana@wises.com.br", verified: false }]),
      userEmail: "ana@wises.com.br",
    });
    const unverifiedDenied = await callback("github", env());
    assert.equal(unverifiedDenied.status, 403);
    assert.equal(await unverifiedDenied.text(), domainBody);
  });

  it("keeps the existing Google domain-denied text", async () => {
    mockIdp({
      tokenUrlPart: "oauth2.googleapis.com/token",
      userUrlPart: "googleapis.com/oauth2/v2/userinfo",
      profile: { email: "ana@gmail.com" },
    });
    const res = await callback("google", env());
    assert.equal(res.status, 403);
    assert.equal(await res.text(), GOOGLE_MS_DENIED);
  });

  it("keeps the existing Microsoft domain-denied text", async () => {
    mockIdp({
      tokenUrlPart: "login.microsoftonline.com",
      userUrlPart: "graph.microsoft.com/v1.0/me",
      profile: { mail: "ana@gmail.com" },
    });
    const res = await callback("microsoft", env());
    assert.equal(res.status, 403);
    assert.equal(await res.text(), GOOGLE_MS_DENIED);
  });
});
