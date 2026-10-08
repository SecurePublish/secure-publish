/**
 * Self-service signup by company email domain (blocklist, org-by-domain,
 * GitHub verified work email, Microsoft xms_edov).
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import {
  handleAuthRoutes,
  mintSessionCookie,
  readSessionCookie,
  COOKIE_NAME,
  MICROSOFT_DOMAIN_UNVERIFIED,
} from "../src/sso.js";
import { getOrg, orgKvKey } from "../src/kv.js";
import { memoryKv, oauthEnv } from "./helpers.js";

const APP = "https://app.securepublish.work";
const CLOVIS = "clovis@furk.tech";
const TEAMMATE = "x@furk.tech";
const ANA = "ana@wises.com.br";
const WISE_PANEL = "aaaaaaaaaaaaaaaaaaaaaaaa";
const FURK_PANEL = "bbbbbbbbbbbbbbbbbbbbbbbb";
const PANEL_HTML = "<html>org-isolation</html>";
const GITHUB_DENIED =
  "Não conseguimos entrar com essa conta do GitHub. Ela precisa ter o e-mail da empresa confirmado no GitHub. Confira em github.com/settings/emails ou entre com outra conta.\n" +
  "We couldn't sign you in with this GitHub account. It needs your company email confirmed on GitHub. Check github.com/settings/emails or sign in with another account.\n";

function unsignedJwt(payload) {
  const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  return `${enc({ alg: "none", typ: "JWT" })}.${enc(payload)}.`;
}

function encodeState(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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

async function sessionCookie(env, email) {
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

function apiHeaders(cookie, extra = {}) {
  return {
    Origin: APP,
    Cookie: cookie,
    ...extra,
  };
}

function fullOauthEnv(kv, extra = {}) {
  return oauthEnv(kv, {
    GITHUB_CLIENT_ID: "gh-id",
    GITHUB_CLIENT_SECRET: "gh-secret",
    MICROSOFT_CLIENT_ID: "ms-id",
    MICROSOFT_CLIENT_SECRET: "ms-secret",
    OAUTH_ALLOWED_DOMAINS: "wises.com.br",
    ...extra,
  });
}

function seedWisesOrg(kvExtra = {}) {
  return memoryKv({
    [WISE_PANEL]: JSON.stringify({
      v: 1,
      title: "Wises Co",
      publishedAt: "2026-10-01T00:00:00Z",
      publisherEmail: ANA,
      access: { mode: "company", domains: ["wises.com.br"] },
      html: PANEL_HTML,
    }),
    [`view:${WISE_PANEL}`]: JSON.stringify({
      count: 2,
      byEmail: {
        "bob@wises.com.br": {
          first: "2026-10-07T00:00:00.000Z",
          last: "2026-10-08T00:00:00.000Z",
        },
      },
    }),
    "idx:domain:wises.com.br": JSON.stringify([WISE_PANEL]),
    [`idx:pub:${ANA}`]: JSON.stringify([WISE_PANEL]),
    [`tenant:user:${ANA}`]: JSON.stringify({
      email: ANA,
      domain: "wises.com.br",
      slug: "wise",
      host: "wise.securepublish.work",
      customHostname: "share.wises.com.br",
      customVerified: true,
      customStatus: "active",
    }),
    "host:sub:wise": ANA,
    "host:custom:share.wises.com.br": ANA,
    "org:wises.com.br": JSON.stringify({
      v: 1,
      domain: "wises.com.br",
      createdBy: ANA,
      createdAt: "2026-01-01T00:00:00.000Z",
    }),
    ...kvExtra,
  });
}

describe("self-service signup — Google org create/join", () => {
  const origFetch = globalThis.fetch;

  after(() => {
    globalThis.fetch = origFetch;
  });

  function mockGoogle(email, extra = {}) {
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes("oauth2.googleapis.com/token")) {
        return new Response(JSON.stringify({ access_token: "tok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (u.includes("googleapis.com/oauth2/v2/userinfo")) {
        return new Response(
          JSON.stringify({
            email,
            verified_email: true,
            ...extra,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      throw new Error(`unexpected fetch ${u}`);
    };
  }

  async function googleCallback(testEnv) {
    const state = encodeState({ returnTo: "/", provider: "google", n: "n1" });
    return handleAuthRoutes(
      new Request(`${APP}/_auth/callback/google?code=abc&state=${state}`, {
        redirect: "manual",
      }),
      testEnv
    );
  }

  it("creates an org for furk.tech on first verified Google sign-in; second user joins it", async () => {
    const kv = memoryKv();
    const env = fullOauthEnv(kv);
    mockGoogle(CLOVIS, { hd: "furk.tech" });
    const first = await googleCallback(env);
    assert.equal(first.status, 302);
    const org = await getOrg(kv, "furk.tech");
    assert.ok(org);
    assert.equal(org.domain, "furk.tech");
    assert.equal(org.createdBy, CLOVIS);
    assert.equal(await kv.get(orgKvKey("furk.tech")), JSON.stringify(org));
    const firstTenant = JSON.parse(await kv.get(`tenant:user:${CLOVIS}`));
    assert.equal(firstTenant.domain, "furk.tech");

    mockGoogle(TEAMMATE, { hd: "furk.tech" });
    const second = await googleCallback(env);
    assert.equal(second.status, 302);
    const orgAgain = await getOrg(kv, "furk.tech");
    assert.equal(orgAgain.createdBy, CLOVIS);
    assert.equal(orgAgain.createdAt, org.createdAt);
    const secondTenant = JSON.parse(await kv.get(`tenant:user:${TEAMMATE}`));
    assert.equal(secondTenant.domain, "furk.tech");
  });

  it("denies Google when email_verified/verified_email is not true", async () => {
    const env = fullOauthEnv(memoryKv());
    mockGoogle(CLOVIS);
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes("oauth2.googleapis.com/token")) {
        return new Response(JSON.stringify({ access_token: "tok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (u.includes("userinfo")) {
        return new Response(JSON.stringify({ email: CLOVIS, verified_email: false }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch ${u}`);
    };
    const res = await googleCallback(env);
    assert.equal(res.status, 502);
    assert.equal(sessionCookieLines(res).length, 0);
    assert.equal(await env.PANELS.get("org:furk.tech"), null);
  });

  it("denies a verified gmail Google sign-in", async () => {
    const env = fullOauthEnv(memoryKv());
    mockGoogle("eve@gmail.com");
    const res = await googleCallback(env);
    assert.equal(res.status, 403);
    assert.equal(sessionCookieLines(res).length, 0);
    assert.equal(await env.PANELS.get("org:gmail.com"), null);
  });
});

describe("self-service signup — GitHub verified work email", () => {
  const origFetch = globalThis.fetch;

  after(() => {
    globalThis.fetch = origFetch;
  });

  function mockGithub(emailList) {
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
      if (/\/user\/?$/.test(new URL(u).pathname)) {
        throw new Error("must not call /user");
      }
      throw new Error(`unexpected fetch ${u}`);
    };
  }

  async function githubCallback(testEnv) {
    const state = encodeState({ returnTo: "/", provider: "github", n: "n1" });
    return handleAuthRoutes(
      new Request(`${APP}/_auth/callback/github?code=abc&state=${state}`, {
        redirect: "manual",
      }),
      testEnv
    );
  }

  it("picks the verified non-personal email over a personal primary", async () => {
    const kv = memoryKv();
    const env = fullOauthEnv(kv);
    mockGithub([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: CLOVIS, primary: false, verified: true },
    ]);
    const res = await githubCallback(env);
    assert.equal(res.status, 302);
    const parts = setCookieLines(res).map((c) => c.split(";")[0]);
    const session = await readSessionCookie(
      new Request(APP + "/", { headers: { cookie: parts.join("; ") } }),
      env.SESSION_SECRET
    );
    assert.equal(session.email, CLOVIS);
    const org = await getOrg(kv, "furk.tech");
    assert.equal(org.createdBy, CLOVIS);
  });

  it("denies a GitHub account that only has gmail + noreply", async () => {
    const env = fullOauthEnv(memoryKv());
    mockGithub([
      { email: "ana@gmail.com", primary: true, verified: true },
      { email: "12345+ana@users.noreply.github.com", verified: true },
    ]);
    const res = await githubCallback(env);
    assert.equal(res.status, 403);
    assert.equal(await res.text(), GITHUB_DENIED);
    assert.equal(sessionCookieLines(res).length, 0);
  });

  it("denies a GitHub noreply-only account", async () => {
    const env = fullOauthEnv(memoryKv());
    mockGithub([{ email: "1+x@users.noreply.github.com", primary: true, verified: true }]);
    const res = await githubCallback(env);
    assert.equal(res.status, 403);
    assert.equal(sessionCookieLines(res).length, 0);
  });
});

describe("self-service signup — Microsoft xms_edov", () => {
  const origFetch = globalThis.fetch;

  after(() => {
    globalThis.fetch = origFetch;
  });

  async function microsoftCallback(testEnv, tokenJson) {
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes("login.microsoftonline.com")) {
        return new Response(JSON.stringify(tokenJson), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch ${u} (Graph must not be used for identity)`);
    };
    const state = encodeState({ returnTo: "/", provider: "microsoft", n: "n1" });
    return handleAuthRoutes(
      new Request(`${APP}/_auth/callback/microsoft?code=abc&state=${state}`, {
        redirect: "manual",
      }),
      testEnv
    );
  }

  it("creates/joins the furk.tech org when xms_edov is true", async () => {
    const kv = memoryKv();
    const env = fullOauthEnv(kv);
    const res = await microsoftCallback(env, {
      access_token: "tok",
      id_token: unsignedJwt({ email: CLOVIS, xms_edov: true }),
    });
    assert.equal(res.status, 302);
    const org = await getOrg(kv, "furk.tech");
    assert.equal(org.createdBy, CLOVIS);

    const res2 = await microsoftCallback(env, {
      access_token: "tok",
      id_token: unsignedJwt({ email: TEAMMATE, xms_edov: true }),
    });
    assert.equal(res2.status, 302);
    assert.equal((await getOrg(kv, "furk.tech")).createdBy, CLOVIS);
  });

  it("denies Microsoft when xms_edov is missing, including wises.com.br", async () => {
    const env = fullOauthEnv(memoryKv());
    const res = await microsoftCallback(env, {
      access_token: "tok",
      id_token: unsignedJwt({
        email: ANA,
        upn: ANA,
        preferred_username: ANA,
      }),
    });
    assert.equal(res.status, 403);
    assert.match(await res.text(), new RegExp(MICROSOFT_DOMAIN_UNVERIFIED));
    assert.equal(sessionCookieLines(res).length, 0);
    assert.equal(await env.PANELS.get("org:wises.com.br"), null);
  });

  it("denies Microsoft when xms_edov is false, including wises.com.br", async () => {
    const env = fullOauthEnv(memoryKv());
    const res = await microsoftCallback(env, {
      access_token: "tok",
      id_token: unsignedJwt({ email: ANA, xms_edov: false }),
    });
    assert.equal(res.status, 403);
    assert.match(await res.text(), new RegExp(MICROSOFT_DOMAIN_UNVERIFIED));
    assert.equal(sessionCookieLines(res).length, 0);
  });

  it("does not trust upn or Graph mail when the id_token is absent", async () => {
    const env = fullOauthEnv(memoryKv());
    const res = await microsoftCallback(env, { access_token: "tok" });
    assert.equal(res.status, 403);
    assert.match(await res.text(), new RegExp(MICROSOFT_DOMAIN_UNVERIFIED));
  });
});

describe("org isolation — furk.tech cannot access wises.com.br", () => {
  it("does not list, read logs of, modify, or share wises panels", async () => {
    const kv = seedWisesOrg({
      [FURK_PANEL]: JSON.stringify({
        v: 1,
        title: "Furk Co",
        publishedAt: "2026-10-08T00:00:00Z",
        publisherEmail: CLOVIS,
        access: { mode: "company", domains: ["furk.tech"] },
        html: PANEL_HTML,
      }),
      "idx:domain:furk.tech": JSON.stringify([FURK_PANEL]),
      [`idx:pub:${CLOVIS}`]: JSON.stringify([FURK_PANEL]),
      [`tenant:user:${CLOVIS}`]: JSON.stringify({
        email: CLOVIS,
        domain: "furk.tech",
        slug: "furk",
        host: "furk.securepublish.work",
      }),
      "host:sub:furk": CLOVIS,
    });
    const env = fullOauthEnv(kv);
    const cookie = await sessionCookie(env, CLOVIS);
    const headers = apiHeaders(cookie, { "content-type": "application/json" });

    const company = await worker.fetch(
      new Request(`${APP}/api/panels?scope=company`, { headers: apiHeaders(cookie) }),
      env
    );
    assert.equal(company.status, 200);
    const companyBody = await company.json();
    assert.equal(
      companyBody.panels.find((p) => p.id === WISE_PANEL),
      undefined
    );
    assert.ok(companyBody.panels.find((p) => p.id === FURK_PANEL));

    const mine = await worker.fetch(
      new Request(`${APP}/api/panels?scope=mine`, { headers: apiHeaders(cookie) }),
      env
    );
    const mineBody = await mine.json();
    assert.equal(
      mineBody.panels.find((p) => p.id === WISE_PANEL),
      undefined
    );

    const patch = await worker.fetch(
      new Request(`${APP}/api/panels/${WISE_PANEL}/access`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ mode: "allowlist", allowlist: [CLOVIS] }),
      }),
      env
    );
    assert.equal(patch.status, 403);
    assert.deepEqual(await patch.json(), { error: "forbidden" });

    const name = await worker.fetch(
      new Request(`${APP}/api/panels/${WISE_PANEL}/name`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ name: "stolen" }),
      }),
      env
    );
    assert.equal(name.status, 403);

    const viewHtml = await worker.fetch(
      new Request(`https://edge.workers.dev/${WISE_PANEL}`, {
        headers: { Host: "edge.workers.dev", Cookie: cookie },
        redirect: "manual",
      }),
      env
    );
    assert.equal(viewHtml.status, 403);
  });

  it("cannot steal wises hosting or custom domain; missing and no-access look the same", async () => {
    const kv = seedWisesOrg();
    const env = fullOauthEnv(kv);
    const cookie = await sessionCookie(env, CLOVIS);
    const headers = apiHeaders(cookie, { "content-type": "application/json" });

    const me = await worker.fetch(
      new Request(`${APP}/api/me`, { headers: apiHeaders(cookie) }),
      env
    );
    assert.equal(me.status, 200);
    const meBody = await me.json();
    assert.equal(meBody.domain, "furk.tech");
    assert.notEqual(meBody.host, "wise.securepublish.work");
    assert.notEqual(meBody.customHostname, "share.wises.com.br");

    const sub = await worker.fetch(
      new Request(`${APP}/api/hosting/subdomain`, {
        method: "PUT",
        headers,
        body: JSON.stringify({ slug: "wise" }),
      }),
      env
    );
    assert.equal(sub.status, 409);
    assert.deepEqual(await sub.json(), { error: "subdomain_taken" });
    assert.equal(await kv.get("host:sub:wise"), ANA);

    const custom = await worker.fetch(
      new Request(`${APP}/api/hosting/custom`, {
        method: "PUT",
        headers,
        body: JSON.stringify({ hostname: "share.wises.com.br" }),
      }),
      env
    );
    assert.equal(custom.status, 409);
    assert.deepEqual(await custom.json(), { error: "hostname_taken" });
    assert.equal(await kv.get("host:custom:share.wises.com.br"), ANA);

    const del = await worker.fetch(
      new Request(`${APP}/api/hosting/custom`, {
        method: "DELETE",
        headers,
      }),
      env
    );
    assert.equal(del.status, 404);
    assert.deepEqual(await del.json(), { error: "no_custom_hostname" });
    assert.equal(await kv.get("host:custom:share.wises.com.br"), ANA);

    const missingPanel = await worker.fetch(
      new Request(`${APP}/api/panels/zzzzzzzzzzzzzzzzzzzzzzzz/access`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ mode: "company" }),
      }),
      env
    );
    assert.equal(missingPanel.status, 404);

    const customHost = await worker.fetch(
      new Request(`https://share.wises.com.br/${WISE_PANEL}`, {
        headers: { Host: "share.wises.com.br", Cookie: cookie },
        redirect: "manual",
      }),
      env
    );
    assert.equal(customHost.status, 302);
    assert.match(customHost.headers.get("location") || "", /\/auth\/handoff/);
  });
});
