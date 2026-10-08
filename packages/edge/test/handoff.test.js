import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker, { UNKNOWN_PANEL_BODY } from "../src/worker.js";
import {
  mintSessionCookie,
  mintHostBoundSessionCookie,
  mintHandoffNonce,
  hashHandoffNonce,
  HOST_HANDOFF_COOKIE,
  HANDOFF_COOKIE_MAX_AGE,
  requireSsoSession,
  safeReturnTo,
  HOST_SESSION_COOKIE,
  SESSION_TTL_SEC,
} from "../src/sso.js";
import {
  memoryKv,
  PANEL_ID,
  panelRecord,
  oauthEnv,
  setCookies,
} from "./helpers.js";

const HOST_A = "share.wises.com.br";
const HOST_B = "other.example.com";
const EMAIL = "marcus@wises.com.br";
const PANEL_HTML = "<html>bound</html>";

function activeCustomKv(hostname = HOST_A, status = "active", extra = {}) {
  return memoryKv({
    [PANEL_ID]: JSON.stringify(
      panelRecord(EMAIL, {
        access: { mode: "company", domains: ["wises.com.br"] },
        html: PANEL_HTML,
      })
    ),
    "host:sub:wise": EMAIL,
    [`host:custom:${hostname}`]: EMAIL,
    [`tenant:user:${EMAIL}`]: JSON.stringify({
      email: EMAIL,
      slug: "wise",
      host: status === "active" ? hostname : "wise.securepublish.work",
      customHostname: hostname,
      customVerified: status === "active",
      customStatus: status,
      customVerifyToken: "e".repeat(64),
      customCfId: "cf-1",
      ...extra,
    }),
  });
}

async function appCookie(env, email = EMAIL) {
  const setCookie = await mintSessionCookie(
    { email, provider: "google", exp: Math.floor(Date.now() / 1000) + 3600 },
    env.SESSION_SECRET,
    env,
    "https://app.securepublish.work/_auth/callback/google"
  );
  return setCookie.split(";")[0];
}

function sessionSetCookies(res) {
  return setCookies(res).filter(
    (c) => c.startsWith(`${HOST_SESSION_COOKIE}=`) && !/Max-Age=0/.test(c)
  );
}

function handoffClearCookies(res) {
  return setCookies(res).filter(
    (c) => c.startsWith(`${HOST_HANDOFF_COOKIE}=`) && /Max-Age=0/.test(c)
  );
}

async function mintCode(env, kv, { nonceHash, host = HOST_A, ret = `/${PANEL_ID}` } = {}) {
  const cookie = await appCookie(env);
  const nh = nonceHash ?? (await hashHandoffNonce(mintHandoffNonce()));
  const mint = await worker.fetch(
    new Request(
      `https://app.securepublish.work/auth/handoff?host=${host}&return=${encodeURIComponent(ret)}&nh=${encodeURIComponent(nh)}`,
      {
        headers: { Host: "app.securepublish.work", Cookie: cookie },
        redirect: "manual",
      }
    ),
    env
  );
  const loc = new URL(mint.headers.get("location"));
  const code = loc.searchParams.get("code");
  return { mint, loc, code, nh };
}

describe("login next/return_to — custom host allowlist", () => {
  it("(a) verified+active custom host is accepted", async () => {
    const kv = activeCustomKv(HOST_A, "active");
    const env = oauthEnv(kv);
    const out = await safeReturnTo(`https://${HOST_A}/${PANEL_ID}`, env);
    assert.equal(out, `https://${HOST_A}/${PANEL_ID}`);
  });

  it("(b) pending, issuing_cert, records_missing are rejected", async () => {
    for (const status of ["pending_dns", "issuing_cert", "records_missing"]) {
      const kv = activeCustomKv(HOST_A, status);
      const env = oauthEnv(kv);
      const out = await safeReturnTo(`https://${HOST_A}/${PANEL_ID}`, env);
      assert.equal(out, "https://app.securepublish.work/", status);
    }
  });

  it("(c) unknown host and lookalikes are rejected (no suffix/substring match)", async () => {
    const kv = activeCustomKv(HOST_A, "active");
    const env = oauthEnv(kv);
    const fallback = "https://app.securepublish.work/";
    assert.equal(await safeReturnTo("https://evil.example.com/x", env), fallback);
    assert.equal(
      await safeReturnTo("https://share.wises.com.br.evil.com/x", env),
      fallback
    );
    assert.equal(
      await safeReturnTo("https://notshare.wises.com.br/x", env),
      fallback
    );
    assert.equal(
      await safeReturnTo(`https://SHARE.wises.com.br.attacker.com./x`, env),
      fallback
    );
  });

  it("accepts active host after the same normalization as claim (case / trailing dot)", async () => {
    const kv = activeCustomKv(HOST_A, "active");
    const env = oauthEnv(kv);
    const out = await safeReturnTo(`https://SHARE.Wises.com.br./${PANEL_ID}`, env);
    assert.equal(out, `https://share.wises.com.br/${PANEL_ID}`);
  });
});

describe("session handoff", () => {
  it("custom host panel without __Host-sp_session → 302 app /auth/handoff with CSRF cookie + nh", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const res = await worker.fetch(
      new Request(`https://${HOST_A}/${PANEL_ID}`, {
        headers: { Host: HOST_A },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 302);
    const loc = res.headers.get("location");
    assert.match(loc, /^https:\/\/app\.securepublish\.work\/auth\/handoff/);
    assert.match(loc, new RegExp(`host=${encodeURIComponent(HOST_A)}`));
    assert.match(loc, new RegExp(`return=${encodeURIComponent("/" + PANEL_ID)}`));
    const dest = new URL(loc);
    const nh = dest.searchParams.get("nh");
    assert.ok(nh);
    const cookies = setCookies(res);
    assert.equal(cookies.length, 1);
    const c = cookies[0];
    assert.ok(c.startsWith(`${HOST_HANDOFF_COOKIE}=`));
    assert.match(c, /Path=\//);
    assert.match(c, /HttpOnly/);
    assert.match(c, /Secure/);
    assert.match(c, /SameSite=Lax/);
    assert.match(c, new RegExp(`Max-Age=${HANDOFF_COOKIE_MAX_AGE}`));
    assert.equal(/Domain=/i.test(c), false);
    const nonce = c.split(";")[0].slice(`${HOST_HANDOFF_COOKIE}=`.length);
    assert.equal(await hashHandoffNonce(nonce), nh);
  });

  it("app /auth/handoff without session → login then back to handoff", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const res = await worker.fetch(
      new Request(
        `https://app.securepublish.work/auth/handoff?host=${HOST_A}&return=/${PANEL_ID}`,
        { headers: { Host: "app.securepublish.work" }, redirect: "manual" }
      ),
      env
    );
    assert.equal(res.status, 302);
    const loc = res.headers.get("location");
    assert.match(loc, /\/_auth\/login\?return_to=/);
    assert.match(decodeURIComponent(loc), /\/auth\/handoff/);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  });

  it("app /auth/handoff with session mints 60s host-bound code and 302s to customer /_auth/handoff", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const cookie = await appCookie(env);
    const res = await worker.fetch(
      new Request(
        `https://app.securepublish.work/auth/handoff?host=${HOST_A}&return=/${PANEL_ID}`,
        {
          headers: { Host: "app.securepublish.work", Cookie: cookie },
          redirect: "manual",
        }
      ),
      env
    );
    assert.equal(res.status, 302);
    const loc = new URL(res.headers.get("location"));
    assert.equal(loc.hostname, HOST_A);
    assert.equal(loc.pathname, "/_auth/handoff");
    const code = loc.searchParams.get("code");
    assert.ok(code);
    assert.equal(loc.searchParams.get("return"), `/${PANEL_ID}`);
    const stored = JSON.parse(await kv.get(`handoff:${code}`));
    assert.equal(stored.hostname, HOST_A);
    assert.equal(stored.email, EMAIL);
    assert.equal("nonceHash" in stored, true);
    const put = kv._puts.find((p) => p.key === `handoff:${code}`);
    assert.equal(put.options.expirationTtl, 60);
    assert.ok(stored.exp - Math.floor(Date.now() / 1000) <= 60);
    assert.ok(stored.exp - Math.floor(Date.now() / 1000) >= 50);
  });

  it("invalid handoff host on app → default page, no code", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const cookie = await appCookie(env);
    const res = await worker.fetch(
      new Request(
        `https://app.securepublish.work/auth/handoff?host=share.wises.com.br.evil.com&return=/${PANEL_ID}`,
        {
          headers: { Host: "app.securepublish.work", Cookie: cookie },
          redirect: "manual",
        }
      ),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
    assert.equal([...kv._store.keys()].filter((k) => k.startsWith("handoff:")).length, 0);
  });

  it("code minted for host A presented on host B: 403, no session, code burned", async () => {
    const kv = activeCustomKv();
    await kv.put(`host:custom:${HOST_B}`, "other@wises.com.br");
    await kv.put(
      "tenant:user:other@wises.com.br",
      JSON.stringify({
        email: "other@wises.com.br",
        customHostname: HOST_B,
        customVerified: true,
        customStatus: "active",
      })
    );
    const env = oauthEnv(kv);
    const nonce = mintHandoffNonce();
    const nh = await hashHandoffNonce(nonce);
    const { code } = await mintCode(env, kv, { nonceHash: nh });
    assert.ok(await kv.get(`handoff:${code}`));

    const bad = await worker.fetch(
      new Request(`https://${HOST_B}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: {
          Host: HOST_B,
          Cookie: `${HOST_HANDOFF_COOKIE}=${nonce}`,
        },
        redirect: "manual",
      }),
      env
    );
    assert.equal(bad.status, 403);
    assert.equal(sessionSetCookies(bad).length, 0);
    assert.ok(handoffClearCookies(bad).length >= 1);
    assert.equal(await kv.get(`handoff:${code}`), null);
    assert.equal(bad.headers.get("cache-control"), "no-store");
    assert.equal(bad.headers.get("referrer-policy"), "no-referrer");
  });

  it("valid exchange: 302 Location has no code; cookie attributes exact; code single-use", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const nonce = mintHandoffNonce();
    const nh = await hashHandoffNonce(nonce);
    const { code } = await mintCode(env, kv, { nonceHash: nh });

    const ok = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: {
          Host: HOST_A,
          Cookie: `${HOST_HANDOFF_COOKIE}=${nonce}`,
        },
        redirect: "manual",
      }),
      env
    );
    assert.equal(ok.status, 302);
    const location = ok.headers.get("location");
    assert.equal(location, `/${PANEL_ID}`);
    assert.equal(location.includes(code), false);
    assert.equal(ok.headers.get("cache-control"), "no-store");
    assert.equal(ok.headers.get("referrer-policy"), "no-referrer");

    const sessionCookies = sessionSetCookies(ok);
    assert.equal(sessionCookies.length, 1);
    const c = sessionCookies[0];
    assert.ok(c.startsWith(`${HOST_SESSION_COOKIE}=`));
    assert.match(c, /Path=\//);
    assert.match(c, /HttpOnly/);
    assert.match(c, /Secure/);
    assert.match(c, /SameSite=Lax/);
    assert.match(c, new RegExp(`Max-Age=${SESSION_TTL_SEC}`));
    assert.equal(/Domain=/i.test(c), false);
    assert.ok(handoffClearCookies(ok).length >= 1);

    const replay = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: {
          Host: HOST_A,
          Cookie: `${HOST_HANDOFF_COOKIE}=${nonce}`,
        },
        redirect: "manual",
      }),
      env
    );
    assert.equal(replay.status, 403);
    assert.equal(sessionSetCookies(replay).length, 0);
  });

  it("expired code is rejected with no session", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const code = "expiredcode";
    await kv.put(
      `handoff:${code}`,
      JSON.stringify({
        hostname: HOST_A,
        email: EMAIL,
        exp: Math.floor(Date.now() / 1000) - 5,
      })
    );
    const res = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/`, {
        headers: { Host: HOST_A },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.equal(sessionSetCookies(res).length, 0);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  });

  it("host-bound cookie authorizes the panel on the custom host", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const setCookie = await mintHostBoundSessionCookie(
      {
        email: EMAIL,
        provider: "handoff",
        host: HOST_A,
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      env.SESSION_SECRET
    );
    const res = await worker.fetch(
      new Request(`https://${HOST_A}/${PANEL_ID}`, {
        headers: { Host: HOST_A, Cookie: setCookie.split(";")[0] },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 200);
    assert.equal(await res.text(), PANEL_HTML);
  });

  it("logout on custom host clears __Host- cookie then goes to app /auth/logout", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const res = await worker.fetch(
      new Request(`https://${HOST_A}/auth/logout`, {
        headers: { Host: HOST_A },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "https://app.securepublish.work/auth/logout");
    const cookies = setCookies(res);
    assert.ok(
      cookies.some(
        (c) =>
          c.startsWith(`${HOST_SESSION_COOKIE}=`) &&
          /Max-Age=0/.test(c) &&
          /Path=\//.test(c) &&
          !/Domain=/i.test(c)
      )
    );
  });
});

describe("handoff login CSRF", () => {
  it("code with no cookie gives 403 and no session", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const nonce = mintHandoffNonce();
    const nh = await hashHandoffNonce(nonce);
    const { code } = await mintCode(env, kv, { nonceHash: nh });

    const res = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: { Host: HOST_A },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.equal(sessionSetCookies(res).length, 0);
    assert.ok(handoffClearCookies(res).length >= 1);
    assert.equal(await kv.get(`handoff:${code}`), null);
  });

  it("cookie with a different nonce gives 403 and no session", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const nonce = mintHandoffNonce();
    const other = mintHandoffNonce();
    const nh = await hashHandoffNonce(nonce);
    const { code } = await mintCode(env, kv, { nonceHash: nh });

    const res = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: {
          Host: HOST_A,
          Cookie: `${HOST_HANDOFF_COOKIE}=${other}`,
        },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 403);
    assert.equal(sessionSetCookies(res).length, 0);
    assert.ok(handoffClearCookies(res).length >= 1);
    assert.equal(await kv.get(`handoff:${code}`), null);
  });

  it("valid cookie+code gives 302 with session cookie and handoff cookie cleared", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const nonce = mintHandoffNonce();
    const nh = await hashHandoffNonce(nonce);
    const { code } = await mintCode(env, kv, { nonceHash: nh });

    const res = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: {
          Host: HOST_A,
          Cookie: `${HOST_HANDOFF_COOKIE}=${nonce}`,
        },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), `/${PANEL_ID}`);
    assert.equal(sessionSetCookies(res).length, 1);
    assert.ok(handoffClearCookies(res).length >= 1);
  });

  it("replay gives 403", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const nonce = mintHandoffNonce();
    const nh = await hashHandoffNonce(nonce);
    const { code } = await mintCode(env, kv, { nonceHash: nh });
    const headers = {
      Host: HOST_A,
      Cookie: `${HOST_HANDOFF_COOKIE}=${nonce}`,
    };
    const first = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers,
        redirect: "manual",
      }),
      env
    );
    assert.equal(first.status, 302);
    const replay = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers,
        redirect: "manual",
      }),
      env
    );
    assert.equal(replay.status, 403);
    assert.equal(sessionSetCookies(replay).length, 0);
  });
});

describe("handoff 403 HTML page", () => {
  async function expiredHtml(returnParam, extraQs = "") {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const res = await worker.fetch(
      new Request(
        `https://${HOST_A}/_auth/handoff?code=missing&return=${encodeURIComponent(returnParam)}${extraQs}`,
        {
          headers: {
            Host: HOST_A,
            Accept: "text/html",
          },
          redirect: "manual",
        }
      ),
      env
    );
    return { res, html: await res.text() };
  }

  it("unsafe return values give href / and never echo the raw parameter", async () => {
    for (const unsafe of ["//evil.com", "https://evil.com", "/\\evil.com"]) {
      const { res, html } = await expiredHtml(unsafe);
      assert.equal(res.status, 403);
      assert.match(html, /href="\/"/);
      assert.equal(html.includes(unsafe), false);
      assert.equal(html.includes("evil.com"), false);
      assert.match(
        html,
        /Sua entrada expirou antes de terminar\. Abra o dashboard de novo pra entrar\./
      );
      assert.match(html, /Abrir o dashboard/);
      assert.equal(res.headers.get("cache-control"), "no-store");
      assert.equal(res.headers.get("referrer-policy"), "no-referrer");
      assert.equal(sessionSetCookies(res).length, 0);
      assert.ok(handoffClearCookies(res).length >= 1);
    }
  });

  it("safe return is used as the button href; EN copy when lang=en", async () => {
    const { res, html } = await expiredHtml(`/${PANEL_ID}`, "&lang=en");
    assert.equal(res.status, 403);
    assert.match(html, new RegExp(`href="/${PANEL_ID}"`));
    assert.match(
      html,
      /Your sign-in expired before it finished\. Open the dashboard again to sign in\./
    );
    assert.match(html, /Open the dashboard/);
    assert.equal(sessionSetCookies(res).length, 0);
  });
});

describe("route scoping", () => {
  it("/api/* on a customer host returns the clean 404", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const cookie = await mintHostBoundSessionCookie(
      {
        email: EMAIL,
        provider: "handoff",
        host: HOST_A,
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      env.SESSION_SECRET
    );
    const res = await worker.fetch(
      new Request(`https://${HOST_A}/api/me`, {
        headers: { Host: HOST_A, Cookie: cookie.split(";")[0] },
      }),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(await res.text(), UNKNOWN_PANEL_BODY);
  });

  it("requireSsoSession does not accept __Host-sp_session for api:true", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const cookie = await mintHostBoundSessionCookie(
      {
        email: EMAIL,
        provider: "handoff",
        host: HOST_A,
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      env.SESSION_SECRET
    );
    const sso = await requireSsoSession(
      new Request(`https://${HOST_A}/api/me`, {
        headers: { Host: HOST_A, Cookie: cookie.split(";")[0] },
      }),
      env,
      { api: true }
    );
    assert.equal(sso.ok, false);
    assert.equal(sso.status, 401);
  });

  it("/auth/handoff on a customer host returns the clean 404", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const res = await worker.fetch(
      new Request(`https://${HOST_A}/auth/handoff?host=${HOST_A}`, {
        headers: { Host: HOST_A },
      }),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(await res.text(), UNKNOWN_PANEL_BODY);
  });

  it("/auth/handoff on a subdomain host returns the clean 404", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const res = await worker.fetch(
      new Request(`https://wise.securepublish.work/auth/handoff?host=${HOST_A}`, {
        headers: { Host: "wise.securepublish.work" },
      }),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(await res.text(), UNKNOWN_PANEL_BODY);
  });

  it("/_auth/handoff on app.securepublish.work returns the clean 404", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/_auth/handoff?code=abc", {
        headers: { Host: "app.securepublish.work" },
      }),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(await res.text(), UNKNOWN_PANEL_BODY);
  });

  it("/_auth/handoff on an unverified host returns the clean 404", async () => {
    const kv = activeCustomKv(HOST_A, "pending_dns");
    const env = oauthEnv(kv);
    const res = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=abc`, {
        headers: { Host: HOST_A },
      }),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(await res.text(), UNKNOWN_PANEL_BODY);
  });
});

