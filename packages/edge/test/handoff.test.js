import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import {
  mintSessionCookie,
  mintHostBoundSessionCookie,
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
  it("custom host panel without __Host-sp_session → 302 app /auth/handoff", async () => {
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

  it("code minted for host A presented on host B: no Set-Cookie, code burned", async () => {
    const kv = activeCustomKv();
    await kv.put(`host:custom:${HOST_B}`, EMAIL);
    const env = oauthEnv(kv);
    const cookie = await appCookie(env);
    const mint = await worker.fetch(
      new Request(
        `https://app.securepublish.work/auth/handoff?host=${HOST_A}&return=/${PANEL_ID}`,
        {
          headers: { Host: "app.securepublish.work", Cookie: cookie },
          redirect: "manual",
        }
      ),
      env
    );
    const code = new URL(mint.headers.get("location")).searchParams.get("code");
    assert.ok(await kv.get(`handoff:${code}`));

    const bad = await worker.fetch(
      new Request(`https://${HOST_B}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: { Host: HOST_B },
        redirect: "manual",
      }),
      env
    );
    assert.notEqual(bad.status, 302);
    const cookies = setCookies(bad);
    assert.equal(cookies.length, 0);
    assert.equal(await kv.get(`handoff:${code}`), null);
    assert.equal(bad.headers.get("cache-control"), "no-store");
    assert.equal(bad.headers.get("referrer-policy"), "no-referrer");
  });

  it("valid exchange: 302 Location has no code; cookie attributes exact; code single-use", async () => {
    const kv = activeCustomKv();
    const env = oauthEnv(kv);
    const cookie = await appCookie(env);
    const mint = await worker.fetch(
      new Request(
        `https://app.securepublish.work/auth/handoff?host=${HOST_A}&return=/${PANEL_ID}`,
        {
          headers: { Host: "app.securepublish.work", Cookie: cookie },
          redirect: "manual",
        }
      ),
      env
    );
    const loc = new URL(mint.headers.get("location"));
    const code = loc.searchParams.get("code");

    const ok = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: { Host: HOST_A },
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

    const setCookie = setCookies(ok);
    assert.equal(setCookie.length, 1);
    const c = setCookie[0];
    assert.ok(c.startsWith(`${HOST_SESSION_COOKIE}=`));
    assert.match(c, /Path=\//);
    assert.match(c, /HttpOnly/);
    assert.match(c, /Secure/);
    assert.match(c, /SameSite=Lax/);
    assert.match(c, new RegExp(`Max-Age=${SESSION_TTL_SEC}`));
    assert.equal(/Domain=/i.test(c), false);

    const replay = await worker.fetch(
      new Request(`https://${HOST_A}/_auth/handoff?code=${code}&return=/${PANEL_ID}`, {
        headers: { Host: HOST_A },
        redirect: "manual",
      }),
      env
    );
    assert.notEqual(replay.status, 302);
    assert.equal(setCookies(replay).length, 0);
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
    assert.notEqual(res.status, 302);
    assert.equal(setCookies(res).length, 0);
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
