/**
 * Session handoff: app cookie (Domain=.securepublish.work) does not reach
 * customer hosts. One-time KV code (60s, hostname-bound, CSRF-bound to a
 * `__Host-sp_handoff` nonce hash) mints a NEW `__Host-sp_session`.
 *
 * KV read+delete is not strictly atomic (Marcus): a 60s window, hostname-bound.
 */

import {
  APP_HANDOFF_ORIGIN,
  isSafeRelativeReturn,
  normalizeCustomHostname,
  requestHost,
} from "./hostname.js";
import { isActiveCustomHostname } from "./custom-domain.js";
import {
  readSessionCookie,
  mintHostBoundSessionCookie,
  SESSION_TTL_SEC,
  clearHandoffCookie,
  readHandoffNonce,
  handoffNonceMatches,
} from "./sso.js";

const HANDOFF_TTL_SEC = 60;

function noStoreHeaders(extra = {}) {
  return {
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    ...extra,
  };
}

function randomBase64Url(byteLen) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function defaultHandoffPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Secure Publish</title></head>
<body>
<main><h1>Secure Publish</h1><p>Not found.</p></main>
</body>
</html>`;
}

function handoffExpiredHtml(en, href) {
  const copy = en
    ? {
        lang: "en",
        lede: "Your sign-in expired before it finished. Open the dashboard again to sign in.",
        button: "Open the dashboard",
      }
    : {
        lang: "pt-BR",
        lede: "Sua entrada expirou antes de terminar. Abra o dashboard de novo pra entrar.",
        button: "Abrir o dashboard",
      };
  const safeHref = escapeHtml(href);
  return `<!DOCTYPE html>
<html lang="${copy.lang}">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Secure Publish</title>
<style>
:root{
  --cream-2:#F3EFE9;--stone:#E8E2D9;--ink:#292524;--ink-soft:#57534E;
  --sage:#5F7A61;--sage-hover:#4E6650;--white:#FFFEFC;
  --display:Georgia,serif;--sans:system-ui,sans-serif;
  --radius:14px;--shadow:0 1px 2px rgba(41,37,36,.04),0 8px 24px rgba(41,37,36,.05);
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;font-family:var(--sans);font-size:1rem;line-height:1.5;color:var(--ink);
  background:var(--cream-2);
}
.main{width:min(100% - 2rem,540px);margin:2.25rem auto 3rem}
h1{margin:0 0 1rem;font-family:var(--display);font-weight:600;font-size:1.35rem;color:var(--ink)}
.lede{margin:0 0 1.25rem;color:var(--ink-soft);font-size:1.02rem;line-height:1.55}
.btn{
  display:inline-flex;align-items:center;justify-content:center;
  padding:.85rem 1.15rem;border-radius:10px;background:var(--sage);color:var(--white);
  font:inherit;font-weight:600;text-decoration:none;
}
.btn:hover{background:var(--sage-hover);color:var(--white)}
</style>
</head>
<body>
<main class="main">
  <h1>Secure Publish</h1>
  <p class="lede">${escapeHtml(copy.lede)}</p>
  <p><a class="btn" href="${safeHref}">${escapeHtml(copy.button)}</a></p>
</main>
</body>
</html>`;
}

function handoffFailResponse(request) {
  const url = new URL(request.url);
  const returnParam = url.searchParams.get("return") || "";
  const href = isSafeRelativeReturn(returnParam) ? returnParam : "/";
  const accept = (request.headers.get("accept") || "").toLowerCase();
  const headers = new Headers(noStoreHeaders());
  headers.append("set-cookie", clearHandoffCookie());
  if (accept.includes("text/html")) {
    const en = url.searchParams.get("lang") === "en";
    headers.set("content-type", "text/html; charset=utf-8");
    return new Response(handoffExpiredHtml(en, href), { status: 403, headers });
  }
  headers.set("content-type", "text/plain; charset=utf-8");
  return new Response("Invalid handoff.\n", { status: 403, headers });
}

/**
 * GET /auth/handoff on app.securepublish.work
 * ?host= &return= &nh=  (nh = SHA-256 base64url of the customer-host nonce)
 */
export async function handleAppHandoff(request, env) {
  const url = new URL(request.url);
  const hostParam = url.searchParams.get("host") || "";
  const returnParam = url.searchParams.get("return") || "/";
  const safeReturn = isSafeRelativeReturn(returnParam) ? returnParam : "/";
  const nonceHash = url.searchParams.get("nh") || "";

  const n = normalizeCustomHostname(hostParam);
  const active = n.ok ? await isActiveCustomHostname(env, n.hostname) : false;
  if (!n.ok || !active) {
    return new Response(defaultHandoffPage(), {
      status: 404,
      headers: noStoreHeaders({ "content-type": "text/html; charset=utf-8" }),
    });
  }

  if (!env.SESSION_SECRET) {
    return new Response("SSO not configured.\n", {
      status: 503,
      headers: noStoreHeaders({ "content-type": "text/plain; charset=utf-8" }),
    });
  }

  const session = await readSessionCookie(request, env.SESSION_SECRET);
  if (!session) {
    const back = `/auth/handoff?host=${encodeURIComponent(n.hostname)}&return=${encodeURIComponent(safeReturn)}&nh=${encodeURIComponent(nonceHash)}`;
    return new Response(null, {
      status: 302,
      headers: noStoreHeaders({
        location: `/_auth/login?return_to=${encodeURIComponent(back)}`,
      }),
    });
  }

  const code = randomBase64Url(32);
  const rec = {
    hostname: n.hostname,
    email: session.email,
    provider: session.provider || "oauth",
    nonceHash,
    exp: Math.floor(Date.now() / 1000) + HANDOFF_TTL_SEC,
  };
  await env.PANELS.put(`handoff:${code}`, JSON.stringify(rec), {
    expirationTtl: HANDOFF_TTL_SEC,
  });

  const dest = new URL(`https://${n.hostname}/_auth/handoff`);
  dest.searchParams.set("code", code);
  dest.searchParams.set("return", safeReturn);
  return new Response(null, {
    status: 302,
    headers: noStoreHeaders({ location: dest.toString() }),
  });
}

/**
 * GET /_auth/handoff on a verified customer host.
 * Cookie `__Host-sp_handoff` must hash to the stored nonceHash AND Host must
 * match. Any failure burns the code, clears the handoff cookie, mints no
 * session, and returns 403.
 */
export async function handleCustomerHandoff(request, env) {
  const url = new URL(request.url);
  const fail = () => handoffFailResponse(request);

  const code = url.searchParams.get("code") || "";
  const returnParam = url.searchParams.get("return") || "/";
  const safeReturn = isSafeRelativeReturn(returnParam) ? returnParam : "/";
  const reqHost = normalizeCustomHostname(requestHost(request));

  const key = `handoff:${code}`;
  const raw = code ? await env.PANELS.get(key) : null;
  if (code) {
    await env.PANELS.delete(key);
  }
  if (!raw) return fail();

  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return fail();
  }
  const now = Math.floor(Date.now() / 1000);
  if (!rec?.exp || rec.exp < now) return fail();

  const bound = normalizeCustomHostname(String(rec.hostname || ""));
  if (!bound.ok || !reqHost.ok || bound.hostname !== reqHost.hostname) {
    return fail();
  }

  const cookieNonce = readHandoffNonce(request);
  const hashOk = await handoffNonceMatches(cookieNonce, rec.nonceHash);
  if (!hashOk) return fail();

  if (!env.SESSION_SECRET) return fail();

  const cookie = await mintHostBoundSessionCookie(
    {
      email: rec.email,
      provider: rec.provider || "handoff",
      host: bound.hostname,
      exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SEC,
    },
    env.SESSION_SECRET
  );

  const headers = new Headers(noStoreHeaders({ location: safeReturn }));
  headers.append("set-cookie", clearHandoffCookie());
  headers.append("set-cookie", cookie);
  return new Response(null, { status: 302, headers });
}

export function customerHandoffLoginUrl(hostname, returnPath, nonceHash) {
  const dest = new URL(`${APP_HANDOFF_ORIGIN}/auth/handoff`);
  dest.searchParams.set("host", hostname);
  dest.searchParams.set(
    "return",
    isSafeRelativeReturn(returnPath) ? returnPath : "/"
  );
  if (nonceHash) dest.searchParams.set("nh", nonceHash);
  return dest.toString();
}

export { HANDOFF_TTL_SEC, APP_HANDOFF_ORIGIN };
