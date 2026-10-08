/**
 * Session handoff: app cookie (Domain=.securepublish.work) does not reach
 * customer hosts. One-time KV code (60s, hostname-bound) mints a NEW
 * __Host-sp_session on the customer host.
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

/**
 * GET /auth/handoff on app.securepublish.work
 * ?host= &return=
 */
export async function handleAppHandoff(request, env) {
  const url = new URL(request.url);
  const hostParam = url.searchParams.get("host") || "";
  const returnParam = url.searchParams.get("return") || "/";
  const safeReturn = isSafeRelativeReturn(returnParam) ? returnParam : "/";

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
    const back = `/auth/handoff?host=${encodeURIComponent(n.hostname)}&return=${encodeURIComponent(safeReturn)}`;
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
 * GET /_auth/handoff on the customer host.
 * Host must exactly equal the hostname bound to the code (after claim
 * normalization). Mismatch → no session, code burned.
 */
export async function handleCustomerHandoff(request, env) {
  const url = new URL(request.url);
  const fail = (status = 400) =>
    new Response("Invalid handoff.\n", {
      status,
      headers: noStoreHeaders({ "content-type": "text/plain; charset=utf-8" }),
    });

  const code = url.searchParams.get("code") || "";
  const returnParam = url.searchParams.get("return") || "/";
  const safeReturn = isSafeRelativeReturn(returnParam) ? returnParam : "/";
  const reqHost = normalizeCustomHostname(requestHost(request));

  const key = `handoff:${code}`;
  const raw = code ? await env.PANELS.get(key) : null;
  if (code) {
    await env.PANELS.delete(key);
  }
  if (!raw) return fail(400);

  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return fail(400);
  }
  const now = Math.floor(Date.now() / 1000);
  if (!rec?.exp || rec.exp < now) return fail(400);

  const bound = normalizeCustomHostname(String(rec.hostname || ""));
  if (!bound.ok || !reqHost.ok || bound.hostname !== reqHost.hostname) {
    return fail(403);
  }

  if (!env.SESSION_SECRET) return fail(503);

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
  headers.append("set-cookie", cookie);
  return new Response(null, { status: 302, headers });
}

export function customerHandoffLoginUrl(hostname, returnPath) {
  const dest = new URL(`${APP_HANDOFF_ORIGIN}/auth/handoff`);
  dest.searchParams.set("host", hostname);
  dest.searchParams.set(
    "return",
    isSafeRelativeReturn(returnPath) ? returnPath : "/"
  );
  return dest.toString();
}

export { HANDOFF_TTL_SEC, APP_HANDOFF_ORIGIN };
