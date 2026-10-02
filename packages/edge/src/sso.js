/**
 * Secure Publish SSO — Access JWT (preferred) or Worker OAuth session cookie.
 *
 * Modes (auto-detected from env):
 *   access — TEAM_DOMAIN + POLICY_AUD set → validate Cf-Access-Jwt-Assertion
 *   oauth  — SESSION_SECRET + at least one IdP CLIENT_ID/SECRET → cookie session
 *   none   — fail closed (no HTML served)
 *
 * Optional local-only: SSO_DEV_BYPASS=1 (never set in production).
 *
 * Console contract also uses GET /auth/{google|microsoft|github} (alias of /_auth/start/…)
 * and GET|POST /auth/logout (clear cookie → console /signup/).
 */

import { jwtVerify, createRemoteJWKSet } from "jose";

const COOKIE_NAME = "secure_publish_session";
const SESSION_TTL_SEC = 60 * 60 * 12; // 12h

/** @param {Record<string, string | undefined>} env */
export function ssoMode(env) {
  if (env.SSO_DEV_BYPASS === "1" || env.SSO_DEV_BYPASS === "true") {
    return "dev-bypass";
  }
  if (env.TEAM_DOMAIN && env.POLICY_AUD) {
    return "access";
  }
  if (env.SESSION_SECRET && hasAnyOauthProvider(env)) {
    return "oauth";
  }
  return "none";
}

/** @param {Record<string, string | undefined>} env */
function hasAnyOauthProvider(env) {
  return Boolean(
    (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) ||
      (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) ||
      (env.MICROSOFT_CLIENT_ID && env.MICROSOFT_CLIENT_SECRET)
  );
}

function consoleOrigins(env) {
  const raw = env.CONSOLE_ORIGIN || env.CONSOLE_ORIGINS || "";
  return String(raw)
    .split(",")
    .map((s) => s.trim().replace(/\/$/, ""))
    .filter(Boolean);
}

/**
 * Enforce a real SSO session.
 * @param {Request} request
 * @param {Record<string, string | undefined>} env
 * @param {{ api?: boolean }} [opts] — api: true → 401 JSON, never redirect
 * @returns {Promise<{ ok: boolean, redirectUrl?: string, status?: number, body?: string, user?: { email?: string, provider?: string } }>}
 */
export async function requireSsoSession(request, env, opts = {}) {
  const mode = ssoMode(env);
  const forApi = Boolean(opts.api);

  if (mode === "dev-bypass") {
    return { ok: true, user: { email: "dev@localhost", provider: "dev-bypass" } };
  }

  if (mode === "none") {
    return {
      ok: false,
      status: forApi ? 401 : 403,
      body: forApi
        ? "unauthorized"
        : "Secure Publish: SSO não configurado.\n" +
          "A chave na URL identifica o painel; não autentica o visitante.\n" +
          "Configure Cloudflare Access (TEAM_DOMAIN + POLICY_AUD) ou OAuth no Worker.\n" +
          "Ver README → secção «Ligar SSO no dashboard».\n",
    };
  }

  if (mode === "access") {
    const result = await verifyAccessJwt(request, env);
    if (!result.ok && forApi) {
      return { ok: false, status: 401, body: "unauthorized" };
    }
    return result;
  }

  // oauth
  const session = await readSessionCookie(request, env.SESSION_SECRET);
  if (session) {
    if (env.OAUTH_ALLOWED_DOMAINS) {
      const allowed = env.OAUTH_ALLOWED_DOMAINS.split(",")
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean);
      const domain = (session.email || "").split("@")[1]?.toLowerCase();
      if (allowed.length && (!domain || !allowed.includes(domain))) {
        return {
          ok: false,
          status: 403,
          body: forApi ? "domain_not_allowed" : "Acesso negado: domínio de e-mail não autorizado.\n",
        };
      }
    }
    return { ok: true, user: { email: session.email, provider: session.provider } };
  }

  if (forApi) {
    return { ok: false, status: 401, body: "unauthorized" };
  }

  const url = new URL(request.url);
  const returnTo = url.pathname + url.search;
  return {
    ok: false,
    redirectUrl: `/_auth/login?return_to=${encodeURIComponent(returnTo)}`,
  };
}

/**
 * @param {Request} request
 * @param {Record<string, string | undefined>} env
 */
async function verifyAccessJwt(request, env) {
  const teamDomain = String(env.TEAM_DOMAIN).replace(/\/$/, "");
  const aud = env.POLICY_AUD;
  const token = request.headers.get("cf-access-jwt-assertion");

  if (!token) {
    return {
      ok: false,
      status: 403,
      body:
        "Secure Publish: sessão SSO ausente (Cf-Access-Jwt-Assertion).\n" +
        "Confirme que a aplicação Cloudflare Access cobre este hostname.\n",
    };
  }

  try {
    const JWKS = createRemoteJWKSet(new URL(`${teamDomain}/cdn-cgi/access/certs`));
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: teamDomain,
      audience: aud,
    });

    const email = typeof payload.email === "string" ? payload.email : undefined;
    if (env.OAUTH_ALLOWED_DOMAINS && email) {
      const allowed = env.OAUTH_ALLOWED_DOMAINS.split(",")
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean);
      const domain = email.split("@")[1]?.toLowerCase();
      if (allowed.length && (!domain || !allowed.includes(domain))) {
        return {
          ok: false,
          status: 403,
          body: "Acesso negado: domínio de e-mail não autorizado.\n",
        };
      }
    }

    return {
      ok: true,
      user: {
        email,
        provider:
          typeof payload.identity_provider === "string"
            ? payload.identity_provider
            : "cloudflare-access",
      },
    };
  } catch {
    return {
      ok: false,
      status: 403,
      body: "Secure Publish: JWT Access inválido ou expirado.\n",
    };
  }
}

/* ─── OAuth routes ─── */

const PROVIDERS = {
  google: {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userUrl: "https://www.googleapis.com/oauth2/v2/userinfo",
    scope: "openid email profile",
    idEnv: "GOOGLE_CLIENT_ID",
    secretEnv: "GOOGLE_CLIENT_SECRET",
  },
  github: {
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userUrl: "https://api.github.com/user",
    emailUrl: "https://api.github.com/user/emails",
    scope: "read:user user:email",
    idEnv: "GITHUB_CLIENT_ID",
    secretEnv: "GITHUB_CLIENT_SECRET",
  },
  microsoft: {
    authUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userUrl: "https://graph.microsoft.com/v1.0/me",
    scope: "openid email profile User.Read",
    idEnv: "MICROSOFT_CLIENT_ID",
    secretEnv: "MICROSOFT_CLIENT_SECRET",
  },
};

/**
 * Handle /_auth/* and contract /auth/{provider}.
 * @returns {Promise<Response | null>}
 */
export async function handleAuthRoutes(request, env) {
  const url = new URL(request.url);

  // Logout: idempotent, no prior auth required (GET + POST).
  if (
    (url.pathname === "/auth/logout" ||
      url.pathname === "/auth/logout/" ||
      url.pathname === "/_auth/logout" ||
      url.pathname === "/_auth/logout/") &&
    (request.method === "GET" || request.method === "POST" || request.method === "HEAD")
  ) {
    return logoutResponse(request, env);
  }

  // Cameron contract: GET /auth/{google|microsoft|github}
  const contractStart = url.pathname.match(/^\/auth\/(google|github|microsoft)\/?$/);
  if (contractStart) {
    if (ssoMode(env) !== "oauth" && ssoMode(env) !== "dev-bypass") {
      return new Response(
        "OAuth Worker não está ativo. Configure SESSION_SECRET + CLIENT_ID/SECRET.\n",
        { status: 503, headers: { "content-type": "text/plain; charset=utf-8" } }
      );
    }
    // Map ?next= → return_to (console may pass absolute CONSOLE_ORIGIN URL)
    if (url.searchParams.has("next") && !url.searchParams.has("return_to")) {
      url.searchParams.set("return_to", url.searchParams.get("next"));
    }
    return oauthStart(url, env, contractStart[1]);
  }

  if (!url.pathname.startsWith("/_auth/")) return null;

  if (ssoMode(env) !== "oauth") {
    return new Response(
      "OAuth Worker não está ativo. Use Cloudflare Access (TEAM_DOMAIN + POLICY_AUD) ou configure SESSION_SECRET + CLIENT_ID/SECRET.\n",
      { status: 503, headers: { "content-type": "text/plain; charset=utf-8" } }
    );
  }

  if (url.pathname === "/_auth/login" || url.pathname === "/_auth/login/") {
    return loginPage(url, env);
  }

  const cb = url.pathname.match(/^\/_auth\/callback\/(google|github|microsoft)\/?$/);
  if (cb) {
    return oauthCallback(request, env, cb[1]);
  }

  const start = url.pathname.match(/^\/_auth\/start\/(google|github|microsoft)\/?$/);
  if (start) {
    return oauthStart(url, env, start[1]);
  }

  return new Response("Not found\n", { status: 404 });
}

/** @param {URL} url @param {Record<string, string | undefined>} env */
function loginPage(url, env) {
  const returnTo = url.searchParams.get("return_to") || "/";
  const links = [];
  for (const [name, cfg] of Object.entries(PROVIDERS)) {
    if (env[cfg.idEnv] && env[cfg.secretEnv]) {
      const href = `/_auth/start/${name}?return_to=${encodeURIComponent(returnTo)}`;
      links.push(`<li><a href="${href}">Entrar com ${labelProvider(name)}</a></li>`);
    }
  }
  if (!links.length) {
    return new Response("Nenhum provedor OAuth configurado.\n", {
      status: 503,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
  const html = `<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>Secure Publish — Login</title>
<style>body{font-family:system-ui;max-width:28rem;margin:4rem auto;padding:0 1rem}
a{display:inline-block;margin:.4rem 0;padding:.6rem 1rem;background:#111;color:#fff;text-decoration:none;border-radius:6px}
ul{list-style:none;padding:0}</style></head>
<body><h1>Secure Publish</h1><p>Entre com a conta da empresa para ver o dashboard.</p><ul>${links.join("")}</ul></body></html>`;
  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

function labelProvider(name) {
  if (name === "google") return "Google";
  if (name === "github") return "GitHub";
  if (name === "microsoft") return "Microsoft";
  return name;
}

/** @param {URL} url @param {Record<string, string | undefined>} env @param {string} provider */
function oauthStart(url, env, provider) {
  const cfg = PROVIDERS[provider];
  const clientId = env[cfg.idEnv];
  if (!clientId) {
    return new Response(`Provedor ${provider} não configurado.\n`, { status: 503 });
  }
  const returnTo = url.searchParams.get("return_to") || url.searchParams.get("next") || "/";
  const redirectUri = `${url.origin}/_auth/callback/${provider}`;
  const state = encodeState({ returnTo, provider, n: crypto.randomUUID() });

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: cfg.scope,
    state,
  });
  if (provider === "google" || provider === "microsoft") {
    params.set("access_type", "online");
  }

  return Response.redirect(`${cfg.authUrl}?${params}`, 302);
}

/**
 * @param {Request} request
 * @param {Record<string, string | undefined>} env
 * @param {string} provider
 */
async function oauthCallback(request, env, provider) {
  const url = new URL(request.url);
  const cfg = PROVIDERS[provider];
  const code = url.searchParams.get("code");
  const stateRaw = url.searchParams.get("state");
  if (!code || !stateRaw) {
    return new Response("OAuth callback incompleto.\n", { status: 400 });
  }

  let state;
  try {
    state = decodeState(stateRaw);
  } catch {
    return new Response("State OAuth inválido.\n", { status: 400 });
  }

  const clientId = env[cfg.idEnv];
  const clientSecret = env[cfg.secretEnv];
  const redirectUri = `${url.origin}/_auth/callback/${provider}`;

  const tokenRes = await fetch(cfg.tokenUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenRes.ok) {
    return new Response("Falha ao trocar código OAuth.\n", { status: 502 });
  }

  const tokenJson = await tokenRes.json();
  const accessToken = tokenJson.access_token;
  if (!accessToken) {
    return new Response("Token OAuth ausente.\n", { status: 502 });
  }

  const email = await fetchUserEmail(provider, cfg, accessToken);
  if (!email) {
    return new Response("Não foi possível obter e-mail do provedor.\n", { status: 502 });
  }

  if (env.OAUTH_ALLOWED_DOMAINS) {
    const allowed = env.OAUTH_ALLOWED_DOMAINS.split(",")
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean);
    const domain = email.split("@")[1]?.toLowerCase();
    if (allowed.length && (!domain || !allowed.includes(domain))) {
      return new Response("Acesso negado: domínio de e-mail não autorizado.\n", {
        status: 403,
      });
    }
  }

  const cookie = await mintSessionCookie(
    { email, provider, exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SEC },
    env.SESSION_SECRET,
    env,
    request.url
  );

  const returnTo = safeReturnTo(state.returnTo, env);
  return new Response(null, {
    status: 302,
    headers: {
      location: returnTo,
      "set-cookie": cookie,
    },
  });
}

async function fetchUserEmail(provider, cfg, accessToken) {
  if (provider === "github") {
    const emailsRes = await fetch(cfg.emailUrl, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/vnd.github+json",
        "user-agent": "secure-publish",
      },
    });
    if (emailsRes.ok) {
      const emails = await emailsRes.json();
      const primary = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified);
      if (primary?.email) return primary.email;
    }
    const userRes = await fetch(cfg.userUrl, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/vnd.github+json",
        "user-agent": "secure-publish",
      },
    });
    if (!userRes.ok) return null;
    const user = await userRes.json();
    return user.email || null;
  }

  if (provider === "microsoft") {
    const res = await fetch(cfg.userUrl, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) return null;
    const me = await res.json();
    return me.mail || me.userPrincipalName || null;
  }

  const res = await fetch(cfg.userUrl, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) return null;
  const me = await res.json();
  return me.email || null;
}

/**
 * Relative paths on Worker, or absolute URLs only if origin ∈ CONSOLE_ORIGIN.
 */
function safeReturnTo(path, env) {
  if (!path || typeof path !== "string") return "/";
  const allowed = consoleOrigins(env);
  // Relative paths belong to the console (Pages), not panel ids on the Worker.
  if (path.startsWith("/") && !path.startsWith("//")) {
    if (allowed.length) {
      try {
        return new URL(path, allowed[0] + "/").toString();
      } catch {
        /* fall through */
      }
    }
    return path;
  }
  try {
    const u = new URL(path);
    if (allowed.includes(u.origin)) return u.toString();
  } catch {
    /* ignore */
  }
  return allowed.length ? allowed[0] + "/" : "/";
}


/**
 * Canonical logout destination. Never honor a caller-supplied redirect: logout
 * must end at signup on the first configured console origin.
 * @param {Record<string, string | undefined>} env
 */
function logoutRedirectTarget(env) {
  const origin = consoleOrigins(env)[0];
  if (origin) {
    try {
      const target = new URL(origin);
      if (target.protocol === "http:" || target.protocol === "https:") {
        target.pathname = "/signup/";
        target.search = "";
        target.hash = "";
        return target.toString();
      }
    } catch {
      /* fall through to the canonical production console */
    }
  }
  return "https://app.securepublish.work/signup/";
}

/**
 * Clear session cookie (matching mint attrs) and redirect to console signup.
 * @param {Request} request
 * @param {Record<string, string | undefined>} env
 */
function logoutResponse(request, env) {
  const url = new URL(request.url);
  const headers = new Headers({
    "set-cookie": clearSessionCookie(env, request.url),
    "cache-control": "no-store",
  });

  // Preserve the text response for API callers and explicit non-redirect use;
  // browser navigation defaults to the canonical signup redirect.
  if (url.searchParams.get("redirect") === "0" || acceptPrefersJson(request)) {
    headers.set("content-type", "text/plain; charset=utf-8");
    return new Response("Sessão encerrada.\n", { status: 200, headers });
  }

  headers.set("location", logoutRedirectTarget(env));
  return new Response(null, { status: 302, headers });
}

function acceptPrefersJson(request) {
  const raw = request.headers.get("accept") || "";
  let jsonQ = 0;
  let htmlQ = 0;
  let wildcardQ = 0;
  for (const item of raw.toLowerCase().split(",")) {
    const [media, ...params] = item.trim().split(";");
    if (!media) continue;
    let q = 1;
    for (const param of params) {
      const [key, value] = param.trim().split("=");
      if (key === "q") {
        const parsed = Number(value);
        q = Number.isFinite(parsed) ? parsed : 0;
      }
    }
    if (media === "application/json" || media.endsWith("+json")) jsonQ = Math.max(jsonQ, q);
    else if (media === "text/html" || media === "application/xhtml+xml") htmlQ = Math.max(htmlQ, q);
    else if (media === "*/*") wildcardQ = Math.max(wildcardQ, q);
  }
  return jsonQ > 0 && jsonQ >= htmlQ && jsonQ >= wildcardQ;
}

function encodeState(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeState(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return JSON.parse(atob(b64));
}

/* ─── signed session cookie (Web Crypto HMAC) ─── */

function cookieAttrs(env, requestUrl) {
  let host = "";
  try {
    host = new URL(requestUrl).hostname.toLowerCase();
  } catch {
    /* ignore */
  }
  // Same eTLD+1 as console (app.*.work): Lax + Domain. Cross-site workers.dev: None.
  if (host.endsWith(".securepublish.work") || host === "securepublish.work") {
    return { sameSite: "Lax", domain: "; Domain=.securepublish.work" };
  }
  if (consoleOrigins(env).length) return { sameSite: "None", domain: "" };
  return { sameSite: "Lax", domain: "" };
}

async function mintSessionCookie(payload, secret, env = {}, requestUrl = "") {
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const sig = await hmacSign(body, secret);
  const value = `${body}.${sig}`;
  const { sameSite, domain } = cookieAttrs(env, requestUrl);
  return `${COOKIE_NAME}=${value}; Path=/${domain}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=${SESSION_TTL_SEC}`;
}

function clearSessionCookie(env = {}, requestUrl = "") {
  const { sameSite, domain } = cookieAttrs(env, requestUrl);
  return `${COOKIE_NAME}=; Path=/${domain}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`;
}

async function readSessionCookie(request, secret) {
  const raw = request.headers.get("cookie") || "";
  const match = raw.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  if (!match) return null;
  const [body, sig] = match[1].split(".");
  if (!body || !sig) return null;
  const expected = await hmacSign(body, secret);
  if (!timingSafeEqual(sig, expected)) return null;
  try {
    const pad = body.length % 4 === 0 ? "" : "=".repeat(4 - (body.length % 4));
    const json = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/") + pad));
    if (!json.exp || json.exp < Math.floor(Date.now() / 1000)) return null;
    return json;
  } catch {
    return null;
  }
}

async function hmacSign(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

/** Test/helper export */
export { readSessionCookie, mintSessionCookie, clearSessionCookie, COOKIE_NAME };
