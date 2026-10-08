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
import { approveDeviceCode, getTenant } from "./kv.js";
import {
  isCustomCustomerHost,
  isOwnZoneHost,
  isSafeRelativeReturn,
  normalizeCustomHostname,
  requestHost,
} from "./hostname.js";

const COOKIE_NAME = "secure_publish_session";
/** Host-only cookie on customer custom hostnames. `__Host-` forbids Domain=. */
export const HOST_SESSION_COOKIE = "__Host-sp_session";
/** Login-CSRF nonce on the customer host; hash-only is sent to `app.`. */
export const HOST_HANDOFF_COOKIE = "__Host-sp_handoff";
export const HANDOFF_COOKIE_MAX_AGE = 60;
export const SESSION_TTL_SEC = 60 * 60 * 12; // 12h

/** Single production OAuth callback host (Google allows one primary redirect URI). */
const DEFAULT_OAUTH_CALLBACK_ORIGIN = "https://app.securepublish.work";

/**
 * Canonical origin for IdP redirect_uri + Domain-scoped session mint.
 * Override with OAUTH_CALLBACK_ORIGIN for local wrangler.
 * @param {Record<string, string | undefined>} env
 */
export function oauthCallbackOrigin(env = {}) {
  const raw = env.OAUTH_CALLBACK_ORIGIN || DEFAULT_OAUTH_CALLBACK_ORIGIN;
  return String(raw).replace(/\/$/, "");
}

/** @param {Record<string, string | undefined>} env @param {string} provider */
export function oauthRedirectUri(env, provider) {
  return `${oauthCallbackOrigin(env)}/_auth/callback/${provider}`;
}

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

const GITHUB_NOREPLY_DOMAIN = "users.noreply.github.com";

/**
 * Parse OAUTH_ALLOWED_DOMAINS the same way the domain gate does:
 * comma-separated, trim, lower-case. Match the host after @ only — never
 * `includes`/`endsWith` on the raw email string.
 * @param {Record<string, string | undefined>} env
 * @returns {string[]}
 */
function oauthAllowedDomainList(env = {}) {
  return String(env.OAUTH_ALLOWED_DOMAINS || "")
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
}

/** @param {string | undefined} email */
function oauthEmailDomain(email) {
  return String(email || "").split("@")[1]?.toLowerCase() || "";
}

/** Exact domain or a subdomain of users.noreply.github.com. */
function isGithubNoreplyDomain(domain) {
  const d = String(domain || "").toLowerCase();
  return d === GITHUB_NOREPLY_DOMAIN || d.endsWith(`.${GITHUB_NOREPLY_DOMAIN}`);
}

/**
 * Domain gate: deny when an allowlist is set and the email domain is not an
 * exact member (case-insensitive). GitHub noreply addresses never count as
 * allowed, even if listed in OAUTH_ALLOWED_DOMAINS.
 * @param {string | undefined} email
 * @param {Record<string, string | undefined>} env
 */
function oauthEmailDeniedByDomainGate(email, env = {}) {
  const allowed = oauthAllowedDomainList(env);
  if (!allowed.length) return false;
  const domain = oauthEmailDomain(email);
  if (!domain || isGithubNoreplyDomain(domain)) return true;
  return !allowed.includes(domain);
}

/**
 * Pick a GitHub `/user/emails` address for the SSO session.
 *
 * Only `verified: true`. If OAUTH_ALLOWED_DOMAINS is set, the first verified
 * email whose domain is an exact (case-insensitive) allowlist member wins —
 * except `users.noreply.github.com` and its subdomains, which never match.
 * If none match, fall back to the primary verified email (or first verified).
 * Empty/unset allowlist keeps primary-verified behaviour.
 *
 * @param {Array<{ email?: string, verified?: boolean, primary?: boolean }>} emails
 * @param {Record<string, string | undefined>} [env]
 * @returns {string | null}
 */
export function selectGitHubEmail(emails, env = {}) {
  if (!Array.isArray(emails)) return null;
  const verified = emails.filter(
    (e) => e && e.verified === true && typeof e.email === "string" && e.email
  );
  if (!verified.length) return null;

  const allowed = oauthAllowedDomainList(env);
  if (allowed.length) {
    const match = verified.find((e) => {
      const domain = oauthEmailDomain(e.email);
      return Boolean(domain) && !isGithubNoreplyDomain(domain) && allowed.includes(domain);
    });
    if (match) return match.email;
  }

  const primary = verified.find((e) => e.primary);
  return (primary || verified[0]).email;
}

/** Exact origins from CONSOLE_ORIGIN via `new URL().origin` — no suffix matching. */
export function consoleOrigins(env) {
  const raw = env.CONSOLE_ORIGIN || env.CONSOLE_ORIGINS || "";
  const out = [];
  for (const part of String(raw).split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    try {
      out.push(new URL(trimmed).origin);
    } catch {
      /* skip invalid */
    }
  }
  return out;
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

  const host = requestHost(request);

  // Customer custom host: Domain=.securepublish.work is not sent here.
  // Panel HTML needs a host-bound __Host-sp_session. API must never accept it.
  if (isCustomCustomerHost(host) && mode === "oauth") {
    if (forApi) {
      return { ok: false, status: 401, body: "unauthorized" };
    }
    const bound = await readHostBoundSessionCookie(request, env.SESSION_SECRET);
    if (bound && bound.host === host) {
      if (env.OAUTH_ALLOWED_DOMAINS) {
        const allowed = env.OAUTH_ALLOWED_DOMAINS.split(",")
          .map((d) => d.trim().toLowerCase())
          .filter(Boolean);
        const domain = (bound.email || "").split("@")[1]?.toLowerCase();
        if (allowed.length && (!domain || !allowed.includes(domain))) {
          return {
            ok: false,
            status: 403,
            body: "Acesso negado: domínio de e-mail não autorizado.\n",
          };
        }
      }
      return { ok: true, user: { email: bound.email, provider: bound.provider } };
    }
    const url = new URL(request.url);
    const ret = isSafeRelativeReturn(url.pathname) ? url.pathname : "/";
    const nonce = mintHandoffNonce();
    const nonceHash = await hashHandoffNonce(nonce);
    const dest = new URL("https://app.securepublish.work/auth/handoff");
    dest.searchParams.set("host", host);
    dest.searchParams.set("return", ret);
    dest.searchParams.set("nh", nonceHash);
    return { ok: false, redirectUrl: dest.toString(), handoffNonce: nonce };
  }

  // oauth
  const session = await readSessionCookie(request, env.SESSION_SECRET);
  if (session) {
    if (oauthEmailDeniedByDomainGate(session.email, env)) {
      return {
        ok: false,
        status: 403,
        body: forApi ? "domain_not_allowed" : "Acesso negado: domínio de e-mail não autorizado.\n",
      };
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
    if (email && oauthEmailDeniedByDomainGate(email, env)) {
      return {
        ok: false,
        status: 403,
        body: "Acesso negado: domínio de e-mail não autorizado.\n",
      };
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
 * IdPs with both CLIENT_ID and CLIENT_SECRET set (order matches PROVIDERS).
 * @param {Record<string, string | undefined>} env
 * @returns {string[]}
 */
function configuredProviders(env) {
  return Object.keys(PROVIDERS).filter((name) => {
    const cfg = PROVIDERS[name];
    return Boolean(env[cfg.idEnv] && env[cfg.secretEnv]);
  });
}

/**
 * GET /auth/providers — public IdP discovery for console signup/login.
 * CORS + credentials match /api/* so a cross-origin CONSOLE_ORIGIN works.
 */
function oauthProvidersResponse(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = consoleOrigins(env);
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    Vary: "Origin",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
  };
  if (origin && allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return new Response(JSON.stringify({ providers: configuredProviders(env) }), {
    status: 200,
    headers,
  });
}

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

  // Console discovery: GET /auth/providers (must not fall through to panel 404).
  if (
    (url.pathname === "/auth/providers" || url.pathname === "/auth/providers/") &&
    (request.method === "GET" || request.method === "HEAD")
  ) {
    return oauthProvidersResponse(request, env);
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

  // Claim remaining /auth/* so they never hit panel-id 404 on app.*.
  if (url.pathname.startsWith("/auth/")) {
    return new Response("Not found\n", {
      status: 404,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
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

  if (url.pathname === "/_auth/device/done" || url.pathname === "/_auth/device/done/") {
    return deviceDonePage(url.searchParams.get("retry") !== "1");
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

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** @param {URL} url @param {Record<string, string | undefined>} env */
function loginPage(url, env) {
  const returnTo = url.searchParams.get("return_to") || "/";
  const device = url.searchParams.get("device") || "";
  const deviceQs = /^[a-f0-9]{64}$/.test(device) ? `&device=${device}` : "";
  const en = url.searchParams.get("lang") === "en";
  const copy = en
    ? {
        title: "Sign in to view",
        lede: "Sign in with your company account to view the dashboard.",
        tip: "Use your company Google account — the same email domain controls who can view.",
        google: "Continue with Google",
        other: (n) => `Continue with ${n}`,
        langLabel: "Language",
      }
    : {
        title: "Entrar para ver",
        lede: "Entre com a conta da empresa para ver o dashboard.",
        tip: "Use a conta Google da empresa — o mesmo domínio de e-mail define quem pode ver.",
        google: "Continuar com Google",
        other: (n) => `Entrar com ${n}`,
        langLabel: "Idioma",
      };

  const links = [];
  for (const [name, cfg] of Object.entries(PROVIDERS)) {
    if (env[cfg.idEnv] && env[cfg.secretEnv]) {
      const href = `/_auth/start/${name}?return_to=${encodeURIComponent(returnTo)}${deviceQs}`;
      const label =
        name === "google" ? copy.google : copy.other(labelProvider(name));
      const icon =
        name === "google"
          ? `<span class="idp-btn__icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="20" height="20" focusable="false"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg></span>`
          : "";
      links.push(
        `<a class="idp-btn" href="${href}">${icon}<span class="idp-btn__label">${escapeHtml(label)}</span></a>`
      );
    }
  }
  if (!links.length) {
    return new Response("Nenhum provedor OAuth configurado.\n", {
      status: 503,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const langQs = (code) => {
    const q = new URLSearchParams();
    q.set("return_to", returnTo);
    q.set("lang", code);
    return `/_auth/login?${q.toString()}`;
  };

  const html = `<!DOCTYPE html>
<html lang="${en ? "en" : "pt-BR"}">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(copy.title)} — Secure Publish</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=Fraunces:opsz,wght@9..144,550;9..144,600&display=swap" rel="stylesheet"/>
<style>
:root{
  --cream:#FAF8F5;--cream-2:#F3EFE9;--stone:#E8E2D9;--ink:#292524;--ink-soft:#57534E;--muted:#78716C;
  --line:#E7E0D6;--sage:#5F7A61;--sage-hover:#4E6650;--sage-soft:#E8F0E9;--white:#FFFEFC;
  --display:"Fraunces",Georgia,serif;--sans:"DM Sans",system-ui,sans-serif;
  --radius:14px;--radius-sm:10px;
  --shadow:0 1px 2px rgba(41,37,36,.04),0 8px 24px rgba(41,37,36,.05);
  --max:540px;
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;
  font-family:var(--sans);font-size:1rem;line-height:1.5;color:var(--ink);
  background:
    radial-gradient(1200px 600px at 10% -10%,rgba(95,122,97,.08),transparent 55%),
    var(--cream-2);
}
.topbar{
  display:flex;align-items:center;justify-content:space-between;gap:1rem;
  padding:.85rem 1.35rem;border-bottom:1px solid var(--line);
  background:rgba(255,254,252,.94);backdrop-filter:blur(10px);
  position:sticky;top:0;z-index:20;
}
.topbar__brand{
  font-family:var(--display);font-weight:600;font-size:1.12rem;letter-spacing:-.02em;
  color:var(--ink);text-decoration:none;display:inline-flex;align-items:center;gap:.45rem;
}
.topbar__mark{display:inline-flex;width:1.35rem;height:1.35rem;color:var(--sage);flex-shrink:0}
.topbar__mark svg{width:100%;height:100%;display:block}
.topbar__lang{display:inline-flex;align-items:center;gap:.35rem}
.topbar__lang a{font-size:.8rem;font-weight:500;color:var(--muted);text-decoration:none;padding:.15rem .2rem}
.topbar__lang a.is-active{color:var(--ink);font-weight:650}
.topbar__lang-sep{color:var(--stone);font-size:.75rem;user-select:none}
.main{width:min(100% - 2rem,var(--max));margin:2.25rem auto 3rem}
.page-head{margin-bottom:1.35rem}
.page-head h1{
  margin:0 0 .4rem;font-family:var(--display);font-weight:600;font-size:clamp(1.55rem,3vw,1.85rem);
  letter-spacing:-.02em;line-height:1.2;color:var(--ink);
}
.lede{margin:0;color:var(--ink-soft);font-size:1.02rem;line-height:1.55}
.card{
  background:var(--white);border:1px solid var(--stone);border-radius:var(--radius);
  padding:1.35rem 1.35rem 1.4rem;box-shadow:var(--shadow);
}
.idp-list{display:grid;gap:.7rem}
.idp-btn{
  display:flex;flex-direction:row;align-items:center;justify-content:center;gap:.65rem;
  width:100%;padding:.95rem 1.15rem;border:1px solid var(--stone);border-radius:var(--radius-sm);
  background:var(--cream);font:inherit;font-weight:600;font-size:.98rem;color:var(--ink);
  text-decoration:none;transition:border-color .15s,background .15s,box-shadow .15s;
}
.idp-btn__icon{display:inline-flex;width:20px;height:20px;flex-shrink:0}
.idp-btn__icon svg{display:block;width:20px;height:20px}
.idp-btn__label{line-height:1.2}
.idp-btn:hover{
  border-color:var(--sage);background:var(--sage-soft);box-shadow:var(--shadow);
  color:var(--ink);text-decoration:none;
}
.oauth-tip{margin:.9rem 0 0;font-size:.84rem;color:var(--muted);text-align:center;line-height:1.45}
</style>
</head>
<body>
<header class="topbar">
  <span class="topbar__brand">
    <span class="topbar__mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none"><rect x="3" y="11" width="18" height="10" rx="2" stroke="currentColor" stroke-width="1.75"/><path d="M7 11V8a5 5 0 0 1 10 0v3" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/><circle cx="12" cy="16" r="1.5" fill="currentColor"/></svg>
    </span>
    Secure Publish
  </span>
  <nav class="topbar__lang" aria-label="${escapeHtml(copy.langLabel)}">
    <a href="${langQs("en")}" class="${en ? "is-active" : ""}">EN</a>
    <span class="topbar__lang-sep" aria-hidden="true">|</span>
    <a href="${langQs("pt")}" class="${en ? "" : "is-active"}">PT</a>
  </nav>
</header>
<main class="main">
  <div class="page-head">
    <h1>${escapeHtml(copy.title)}</h1>
    <p class="lede">${escapeHtml(copy.lede)}</p>
  </div>
  <div class="card">
    <div class="idp-list">${links.join("")}</div>
    <p class="oauth-tip">${escapeHtml(copy.tip)}</p>
  </div>
</main>
</body>
</html>`;
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
  const device = url.searchParams.get("device") || "";
  // Always use the canonical callback host so Set-Cookie can set
  // Domain=.securepublish.work (panel hosts share that cookie). Starting OAuth
  // on wise.* or workers.dev must not mint a host-only cookie on that host.
  const redirectUri = oauthRedirectUri(env, provider);
  const stateBody = { returnTo, provider, n: crypto.randomUUID() };
  if (/^[a-f0-9]{64}$/.test(device)) stateBody.device = device;
  const state = encodeState(stateBody);

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

  // If the user started OAuth on a non-canonical host, bounce through the
  // canonical origin so the callback response can mint Domain=.securepublish.work.
  const canonical = oauthCallbackOrigin(env);
  if (url.origin !== canonical && !env.OAUTH_CALLBACK_ORIGIN) {
    const startPath = url.pathname.startsWith("/auth/")
      ? `/auth/${provider}`
      : `/_auth/start/${provider}`;
    const bounce = new URL(startPath, canonical + "/");
    bounce.searchParams.set("return_to", returnTo);
    if (stateBody.device) bounce.searchParams.set("device", stateBody.device);
    return Response.redirect(bounce.toString(), 302);
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
  const redirectUri = oauthRedirectUri(env, provider);

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

  const email = String((await fetchUserEmail(provider, cfg, accessToken, env)) || "")
    .trim()
    .toLowerCase();
  if (!email) {
    if (provider === "github") return githubLoginDeniedResponse();
    return new Response("Não foi possível obter e-mail do provedor.\n", { status: 502 });
  }

  if (oauthEmailDeniedByDomainGate(email, env)) {
    if (provider === "github") return githubLoginDeniedResponse();
    return new Response("Acesso negado: domínio de e-mail não autorizado.\n", {
      status: 403,
    });
  }

  // Mint against the canonical callback URL so cookieAttrs always applies
  // Domain=.securepublish.work (panel hosts *.securepublish.work share it).
  const mintUrl = `${oauthCallbackOrigin(env)}/_auth/callback/${provider}`;
  const cookie = await mintSessionCookie(
    { email, provider, exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SEC },
    env.SESSION_SECRET,
    env,
    mintUrl
  );

  let location = await safeReturnTo(state.returnTo, env);
  if (state.device && /^[a-f0-9]{64}$/.test(state.device)) {
    let linked = false;
    try {
      const approved = await approveDeviceCode(env.PANELS, state.device, email);
      linked = Boolean(approved?.ok);
    } catch {
      linked = false;
    }
    location = linked ? "/_auth/device/done" : "/_auth/device/done?retry=1";
  }

  const headers = new Headers({ location });
  // Kill host-only zombies on app.* so the Domain-scoped cookie is authoritative
  // for both console API and panel hosts (see readSessionCookie multi-value).
  headers.append(
    "set-cookie",
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  );
  headers.append(
    "set-cookie",
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`
  );
  headers.append("set-cookie", cookie);

  return new Response(null, {
    status: 302,
    headers,
  });
}

function deviceDonePage(ok) {
  const retry = !ok;
  const title = retry ? "Não consegui ligar agora" : "Conta ligada";
  const lede = retry
    ? "Volta e tenta de novo em instantes."
    : "Pode fechar esta aba.";
  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${title}</title>
</head>
<body style="font-family:Georgia,serif;background:#F3EFE9;color:#292524;margin:0">
<main style="max-width:32rem;margin:4rem auto;padding:0 1.25rem">
<h1 style="font-weight:600">${title}</h1>
<p>${lede}</p>
</main>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

const GITHUB_LOGIN_DENIED_BODY =
  "Não conseguimos entrar com essa conta do GitHub. Ela precisa ter o e-mail da empresa confirmado no GitHub. Confira em github.com/settings/emails ou entre com outra conta.\n" +
  "We couldn't sign you in with this GitHub account. It needs your company email confirmed on GitHub. Check github.com/settings/emails or sign in with another account.\n";

function githubLoginDeniedResponse() {
  return new Response(GITHUB_LOGIN_DENIED_BODY, {
    status: 403,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

async function fetchUserEmail(provider, cfg, accessToken, env = {}) {
  if (provider === "github") {
    // Email must come only from /user/emails with verified: true. Never /user.
    try {
      const emailsRes = await fetch(cfg.emailUrl, {
        headers: {
          authorization: `Bearer ${accessToken}`,
          accept: "application/vnd.github+json",
          "user-agent": "secure-publish",
        },
      });
      if (!emailsRes.ok) return null;
      const emails = await emailsRes.json();
      return selectGitHubEmail(emails, env);
    } catch {
      return null;
    }
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

function defaultReturnTo(env) {
  const allowed = consoleOrigins(env);
  return allowed.length ? allowed[0] + "/" : "/";
}

/**
 * Login `next` / `return_to`.
 * Relative paths (no //, no backslash) remap to CONSOLE_ORIGIN.
 * Absolute https URLs: CONSOLE_ORIGIN, or *.securepublish.work / apex, or a
 * customer hostname that exact-matches KV after claim normalization with
 * customVerified:true AND status active. No suffix/substring matching for
 * customer hosts. No open redirect.
 */
export async function safeReturnTo(path, env) {
  if (!path || typeof path !== "string") return defaultReturnTo(env);
  const allowed = consoleOrigins(env);
  if (isSafeRelativeReturn(path)) {
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
    if (u.protocol !== "https:") return defaultReturnTo(env);
    if (u.username || u.password) return defaultReturnTo(env);
    if (allowed.includes(u.origin)) return u.toString();

    const n = normalizeCustomHostname(u.hostname);
    if (!n.ok) return defaultReturnTo(env);
    u.hostname = n.hostname;
    if (isOwnZoneHost(n.hostname)) return u.toString();

    if (env?.PANELS) {
      const owner = await env.PANELS.get(`host:custom:${n.hostname}`);
      if (owner) {
        const tenant = await getTenant(env.PANELS, owner);
        const claimed = normalizeCustomHostname(String(tenant?.customHostname || ""));
        if (
          claimed.ok &&
          claimed.hostname === n.hostname &&
          tenant?.customVerified === true &&
          tenant?.customStatus === "active"
        ) {
          return u.toString();
        }
      }
    }
  } catch {
    /* ignore */
  }
  return defaultReturnTo(env);
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
    "cache-control": "no-store",
  });
  const host = requestHost(request);
  if (isCustomCustomerHost(host)) {
    headers.append("set-cookie", clearHostBoundSessionCookie());
    headers.set("location", "https://app.securepublish.work/auth/logout");
    return new Response(null, { status: 302, headers });
  }
  // Append (not set): browsers keep host-only cookies separate from Domain=
  // cookies. Clearing only Domain=.securepublish.work leaves a pre-Domain
  // host-only secure_publish_session on app.securepublish.work as a zombie.
  for (const cookie of clearSessionCookieVariants(env, request.url)) {
    headers.append("set-cookie", cookie);
  }

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
  // Do not invent Domain= from workers.dev responses — browsers reject Domain that
  // does not match the response host. OAuth callbacks are pinned to app.* instead.
  if (host.endsWith(".securepublish.work") || host === "securepublish.work") {
    return { sameSite: "Lax", domain: "; Domain=.securepublish.work" };
  }
  if (consoleOrigins(env).length) return { sameSite: "None", domain: "" };
  return { sameSite: "Lax", domain: "" };
}

async function signedCookieValue(payload, secret) {
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const sig = await hmacSign(body, secret);
  return `${body}.${sig}`;
}

async function mintSessionCookie(payload, secret, env = {}, requestUrl = "") {
  const value = await signedCookieValue(payload, secret);
  const { sameSite, domain } = cookieAttrs(env, requestUrl);
  return `${COOKIE_NAME}=${value}; Path=/${domain}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=${SESSION_TTL_SEC}`;
}

/**
 * New host-bound session on a customer hostname. The handoff code is never
 * the session. No Domain= (forbidden by __Host- prefix).
 */
export async function mintHostBoundSessionCookie(payload, secret) {
  const value = await signedCookieValue(payload, secret);
  return `${HOST_SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SEC}`;
}

export function clearHostBoundSessionCookie() {
  return `${HOST_SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function bytesToBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(s) {
  const raw = String(s || "");
  const pad = raw.length % 4 === 0 ? "" : "=".repeat(4 - (raw.length % 4));
  const b64 = raw.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Random 32-byte nonce, base64url-encoded for the `__Host-sp_handoff` cookie. */
export function mintHandoffNonce() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

/** SHA-256 of the nonce bytes, base64url — the only value sent to `app.`. */
export async function hashHandoffNonce(nonce) {
  const bytes = base64UrlToBytes(nonce);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64Url(new Uint8Array(digest));
}

export function mintHandoffCookie(nonce) {
  return `${HOST_HANDOFF_COOKIE}=${nonce}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${HANDOFF_COOKIE_MAX_AGE}`;
}

export function clearHandoffCookie() {
  return `${HOST_HANDOFF_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function readHandoffNonce(request) {
  const values = sessionCookieValues(
    request.headers.get("cookie") || "",
    HOST_HANDOFF_COOKIE
  );
  return values[0] || "";
}

export async function handoffNonceMatches(cookieNonce, storedHash) {
  if (!cookieNonce || !storedHash) return false;
  let got;
  try {
    got = await hashHandoffNonce(cookieNonce);
  } catch {
    return false;
  }
  if (got.length !== storedHash.length) return false;
  return timingSafeEqual(got, storedHash);
}

function clearSessionCookie(env = {}, requestUrl = "") {
  const { sameSite, domain } = cookieAttrs(env, requestUrl);
  return `${COOKIE_NAME}=; Path=/${domain}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`;
}

/**
 * All Set-Cookie clears needed to kill current + legacy session cookies.
 * Domain-scoped clear alone does NOT delete a host-only cookie of the same name
 * (zombie session on app.securepublish.work after logout). Always emit every
 * historical mint shape — host-only vs Domain, Lax vs None (workers.dev era).
 * Callers must Headers.append each line (never join into one Set-Cookie).
 * @returns {string[]}
 */
function clearSessionCookieVariants(_env = {}, _requestUrl = "") {
  return [
    // 1) Host-only Lax
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    // 2) Domain Lax (current *.securepublish.work mint)
    `${COOKIE_NAME}=; Path=/; Domain=.securepublish.work; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    // 3) Host-only None (workers.dev / early cross-site mint)
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`,
    // 4) Domain None (legacy pairing)
    `${COOKIE_NAME}=; Path=/; Domain=.securepublish.work; HttpOnly; Secure; SameSite=None; Max-Age=0`,
  ];
}

/**
 * Parse Cookie header values for COOKIE_NAME. Browsers may send both a host-only
 * zombie and a Domain=.securepublish.work cookie with the same name; first-match
 * alone rejected valid Domain cookies when an invalid sibling was listed first.
 * @returns {string[]}
 */
function sessionCookieValues(raw, cookieName = COOKIE_NAME) {
  const out = [];
  const escaped = cookieName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`(?:^|;\\s*)${escaped}=([^;]*)`, "g");
  let m;
  while ((m = re.exec(String(raw || "")))) {
    let v = (m[1] || "").trim();
    if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
      v = v.slice(1, -1);
    }
    if (v) out.push(v);
  }
  return out;
}

async function parseSessionValue(value, secret) {
  const [body, sig] = String(value).split(".");
  if (!body || !sig) return null;
  const expected = await hmacSign(body, secret);
  if (!timingSafeEqual(sig.toLowerCase(), expected)) return null;
  try {
    const pad = body.length % 4 === 0 ? "" : "=".repeat(4 - (body.length % 4));
    const json = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/") + pad));
    if (!json.exp || json.exp < Math.floor(Date.now() / 1000)) return null;
    return json;
  } catch {
    return null;
  }
}

async function readSessionCookie(request, secret) {
  if (!secret) return null;
  const values = sessionCookieValues(request.headers.get("cookie") || "");
  for (const value of values) {
    const session = await parseSessionValue(value, secret);
    if (session) return session;
  }
  return null;
}

export async function readHostBoundSessionCookie(request, secret) {
  if (!secret) return null;
  const values = sessionCookieValues(
    request.headers.get("cookie") || "",
    HOST_SESSION_COOKIE
  );
  const host = requestHost(request);
  for (const value of values) {
    const session = await parseSessionValue(value, secret);
    if (session && session.host === host) return session;
  }
  return null;
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
export {
  readSessionCookie,
  mintSessionCookie,
  clearSessionCookie,
  clearSessionCookieVariants,
  COOKIE_NAME,
};
