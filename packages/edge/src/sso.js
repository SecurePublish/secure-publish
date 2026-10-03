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
import { approveDeviceCode } from "./kv.js";

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

/**
 * True when both CLIENT_ID and CLIENT_SECRET are set for the IdP.
 * @param {Record<string, string | undefined>} env
 * @param {string} provider
 */
export function isProviderConfigured(env, provider) {
  const cfg = PROVIDERS[provider];
  if (!cfg) return false;
  return Boolean(env[cfg.idEnv] && env[cfg.secretEnv]);
}

/** @param {Record<string, string | undefined>} env */
function hasAnyOauthProvider(env) {
  return (
    isProviderConfigured(env, "google") ||
    isProviderConfigured(env, "github") ||
    isProviderConfigured(env, "microsoft")
  );
}

/** @param {Record<string, string | undefined>} env */
function configuredProviders(env) {
  return Object.keys(PROVIDERS).filter((name) => isProviderConfigured(env, name));
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
  const providers = configuredProviders(env);
  const googleOnly = providers.length === 1 && providers[0] === "google";
  const copy = en
    ? {
        title: "Sign in to view",
        lede: "Sign in with your company account to view the dashboard.",
        tip: googleOnly
          ? "Use your company Google account — the same email domain controls who can view."
          : "Use your company account — the same email domain controls who can view.",
        google: "Continue with Google",
        other: (n) => `Continue with ${n}`,
        langLabel: "Language",
      }
    : {
        title: "Entrar para ver",
        lede: "Entre com a conta da empresa para ver o dashboard.",
        tip: googleOnly
          ? "Use a conta Google da empresa — o mesmo domínio de e-mail define quem pode ver."
          : "Use a conta da empresa — o mesmo domínio de e-mail define quem pode ver.",
        google: "Continuar com Google",
        other: (n) => `Entrar com ${n}`,
        langLabel: "Idioma",
      };

  const links = [];
  for (const name of providers) {
    const href = `/_auth/start/${name}?return_to=${encodeURIComponent(returnTo)}${deviceQs}`;
    const label =
      name === "google" ? copy.google : copy.other(labelProvider(name));
    const icon = providerIcon(name);
    links.push(
      `<a class="idp-btn" href="${href}">${icon}<span class="idp-btn__label">${escapeHtml(label)}</span></a>`
    );
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

function providerIcon(name) {
  if (name === "google") {
    return `<span class="idp-btn__icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="20" height="20" focusable="false"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg></span>`;
  }
  if (name === "github") {
    return `<span class="idp-btn__icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20" focusable="false"><path fill="#24292F" d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.1c-3.3.7-4-1.4-4-1.4-.5-1.3-1.3-1.7-1.3-1.7-1-.7.1-.7.1-.7 1.1.1 1.7 1.2 1.7 1.2 1 .1.8 1.6 2.8 1.1.1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-6a4.6 4.6 0 0 1 1.2-3.2 4.3 4.3 0 0 1 .1-3.1s1-.3 3.3 1.2a11.4 11.4 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.7 1.7.2 2.9.1 3.1a4.6 4.6 0 0 1 1.2 3.2c0 4.7-2.8 5.7-5.5 6 .4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .3z"/></svg></span>`;
  }
  if (name === "microsoft") {
    return `<span class="idp-btn__icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 23 23" width="20" height="20" focusable="false"><path fill="#F25022" d="M1 1h10v10H1z"/><path fill="#00A4EF" d="M12 1h10v10H12z"/><path fill="#7FBA00" d="M1 12h10v10H1z"/><path fill="#FFB900" d="M12 12h10v10H12z"/></svg></span>`;
  }
  return "";
}

/** @param {URL} url @param {Record<string, string | undefined>} env @param {string} provider */
function oauthStart(url, env, provider) {
  const cfg = PROVIDERS[provider];
  if (!cfg || !isProviderConfigured(env, provider)) {
    return new Response(`Provedor ${provider} não configurado.\n`, {
      status: 503,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
  const clientId = env[cfg.idEnv];
  const returnTo = url.searchParams.get("return_to") || url.searchParams.get("next") || "/";
  const device = url.searchParams.get("device") || "";
  const redirectUri = `${url.origin}/_auth/callback/${provider}`;
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
  if (provider === "google") {
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
  if (!cfg || !isProviderConfigured(env, provider)) {
    return new Response(`Provedor ${provider} não configurado.\n`, {
      status: 503,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
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

  const idTokenClaims = decodeJwtPayload(tokenJson.id_token);
  const email = await resolveOauthEmail(provider, accessToken, { idTokenClaims });
  if (!email) {
    return emailRequiredPage(provider);
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

  let location = safeReturnTo(state.returnTo, env);
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

  return new Response(null, {
    status: 302,
    headers: {
      location,
      "set-cookie": cookie,
    },
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

function isValidEmail(value) {
  if (typeof value !== "string") return false;
  const email = value.trim().toLowerCase();
  if (!email || email.includes(" ")) return false;
  if (email.includes("#ext#")) return false;
  if (email.endsWith("@users.noreply.github.com")) return false;
  const at = email.indexOf("@");
  if (at < 1 || at !== email.lastIndexOf("@")) return false;
  const domain = email.slice(at + 1);
  return domain.includes(".") && !domain.startsWith(".") && !domain.endsWith(".");
}

function decodeJwtPayload(jwt) {
  if (!jwt || typeof jwt !== "string") return null;
  try {
    const parts = jwt.split(".");
    if (parts.length < 2) return null;
    const pad = parts[1].length % 4 === 0 ? "" : "=".repeat(4 - (parts[1].length % 4));
    const json = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/") + pad);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * Resolve a verified email from an IdP. Fail closed — never noreply / unverified /
 * preferred_username-only guesses.
 * @param {string} provider
 * @param {string} accessToken
 * @param {{ idTokenClaims?: Record<string, unknown> | null }} [opts]
 * @returns {Promise<string | null>}
 */
export async function resolveOauthEmail(provider, accessToken, opts = {}) {
  const cfg = PROVIDERS[provider];
  if (!cfg) return null;

  if (provider === "github") {
    const emailsRes = await fetch(cfg.emailUrl, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/vnd.github+json",
        "user-agent": "secure-publish",
      },
    });
    if (!emailsRes.ok) return null;
    const emails = await emailsRes.json();
    if (!Array.isArray(emails)) return null;
    const primary = emails.find((e) => e && e.primary && e.verified);
    if (primary?.email && isValidEmail(primary.email)) {
      return primary.email.trim().toLowerCase();
    }
    return null;
  }

  if (provider === "microsoft") {
    const claims = opts.idTokenClaims || null;
    if (claims && claims.email_verified === false) {
      /* continue to Graph mail only */
    } else if (claims && isValidEmail(claims.email) && claims.email_verified !== false) {
      return String(claims.email).trim().toLowerCase();
    }

    const res = await fetch(cfg.userUrl, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) return null;
    const me = await res.json();
    if (isValidEmail(me.mail)) return String(me.mail).trim().toLowerCase();
    // Do not use preferred_username or guest UPNs as an email guess.
    return null;
  }

  const res = await fetch(cfg.userUrl, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) return null;
  const me = await res.json();
  if (!isValidEmail(me.email) || me.verified_email === false) return null;
  return String(me.email).trim().toLowerCase();
}

function emailRequiredPage(provider) {
  const name = labelProvider(provider);
  const isGithub = provider === "github";
  const title = "E-mail verificado necessário";
  const lede = isGithub
    ? "Não encontramos um e-mail primário verificado na sua conta GitHub. Torne um e-mail primário e verificado visível (Settings → Emails) e tente de novo. Não usamos endereços noreply."
    : `Não encontramos um e-mail verificado na sua conta ${name}. Use uma conta com e-mail verificado e tente de novo.`;
  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)} — Secure Publish</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=Fraunces:opsz,wght@9..144,550;9..144,600&display=swap" rel="stylesheet"/>
<style>
:root{--cream-2:#F3EFE9;--ink:#292524;--ink-soft:#57534E;--line:#E7E0D6;--sage:#5F7A61;--display:"Fraunces",Georgia,serif;--sans:"DM Sans",system-ui,sans-serif}
body{margin:0;min-height:100vh;font-family:var(--sans);color:var(--ink);background:radial-gradient(1200px 600px at 10% -10%,rgba(95,122,97,.08),transparent 55%),var(--cream-2)}
.topbar{padding:.85rem 1.35rem;border-bottom:1px solid var(--line);background:rgba(255,254,252,.94);font-family:var(--display);font-weight:600}
main{max-width:32rem;margin:3rem auto;padding:0 1.25rem}
h1{font-family:var(--display);font-weight:600;font-size:1.55rem;letter-spacing:-.02em}
p{color:var(--ink-soft);line-height:1.55}
a{color:var(--sage);font-weight:600}
</style>
</head>
<body>
<header class="topbar">Secure Publish</header>
<main>
  <h1>${escapeHtml(title)}</h1>
  <p>${escapeHtml(lede)}</p>
  <p><a href="/_auth/login">Voltar ao login</a></p>
</main>
</body>
</html>`;
  return new Response(html, {
    status: 403,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
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
    "cache-control": "no-store",
  });
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
export {
  readSessionCookie,
  mintSessionCookie,
  clearSessionCookie,
  clearSessionCookieVariants,
  COOKIE_NAME,
  PROVIDERS,
};
