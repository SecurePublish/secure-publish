/**
 * Console ↔ Worker API (Cameron contract / API-CONTRACT.md).
 *
 * Marcus checklist:
 * 1) Every /api/* requires SSO session
 * 2) PATCH access = publisher only
 * 3) CORS = exact CONSOLE_ORIGIN + credentials
 * 4) viewers[] PII only for authenticated tenant users
 * 5) Custom domain: claim + verify ownership before serving as host
 */

import { requireSsoSession, ssoMode } from "./sso.js";
import { isPublicEmailDomain, normalizeDomains } from "./acl.js";
import {
  getPanel,
  putPanel,
  listPanelIdsForPublisher,
  listPanelIdsForDomain,
  listAllPanelIds,
  getViews,
  getTenant,
  claimSubdomain,
  claimCustomHostname,
  clearPendingCustomHostname,
  verifyCustomHostname,
  customVerifyChallenge,
  accessToApiMode,
  accessToAllowlist,
  formatPublishedLabel,
  viewsToApi,
  buildAccessFromPatch,
  indexPanel,
  PANEL_ID_RE,
  createDeviceCode,
  approveDeviceCode,
  pollDeviceCode,
  userFromPublishToken,
  revokePublishToken,
} from "./kv.js";

/** @returns {string[]} */
export function consoleOrigins(env) {
  const raw = env.CONSOLE_ORIGIN || env.CONSOLE_ORIGINS || "";
  return String(raw)
    .split(",")
    .map((s) => s.trim().replace(/\/$/, ""))
    .filter(Boolean);
}

export function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = consoleOrigins(env);
  const headers = {
    Vary: "Origin",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
  };
  if (origin && allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return headers;
}

function json(data, status, request, env, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...corsHeaders(request, env),
      ...extraHeaders,
    },
  });
}

function err(message, status, request, env) {
  return json({ error: message }, status, request, env);
}

/**
 * @returns {Promise<Response | null>} null if not an /api route
 */
export async function handleApiRoutes(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/api/")) return null;

  // Preflight — no session required, but origin must match allowlist.
  if (request.method === "OPTIONS") {
    const origin = request.headers.get("Origin") || "";
    const allowed = consoleOrigins(env);
    if (origin && !allowed.includes(origin)) {
      return new Response(null, { status: 403 });
    }
    return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  }

  // Device login start/poll and publish-credential revoke do not use the
  // browser cookie. Panel routes still require the account owner.
  if (url.pathname === "/api/device/code" && request.method === "POST") {
    return handleDeviceCode(request, env);
  }
  if (url.pathname === "/api/device/token" && request.method === "POST") {
    return handleDevicePoll(request, env);
  }
  if (url.pathname === "/api/session/revoke" && request.method === "POST") {
    return handleRevokePublish(request, env);
  }

  const publishPost = url.pathname === "/api/panels" && request.method === "POST";
  let bearerEmail = null;
  if (publishPost) {
    const header = request.headers.get("authorization") || "";
    const match = header.match(/^Bearer\s+(\S+)/i);
    if (match) {
      const tokenUser = await userFromPublishToken(env.PANELS, match[1]);
      if (!tokenUser?.email) return err("unauthorized", 401, request, env);
      bearerEmail = tokenUser.email;
    }
  }

  // (1) Every other /api/* requires SSO — no anonymous data.
  // POST /api/panels also accepts the publish credential in Authorization.
  const sso = await requireSsoSession(request, env, { api: true });
  if (!sso.ok && !(publishPost && bearerEmail)) {
    return err(sso.body || "unauthorized", sso.status || 401, request, env);
  }
  const user = sso.ok ? sso.user : { email: bearerEmail, provider: "device" };
  const email = (user.email || "").trim().toLowerCase();
  if (bearerEmail && email && bearerEmail !== email) {
    return err("forbidden", 403, request, env);
  }
  if (!email || !email.includes("@")) {
    return err("missing_email", 403, request, env);
  }
  const domain = email.split("@")[1];
  const idp = user.provider || user.idp || "unknown";

  if (url.pathname === "/api/me" && request.method === "GET") {
    return handleMe(request, env, { email, domain, idp });
  }

  if (url.pathname === "/api/panels" && request.method === "GET") {
    return handleListPanels(request, env, url, { email, domain });
  }

  if (url.pathname === "/api/panels" && request.method === "POST") {
    return handlePublishPanel(request, env, { email, domain });
  }

  if (url.pathname === "/api/device/bind" && request.method === "POST") {
    return handleDeviceBind(request, env, { email });
  }

  const accessMatch = url.pathname.match(/^\/api\/panels\/([^/]+)\/access\/?$/);
  if (accessMatch && request.method === "PATCH") {
    return handlePatchAccess(request, env, accessMatch[1], { email, domain });
  }

  if (url.pathname === "/api/hosting/subdomain" && request.method === "PUT") {
    return handleSubdomain(request, env, { email, domain });
  }

  if (url.pathname === "/api/hosting/custom" && request.method === "PUT") {
    return handleCustom(request, env, { email, domain });
  }

  if (url.pathname === "/api/hosting/custom" && request.method === "DELETE") {
    return handleCustomDelete(request, env, { email });
  }

  if (url.pathname === "/api/hosting/custom/verify" && request.method === "POST") {
    return handleCustomVerify(request, env, { email, domain });
  }

  return err("not_found", 404, request, env);
}

/**
 * Serving host for console URLs. Returns null until the tenant claims hosting
 * (subdomain / verified custom). Never returns "" — empty string made the
 * console fabricate https:///{id}.
 */
function normalizeHost(host) {
  if (host == null) return null;
  const h = String(host).trim();
  return h || null;
}

async function resolveHost(kv, email, env) {
  const tenant = await getTenant(kv, email);
  if (tenant?.customHostname && tenant.customVerified) {
    return normalizeHost(tenant.customHostname);
  }
  if (tenant?.host) return normalizeHost(tenant.host);
  if (tenant?.slug) {
    const slug = String(tenant.slug).trim();
    if (slug) return `${slug}.securepublish.work`;
  }
  // Optional env hint only — still must be non-empty.
  return normalizeHost(env.DEFAULT_PANEL_HOST);
}

async function handleMe(request, env, { email, domain, idp }) {
  const host = await resolveHost(env.PANELS, email, env);
  const tenant = await getTenant(env.PANELS, email);
  const customHostname = tenant?.customHostname
    ? String(tenant.customHostname).trim().toLowerCase() || null
    : null;
  const customVerified = Boolean(tenant?.customVerified);
  const body = {
    email,
    idp,
    domain,
    publicDomain: isPublicEmailDomain(email),
    // Serving host only (verified custom or subdomain) — never "".
    host,
    customHostname,
    customVerified,
  };
  if (customHostname && !customVerified) {
    const token = tenant?.customVerifyToken || null;
    body.verify = customVerifyChallenge(customHostname, token);
  }
  return json(body, 200, request, env);
}

async function handleListPanels(request, env, url, { email, domain }) {
  const scope = (url.searchParams.get("scope") || "mine").toLowerCase();
  const kv = env.PANELS;
  const host = await resolveHost(kv, email, env);

  let ids;
  if (scope === "company") {
    ids = await listPanelIdsForDomain(kv, domain);
    if (!ids.length) {
      // Legacy scan — filter company mode + same publisher domain
      ids = await listAllPanelIds(kv);
    }
  } else {
    ids = await listPanelIdsForPublisher(kv, email);
    if (!ids.length) {
      ids = await listAllPanelIds(kv);
    }
  }

  const panels = [];
  for (const id of ids) {
    const record = await getPanel(kv, id);
    if (!record) continue;
    const publisherEmail = (record.publisherEmail || "").trim().toLowerCase();
    const mode = accessToApiMode(record.access);

    if (scope === "mine") {
      if (publisherEmail !== email) continue;
    } else {
      // company scope: company|org mode only; publisher must share domain
      if (mode !== "company") continue;
      const pubDomain = publisherEmail.includes("@")
        ? publisherEmail.split("@")[1]
        : (record.access?.domains || [])[0];
      const companyDomains = normalizeDomains(
        record.access?.domains?.length
          ? record.access.domains
          : pubDomain
            ? [pubDomain]
            : []
      );
      if (companyDomains.some((d) => isPublicEmailDomain(d))) continue;
      if (pubDomain && pubDomain !== domain) continue;
      // If no publisherEmail (legacy), require access.domains includes viewer domain
      if (!publisherEmail) {
        const domains = record.access?.domains || [];
        if (domains.length && !domains.includes(domain)) continue;
        if (!domains.length) continue;
      }
    }

    // (4) viewers PII only for authenticated tenant (we already require SSO).
    // Same-domain publishers / company viewers may see analytics for panels they can list.
    const viewData = await getViews(kv, id);
    const { views, viewers } = viewsToApi(viewData);

    const title =
      typeof record.title === "string" && record.title.trim()
        ? record.title.trim()
        : "untitled";

    panels.push({
      id,
      title,
      publisherEmail: publisherEmail || null,
      mode,
      allowlist: accessToAllowlist(record.access),
      publishedAt: record.publishedAt || null,
      publishedLabel: formatPublishedLabel(record.publishedAt),
      views,
      viewers,
    });
  }

  panels.sort((a, b) => String(b.publishedAt || "").localeCompare(String(a.publishedAt || "")));
  return json({ host, panels }, 200, request, env);
}

async function handlePatchAccess(request, env, panelId, { email }) {
  if (!PANEL_ID_RE.test(panelId)) {
    return err("not_found", 404, request, env);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return err("invalid_json", 400, request, env);
  }

  const kv = env.PANELS;
  const record = await getPanel(kv, panelId);
  if (!record) return err("not_found", 404, request, env);

  // (2) Publisher only
  const publisher = (record.publisherEmail || "").trim().toLowerCase();
  if (!publisher || publisher !== email) {
    return err("forbidden", 403, request, env);
  }

  const mode = (body.mode || "company").toLowerCase() === "allowlist" ? "allowlist" : "company";
  if (mode === "company" && isPublicEmailDomain(email)) {
    return err("company_requires_work_domain", 400, request, env);
  }
  if (mode === "allowlist") {
    const list = Array.isArray(body.allowlist) ? body.allowlist : [];
    if (!list.length) {
      return err("min_email", 400, request, env);
    }
  }

  const access = buildAccessFromPatch(body, email);
  record.access = access;
  await putPanel(kv, panelId, record);
  await indexPanel(kv, panelId, publisher, access);

  // sendInvite? — stub only; do not claim email sent
  let inviteStub = undefined;
  if (body.sendInvite && mode === "allowlist") {
    console.log(
      JSON.stringify({
        type: "invite_stub",
        panelId,
        to: access.emails,
        from: email,
        note: "email provider not configured",
      })
    );
    inviteStub = { queued: false, reason: "email_provider_not_configured" };
  }

  const viewData = await getViews(kv, panelId);
  const { views, viewers } = viewsToApi(viewData);
  const panel = {
    id: panelId,
    publisherEmail: publisher,
    mode: accessToApiMode(access),
    allowlist: accessToAllowlist(access),
    publishedAt: record.publishedAt || null,
    publishedLabel: formatPublishedLabel(record.publishedAt),
    views,
    viewers,
  };

  return json({ ok: true, panel, inviteStub }, 200, request, env);
}



async function handleDeviceCode(request, env) {
  const created = await createDeviceCode(env.PANELS);
  const origin = new URL(request.url).origin;
  return json(
    {
      device_code: created.device_code,
      verification_url: `${origin}/auth/google?device=${created.device_code}`,
      expires_in: created.expires_in,
      interval: created.interval,
    },
    200,
    request,
    env
  );
}

async function handleDevicePoll(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return err("invalid_json", 400, request, env);
  }
  const result = await pollDeviceCode(env.PANELS, body?.device_code);
  if (!result.ok) return err(result.error || "error", result.status || 400, request, env);
  const host = await resolveHost(env.PANELS, result.email, env);
  const now = Math.floor(Date.now() / 1000);
  return json(
    {
      access_token: result.accessToken,
      token_type: "Bearer",
      email: result.email,
      host,
      expires_in: Math.max(0, (result.tokenExp || now) - now),
    },
    200,
    request,
    env
  );
}

async function handleDeviceBind(request, env, { email }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return err("invalid_json", 400, request, env);
  }
  const result = await approveDeviceCode(env.PANELS, body?.device_code, email);
  if (!result.ok) return err(result.error || "error", result.status || 400, request, env);
  return json({ ok: true }, 200, request, env);
}

async function handleRevokePublish(request, env) {
  const header = request.headers.get("authorization") || "";
  const match = header.match(/^Bearer\s+(\S+)/i);
  if (!match) return err("unauthorized", 401, request, env);
  const result = await revokePublishToken(env.PANELS, match[1]);
  if (!result.ok) return err(result.error || "unauthorized", result.status || 401, request, env);
  return json({ ok: true }, 200, request, env);
}

/** Customer publish cap. Operator KV path is not this route. */
const MAX_HTML_BYTES = Math.floor(1.5 * 1024 * 1024);

function newPanelId() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function utf8ByteLength(value) {
  return new TextEncoder().encode(value).length;
}

/**
 * POST /api/panels — signed-in user publishes HTML. No Cloudflare API token.
 * Body: { html, title?, to?: string | string[] }
 * Default access = company (session email domain).
 */
async function handlePublishPanel(request, env, { email, domain }) {
  const len = Number(request.headers.get("content-length") || 0);
  if (len && len > MAX_HTML_BYTES + 64 * 1024) {
    return err("html_too_large", 413, request, env);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return err("invalid_json", 400, request, env);
  }
  if (!body || typeof body !== "object") {
    return err("invalid_json", 400, request, env);
  }

  const html = typeof body.html === "string" ? body.html : "";
  if (!html.trim()) return err("missing_html", 400, request, env);
  if (utf8ByteLength(html) > MAX_HTML_BYTES) {
    return err("html_too_large", 413, request, env);
  }

  const toField = body.to !== undefined ? body.to : body.allowlist;
  const toProvided = body.to !== undefined || body.allowlist !== undefined;
  let toList = [];
  if (toProvided) {
    if (Array.isArray(toField)) toList = toField;
    else if (typeof toField === "string") toList = toField.split(/[,;\s]+/);
    else return err("min_email", 400, request, env);
  }

  const access = buildAccessFromPatch(
    toProvided ? { mode: "allowlist", allowlist: toList } : { mode: "company" },
    email
  );
  if (access.mode === "allowlist" && !(access.emails || []).length) {
    return err("min_email", 400, request, env);
  }
  if (access.mode === "company") {
    if (isPublicEmailDomain(email)) {
      return err("company_requires_work_domain", 400, request, env);
    }
    access.domains = [domain];
  }

  const host = await resolveHost(env.PANELS, email, env);
  if (!host) return err("no_host", 409, request, env);

  let title = "untitled";
  if (typeof body.title === "string" && body.title.trim()) {
    title = body.title.trim().replace(/\s+/g, " ").slice(0, 200);
  }

  const id = newPanelId();
  const publishedAt = new Date().toISOString();
  const record = {
    v: 1,
    title,
    publishedAt,
    publisherEmail: email,
    access,
    html,
  };
  await putPanel(env.PANELS, id, record);
  await indexPanel(env.PANELS, id, email, access);

  const url = `https://${host}/${id}`;
  return json(
    {
      ok: true,
      id,
      url,
      host,
      mode: accessToApiMode(access),
      allowlist: accessToAllowlist(access),
      title,
      publishedAt,
    },
    201,
    request,
    env
  );
}

async function handleSubdomain(request, env, { email }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return err("invalid_json", 400, request, env);
  }
  const result = await claimSubdomain(env.PANELS, body.slug, email);
  if (!result.ok) {
    return err(result.error || "error", result.status || 400, request, env);
  }
  return json({ host: result.host }, 200, request, env);
}

async function handleCustom(request, env, { email }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return err("invalid_json", 400, request, env);
  }
  // (5) Claim only — ownership verification required before serving as host
  const result = await claimCustomHostname(env.PANELS, body.hostname, email);
  if (!result.ok) {
    return err(result.error || "error", result.status || 400, request, env);
  }
  // Contract: { host }. Until verified, return current serving host (subdomain) if any.
  return json(
    {
      // Serving host only if already claimed (subdomain); never "" .
      host: normalizeHost(result.host),
      customHostname: result.customHostname,
      customVerified: false,
      verify: result.verify,
    },
    200,
    request,
    env
  );
}

async function handleCustomDelete(request, env, { email }) {
  const result = await clearPendingCustomHostname(env.PANELS, email);
  if (!result.ok) {
    return err(result.error || "error", result.status || 400, request, env);
  }
  return json({ ok: true }, 200, request, env);
}

async function handleCustomVerify(request, env, { email }) {
  // Body optional/ignored — uses claimed tenant.customHostname + session email.
  const result = await verifyCustomHostname(env.PANELS, email, {
    lookupTxt: env.__lookupTxt,
  });
  if (!result.ok) {
    return json(
      {
        error: result.error || "error",
        verify: result.verify,
      },
      result.status || 400,
      request,
      env
    );
  }
  return json(
    {
      ok: true,
      host: result.host,
      customHostname: result.customHostname,
      customVerified: true,
      verify: result.verify,
    },
    200,
    request,
    env
  );
}


export { ssoMode };
