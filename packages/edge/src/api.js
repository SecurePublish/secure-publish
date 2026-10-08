/**
 * Console ↔ Worker API (Cameron contract / API-CONTRACT.md).
 *
 * Marcus checklist:
 * 1) Every /api/* requires SSO session
 * 2) PATCH access = publisher only
 * 3) CORS = exact CONSOLE_ORIGIN + credentials
 * 4) viewers[] PII only for the panel publisher (email === publisherEmail)
 * 5) Custom domain: claim + verify ownership before serving as host
 * 6) /api/* only on the app host (OAUTH_CALLBACK_ORIGIN / APP_HOST)
 * 7) Cookie mutations: exact console Origin + application/json
 */

import { requireSsoSession, ssoMode, oauthCallbackOrigin, consoleOrigins } from "./sso.js";
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
  accessToApiMode,
  accessToAllowlist,
  formatPublishedLabel,
  viewsToApi,
  buildAccessFromPatch,
  indexPanel,
  PANEL_ID_RE,
  lookupPanelId,
  allocatePanelCode,
  normalizePanelName,
  panelPath,
  storedPanelName,
  createDeviceCode,
  approveDeviceCode,
  pollDeviceCode,
  userFromPublishToken,
  revokePublishToken,
} from "./kv.js";
import {
  claimCustomHostname,
  verifyCustomHostname,
  deleteCustomHostnameClaim,
  tenantIsActiveCustom,
} from "./custom-domain.js";
import { customDomainsEnabled, customDnsRecords, validateCustomHostname } from "./hostname.js";

export { consoleOrigins };

/**
 * Hostname that may serve `/api/*`. APP_HOST if set, else the existing
 * OAuth callback origin — no second hardcoded app host here.
 */
export function apiHost(env = {}) {
  const raw = String(env.APP_HOST || "").trim();
  if (raw) {
    try {
      return new URL(raw.includes("://") ? raw : `https://${raw}`).hostname.toLowerCase();
    } catch {
      return raw.split("/")[0].split(":")[0].toLowerCase();
    }
  }
  return new URL(oauthCallbackOrigin(env)).hostname.toLowerCase();
}

function requestHostname(request) {
  const header = (request.headers.get("Host") || "").split(":")[0].toLowerCase();
  if (header) return header;
  try {
    return new URL(request.url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function jsonMediaType(request) {
  const raw = request.headers.get("content-type") || "";
  return raw.split(";")[0].trim().toLowerCase() === "application/json";
}

const UNKNOWN_PATH_404 = "Not found — invalid or unknown panel id.";

function unknownPath404() {
  return new Response(UNKNOWN_PATH_404, {
    status: 404,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "referrer-policy": "no-referrer",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

/**
 * Cookie-authenticated POST/PATCH/PUT/DELETE under /api/*.
 * Bearer and unauthenticated device/code + device/token are exempt.
 * device/bind is not.
 */
function cookieCsrfError(request, env, url) {
  const method = request.method.toUpperCase();
  if (!["POST", "PATCH", "PUT", "DELETE"].includes(method)) return null;
  const auth = request.headers.get("authorization") || "";
  if (/^Bearer\s+\S+/i.test(auth)) return null;
  if (
    method === "POST" &&
    (url.pathname === "/api/device/code" || url.pathname === "/api/device/token")
  ) {
    return null;
  }
  if (!(request.headers.get("Cookie") || request.headers.get("cookie"))) return null;

  const originHeader = request.headers.get("Origin") || "";
  let origin = "";
  try {
    origin = new URL(originHeader).origin;
  } catch {
    origin = "";
  }
  if (!origin || !consoleOrigins(env).includes(origin)) {
    return err("csrf_origin", 403, request, env);
  }
  if (!jsonMediaType(request)) {
    return err("csrf_content_type", 403, request, env);
  }
  return null;
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
  let requestOrigin = "";
  try {
    requestOrigin = origin ? new URL(origin).origin : "";
  } catch {
    requestOrigin = "";
  }
  if (requestOrigin && allowed.includes(requestOrigin)) {
    headers["Access-Control-Allow-Origin"] = requestOrigin;
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

/** viewers[] is publisher-only. Missing/blank publisherEmail never qualifies. */
export function isPanelPublisher(requesterEmail, publisherEmail) {
  const a = String(requesterEmail || "").trim().toLowerCase();
  const b = String(publisherEmail || "").trim().toLowerCase();
  return Boolean(a && b && a === b);
}

/** Always `views`; `viewers` only when requester owns the panel. */
function viewFields(viewData, requesterEmail, publisherEmail) {
  const { views, viewers } = viewsToApi(viewData);
  const out = { views };
  if (isPanelPublisher(requesterEmail, publisherEmail)) out.viewers = viewers;
  return out;
}

/**
 * @returns {Promise<Response | null>} null if not an /api route
 */
export async function handleApiRoutes(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith("/api/")) return null;
  // Any other Host (panel slug, apex, workers.dev) is an unknown path.
  if (requestHostname(request) !== apiHost(env)) return unknownPath404();

  // Preflight — no session required, but origin must match allowlist.
  if (request.method === "OPTIONS") {
    const originHeader = request.headers.get("Origin") || "";
    const allowed = consoleOrigins(env);
    let origin = "";
    try {
      origin = originHeader ? new URL(originHeader).origin : "";
    } catch {
      origin = "";
    }
    if (originHeader && !allowed.includes(origin)) {
      return new Response(null, { status: 403 });
    }
    return new Response(null, { status: 204, headers: corsHeaders(request, env) });
  }

  const csrf = cookieCsrfError(request, env, url);
  if (csrf) return csrf;

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

  // Bearer present → never use the session cookie. Invalid/unknown/expired → 401.
  const authHeader = request.headers.get("authorization") || "";
  let email;
  let domain;
  let idp;
  if (/^Bearer\b/i.test(authHeader.trim())) {
    const match = authHeader.match(/^Bearer\s+(\S+)/i);
    const tokenUser = match
      ? await userFromPublishToken(env.PANELS, match[1])
      : null;
    if (!tokenUser?.email) return err("unauthorized", 401, request, env);
    email = tokenUser.email;
    idp = "device";
  } else {
    const sso = await requireSsoSession(request, env, { api: true });
    if (!sso.ok) {
      return err(sso.body || "unauthorized", sso.status || 401, request, env);
    }
    email = (sso.user?.email || "").trim().toLowerCase();
    idp = sso.user?.provider || sso.user?.idp || "unknown";
  }
  if (!email || !email.includes("@")) {
    return err("missing_email", 403, request, env);
  }
  domain = email.split("@")[1];

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

  const nameMatch = url.pathname.match(/^\/api\/panels\/([^/]+)\/name\/?$/);
  if (nameMatch && request.method === "PATCH") {
    return handlePatchName(request, env, nameMatch[1], { email });
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
  if (tenantIsActiveCustom(tenant)) {
    return normalizeHost(tenant.customHostname);
  }
  if (tenant?.slug) {
    const slug = String(tenant.slug).trim();
    if (slug) return `${slug}.securepublish.work`;
  }
  if (tenant?.host) {
    const h = normalizeHost(tenant.host);
    if (h && (h.endsWith(".securepublish.work") || !tenant.customHostname)) {
      return h;
    }
  }
  // Optional env hint only — still must be non-empty.
  return normalizeHost(env.DEFAULT_PANEL_HOST);
}

async function handleMe(request, env, { email, domain, idp }) {
  const host = await resolveHost(env.PANELS, email, env);
  const tenant = await getTenant(env.PANELS, email);
  const flagOn = customDomainsEnabled(env);
  const customHostname = tenant?.customHostname
    ? String(tenant.customHostname).trim().toLowerCase() || null
    : null;
  const customVerified = Boolean(tenant?.customVerified) && tenant?.customStatus === "active";
  const body = {
    email,
    idp,
    domain,
    publicDomain: isPublicEmailDomain(email),
    // Serving host only (verified custom or subdomain) — never "".
    host,
    customHostname,
    customVerified,
    customDomainsEnabled: flagOn,
  };
  // When the flag is off, never include records (cname.securepublish.work must not appear).
  if (flagOn && customHostname) {
    body.customStatus = tenant.customStatus || "pending_dns";
    body.customRecords = customDnsRecords(
      customHostname,
      tenant.customVerifyToken || ""
    );
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

    const viewData = await getViews(kv, id);
    const stats = viewFields(viewData, email, publisherEmail);

    const title =
      typeof record.title === "string" && record.title.trim()
        ? record.title.trim()
        : "untitled";

    const name = storedPanelName(record);
    const path = panelPath(id, name);
    panels.push({
      id,
      title,
      name,
      path,
      url: host ? `https://${host}${path}` : null,
      publisherEmail: publisherEmail || null,
      mode,
      allowlist: accessToAllowlist(record.access),
      publishedAt: record.publishedAt || null,
      publishedLabel: formatPublishedLabel(record.publishedAt),
      ...stats,
    });
  }

  panels.sort((a, b) => String(b.publishedAt || "").localeCompare(String(a.publishedAt || "")));
  return json({ host, panels }, 200, request, env);
}

async function handlePatchName(request, env, panelId, { email }) {
  if (!lookupPanelId(panelId)) {
    return err("not_found", 404, request, env);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return err("invalid_json", 400, request, env);
  }
  if (!body || typeof body !== "object" || !("name" in body)) {
    return err("invalid_json", 400, request, env);
  }

  const kv = env.PANELS;
  const id = lookupPanelId(panelId);
  const record = await getPanel(kv, id);
  if (!record) return err("not_found", 404, request, env);

  const publisher = (record.publisherEmail || "").trim().toLowerCase();
  if (!publisher || publisher !== email) {
    return err("forbidden", 403, request, env);
  }

  const normalized = normalizePanelName(body.name);
  if (normalized) record.name = normalized;
  else delete record.name;
  await putPanel(kv, id, record);

  const host = await resolveHost(kv, email, env);
  const name = storedPanelName(record);
  const path = panelPath(id, name);
  const viewData = await getViews(kv, id);
  return json(
    {
      id,
      name,
      path,
      url: host ? `https://${host}${path}` : null,
      ...viewFields(viewData, email, publisher),
    },
    200,
    request,
    env
  );
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
  const panel = {
    id: panelId,
    publisherEmail: publisher,
    mode: accessToApiMode(access),
    allowlist: accessToAllowlist(access),
    publishedAt: record.publishedAt || null,
    publishedLabel: formatPublishedLabel(record.publishedAt),
    ...viewFields(viewData, email, publisher),
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


function utf8ByteLength(value) {
  return new TextEncoder().encode(value).length;
}

/**
 * POST /api/panels — signed-in user publishes HTML. No Cloudflare API token.
 * Body: { html, title?, name?, to?: string | string[] }
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

  const id = await allocatePanelCode(env.PANELS);
  if (!id) return err("id_collision", 500, request, env);

  const name = normalizePanelName(body.name);
  const publishedAt = new Date().toISOString();
  const record = {
    v: 1,
    title,
    publishedAt,
    publisherEmail: email,
    access,
    html,
  };
  if (name) record.name = name;
  await putPanel(env.PANELS, id, record);
  await indexPanel(env.PANELS, id, email, access);

  const path = panelPath(id, name);
  const url = `https://${host}${path}`;
  const stats = viewFields({ count: 0, byEmail: {} }, email, email);
  return json(
    {
      ok: true,
      id,
      url,
      path,
      name,
      host,
      mode: accessToApiMode(access),
      allowlist: accessToAllowlist(access),
      title,
      publishedAt,
      ...stats,
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
  if (!customDomainsEnabled(env)) {
    return err("custom_domains_disabled", 403, request, env);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return err("invalid_json", 400, request, env);
  }
  // Validate before ANY KV write or Cloudflare call.
  const v = validateCustomHostname(body?.hostname);
  if (!v.ok) {
    return err(v.error, 400, request, env);
  }
  const result = await claimCustomHostname(env, v.hostname, email);
  if (!result.ok) {
    return err(result.error || "error", result.status || 400, request, env);
  }
  return json(
    {
      host: normalizeHost(result.host),
      customHostname: result.customHostname,
      customVerified: false,
      status: result.status,
      records: result.records,
    },
    200,
    request,
    env
  );
}

async function handleCustomDelete(request, env, { email }) {
  const result = await deleteCustomHostnameClaim(env, email);
  if (!result.ok) {
    return err(result.error || "error", result.status || 400, request, env);
  }
  return json({ ok: true }, 200, request, env);
}

async function handleCustomVerify(request, env, { email }) {
  if (!customDomainsEnabled(env)) {
    return err("custom_domains_disabled", 403, request, env);
  }
  const result = await verifyCustomHostname(env, email, {
    lookupTxt: env.__lookupTxt,
    fetchFn: env.__fetch,
  });
  if (!result.ok) {
    return json(
      { error: result.error || "error" },
      result.statusCode || result.status || 400,
      request,
      env
    );
  }
  return json(
    {
      status: result.status,
      records: result.records,
      customHostname: result.customHostname,
    },
    200,
    request,
    env
  );
}


export { ssoMode };
