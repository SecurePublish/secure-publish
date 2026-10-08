/**
 * Secure Publish — edge for AI-published HTML dashboards.
 *
 * Auth model (V1 Lock A):
 *   - Path key = panel id only (look up HTML in KV). Knowing the URL is NOT auth.
 *   - requireSsoSession must succeed (Access JWT or OAuth cookie).
 *   - Then per-panel ACL:
 *       company | org  → email domain allowlist (OAUTH_ALLOWED_DOMAINS / record.domains)
 *                        NOT Workspace/Entra/GitHub Org membership
 *       allowlist      → explicit emails from CLI --to
 *
 * Console API: see ../README.md and secure-publish-app/API-CONTRACT.md
 */

import { requireSsoSession, handleAuthRoutes, ssoMode } from "./sso.js";
import { checkPanelAccess, accessDeniedBody } from "./acl.js";
import { handleApiRoutes } from "./api.js";
import {
  decodeRecord,
  recordView,
  getTenant,
  lookupPanelId,
  panelPath,
  storedPanelName,
} from "./kv.js";

const PANEL_404_BODY = "Not found — invalid or unknown panel id.";

function panelHeaders(extra = {}) {
  return {
    "referrer-policy": "no-referrer",
    "x-robots-tag": "noindex",
    ...extra,
  };
}

async function resolvePanel(key, panels) {
  const id = lookupPanelId(key);
  if (!id) return { ok: false };
  const raw = await panels.get(id);
  if (raw == null) return { ok: false };
  return { ok: true, id, record: decodeRecord(raw) };
}

/** Normalize Host header (or URL hostname). */
function requestHost(request) {
  let host = (request.headers.get("Host") || "").split(":")[0].toLowerCase();
  if (!host) {
    try {
      host = new URL(request.url).hostname.toLowerCase();
    } catch {
      host = "";
    }
  }
  return host;
}

/**
 * Host-header gate for custom domains (Marcus #5).
 * Subdomain / workers.dev always OK. Custom host only if tenant.customVerified.
 */
async function assertHostAllowed(request, env) {
  const host = requestHost(request);
  if (!host) return { ok: true };
  if (host.endsWith(".workers.dev") || host.endsWith(".securepublish.work")) {
    return { ok: true };
  }
  if (host === "localhost" || host === "127.0.0.1") return { ok: true };

  const owner = await env.PANELS.get(`host:custom:${host}`);
  if (!owner) {
    return { ok: false, status: 404, body: "Unknown host.\n" };
  }
  const tenant = await getTenant(env.PANELS, owner);
  if (!tenant?.customVerified) {
    return {
      ok: false,
      status: 403,
      body:
        "Custom domain reserved but not verified. Complete DNS ownership check before serving.\n",
    };
  }
  return { ok: true };
}

/**
 * Product hosts the Worker treats as its own (Pages proxy + skip panel
 * host-owner binding). Keep this list NARROW: only app, www, and the apex.
 *
 * Claim-blocked slugs live separately in kv.js (CLAIM_RESERVED_SLUGS).
 * Widening this set to api/admin/auth/login/cname would make
 * assertPanelHostBinding return ok:true and serve any panel on those hosts
 * without checking host:sub:{slug}. Unowned infra hosts must 404 fail-closed.
 */
const PAGES_ORIGIN = {
  "app.securepublish.work": "https://secure-publish-app.pages.dev",
  "www.securepublish.work": "https://secure-publish-landing.pages.dev",
  "securepublish.work": "https://secure-publish-landing.pages.dev",
};

const RESERVED_PRODUCT_HOSTS = new Set(Object.keys(PAGES_ORIGIN));
const BASE_SUFFIX = ".securepublish.work";

/**
 * Fail-closed host ↔ publisher binding (Marcus / host swap).
 * After panel resolve, before SSO: old slug without lock must 404 (no OAuth redirect).
 * - *.securepublish.work (not reserved): require host:sub:{slug} + publisherEmail match
 * - custom host: require host:custom:{host} owner === publisherEmail
 * - *.workers.dev / localhost: serve by panel id (interim)
 */
export async function assertPanelHostBinding(request, env, panelRecord) {
  const host = requestHost(request);
  if (!host) return { ok: true };
  if (host.endsWith(".workers.dev") || host === "localhost" || host === "127.0.0.1") {
    return { ok: true };
  }

  const publisher = (panelRecord?.publisherEmail || "").trim().toLowerCase();
  const deny = {
    ok: false,
    status: 404,
    body: "Not found — host not bound.\n",
  };

  if (host.endsWith(BASE_SUFFIX) || host === "securepublish.work") {
    if (RESERVED_PRODUCT_HOSTS.has(host)) return { ok: true };
    const slug = host.slice(0, -BASE_SUFFIX.length);
    if (!slug || slug.includes(".")) return deny;
    const lock = await env.PANELS.get(`host:sub:${slug}`);
    if (!lock) return deny;
    if (!publisher || lock.trim().toLowerCase() !== publisher) return deny;
    return { ok: true };
  }

  const lock = await env.PANELS.get(`host:custom:${host}`);
  if (!lock) return deny;
  if (!publisher || lock.trim().toLowerCase() !== publisher) return deny;
  return { ok: true };
}

async function proxyReservedHost(request, url) {
  const origin = PAGES_ORIGIN[url.hostname.toLowerCase()];
  if (!origin) return null;
  // Same-origin API + OAuth on app.* — do not forward these to Pages.
  const p = url.pathname;
  if (
    p.startsWith("/api/") ||
    p.startsWith("/auth/") ||
    p.startsWith("/_auth/")
  ) {
    return null;
  }
  const target = new URL(url.pathname + url.search, origin);
  const headers = new Headers(request.headers);
  headers.set("Host", new URL(origin).host);
  headers.delete("cf-connecting-ip");
  const init = {
    method: request.method,
    headers,
    redirect: "manual",
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = request.body;
  }
  return fetch(target.toString(), init);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const pagesProxy = await proxyReservedHost(request, url);
    if (pagesProxy) return pagesProxy;

    const authRes = await handleAuthRoutes(request, env);
    if (authRes) return authRes;

    const apiRes = await handleApiRoutes(request, env);
    if (apiRes) return apiRes;

    const hostGate = await assertHostAllowed(request, env);
    if (!hostGate.ok) {
      const partsEarly = url.pathname.split("/").filter(Boolean);
      const headers = { "content-type": "text/plain; charset=utf-8" };
      if (partsEarly.length) Object.assign(headers, panelHeaders());
      return new Response(hostGate.body || "Forbidden\n", {
        status: hostGate.status || 403,
        headers,
      });
    }

    const parts = url.pathname.split("/").filter(Boolean);

    if (parts.length === 0) {
      const mode = ssoMode(env);
      return new Response(
        [
          "Secure Publish",
          "",
          "URL identifica o dashboard; SSO autentica; ACL de domínio/--to autoriza.",
          `SSO mode: ${mode}`,
          "V1: company-wide = email domain (not org membership).",
          "",
          "Console API: /api/me /api/panels /api/hosting/* (SSO required)",
          "OAuth: /auth/{google|microsoft|github} · /auth/logout",
          "Use /{panel-id} após login SSO.",
          "Publish: securepublish-cli publish <file.html> [--to email,email]",
          "",
        ].join("\n"),
        {
          status: 404,
          headers: { "content-type": "text/plain; charset=utf-8" },
        }
      );
    }

    const panel = await resolvePanel(parts[0], env.PANELS);
    if (!panel.ok) {
      return new Response(PANEL_404_BODY, {
        status: 404,
        headers: panelHeaders({ "content-type": "text/plain; charset=utf-8" }),
      });
    }

    const bind = await assertPanelHostBinding(request, env, panel.record);
    if (!bind.ok) {
      return new Response(bind.body || "Not found — host not bound.\n", {
        status: bind.status || 404,
        headers: panelHeaders({ "content-type": "text/plain; charset=utf-8" }),
      });
    }

    const sso = await requireSsoSession(request, env);
    if (!sso.ok) {
      if (sso.redirectUrl) {
        return new Response(null, {
          status: 302,
          headers: panelHeaders({
            location: new URL(sso.redirectUrl, url.origin).toString(),
          }),
        });
      }
      return new Response(sso.body || "Unauthorized — SSO required.\n", {
        status: sso.status || 403,
        headers: panelHeaders({ "content-type": "text/plain; charset=utf-8" }),
      });
    }

    const acl = checkPanelAccess(
      sso.user,
      panel.record.access,
      env,
      panel.record.publisherEmail
    );
    if (!acl.ok) {
      return new Response(accessDeniedBody(acl.reason), {
        status: 403,
        headers: panelHeaders({
          "content-type": "text/plain; charset=utf-8",
          "x-secure-publish-acl": acl.reason || "denied",
        }),
      });
    }

    const storedName = storedPanelName(panel.record);
    const rest = parts.slice(1);
    const nameOk =
      rest.length === 0 ||
      (Boolean(storedName) && rest.length === 1 && rest[0] === storedName);
    if (!nameOk) {
      return new Response(null, {
        status: 301,
        headers: panelHeaders({
          location: panelPath(panel.id, storedName),
          "cache-control": "private, no-store",
        }),
      });
    }

    // Best-effort view analytics (PII stored server-side; API exposes only to SSO tenant).
    try {
      await recordView(env.PANELS, panel.id, sso.user?.email);
    } catch {
      /* non-fatal */
    }

    const headers = panelHeaders({
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-secure-publish": "sso",
    });
    if (sso.user?.email) {
      headers["x-secure-publish-user"] = sso.user.email;
    }

    return new Response(panel.record.html, {
      status: 200,
      headers,
    });
  },
};
