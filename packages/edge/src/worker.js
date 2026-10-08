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

import { requireSsoSession, handleAuthRoutes } from "./sso.js";
import { checkPanelAccess } from "./acl.js";
import { handleApiRoutes } from "./api.js";
import { decodeRecord, recordView, getTenant, PANEL_ID_RE } from "./kv.js";
import {
  notFoundViewerPage,
  rootViewerPage,
  generic403ViewerPage,
  domainNotAllowedViewerPage,
} from "./viewer-page.js";

async function resolvePanel(key, panels) {
  if (!key || typeof key !== "string") return { ok: false };
  if (!PANEL_ID_RE.test(key)) return { ok: false };
  const raw = await panels.get(key);
  if (raw == null) return { ok: false };
  return { ok: true, record: decodeRecord(raw) };
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
      if (hostGate.status === 404) return notFoundViewerPage();
      return new Response(hostGate.body || "Forbidden\n", {
        status: hostGate.status || 403,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
      });
    }

    const parts = url.pathname.split("/").filter(Boolean);

    if (parts.length === 0) {
      return rootViewerPage();
    }

    const panelId = parts[0];
    const panel = await resolvePanel(panelId, env.PANELS);
    if (!panel.ok) {
      return notFoundViewerPage();
    }

    const bind = await assertPanelHostBinding(request, env, panel.record);
    if (!bind.ok) {
      return notFoundViewerPage();
    }

    const sso = await requireSsoSession(request, env);
    if (!sso.ok) {
      if (sso.redirectUrl) {
        return Response.redirect(new URL(sso.redirectUrl, url.origin).toString(), 302);
      }
      if (sso.reason === "domain_not_allowed") {
        return domainNotAllowedViewerPage(sso.user?.email);
      }
      return new Response(sso.body || "Unauthorized — SSO required.\n", {
        status: sso.status || 403,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
      });
    }

    const acl = checkPanelAccess(
      sso.user,
      panel.record.access,
      env,
      panel.record.publisherEmail
    );
    if (!acl.ok) {
      const email = sso.user?.email;
      if (acl.reason === "domain_not_allowed") {
        return domainNotAllowedViewerPage(email);
      }
      return generic403ViewerPage(email);
    }

    // Best-effort view analytics (PII stored server-side; API exposes only to SSO tenant).
    try {
      await recordView(env.PANELS, panelId, sso.user?.email);
    } catch {
      /* non-fatal */
    }

    const headers = {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
      "x-secure-publish": "sso",
    };
    if (sso.user?.email) {
      headers["x-secure-publish-user"] = sso.user.email;
    }

    return new Response(panel.record.html, {
      status: 200,
      headers,
    });
  },
};
