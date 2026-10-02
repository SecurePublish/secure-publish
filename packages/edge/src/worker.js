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
import { decodeRecord, recordView, getTenant, PANEL_ID_RE } from "./kv.js";

async function resolvePanel(key, panels) {
  if (!key || typeof key !== "string") return { ok: false };
  if (!PANEL_ID_RE.test(key)) return { ok: false };
  const raw = await panels.get(key);
  if (raw == null) return { ok: false };
  return { ok: true, record: decodeRecord(raw) };
}

/**
 * Host-header gate for custom domains (Marcus #5).
 * Subdomain / workers.dev always OK. Custom host only if tenant.customVerified.
 */
async function assertHostAllowed(request, env) {
  let host = (request.headers.get("Host") || "").split(":")[0].toLowerCase();
  if (!host) {
    try {
      host = new URL(request.url).hostname.toLowerCase();
    } catch {
      host = "";
    }
  }
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const authRes = await handleAuthRoutes(request, env);
    if (authRes) return authRes;

    const apiRes = await handleApiRoutes(request, env);
    if (apiRes) return apiRes;

    const hostGate = await assertHostAllowed(request, env);
    if (!hostGate.ok) {
      return new Response(hostGate.body || "Forbidden\n", {
        status: hostGate.status || 403,
        headers: { "content-type": "text/plain; charset=utf-8" },
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
          "OAuth: /auth/{google|microsoft|github}",
          "Use /{panel-id} após login SSO.",
          "Publish: secure-publish publish <file.html> [--to email,email]",
          "",
        ].join("\n"),
        {
          status: 404,
          headers: { "content-type": "text/plain; charset=utf-8" },
        }
      );
    }

    const panelId = parts[0];
    const panel = await resolvePanel(panelId, env.PANELS);
    if (!panel.ok) {
      return new Response("Not found — invalid or unknown panel id.", {
        status: 404,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    const sso = await requireSsoSession(request, env);
    if (!sso.ok) {
      if (sso.redirectUrl) {
        return Response.redirect(new URL(sso.redirectUrl, url.origin).toString(), 302);
      }
      return new Response(sso.body || "Unauthorized — SSO required.\n", {
        status: sso.status || 403,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    const acl = checkPanelAccess(sso.user, panel.record.access, env);
    if (!acl.ok) {
      return new Response(accessDeniedBody(acl.reason), {
        status: 403,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "x-secure-publish-acl": acl.reason || "denied",
        },
      });
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
