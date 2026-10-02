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
 */

import { requireSsoSession, handleAuthRoutes, ssoMode } from "./sso.js";
import { checkPanelAccess, accessDeniedBody } from "./acl.js";

function decodeRecord(raw) {
  if (raw == null) return null;
  try {
    const j = JSON.parse(raw);
    if (j && typeof j.html === "string") return j;
  } catch {
    /* legacy raw HTML from panel-gate era */
  }
  return { v: 0, html: raw, access: { mode: "company", domains: [] } };
}

async function resolvePanel(key, panels) {
  if (!key || typeof key !== "string") return { ok: false };
  if (!/^[0-9a-f]{24}$/i.test(key)) return { ok: false };
  const raw = await panels.get(key);
  if (raw == null) return { ok: false };
  return { ok: true, record: decodeRecord(raw) };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const authRes = await handleAuthRoutes(request, env);
    if (authRes) return authRes;

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
