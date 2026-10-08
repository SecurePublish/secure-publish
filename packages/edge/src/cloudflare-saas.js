/**
 * Cloudflare for SaaS — Custom Hostnames API.
 *
 * Auth: Bearer env.CF_SAAS_TOKEN (zone-scoped, SSL and Certificates: Edit).
 * NEVER log the token, NEVER return it in responses or error bodies.
 */

const CF_API = "https://api.cloudflare.com/client/v4";

function bearer(env) {
  return String(env?.CF_SAAS_TOKEN || "");
}

function zoneId(env) {
  return String(env?.CF_ZONE_ID || "");
}

function fetchImpl(env, fetchFn) {
  return fetchFn || env?.__fetch || fetch;
}

function authHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

/**
 * @returns {Promise<{ ok: true, id: string, result: object } | { ok: false, error: "cloudflare_error" }>}
 */
export async function createCustomHostname(env, hostname, fetchFn) {
  const token = bearer(env);
  const zone = zoneId(env);
  if (!token || !zone) return { ok: false, error: "cloudflare_error" };
  const h = String(hostname || "").trim().toLowerCase();
  if (!h) return { ok: false, error: "cloudflare_error" };
  try {
    const res = await fetchImpl(env, fetchFn)(
      `${CF_API}/zones/${zone}/custom_hostnames`,
      {
        method: "POST",
        headers: authHeaders(token),
        body: JSON.stringify({
          hostname: h,
          ssl: {
            method: "http",
            type: "dv",
            settings: { min_tls_version: "1.2" },
          },
        }),
      }
    );
    let json = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    const id = json?.result?.id;
    if (!res.ok || !json?.success || !id) {
      return { ok: false, error: "cloudflare_error" };
    }
    return { ok: true, id: String(id), result: json.result };
  } catch {
    return { ok: false, error: "cloudflare_error" };
  }
}

/**
 * @returns {Promise<{ ok: true, result: object } | { ok: false, error: "cloudflare_error" }>}
 */
export async function getCustomHostname(env, id, fetchFn) {
  const token = bearer(env);
  const zone = zoneId(env);
  const cfId = String(id || "").trim();
  if (!token || !zone || !cfId) return { ok: false, error: "cloudflare_error" };
  try {
    const res = await fetchImpl(env, fetchFn)(
      `${CF_API}/zones/${zone}/custom_hostnames/${encodeURIComponent(cfId)}`,
      { method: "GET", headers: authHeaders(token) }
    );
    let json = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    if (!res.ok || !json?.success || !json.result) {
      return { ok: false, error: "cloudflare_error" };
    }
    return { ok: true, result: json.result };
  } catch {
    return { ok: false, error: "cloudflare_error" };
  }
}

/**
 * @returns {Promise<{ ok: true } | { ok: false, error: "cloudflare_error" }>}
 */
export async function deleteCustomHostname(env, id, fetchFn) {
  const token = bearer(env);
  const zone = zoneId(env);
  const cfId = String(id || "").trim();
  if (!cfId) return { ok: true };
  if (!token || !zone) return { ok: false, error: "cloudflare_error" };
  try {
    const res = await fetchImpl(env, fetchFn)(
      `${CF_API}/zones/${zone}/custom_hostnames/${encodeURIComponent(cfId)}`,
      { method: "DELETE", headers: authHeaders(token) }
    );
    if (res.status === 404) return { ok: true };
    let json = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    if (!res.ok || json?.success === false) {
      return { ok: false, error: "cloudflare_error" };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: "cloudflare_error" };
  }
}

export function mapCfHostnameStatus(result) {
  const hostActive = result?.status === "active";
  const sslActive = result?.ssl?.status === "active";
  if (!hostActive) return "pending_dns";
  if (!sslActive) return "issuing_cert";
  return "active";
}
