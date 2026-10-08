/** Shared in-memory KV + fetch mocks for Worker unit tests. */

export function memoryKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  const expirations = new Map();
  const puts = [];
  return {
    async get(key) {
      if (expirations.has(key) && Date.now() >= expirations.get(key)) {
        store.delete(key);
        expirations.delete(key);
        return null;
      }
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value, options = {}) {
      puts.push({ key, options: { ...options } });
      store.set(key, value);
      if (options.expirationTtl) {
        expirations.set(key, Date.now() + Number(options.expirationTtl) * 1000);
      } else {
        expirations.delete(key);
      }
    },
    async delete(key) {
      store.delete(key);
      expirations.delete(key);
    },
    async list({ prefix = "", cursor, limit = 1000 } = {}) {
      const keys = [...store.keys()]
        .filter((k) => k.startsWith(prefix))
        .sort()
        .map((name) => ({ name }));
      return { keys: keys.slice(0, limit), list_complete: true, cursor: undefined };
    },
    _store: store,
    _puts: puts,
  };
}

export const PANEL_ID = "aaaaaaaaaaaaaaaaaaaaaaaa";
export const UNKNOWN_PANEL_BODY = "Not found — invalid or unknown panel id.";
export const CF_ZONE_ID = "397f24981bc11c467ae86b5ee71a43e1";
export const CF_SAAS_TOKEN = "cf-saas-test-token-do-not-leak";

export function panelRecord(publisherEmail = "dev@localhost", extra = {}) {
  return {
    v: 1,
    title: "Bound",
    publishedAt: "2026-10-02T15:00:00-03:00",
    publisherEmail,
    access: { mode: "company", domains: ["localhost"] },
    html: "<html>bound</html>",
    ...extra,
  };
}

export function enabledEnv(kv, extra = {}) {
  return {
    PANELS: kv,
    SSO_DEV_BYPASS: "1",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
    OAUTH_ALLOWED_DOMAINS: "localhost",
    CUSTOM_DOMAINS_ENABLED: "true",
    CF_ZONE_ID,
    CF_SAAS_TOKEN,
    ...extra,
  };
}

export function oauthEnv(kv, extra = {}) {
  return {
    PANELS: kv,
    SESSION_SECRET: "test-session-secret-at-least-32-chars!!",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
    OAUTH_ALLOWED_DOMAINS: "wises.com.br",
    CUSTOM_DOMAINS_ENABLED: "true",
    CF_ZONE_ID,
    CF_SAAS_TOKEN,
    ...extra,
  };
}

export function dohResponse(records) {
  return new Response(
    JSON.stringify({
      Status: 0,
      Answer: (records || []).map((data) => ({
        name: "_secure-publish.",
        type: 16,
        TTL: 60,
        data: `"${data}"`,
      })),
    }),
    { status: 200, headers: { "content-type": "application/dns-json" } }
  );
}

/**
 * Mock fetch for Cloudflare DNS-over-HTTPS + Custom Hostnames API.
 */
export function installCfFetchMock({
  txtRecords = [],
  createId = "cf-hn-1",
  hostnameStatus = "active",
  sslStatus = "active",
  createError = false,
  getError = false,
  deleteError = false,
} = {}) {
  const calls = [];
  const prev = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url);
    calls.push({ url: u, method: (init.method || "GET").toUpperCase(), init });
    if (u.includes("cloudflare-dns.com")) {
      return dohResponse(typeof txtRecords === "function" ? txtRecords() : txtRecords);
    }
    if (u.includes("api.cloudflare.com") && u.includes("/custom_hostnames")) {
      const method = (init.method || "GET").toUpperCase();
      if (method === "POST") {
        if (createError) {
          return new Response(JSON.stringify({ success: false, errors: [{ message: "nope" }] }), {
            status: 400,
          });
        }
        return new Response(
          JSON.stringify({
            success: true,
            result: {
              id: createId,
              hostname: "x",
              status: hostnameStatus,
              ssl: { status: sslStatus },
            },
          }),
          { status: 200 }
        );
      }
      if (method === "GET") {
        if (getError) {
          return new Response(JSON.stringify({ success: false }), { status: 500 });
        }
        return new Response(
          JSON.stringify({
            success: true,
            result: {
              id: createId,
              status: hostnameStatus,
              ssl: { status: sslStatus },
            },
          }),
          { status: 200 }
        );
      }
      if (method === "DELETE") {
        if (deleteError) {
          return new Response(JSON.stringify({ success: false }), { status: 500 });
        }
        return new Response(JSON.stringify({ success: true, result: { id: createId } }), {
          status: 200,
        });
      }
    }
    return new Response("unexpected fetch", { status: 500 });
  };
  return {
    calls,
    restore() {
      globalThis.fetch = prev;
    },
  };
}

export function setCookies(res) {
  if (typeof res.headers.getSetCookie === "function") {
    return res.headers.getSetCookie();
  }
  const raw = res.headers.get("set-cookie");
  return raw ? [raw] : [];
}

export function tenantSnapshot(raw) {
  if (!raw) return null;
  const t = typeof raw === "string" ? JSON.parse(raw) : raw;
  const { updatedAt, ...rest } = t;
  return rest;
}
