/**
 * Custom-hostname validation (claim-time) and Host-header helpers.
 *
 * Normalization (Marcus): trim, lowercase, IDN→punycode via `new URL('https://'+h).hostname`,
 * strip trailing dots. Anything besides a bare hostname → invalid_hostname.
 *
 * Reserved suffixes use exact equality or endsWith('.'+suffix) — never String.includes.
 */

import { parse } from "tldts";

export const FALLBACK_CNAME = "cname.securepublish.work";
export const APP_HANDOFF_ORIGIN = "https://app.securepublish.work";

const RESERVED_SUFFIXES = ["securepublish.work", "workers.dev", "pages.dev"];

const TLDTS_OPTS = {
  allowIcannDomains: true,
  allowPrivateDomains: false,
  detectIp: true,
  extractHostname: false,
  validateHostname: true,
};

export function customDomainsEnabled(env) {
  return String(env?.CUSTOM_DOMAINS_ENABLED || "") === "true";
}

/**
 * @param {string} input
 * @returns {{ ok: true, hostname: string } | { ok: false, error: "invalid_hostname" }}
 */
export function normalizeCustomHostname(input) {
  if (typeof input !== "string") {
    return { ok: false, error: "invalid_hostname" };
  }
  let h = input.trim().toLowerCase();
  if (!h) return { ok: false, error: "invalid_hostname" };
  h = h.replace(/\.+$/, "");
  if (!h) return { ok: false, error: "invalid_hostname" };

  if (/\s/.test(h)) return { ok: false, error: "invalid_hostname" };
  if (h.includes("@") || h.includes("/") || h.includes("?") || h.includes("#")) {
    return { ok: false, error: "invalid_hostname" };
  }
  if (h.includes("\\")) return { ok: false, error: "invalid_hostname" };
  // Port, userinfo-with-colon, or IPv6. Bare hostnames do not contain ":".
  if (h.includes(":") || h.includes("[") || h.includes("]")) {
    return { ok: false, error: "invalid_hostname" };
  }

  let url;
  try {
    url = new URL("https://" + h);
  } catch {
    return { ok: false, error: "invalid_hostname" };
  }
  if (url.port || url.username || url.password || url.search || url.hash) {
    return { ok: false, error: "invalid_hostname" };
  }
  if (url.pathname && url.pathname !== "/") {
    return { ok: false, error: "invalid_hostname" };
  }

  const host = url.hostname.toLowerCase().replace(/\.+$/, "");
  if (!host) return { ok: false, error: "invalid_hostname" };

  // ASCII input must round-trip; IDN is expected to become punycode.
  if (/^[a-z0-9.-]+$/.test(h) && host !== h) {
    return { ok: false, error: "invalid_hostname" };
  }

  if (!host.includes(".")) {
    return { ok: false, error: "invalid_hostname" };
  }
  if (host.includes("..") || host.startsWith(".") || host.startsWith("-") || host.endsWith("-")) {
    return { ok: false, error: "invalid_hostname" };
  }

  return { ok: true, hostname: host };
}

function isReservedHostname(hostname) {
  const h = String(hostname || "");
  for (const suffix of RESERVED_SUFFIXES) {
    if (h === suffix || h.endsWith("." + suffix)) return true;
  }
  return false;
}

/**
 * Claim-time validation. Call before any KV write or Cloudflare API call.
 * @param {string} input
 * @returns {{ ok: true, hostname: string, domain: string, subdomain: string } | { ok: false, error: string }}
 */
export function validateCustomHostname(input) {
  const n = normalizeCustomHostname(input);
  if (!n.ok) return n;
  const h = n.hostname;

  const parsed = parse(h, TLDTS_OPTS);
  if (parsed.isIp) {
    return { ok: false, error: "invalid_hostname" };
  }
  if (isReservedHostname(h)) {
    return { ok: false, error: "reserved_hostname" };
  }
  // Bare public suffix (com.br) or unparseable / non-ICANN.
  if (!parsed.domain || parsed.isIcann !== true) {
    return { ok: false, error: "invalid_hostname" };
  }
  if (h === parsed.domain) {
    return { ok: false, error: "apex_domain_not_supported" };
  }
  return {
    ok: true,
    hostname: h,
    domain: parsed.domain,
    subdomain: parsed.subdomain || "",
  };
}

/**
 * DNS records whose `name` is relative to the registrable domain (eTLD+1).
 * `share.example.com` → CNAME `share`, TXT `_secure-publish.share`
 * `a.b.example.co.uk` → CNAME `a.b`, TXT `_secure-publish.a.b`
 */
export function customDnsRecords(hostname, token) {
  const h = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");
  const parsed = parse(h, TLDTS_OPTS);
  const domain = parsed.domain || "";
  let relative = h;
  if (domain && h.endsWith("." + domain)) {
    relative = h.slice(0, -(domain.length + 1));
  }
  const t = String(token || "").trim();
  return [
    { type: "CNAME", name: relative, value: FALLBACK_CNAME },
    {
      type: "TXT",
      name: `_secure-publish.${relative}`,
      value: t ? `sp-verify=${t}` : "",
    },
  ];
}

export function txtLookupFqdn(hostname) {
  const h = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");
  return `_secure-publish.${h}`;
}

export function requestHost(request) {
  let host = (request.headers.get("Host") || "").split(":")[0].toLowerCase();
  if (!host) {
    try {
      host = new URL(request.url).hostname.toLowerCase();
    } catch {
      host = "";
    }
  }
  return host.replace(/\.+$/, "");
}

export function isOwnZoneHost(host) {
  const h = String(host || "").toLowerCase();
  return h === "securepublish.work" || h.endsWith(".securepublish.work");
}

export function isWorkersDevHost(host) {
  return String(host || "")
    .toLowerCase()
    .endsWith(".workers.dev");
}

export function isLoopbackHost(host) {
  const h = String(host || "").toLowerCase();
  return h === "localhost" || h === "127.0.0.1";
}

/** Customer custom hostname (not our zone, not workers.dev, not loopback). */
export function isCustomCustomerHost(host) {
  if (!host) return false;
  if (isOwnZoneHost(host) || isWorkersDevHost(host) || isLoopbackHost(host)) {
    return false;
  }
  return true;
}

export function isSafeRelativeReturn(path) {
  if (typeof path !== "string") return false;
  if (!path.startsWith("/")) return false;
  if (path.startsWith("//")) return false;
  if (path.includes("\\")) return false;
  if (/[\r\n\0]/.test(path)) return false;
  return true;
}

export function servingSubdomainHost(tenant) {
  const slug = String(tenant?.slug || "").trim();
  if (slug) return `${slug}.securepublish.work`;
  const host = String(tenant?.host || "").trim();
  if (host && (host === "securepublish.work" || host.endsWith(".securepublish.work"))) {
    return host;
  }
  return null;
}
