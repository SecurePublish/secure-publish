/**
 * Customer custom domains (Cloudflare for SaaS Custom Hostnames).
 *
 * Pending claims do not lock a hostname: each account may hold its own claim
 * and TXT token. The exclusive KV lock `host:custom:{h}` is written only when
 * an account reaches `active` (kept through `records_missing`, no TTL).
 * Verify / daily cron share syncCustomHostname() so TXT loss is applied the
 * same way from POST /api/hosting/custom/verify and the scheduled handler.
 */

import { lookupTxt, txtMatchesVerify } from "./dns.js";
import { getTenant, putTenant } from "./kv.js";
import {
  validateCustomHostname,
  normalizeCustomHostname,
  customDnsRecords,
  txtLookupFqdn,
  customDomainsEnabled,
  servingSubdomainHost,
} from "./hostname.js";
import {
  createCustomHostname,
  getCustomHostname,
  deleteCustomHostname,
  mapCfHostnameStatus,
} from "./cloudflare-saas.js";

function newCustomVerifyToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function ownerEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function wasPreviouslyActive(tenant) {
  return (
    tenant?.customVerified === true ||
    tenant?.customStatus === "active" ||
    tenant?.customStatus === "records_missing"
  );
}

/**
 * TXT missing/mismatch consequences. Shared by verify and cron.
 * records_missing: stop serving, stop 301, subdomain serves, lock stays.
 */
export async function applyTxtFailure(kv, tenant) {
  const status = wasPreviouslyActive(tenant) ? "records_missing" : "pending_dns";
  const updated = await putTenant(kv, {
    ...tenant,
    customVerified: false,
    customStatus: status,
    host: servingSubdomainHost(tenant),
  });
  return { tenant: updated, status };
}

function lookupFn(env, opts) {
  if (opts?.lookupTxt) return opts.lookupTxt;
  if (env?.__lookupTxt) return env.__lookupTxt;
  const fetchFn = opts?.fetchFn || env?.__fetch || fetch;
  return (name) => lookupTxt(name, fetchFn);
}

function hostnameTaken(lock, owner) {
  return Boolean(lock && lock !== owner);
}

function takenResponse(hostname, records) {
  return {
    ok: false,
    statusCode: 409,
    error: "hostname_taken",
    records,
    customHostname: hostname,
  };
}

/**
 * ONE shared TXT-recheck + CF status function.
 * Both the daily cron and POST /api/hosting/custom/verify call this.
 *
 * @param {object} env
 * @param {object} tenant
 * @param {{ createCfIfMissing?: boolean, lookupTxt?: Function, txtMatchesVerify?: Function, fetchFn?: Function }} [opts]
 */
export async function syncCustomHostname(env, tenant, opts = {}) {
  const kv = env.PANELS;
  const hostname = String(tenant?.customHostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");
  const token = String(tenant?.customVerifyToken || "").trim();
  const records = customDnsRecords(hostname, token);

  if (!hostname) {
    return {
      ok: false,
      statusCode: 400,
      error: "no_custom_hostname",
      records,
      customHostname: null,
    };
  }

  const doLookup = lookupFn(env, opts);
  const matches = opts.txtMatchesVerify || txtMatchesVerify;
  const fetchFn = opts.fetchFn || env.__fetch || fetch;
  const expected = token ? `sp-verify=${token}` : "";

  let dnsResult;
  try {
    dnsResult = await doLookup(txtLookupFqdn(hostname));
  } catch {
    return {
      ok: false,
      statusCode: 502,
      error: "dns_lookup_failed",
      records,
      customHostname: hostname,
    };
  }
  if (!dnsResult?.ok) {
    return {
      ok: false,
      statusCode: 502,
      error: "dns_lookup_failed",
      records,
      customHostname: hostname,
    };
  }

  const txtOk = Boolean(expected) && matches(dnsResult.records || [], expected);
  const owner = ownerEmail(tenant.email);
  const lockKey = `host:custom:${hostname}`;
  const lock = await kv.get(lockKey);
  if (hostnameTaken(lock, owner)) {
    return takenResponse(hostname, records);
  }

  if (!txtOk) {
    const failed = await applyTxtFailure(kv, tenant);
    return {
      ok: true,
      status: failed.status,
      records,
      customHostname: hostname,
      tenant: failed.tenant,
    };
  }

  let cfId = tenant.customCfId || null;
  if (!cfId && opts.createCfIfMissing) {
    // Re-read immediately before the Cloudflare create (check-then-write).
    const lockBeforeCreate = await kv.get(lockKey);
    if (hostnameTaken(lockBeforeCreate, owner)) {
      return takenResponse(hostname, records);
    }
    const created = await createCustomHostname(env, hostname, fetchFn);
    if (!created.ok) {
      return {
        ok: false,
        statusCode: 502,
        error: "cloudflare_error",
        records,
        customHostname: hostname,
      };
    }
    cfId = created.id;
    tenant = await putTenant(kv, { ...tenant, customCfId: cfId });
  }

  if (!cfId) {
    const updated = await putTenant(kv, {
      ...tenant,
      customStatus: "pending_dns",
      customVerified: false,
      host: servingSubdomainHost(tenant),
    });
    return {
      ok: true,
      status: "pending_dns",
      records,
      customHostname: hostname,
      tenant: updated,
    };
  }

  const got = await getCustomHostname(env, cfId, fetchFn);
  if (!got.ok) {
    return {
      ok: false,
      statusCode: 502,
      error: "cloudflare_error",
      records,
      customHostname: hostname,
    };
  }

  const status = mapCfHostnameStatus(got.result);
  const active = status === "active";
  if (active) {
    const lockNow = await kv.get(lockKey);
    if (hostnameTaken(lockNow, owner)) {
      return takenResponse(hostname, records);
    }
    if (!lockNow) {
      await kv.put(lockKey, owner);
    }
  }
  const updated = await putTenant(kv, {
    ...tenant,
    customCfId: cfId,
    customStatus: status,
    customVerified: active,
    customHostname: hostname,
    customVerifyToken: token,
    host: active ? hostname : servingSubdomainHost(tenant),
  });

  return {
    ok: true,
    status,
    records,
    customHostname: hostname,
    tenant: updated,
  };
}

/**
 * Reserve a pending custom hostname for this account. No Cloudflare call and
 * no exclusive lock — another account may claim the same host until someone
 * reaches `active`. A new claim replaces this account's previous hostname
 * (delete its CF hostname if one exists; drop the lock only if we own it).
 */
export async function claimCustomHostname(env, hostnameInput, email) {
  if (!customDomainsEnabled(env)) {
    return { ok: false, status: 403, error: "custom_domains_disabled" };
  }
  const v = validateCustomHostname(hostnameInput);
  if (!v.ok) {
    return { ok: false, status: 400, error: v.error };
  }
  const h = v.hostname;
  const kv = env.PANELS;
  const owner = ownerEmail(email);
  if (!owner || !owner.includes("@")) {
    return { ok: false, status: 400, error: "missing_email" };
  }

  const lockKey = `host:custom:${h}`;
  const existing = await kv.get(lockKey);
  if (hostnameTaken(existing, owner)) {
    return { ok: false, status: 409, error: "hostname_taken" };
  }

  const prev = await getTenant(kv, owner);
  const prevHost = prev?.customHostname
    ? normalizeCustomHostname(String(prev.customHostname)).hostname
    : null;

  if (prevHost && prevHost !== h) {
    if (prev.customCfId) {
      const del = await deleteCustomHostname(env, prev.customCfId);
      if (!del.ok) {
        return { ok: false, status: 502, error: "cloudflare_error" };
      }
    }
    const prevLock = await kv.get(`host:custom:${prevHost}`);
    if (prevLock === owner) {
      await kv.delete(`host:custom:${prevHost}`);
    }
  }

  const sameHost = prevHost === h;
  const token =
    sameHost && prev?.customVerifyToken
      ? String(prev.customVerifyToken)
      : newCustomVerifyToken();
  const records = customDnsRecords(h, token);
  const tenant = await putTenant(kv, {
    ...(prev || {}),
    email: owner,
    customHostname: h,
    customVerified: false,
    customStatus: "pending_dns",
    customVerifyToken: token,
    customCfId: sameHost ? prev?.customCfId || null : null,
    host: servingSubdomainHost(prev) || prev?.host || null,
    slug: prev?.slug || null,
  });

  return {
    ok: true,
    host: tenant.host || null,
    customHostname: h,
    customVerified: false,
    status: "pending_dns",
    records,
    tenant,
  };
}

export async function deleteCustomHostnameClaim(env, email) {
  const owner = ownerEmail(email);
  if (!owner || !owner.includes("@")) {
    return { ok: false, status: 400, error: "missing_email" };
  }
  const kv = env.PANELS;
  const tenant = await getTenant(kv, owner);
  if (!tenant?.customHostname) {
    return { ok: false, status: 404, error: "no_custom_hostname" };
  }
  const n = normalizeCustomHostname(String(tenant.customHostname));
  const h = n.ok ? n.hostname : String(tenant.customHostname).trim().toLowerCase();
  const lock = await kv.get(`host:custom:${h}`);
  if (lock === owner) {
    if (tenant.customCfId) {
      const del = await deleteCustomHostname(env, tenant.customCfId);
      if (!del.ok) {
        return { ok: false, status: 502, error: "cloudflare_error" };
      }
    }
    await kv.delete(`host:custom:${h}`);
  } else if (!lock && tenant.customCfId) {
    const del = await deleteCustomHostname(env, tenant.customCfId);
    if (!del.ok) {
      return { ok: false, status: 502, error: "cloudflare_error" };
    }
  }
  await putTenant(kv, {
    ...tenant,
    email: owner,
    customHostname: null,
    customVerified: false,
    customStatus: null,
    customVerifyToken: null,
    customCfId: null,
    host: servingSubdomainHost(tenant),
    slug: tenant.slug || null,
  });
  return { ok: true };
}

export async function verifyCustomHostname(env, email, opts = {}) {
  if (!customDomainsEnabled(env)) {
    return { ok: false, statusCode: 403, error: "custom_domains_disabled" };
  }
  const owner = ownerEmail(email);
  if (!owner || !owner.includes("@")) {
    return { ok: false, statusCode: 400, error: "missing_email" };
  }
  const tenant = await getTenant(env.PANELS, owner);
  if (!tenant?.customHostname) {
    return { ok: false, statusCode: 400, error: "no_custom_hostname" };
  }
  const n = normalizeCustomHostname(String(tenant.customHostname));
  const h = n.ok ? n.hostname : "";
  const lock = await env.PANELS.get(`host:custom:${h}`);
  if (hostnameTaken(lock, owner)) {
    return {
      ok: false,
      statusCode: 409,
      error: "hostname_taken",
      records: customDnsRecords(h, tenant.customVerifyToken),
      customHostname: h,
    };
  }
  return syncCustomHostname(env, tenant, { createCfIfMissing: true, ...opts });
}

/** Daily cron: every custom hostname that already has a CF id. */
export async function recheckAllCustomHostnames(env) {
  const kv = env.PANELS;
  if (!kv?.list) return;
  let cursor;
  do {
    const page = await kv.list({
      prefix: "host:custom:",
      cursor,
      limit: 1000,
    });
    for (const k of page.keys || []) {
      const hostname = String(k.name || "").slice("host:custom:".length);
      const email = await kv.get(k.name);
      if (!email) continue;
      const tenant = await getTenant(kv, email);
      if (!tenant?.customCfId) continue;
      const claimed = String(tenant.customHostname || "")
        .trim()
        .toLowerCase()
        .replace(/\.+$/, "");
      if (claimed !== hostname) continue;
      await syncCustomHostname(env, tenant, { createCfIfMissing: false });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

export async function isActiveCustomHostname(env, hostname) {
  const n = normalizeCustomHostname(hostname);
  if (!n.ok) return false;
  const owner = await env.PANELS.get(`host:custom:${n.hostname}`);
  if (!owner) return false;
  const tenant = await getTenant(env.PANELS, owner);
  if (!tenant) return false;
  const claimed = normalizeCustomHostname(String(tenant.customHostname || ""));
  if (!claimed.ok || claimed.hostname !== n.hostname) return false;
  return tenant.customVerified === true && tenant.customStatus === "active";
}

export function tenantIsActiveCustom(tenant) {
  if (!tenant?.customHostname) return false;
  return tenant.customVerified === true && tenant.customStatus === "active";
}
