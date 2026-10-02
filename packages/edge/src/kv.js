/**
 * KV key design (PANELS binding)
 *
 * Panel HTML + meta (CLI-compatible bare hex id):
 *   {panelId}                 → PanelRecord JSON
 *
 * Indexes (updated by Worker API / CLI publish):
 *   idx:pub:{email}           → string[] panel ids
 *   idx:domain:{domain}       → string[] panel ids
 *
 * View analytics (PII — serve only to authenticated tenant):
 *   view:{panelId}            → { count, byEmail: { email: { first, last } } }
 *
 * Tenant hosting (per signed-in user):
 *   tenant:user:{email}       → { email, domain, host, slug?, customHostname?, customVerified?, updatedAt }
 *   host:sub:{slug}           → email (owner lock)
 *   host:custom:{hostname}    → email (owner lock)
 *
 * PanelRecord v1+:
 *   { v, title?, publishedAt, publisherEmail?, access: { mode, emails?, domains? }, html }
 */

import { normalizeEmails, normalizeDomains } from "./acl.js";

export const PANEL_ID_RE = /^[0-9a-f]{24}$/i;

export function decodeRecord(raw) {
  if (raw == null) return null;
  try {
    const j = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (j && typeof j.html === "string") return j;
  } catch {
    /* legacy raw HTML */
  }
  return { v: 0, html: String(raw), access: { mode: "company", domains: [] } };
}

export function encodeRecord(record) {
  return JSON.stringify(record);
}

export async function getPanel(kv, id) {
  if (!PANEL_ID_RE.test(id)) return null;
  const raw = await kv.get(id);
  if (raw == null) return null;
  return decodeRecord(raw);
}

export async function putPanel(kv, id, record) {
  await kv.put(id, encodeRecord(record));
}

async function readIndex(kv, key) {
  const raw = await kv.get(key);
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.map(String) : [];
  } catch {
    return [];
  }
}

async function writeIndex(kv, key, ids) {
  const uniq = [...new Set(ids.filter(Boolean))];
  await kv.put(key, JSON.stringify(uniq));
}

export async function indexPanel(kv, panelId, publisherEmail, access) {
  const email = (publisherEmail || "").trim().toLowerCase();
  if (email) {
    const pubKey = `idx:pub:${email}`;
    const list = await readIndex(kv, pubKey);
    if (!list.includes(panelId)) {
      list.push(panelId);
      await writeIndex(kv, pubKey, list);
    }
  }
  const domain =
    email.includes("@")
      ? email.split("@")[1]
      : (access?.domains && access.domains[0]) || "";
  if (domain) {
    const dKey = `idx:domain:${domain.toLowerCase()}`;
    const list = await readIndex(kv, dKey);
    if (!list.includes(panelId)) {
      list.push(panelId);
      await writeIndex(kv, dKey, list);
    }
  }
}

export async function listPanelIdsForPublisher(kv, email) {
  return readIndex(kv, `idx:pub:${String(email || "").trim().toLowerCase()}`);
}

export async function listPanelIdsForDomain(kv, domain) {
  return readIndex(kv, `idx:domain:${String(domain || "").trim().toLowerCase()}`);
}

/** Fallback scan when indexes are empty (legacy CLI publishes). */
export async function listAllPanelIds(kv, limit = 500) {
  const ids = [];
  let cursor;
  do {
    const page = await kv.list({ prefix: "", cursor, limit: Math.min(limit, 1000) });
    for (const k of page.keys || []) {
      const name = k.name;
      if (PANEL_ID_RE.test(name)) ids.push(name);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && ids.length < limit);
  return ids;
}

export async function getViews(kv, panelId) {
  const raw = await kv.get(`view:${panelId}`);
  if (!raw) return { count: 0, byEmail: {} };
  try {
    const j = JSON.parse(raw);
    return {
      count: Number(j.count) || 0,
      byEmail: j.byEmail && typeof j.byEmail === "object" ? j.byEmail : {},
    };
  } catch {
    return { count: 0, byEmail: {} };
  }
}

export async function recordView(kv, panelId, email) {
  const e = String(email || "").trim().toLowerCase();
  if (!e || !e.includes("@")) return;
  const views = await getViews(kv, panelId);
  const now = new Date().toISOString();
  const prev = views.byEmail[e];
  views.byEmail[e] = {
    first: prev?.first || now,
    last: now,
  };
  views.count = (Number(views.count) || 0) + 1;
  await kv.put(`view:${panelId}`, JSON.stringify(views));
}

export async function getTenant(kv, email) {
  const e = String(email || "").trim().toLowerCase();
  if (!e) return null;
  const raw = await kv.get(`tenant:user:${e}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function putTenant(kv, tenant) {
  const e = String(tenant.email || "").trim().toLowerCase();
  if (!e) throw new Error("tenant email required");
  const domain = e.includes("@") ? e.split("@")[1] : "";
  const record = {
    ...tenant,
    email: e,
    domain: tenant.domain || domain,
    updatedAt: new Date().toISOString(),
  };
  await kv.put(`tenant:user:${e}`, JSON.stringify(record));
  return record;
}

export async function claimSubdomain(kv, slug, email) {
  const s = String(slug || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "")
    .replace(/^-+|-+$/g, "");
  if (!s || s.length < 2 || s.length > 63) {
    return { ok: false, status: 400, error: "invalid_slug" };
  }
  const lockKey = `host:sub:${s}`;
  const existing = await kv.get(lockKey);
  const owner = String(email || "").trim().toLowerCase();
  if (existing && existing !== owner) {
    return { ok: false, status: 409, error: "subdomain_taken" };
  }
  const prev = await getTenant(kv, owner);
  if (prev?.slug && prev.slug !== s) {
    await kv.delete(`host:sub:${prev.slug}`);
  }
  await kv.put(lockKey, owner);
  const base = "securepublish.work";
  const host = `${s}.${base}`;
  const tenant = await putTenant(kv, {
    ...(prev || {}),
    email: owner,
    slug: s,
    host,
    customHostname: prev?.customHostname || null,
    customVerified: prev?.customVerified || false,
  });
  return { ok: true, host, tenant };
}

/**
 * Reserve custom hostname. Serving requires customVerified === true
 * (TXT/CNAME proof — John/DNS). Until verified, host stays on subdomain.
 */
export async function claimCustomHostname(kv, hostname, email) {
  const h = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
  if (!h || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(h) || h.includes("..")) {
    return { ok: false, status: 400, error: "invalid_hostname" };
  }
  if (h.endsWith(".securepublish.work") || h.endsWith(".workers.dev")) {
    return { ok: false, status: 400, error: "use_subdomain_endpoint" };
  }
  const lockKey = `host:custom:${h}`;
  const existing = await kv.get(lockKey);
  const owner = String(email || "").trim().toLowerCase();
  if (existing && existing !== owner) {
    return { ok: false, status: 409, error: "hostname_taken" };
  }
  const prev = await getTenant(kv, owner);
  if (prev?.customHostname && prev.customHostname !== h) {
    await kv.delete(`host:custom:${prev.customHostname}`);
  }
  await kv.put(lockKey, owner);
  // Ownership not verified yet — do not switch serving host.
  const tenant = await putTenant(kv, {
    ...(prev || {}),
    email: owner,
    customHostname: h,
    customVerified: false,
    host: prev?.host || null,
    slug: prev?.slug || null,
  });
  return {
    ok: true,
    host: tenant.host || null,
    customHostname: h,
    customVerified: false,
    verify: {
      type: "txt",
      name: `_secure-publish.${h}`,
      value: `sp-verify=${owner}`,
      note: "Ownership verification pending (John/DNS). Host not switched until verified.",
    },
    tenant,
  };
}

export function accessToApiMode(access) {
  const mode = (access?.mode || "company").toLowerCase();
  if (mode === "allowlist") return "allowlist";
  return "company"; // company | org → company
}

export function accessToAllowlist(access) {
  if ((access?.mode || "").toLowerCase() !== "allowlist") return [];
  return normalizeEmails(access?.emails || []);
}

export function formatPublishedLabel(iso, timeZone = "America/Sao_Paulo") {
  if (!iso) return undefined;
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return undefined;
    const parts = new Intl.DateTimeFormat("pt-BR", {
      timeZone,
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).formatToParts(d);
    const get = (t) => parts.find((p) => p.type === t)?.value || "";
    return `${get("day")}/${get("month")}/${get("year")} · ${get("hour")}:${get("minute")}`;
  } catch {
    return undefined;
  }
}

/** Map view store → contract viewers[{email,first,last}] (time-of-day labels). */
export function viewsToApi(views, timeZone = "America/Sao_Paulo") {
  const byEmail = views?.byEmail || {};
  const viewers = Object.entries(byEmail)
    .map(([email, v]) => ({
      email,
      first: formatTimeLabel(v.first, timeZone),
      last: formatTimeLabel(v.last, timeZone),
    }))
    .sort((a, b) => String(a.email).localeCompare(String(b.email)));
  return {
    views: Number(views?.count) || viewers.length,
    viewers,
  };
}

function formatTimeLabel(iso, timeZone) {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return new Intl.DateTimeFormat("pt-BR", {
      timeZone,
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(d);
  } catch {
    return "";
  }
}

export function buildAccessFromPatch(body, publisherEmail) {
  const mode = (body?.mode || "company").toLowerCase() === "allowlist" ? "allowlist" : "company";
  if (mode === "allowlist") {
    const emails = normalizeEmails(body?.allowlist || body?.emails || []);
    return { mode: "allowlist", emails };
  }
  const domain = (publisherEmail || "").split("@")[1]?.toLowerCase();
  return {
    mode: "company",
    domains: normalizeDomains(domain ? [domain] : []),
  };
}

export { normalizeEmails, normalizeDomains };
