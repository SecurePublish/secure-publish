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
 * Org (email-domain tenant; created on first verified work-email sign-in):
 *   org:{domain}              → { v, domain, createdBy, createdAt }
 *
 * Tenant hosting (per signed-in user):
 *   tenant:user:{email}       → { email, domain, host, slug?, customHostname?, customVerified?,
 *                                 customVerifyToken?, customStatus?, customCfId?, updatedAt }
 *   host:sub:{slug}           → email (owner lock)
 *   host:custom:{hostname}    → email (exclusive lock at active / records_missing; not at claim)
 *
 * PanelRecord v1+:
 *   { v, title?, name?, publishedAt, publisherEmail?, access: { mode, emails?, domains? }, html }
 * `name` is the stored normalized label (or omitted). Panel KV key is the id:
 *   new panels = 10-char Crockford/RFC4648 base32; legacy = 24-hex.
 */

import { normalizeEmails, normalizeDomains, normalizeEmailDomain } from "./acl.js";

/** Lowercase RFC 4648 base32 alphabet (no padding). */
export const PANEL_CODE_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

/** New panel ids (10-char) or legacy 24-hex. */
export const PANEL_ID_RE = /^(?:[0-9a-f]{24}|[a-z2-7]{10})$/i;

/**
 * KV lookup key for a path segment. 10-char codes are lowercased; 24-hex is
 * unchanged so existing keys keep working exactly as today.
 * @param {string} key
 * @returns {string | null}
 */
export function lookupPanelId(key) {
  if (!key || typeof key !== "string") return null;
  if (/^[0-9a-f]{24}$/i.test(key)) return key;
  if (/^[a-z2-7]{10}$/i.test(key)) return key.toLowerCase();
  return null;
}

/**
 * 10 random bytes from crypto.getRandomValues, each mapped with `byte & 31`.
 * @returns {string}
 */
export function generatePanelCode() {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < 10; i++) {
    out += PANEL_CODE_ALPHABET[bytes[i] & 31];
  }
  return out;
}

/**
 * Allocate a new 10-char code, retrying on the unlikely KV collision.
 * @param {{ get: (key: string) => Promise<string | null> }} kv
 * @returns {Promise<string | null>}
 */
export async function allocatePanelCode(kv) {
  for (let i = 0; i < 8; i++) {
    const id = generatePanelCode();
    if ((await kv.get(id)) == null) return id;
  }
  return null;
}

/**
 * Read-only URL label. Not unique, never reserved.
 * NFKD + strip diacritics, lowercase, non-[a-z0-9] runs → `-`, trim `-`,
 * max 60 (hyphen-boundary cut when possible). Empty → null.
 * @param {unknown} input
 * @returns {string | null}
 */
export function normalizePanelName(input) {
  if (input == null) return null;
  let s = String(input)
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!s) return null;
  if (s.length > 60) {
    let cut = s.slice(0, 60);
    const hyphen = cut.lastIndexOf("-");
    if (hyphen > 0) cut = cut.slice(0, hyphen);
    s = cut.replace(/-+$/g, "");
  }
  s = s.replace(/^-+|-+$/g, "");
  return s || null;
}

/**
 * Canonical path from stored id + normalized name. Nothing from the request.
 * @param {string} id
 * @param {string | null | undefined} name
 */
export function panelPath(id, name) {
  const n = typeof name === "string" && name ? name : null;
  return n ? `/${id}/${n}` : `/${id}`;
}

/** Stored name or null. */
export function storedPanelName(record) {
  const n = record?.name;
  return typeof n === "string" && n ? n : null;
}

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
  const key = lookupPanelId(id);
  if (!key) return null;
  const raw = await kv.get(key);
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
      ? normalizeEmailDomain(email)
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

export function orgKvKey(domain) {
  const d = normalizeEmailDomain(domain);
  return d ? `org:${d}` : "";
}

export async function getOrg(kv, domain) {
  const key = orgKvKey(domain);
  if (!kv || !key) return null;
  const raw = await kv.get(key);
  if (!raw) return null;
  try {
    const j = JSON.parse(raw);
    return j && typeof j === "object" ? j : null;
  } catch {
    return null;
  }
}

/**
 * First verified work-email user of a domain creates `org:{domain}`; later
 * users join the same record (createdBy unchanged). Also upserts tenant:user.
 * @returns {Promise<{ ok: boolean, org?: object, created?: boolean }>}
 */
export async function ensureOrgMembership(kv, email) {
  if (!kv) return { ok: false };
  const e = String(email || "").trim().toLowerCase();
  const domain = normalizeEmailDomain(e);
  if (!e.includes("@") || !domain) return { ok: false };
  const key = orgKvKey(domain);
  let org = await getOrg(kv, domain);
  const created = !org;
  if (!org) {
    org = {
      v: 1,
      domain,
      createdBy: e,
      createdAt: new Date().toISOString(),
    };
    await kv.put(key, JSON.stringify(org));
  }
  const prev = await getTenant(kv, e);
  await putTenant(kv, {
    ...(prev || {}),
    email: e,
    domain,
  });
  return { ok: true, org, created };
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
  const domain = normalizeEmailDomain(e);
  const record = {
    ...tenant,
    email: e,
    domain: tenant.domain || domain,
    updatedAt: new Date().toISOString(),
  };
  await kv.put(`tenant:user:${e}`, JSON.stringify(record));
  return record;
}

/**
 * Slugs tenants may not claim via PUT /api/hosting/subdomain.
 *
 * This list is intentionally broader than product-host routing in worker.js.
 * Product hosts (app/www/apex) skip host-owner binding so the Worker can
 * proxy Pages / serve OAuth. Do NOT reuse this set there: adding api/admin/
 * auth/login/cname to RESERVED_PRODUCT_HOSTS would make
 * api.securepublish.work/{panelId} serve any panel without an owner lock.
 *
 * Unowned claim-blocked hosts still fail closed on panel serve (no lock → 404).
 *
 * Required: app, www, cname, api, admin, auth, login.
 * Extra infra (short): mail/smtp (MX impersonation), status (status page),
 * docs (first-party docs), static/assets/cdn (asset hosts).
 * Not listed: wise (production tenant), demo (documented interim tenant).
 * `_auth` sanitizes to `auth` (underscores stripped).
 */
export const CLAIM_RESERVED_SLUGS = new Set([
  "app",
  "www",
  "cname",
  "api",
  "admin",
  "auth",
  "login",
  "mail",
  "smtp",
  "status",
  "docs",
  "static",
  "assets",
  "cdn",
]);

export async function claimSubdomain(kv, slug, email) {
  const s = String(slug || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "")
    .replace(/^-+|-+$/g, "");
  if (!s || s.length < 2 || s.length > 63) {
    return { ok: false, status: 400, error: "invalid_slug" };
  }
  if (CLAIM_RESERVED_SLUGS.has(s)) {
    return { ok: false, status: 400, error: "reserved_slug" };
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

/** Map view store → contract viewers[{email,first,last,firstAt,lastAt}]. */
export function viewsToApi(views, timeZone = "America/Sao_Paulo") {
  const byEmail = views?.byEmail || {};
  const viewers = Object.entries(byEmail)
    .map(([email, v]) => ({
      email,
      first: formatTimeLabel(v.first, timeZone),
      last: formatTimeLabel(v.last, timeZone),
      firstAt: formatIsoUtc(v.first),
      lastAt: formatIsoUtc(v.last),
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

/** Stored ISO → UTC ISO 8601 (`2026-10-07T00:47:12.000Z`); empty/invalid → null. */
function formatIsoUtc(iso) {
  if (!iso) return null;
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return null;
    return d.toISOString();
  } catch {
    return null;
  }
}

export function buildAccessFromPatch(body, publisherEmail) {
  const mode = (body?.mode || "company").toLowerCase() === "allowlist" ? "allowlist" : "company";
  if (mode === "allowlist") {
    const emails = normalizeEmails(body?.allowlist || body?.emails || []);
    return { mode: "allowlist", emails };
  }
  const domain = normalizeEmailDomain(publisherEmail);
  return {
    mode: "company",
    domains: normalizeDomains(domain ? [domain] : []),
  };
}

export { normalizeEmails, normalizeDomains };

const DEVICE_TTL_SEC = 600;
/** Cloudflare KV rejects expirationTtl below 60s. */
const KV_MIN_TTL_SEC = 60;
/** Publish-only credential. 12h, revocable. Not a browser cookie. */
const PUBLISH_TOKEN_TTL_SEC = 60 * 60 * 12;

function deviceRecordTtlSec(exp, now) {
  const left = Math.floor(Number(exp) - now);
  if (!Number.isFinite(left) || left < KV_MIN_TTL_SEC) return KV_MIN_TTL_SEC;
  return Math.min(DEVICE_TTL_SEC, left);
}

function randomHex(byteLen) {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(value))
  );
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
const BIND_FAIL_LIMIT = 5;
const BIND_FAIL_GLOBAL_LIMIT = 50;
const BIND_FAIL_WINDOW_SEC = 600;
const GLOBAL_BIND_FAIL_KEY = "devbindfail:global";

export function normalizeUserCode(raw) {
  return String(raw ?? "")
    .trim()
    .toUpperCase()
    .replace(/[\s-]/g, "");
}

function formatUserCode(normalized) {
  return `${normalized.slice(0, 4)}-${normalized.slice(4, 8)}`;
}

/** Unbiased draw from USER_CODE_ALPHABET via rejection sampling. */
function randomUserCode() {
  const n = USER_CODE_ALPHABET.length;
  const rejectAt = 256 - (256 % n);
  let out = "";
  while (out.length < 8) {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    for (const b of bytes) {
      if (b >= rejectAt) continue;
      out += USER_CODE_ALPHABET[b % n];
      if (out.length === 8) break;
    }
  }
  return out;
}

/**
 * One-time device login. device_code is the CLI polling secret; user_code is
 * what the account owner types on /device. They are never the same value.
 */
export async function createDeviceCode(kv) {
  const device_code = randomHex(32);
  const exp = Math.floor(Date.now() / 1000) + DEVICE_TTL_SEC;
  let userNorm = randomUserCode();
  for (let i = 0; i < 8; i++) {
    const existing = await kv.get(`devuser:${userNorm}`);
    if (!existing) break;
    userNorm = randomUserCode();
  }
  await kv.put(`device:${device_code}`, JSON.stringify({ status: "pending", exp }), {
    expirationTtl: DEVICE_TTL_SEC,
  });
  await kv.put(`devuser:${userNorm}`, device_code, { expirationTtl: DEVICE_TTL_SEC });
  return {
    device_code,
    user_code: formatUserCode(userNorm),
    expires_in: DEVICE_TTL_SEC,
    interval: 2,
  };
}

export async function bindDeviceByUserCode(kv, userCodeRaw, email) {
  const owner = String(email || "").trim().toLowerCase();
  const failKey = `devbindfail:${owner}`;
  const accountFails = Number(await kv.get(failKey)) || 0;
  const globalFails = Number(await kv.get(GLOBAL_BIND_FAIL_KEY)) || 0;
  if (accountFails >= BIND_FAIL_LIMIT || globalFails >= BIND_FAIL_GLOBAL_LIMIT) {
    return { ok: false, status: 429, error: "device_code_rate_limited" };
  }

  async function invalid() {
    await kv.put(failKey, String(accountFails + 1), { expirationTtl: BIND_FAIL_WINDOW_SEC });
    await kv.put(GLOBAL_BIND_FAIL_KEY, String(globalFails + 1), {
      expirationTtl: BIND_FAIL_WINDOW_SEC,
    });
    return { ok: false, status: 404, error: "device_code_invalid" };
  }

  const userNorm = normalizeUserCode(userCodeRaw);
  if (!/^[BCDFGHJKLMNPQRSTVWXZ]{8}$/.test(userNorm)) {
    return invalid();
  }
  const mapKey = `devuser:${userNorm}`;
  const device_code = await kv.get(mapKey);
  if (!device_code) return invalid();

  const approved = await approveDeviceCode(kv, device_code, owner);
  if (!approved.ok) return invalid();
  await kv.delete(mapKey);
  return { ok: true, email: owner };
}

export async function approveDeviceCode(kv, code, email) {
  if (!/^[a-f0-9]{64}$/.test(String(code || ""))) {
    return { ok: false, status: 400, error: "invalid_request" };
  }
  const owner = String(email || "").trim().toLowerCase();
  if (!owner.includes("@")) return { ok: false, status: 400, error: "missing_email" };
  const key = `device:${code}`;
  const raw = await kv.get(key);
  if (!raw) return { ok: false, status: 400, error: "expired_token" };
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return { ok: false, status: 400, error: "expired_token" };
  }
  const now = Math.floor(Date.now() / 1000);
  if (!rec.exp || rec.exp < now || rec.status === "consumed") {
    await kv.delete(key);
    return { ok: false, status: 400, error: "expired_token" };
  }
  // Single-use: a second approval does not mint another credential or wipe the first.
  if (rec.status !== "pending") {
    return { ok: false, status: 400, error: "expired_token" };
  }
  const accessToken = randomHex(32);
  const tokenHash = await sha256Hex(accessToken);
  const tokenExp = now + PUBLISH_TOKEN_TTL_SEC;
  await kv.put(`pubtok:${tokenHash}`, JSON.stringify({ email: owner, exp: tokenExp }));
  const idxKey = `pubtok-idx:${owner}`;
  const idxRaw = await kv.get(idxKey);
  let hashes = [];
  try {
    const parsed = idxRaw ? JSON.parse(idxRaw) : [];
    if (Array.isArray(parsed)) hashes = parsed.map(String);
  } catch {
    hashes = [];
  }
  if (!hashes.includes(tokenHash)) hashes.push(tokenHash);
  await kv.put(idxKey, JSON.stringify(hashes));
  await kv.put(
    key,
    JSON.stringify({ status: "approved", exp: rec.exp, email: owner, accessToken, tokenExp }),
    { expirationTtl: deviceRecordTtlSec(rec.exp, now) }
  );
  return { ok: true, email: owner };
}

export async function pollDeviceCode(kv, code) {
  if (!/^[a-f0-9]{64}$/.test(String(code || ""))) {
    return { ok: false, status: 400, error: "invalid_request" };
  }
  const key = `device:${code}`;
  const raw = await kv.get(key);
  if (!raw) return { ok: false, status: 400, error: "expired_token" };
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return { ok: false, status: 400, error: "expired_token" };
  }
  const now = Math.floor(Date.now() / 1000);
  if (!rec.exp || rec.exp < now || rec.status === "consumed") {
    await kv.delete(key);
    return { ok: false, status: 400, error: "expired_token" };
  }
  if (rec.status !== "approved" || !rec.accessToken) {
    return { ok: false, status: 400, error: "authorization_pending" };
  }
  const accessToken = rec.accessToken;
  const email = rec.email;
  const tokenExp = rec.tokenExp;
  await kv.put(key, JSON.stringify({ status: "consumed", exp: rec.exp, email }), {
    expirationTtl: deviceRecordTtlSec(rec.exp, now),
  });
  return { ok: true, accessToken, email, tokenExp };
}

export async function userFromPublishToken(kv, token) {
  const rawToken = String(token || "").trim();
  if (!/^[a-f0-9]{64}$/.test(rawToken)) return null;
  const hash = await sha256Hex(rawToken);
  const raw = await kv.get(`pubtok:${hash}`);
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw);
    if (!rec?.email || !rec.exp || rec.exp < Math.floor(Date.now() / 1000)) return null;
    return { email: String(rec.email).trim().toLowerCase() };
  } catch {
    return null;
  }
}


/** Drop one publish credential (logout / revoke). */
export async function revokePublishToken(kv, token) {
  const rawToken = String(token || "").trim();
  if (!/^[a-f0-9]{64}$/.test(rawToken)) {
    return { ok: false, status: 401, error: "unauthorized" };
  }
  const hash = await sha256Hex(rawToken);
  const raw = await kv.get(`pubtok:${hash}`);
  if (!raw) return { ok: false, status: 401, error: "unauthorized" };
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return { ok: false, status: 401, error: "unauthorized" };
  }
  await kv.delete(`pubtok:${hash}`);
  const email = String(rec.email || "").trim().toLowerCase();
  if (email) {
    const idxKey = `pubtok-idx:${email}`;
    const idxRaw = await kv.get(idxKey);
    let hashes = [];
    try {
      const parsed = idxRaw ? JSON.parse(idxRaw) : [];
      if (Array.isArray(parsed)) hashes = parsed.map(String);
    } catch {
      hashes = [];
    }
    hashes = hashes.filter((h) => h !== hash);
    if (hashes.length) await kv.put(idxKey, JSON.stringify(hashes));
    else await kv.delete(idxKey);
  }
  return { ok: true };
}
