/** Fallback when the env var is unset and GET /api/limits is missing or fails. */
export const DEFAULT_MAX_UPLOAD_BYTES = 3 * 1024 * 1024;
export const NEAR_LIMIT_RATIO = 0.9;
export const LIMITS_FETCH_TIMEOUT_MS = 2000;

const ENV_NAME = "SECUREPUBLISH_MAX_UPLOAD_BYTES";

/** @type {number | undefined} */
let cachedApiLimit;

export function resetUploadLimitCache() {
  cachedApiLimit = undefined;
}

export function parsePositiveInt(raw) {
  if (raw == null || raw === "") return null;
  const n = Number(String(raw).trim());
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) return null;
  return n;
}

export function formatMb(bytes) {
  const mb = Number(bytes) / (1024 * 1024);
  return (Math.round(mb * 10) / 10).toFixed(1);
}

export function isOverUploadLimit(fileBytes, maxBytes) {
  return fileBytes > maxBytes;
}

export function isNearUploadLimit(fileBytes, maxBytes) {
  return fileBytes > maxBytes * NEAR_LIMIT_RATIO && fileBytes <= maxBytes;
}

export function uploadTooLargeMessage(fileBytes, maxBytes) {
  const fileMb = formatMb(fileBytes);
  const limitMb = formatMb(maxBytes);
  return [
    "This file is too large to publish.",
    "",
    `There is a per-publish upload limit. This file is ${fileMb} MB; the limit is ${limitMb} MB.`,
    "",
    "To publish it:",
    "- Compress images, or put fewer images inside the HTML",
    "- Move large images or other files out of the page and link to them",
    "- Split the content into several smaller pages",
  ].join("\n");
}

export function nearLimitWarning(fileBytes, maxBytes) {
  return (
    `warn: this file is ${formatMb(fileBytes)} MB, close to the ` +
    `${formatMb(maxBytes)} MB publish limit. Compress or inline fewer images if you add more.`
  );
}

export function isSizeTooLargeResponse(res, data) {
  if (res?.status === 413) return true;
  const err = String(data?.error || data?.code || data?.message || "").toLowerCase();
  if (!err) return false;
  return (
    err === "payload_too_large" ||
    err === "size_too_large" ||
    err === "request_entity_too_large" ||
    /payload.?too.?large|size.?too.?large/.test(err)
  );
}

/**
 * Resolve the per-publish upload limit:
 *   1. SECUREPUBLISH_MAX_UPLOAD_BYTES
 *   2. GET /api/limits → { maxUploadBytes }
 *   3. DEFAULT_MAX_UPLOAD_BYTES (3145728)
 *
 * The limits endpoint is optional; a missing or failing call is not an error.
 * Network results are cached for the rest of this process.
 */
export async function resolveMaxUploadBytes({
  apiBase,
  env = process.env,
  fetchImpl = globalThis.fetch,
  timeoutMs = LIMITS_FETCH_TIMEOUT_MS,
} = {}) {
  const fromEnv = parsePositiveInt(env?.[ENV_NAME]);
  if (fromEnv != null) return fromEnv;
  if (cachedApiLimit != null) return cachedApiLimit;

  const fromApi = await fetchMaxUploadBytes(apiBase, fetchImpl, timeoutMs);
  cachedApiLimit = fromApi ?? DEFAULT_MAX_UPLOAD_BYTES;
  return cachedApiLimit;
}

async function fetchMaxUploadBytes(apiBase, fetchImpl, timeoutMs) {
  const base = String(apiBase || "").replace(/\/$/, "");
  if (!base || typeof fetchImpl !== "function") return null;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(`${base}/api/limits`, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: ctrl.signal,
    });
    if (!res || !res.ok) return null;
    const data = await res.json().catch(() => null);
    return parsePositiveInt(data?.maxUploadBytes);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
