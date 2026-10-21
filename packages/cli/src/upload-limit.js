/** GET /api/limits is best-effort; a miss must not block the upload. */
export const LIMITS_FETCH_TIMEOUT_MS = 3000;
export const SERVER_TEXT_MAX_CHARS = 500;

export function parsePositiveInt(raw) {
  if (raw == null || raw === "") return null;
  const n = Number(String(raw).trim());
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) return null;
  return n;
}

export function isOverUploadLimit(bodyBytes, maxBytes) {
  return bodyBytes > maxBytes;
}

/**
 * Strip ANSI/control characters and cap length so server text cannot inject
 * into the terminal.
 */
export function sanitizeServerText(text, maxLen = SERVER_TEXT_MAX_CHARS) {
  let s = text == null ? "" : String(text);
  s = s.replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "");
  s = s.replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, "");
  s = s.replace(/\u001b[@-Z\\-_]/g, "");
  // Keep TAB/LF; drop CR and other C0 so the terminal cannot be rewritten.
  s = s.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "");
  if (s.length > maxLen) s = s.slice(0, maxLen);
  return s;
}

/** Prefer JSON `message`; otherwise the raw 413 body. Always sanitize. */
export function serverSizeErrorMessage(rawText) {
  const raw = rawText == null ? "" : String(rawText);
  try {
    const data = JSON.parse(raw);
    if (data && typeof data === "object" && typeof data.message === "string") {
      return sanitizeServerText(data.message);
    }
  } catch {
    /* not JSON */
  }
  return sanitizeServerText(raw);
}

/**
 * Fetch the server-owned upload limit.
 * New shape: `{ upload: { maxBytes, message } }`.
 * Legacy `{ maxUploadBytes }` (no `upload`) → null (skip the pre-check).
 * Network/timeout/invalid → null (upload anyway).
 */
export async function fetchUploadLimit({
  apiBase,
  lang = "pt",
  fetchImpl = globalThis.fetch,
  timeoutMs = LIMITS_FETCH_TIMEOUT_MS,
} = {}) {
  const base = String(apiBase || "").replace(/\/$/, "");
  if (!base || typeof fetchImpl !== "function") return null;

  const acceptLanguage = lang === "en" ? "en" : "pt";
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(`${base}/api/limits`, {
      method: "GET",
      headers: {
        accept: "application/json",
        "accept-language": acceptLanguage,
      },
      signal: ctrl.signal,
    });
    if (!res || !res.ok) return null;
    const data = await res.json().catch(() => null);
    const upload = data?.upload;
    if (!upload || typeof upload !== "object") return null;
    const maxBytes = parsePositiveInt(upload.maxBytes);
    if (maxBytes == null) return null;
    return {
      maxBytes,
      message: typeof upload.message === "string" ? upload.message : "",
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
