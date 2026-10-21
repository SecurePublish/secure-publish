/** GET /api/limits is best-effort; a miss must not block the upload. */
export const LIMITS_FETCH_TIMEOUT_MS = 3000;
export const SERVER_TEXT_MAX_CHARS = 500;
export const SIZE_REFUSED_MESSAGE = {
  pt: "O servidor recusou o arquivo por ser grande demais. Diminua o arquivo e tente de novo.",
  en: "The server rejected this file as too large. Make it smaller and try again.",
};

/** Resolved Accept-Language for /api/limits and POST /api/panels. */
export function acceptLanguageHeader(lang) {
  return lang === "en" ? "en" : "pt-BR";
}

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
  // Keep TAB/LF; drop CR, other C0, DEL, and C1 (U+009B is CSI in some terminals).
  s = s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "");
  s = s.replace(/[\u202a-\u202e\u2066-\u2069]/g, "");
  if (s.length > maxLen) s = s.slice(0, maxLen);
  return s;
}

/**
 * Prefer a usable JSON `message`. If missing/empty/non-JSON (including HTML),
 * print one short generic line — never dump the raw body.
 */
export function serverSizeErrorMessage(rawText, lang = "pt") {
  const fallback = lang === "en" ? SIZE_REFUSED_MESSAGE.en : SIZE_REFUSED_MESSAGE.pt;
  const raw = rawText == null ? "" : String(rawText);
  try {
    const data = JSON.parse(raw);
    if (data && typeof data === "object" && typeof data.message === "string") {
      const msg = sanitizeServerText(data.message);
      if (msg.trim()) return msg;
    }
  } catch {
    /* not JSON */
  }
  return fallback;
}

/**
 * Fetch the server-owned upload limit.
 * New shape: `{ upload: { maxBytes, message } }`.
 * Legacy `{ maxUploadBytes }` (no `upload`) → null (skip the pre-check).
 * Missing/empty `upload.message` → null (skip; never a blank error).
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

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(`${base}/api/limits`, {
      method: "GET",
      headers: {
        accept: "application/json",
        "accept-language": acceptLanguageHeader(lang),
      },
      signal: ctrl.signal,
    });
    if (!res || !res.ok) return null;
    const data = await res.json().catch(() => null);
    const upload = data?.upload;
    if (!upload || typeof upload !== "object") return null;
    const maxBytes = parsePositiveInt(upload.maxBytes);
    if (maxBytes == null) return null;
    const message = typeof upload.message === "string" ? upload.message : "";
    if (!message.trim()) return null;
    return { maxBytes, message };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
