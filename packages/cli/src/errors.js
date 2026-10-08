/** Machine-readable CLI / Worker error codes (`error: <code>` on stderr). */
const MACHINE_CODE = /^[a-z][a-z0-9_]{1,80}$/;

/** Worker JSON `error` values that the CLI remaps for agents. */
const API_ERROR_MAP = {
  unauthorized: "session_expired",
  min_email: "invalid_email",
  missing_html: "file_empty",
};

export class CliError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = "CliError";
    this.code = code;
  }
}

export function isMachineErrorCode(value) {
  return typeof value === "string" && MACHINE_CODE.test(value);
}

/**
 * Map a Worker JSON `error` (and HTTP status) to the CLI stderr code.
 * Unknown snake_case codes pass through verbatim.
 * @param {unknown} errorField
 * @param {number} [httpStatus]
 * @param {{ hadSession?: boolean }} [opts]
 */
export function codeFromApiError(errorField, httpStatus, opts = {}) {
  if (isMachineErrorCode(errorField)) {
    if (errorField === "unauthorized") {
      return opts.hadSession ? "session_expired" : "not_logged_in";
    }
    return API_ERROR_MAP[errorField] || errorField;
  }
  if (httpStatus === 401) {
    return opts.hadSession ? "session_expired" : "not_logged_in";
  }
  return "server_error";
}

/** @param {unknown} err */
export function printCliError(err) {
  const code =
    err instanceof CliError && isMachineErrorCode(err.code)
      ? err.code
      : "server_error";
  console.error(`error: ${code}`);
  const msg = err && err.message ? String(err.message) : String(err || "");
  if (msg) console.error(msg);
}
