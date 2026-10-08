/**
 * Edge ACL — V1 Lock A: company = email domain after SSO; --to = email allowlist.
 * Does NOT verify Workspace / Entra / GitHub Org membership.
 */

import { FREE_EMAIL_DOMAINS } from "./free-email-domains.js";

export { FREE_EMAIL_DOMAINS };

/**
 * Hosts to block in addition to free-email-domains@1.12.22:
 * GitHub noreply (required), plus live.com.br / tutanota.com which the
 * dataset omits but are personal/free mailboxes.
 */
const EXTRA_BLOCKED_SIGNUP_DOMAINS = new Set([
  "users.noreply.github.com",
  "live.com.br",
  "tutanota.com",
]);

const BLOCKED_SIGNUP_EXACT = new Set([...FREE_EMAIL_DOMAINS, ...EXTRA_BLOCKED_SIGNUP_DOMAINS]);

/** ASCII host after lowercase + IDN→punycode. Reject anything else; never repair. */
const EMAIL_DOMAIN_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;

function rawEmailDomain(emailOrDomain) {
  const raw = String(emailOrDomain || "")
    .trim()
    .toLowerCase();
  if (!raw) return "";
  const host = raw.includes("@") ? raw.split("@").pop() : raw.replace(/^@/, "");
  return String(host || "").trim();
}

/**
 * IDN → ASCII punycode for Unicode labels only. ASCII input is never passed
 * through `new URL` (that would strip `#` `?` `/` and mint a "valid" host).
 */
function idnToPunycodeNoRepair(domain) {
  if (!domain) return "";
  if (/^[\x00-\x7F]*$/.test(domain)) return domain;
  if (/[#/?\\:@[\]\s]/.test(domain)) return domain;
  try {
    return new URL("https://" + domain).hostname.toLowerCase();
  } catch {
    return domain;
  }
}

/**
 * Lowercase, trim, IDN→punycode, then exact ASCII host regex.
 * Invalid input returns "" — callers must deny; the string is never repaired.
 * `localhost` is allowed only for SSO_DEV_BYPASS / local tests (not a TLD).
 */
export function normalizeEmailDomain(emailOrDomain) {
  const ascii = idnToPunycodeNoRepair(rawEmailDomain(emailOrDomain));
  if (ascii === "localhost") return ascii;
  if (!EMAIL_DOMAIN_RE.test(ascii)) return "";
  return ascii;
}

function domainOrAncestorBlocked(domain) {
  if (BLOCKED_SIGNUP_EXACT.has(domain)) return true;
  let rest = domain;
  let dot;
  while ((dot = rest.indexOf(".")) !== -1) {
    rest = rest.slice(dot + 1);
    if (BLOCKED_SIGNUP_EXACT.has(rest)) return true;
  }
  return false;
}

/**
 * Exact domain match against the free-mail blocklist (case-insensitive).
 * Accepts an email or a bare domain. Subdomains are not matched here.
 */
export function isPublicEmailDomain(emailOrDomain) {
  const domain = normalizeEmailDomain(emailOrDomain);
  return Boolean(domain) && BLOCKED_SIGNUP_EXACT.has(domain);
}

/**
 * Signup / app-login blocklist. Invalid domains, listed free providers, and
 * subdomains of those providers (mail.yahoo.com, users.noreply.github.com).
 */
export function isBlockedSignupDomain(emailOrDomain) {
  const domain = normalizeEmailDomain(emailOrDomain);
  if (!domain) return true;
  return domainOrAncestorBlocked(domain);
}

/** @deprecated use FREE_EMAIL_DOMAINS; kept as the exact-match set for tests. */
export const PUBLIC_EMAIL_DOMAINS = BLOCKED_SIGNUP_EXACT;

export function normalizeEmails(emails) {
  const out = [];
  const seen = new Set();
  for (const e of emails || []) {
    const v = String(e || "").trim().toLowerCase();
    if (!v || !v.includes("@")) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

export function normalizeDomains(domains) {
  const list = Array.isArray(domains)
    ? domains
    : String(domains || "")
        .split(",")
        .map((d) => d.trim());
  const out = [];
  const seen = new Set();
  for (const d of list) {
    const v = String(d || "")
      .trim()
      .toLowerCase()
      .replace(/^@/, "");
    if (!v) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

export function envCompanyDomains(env) {
  return normalizeDomains(env.OAUTH_ALLOWED_DOMAINS || env.SECURE_PUBLISH_COMPANY_DOMAINS || "");
}

/**
 * @param {{ email?: string }} user
 * @param {{ mode?: string, emails?: string[], domains?: string[] }} access
 * @param {Record<string, string | undefined>} env
 * @param {string} [publisherEmail] panel owner (publisherEmail field)
 * @returns {{ ok: boolean, reason?: string }}
 */
export function checkPanelAccess(user, access, env, publisherEmail) {
  const email = (user?.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return { ok: false, reason: "missing_email" };
  }

  const mode = (access?.mode || "company").toLowerCase();
  if (mode === "allowlist") {
    const allowed = normalizeEmails(access?.emails || []);
    if (!allowed.length) return { ok: false, reason: "empty_allowlist" };
    if (!allowed.includes(email)) return { ok: false, reason: "not_on_allowlist" };
    return { ok: true };
  }

  const domains = normalizeDomains(
    access?.domains?.length ? access.domains : envCompanyDomains(env)
  );
  if (domains.some((d) => isPublicEmailDomain(d))) {
    const publisher = String(publisherEmail || "")
      .trim()
      .toLowerCase();
    if (publisher && publisher === email) return { ok: true };
    return { ok: false, reason: "public_company_domain" };
  }
  if (!domains.length) return { ok: false, reason: "no_company_domains" };
  const domain = normalizeEmailDomain(email);
  if (!domain || !domains.includes(domain)) {
    return { ok: false, reason: "domain_not_allowed" };
  }
  return { ok: true };
}

export function accessDeniedBody(reason) {
  if (reason === "domain_not_allowed") {
    return "Seu e-mail não é do domínio desta empresa. Peça acesso ou use a conta corporativa.\n";
  }
  return "Você está logado, mas não tem permissão neste dashboard.\n";
}
