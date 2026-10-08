/**
 * Edge ACL — V1 Lock A: company = email domain after SSO; --to = email allowlist.
 * Does NOT verify Workspace / Entra / GitHub Org membership.
 */

/** Public mailbox domains — company mode is not allowed. Exact match only. */
export const PUBLIC_EMAIL_DOMAINS = [
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "outlook.com.br",
  "hotmail.com",
  "hotmail.com.br",
  "live.com",
  "msn.com",
  "yahoo.com",
  "yahoo.com.br",
  "icloud.com",
  "me.com",
  "mac.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "gmx.com",
  "zoho.com",
  "yandex.com",
  "mail.com",
  "uol.com.br",
  "bol.com.br",
  "terra.com.br",
  "ig.com.br",
  "users.noreply.github.com",
];

const PUBLIC_EMAIL_DOMAIN_SET = new Set(
  PUBLIC_EMAIL_DOMAINS.map((d) => d.toLowerCase())
);

/**
 * Exact domain match against PUBLIC_EMAIL_DOMAINS (case-insensitive).
 * Accepts an email (`User@GMAIL.com`) or a bare domain. Subdomains are not matched.
 */
export function isPublicEmailDomain(emailOrDomain) {
  const raw = String(emailOrDomain || "")
    .trim()
    .toLowerCase();
  if (!raw) return false;
  const domain = raw.includes("@") ? raw.split("@")[1] : raw.replace(/^@/, "");
  return Boolean(domain) && PUBLIC_EMAIL_DOMAIN_SET.has(domain);
}

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
  const domain = email.split("@")[1];
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
