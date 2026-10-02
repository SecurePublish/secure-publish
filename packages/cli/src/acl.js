/**
 * Per-panel ACL helpers (shared conceptually with the edge worker).
 *
 * V1 Lock A (John):
 *   company | org  — same *email domain* as the tenant after SSO.
 *                    NOT Workspace / Entra / GitHub Org membership (later phase).
 *   allowlist      — explicit email list from --to (still requires SSO).
 *
 * Product UI may say “toda a empresa” / company-wide; docs + edge = domain.
 */

/**
 * @param {string | undefined} raw
 * @returns {string[]}
 */
export function parseToFlag(raw) {
  if (!raw || typeof raw !== "string") return [];
  return normalizeEmails(raw.split(/[,;\s]+/));
}

/**
 * @param {string[]} emails
 * @returns {string[]}
 */
export function normalizeEmails(emails) {
  const out = [];
  const seen = new Set();
  for (const e of emails) {
    const v = String(e || "")
      .trim()
      .toLowerCase();
    if (!v || !v.includes("@")) continue;
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }
  return out;
}

/**
 * @param {string[] | string | undefined} domains
 * @returns {string[]}
 */
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

/**
 * Build access metadata stored with the panel.
 * @param {{ toEmails?: string[], companyDomains?: string[] }} opts
 */
export function buildAccessMeta(opts = {}) {
  const emails = normalizeEmails(opts.toEmails || []);
  if (emails.length) {
    return { mode: "allowlist", emails };
  }
  return {
    // Metadata label may be "company" or "org"; semantics = domain allowlist.
    mode: "company",
    domains: normalizeDomains(opts.companyDomains || []),
  };
}

/**
 * Check whether a signed-in viewer may open a panel.
 * Caller must already have verified SSO (session exists).
 *
 * @param {{ email?: string }} user
 * @param {{ mode?: string, emails?: string[], domains?: string[] } | null | undefined} access
 * @param {{ companyDomains?: string[] }} envDefaults
 * @returns {{ ok: boolean, reason?: string }}
 */
export function checkPanelAccess(user, access, envDefaults = {}) {
  const email = (user?.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return { ok: false, reason: "missing_email" };
  }

  const mode = (access?.mode || "company").toLowerCase();
  if (mode === "allowlist") {
    const allowed = normalizeEmails(access?.emails || []);
    if (!allowed.length) {
      return { ok: false, reason: "empty_allowlist" };
    }
    if (!allowed.includes(email)) {
      return { ok: false, reason: "not_on_allowlist" };
    }
    return { ok: true };
  }

  // company | org — domain allowlist (V1 Lock A). Not true org membership.
  const domains = normalizeDomains(
    (access?.domains && access.domains.length
      ? access.domains
      : envDefaults.companyDomains) || []
  );
  if (!domains.length) {
    return { ok: false, reason: "no_company_domains" };
  }
  const domain = email.split("@")[1];
  if (!domain || !domains.includes(domain)) {
    return { ok: false, reason: "domain_not_allowed" };
  }
  return { ok: true };
}

/**
 * Human messages aligned with copy-console-agent-alpha.md §6.2.
 * Ban list: gate, waitlist, early access, compliance, E2E encryption, zero trust.
 * @param {string} reason
 * @param {"pt"|"en"} lang
 */
export function accessDeniedMessage(reason, lang = "pt") {
  const en = lang === "en";
  if (reason === "domain_not_allowed") {
    return en
      ? "Your email isn’t on this company’s domain. Ask for access or use your work account."
      : "Seu e-mail não é do domínio desta empresa. Peça acesso ou use a conta corporativa.";
  }
  if (reason === "not_on_allowlist") {
    return en
      ? "You’re signed in, but you don’t have access to this dashboard."
      : "Você está logado, mas não tem permissão neste dashboard.";
  }
  if (reason === "no_company_domains" || reason === "empty_allowlist") {
    return en
      ? "This dashboard has no access policy configured."
      : "Este dashboard não tem política de acesso configurada.";
  }
  return en
    ? "You’re signed in, but you don’t have access to this dashboard."
    : "Você está logado, mas não tem permissão neste dashboard.";
}

/** Skill/CLI success lines (§6.2 publish org / allowlist). */
export function publishSuccessMessage({ mode, url, emails }, lang = "pt") {
  const en = lang === "en";
  if (mode === "allowlist") {
    const list = (emails || []).join(", ");
    return en
      ? `Published only for ${list}: ${url}`
      : `Publicado só para ${list}: ${url}`;
  }
  return en
    ? `Published for the **whole company**: ${url}`
    : `Publicado pra **toda a empresa**: ${url}`;
}
