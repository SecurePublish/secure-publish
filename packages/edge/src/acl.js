/**
 * Edge ACL — V1 Lock A: company = email domain after SSO; --to = email allowlist.
 * Does NOT verify Workspace / Entra / GitHub Org membership.
 */

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
 * @returns {{ ok: boolean, reason?: string }}
 */
export function checkPanelAccess(user, access, env) {
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
