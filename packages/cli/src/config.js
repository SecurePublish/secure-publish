import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HOME_CONFIG = path.join(os.homedir(), ".secure-publish", "config.json");
const PROJECT_CONFIG = ".secure-publish.json";

/**
 * Load config from (highest priority first):
 *   1. Environment variables
 *   2. Project .secure-publish.json (cwd)
 *   3. ~/.secure-publish/config.json
 */
export function loadConfig(cwd = process.cwd()) {
  const home = readJsonSafe(HOME_CONFIG) || {};
  const project = readJsonSafe(path.join(cwd, PROJECT_CONFIG)) || {};
  const merged = { ...home, ...project };

  const accountId =
    process.env.CLOUDFLARE_ACCOUNT_ID || merged.accountId || null;
  const apiToken =
    process.env.CLOUDFLARE_API_TOKEN ||
    process.env.CF_API_TOKEN ||
    merged.apiToken ||
    null;
  const kvNamespaceId =
    process.env.SECURE_PUBLISH_KV_NAMESPACE_ID ||
    process.env.PANEL_GATE_KV_NAMESPACE_ID ||
    merged.kvNamespaceId ||
    null;
  const workerName = merged.workerName || "secure-publish";
  const baseUrl =
    process.env.SECURE_PUBLISH_BASE_URL ||
    process.env.PANEL_GATE_BASE_URL ||
    merged.baseUrl ||
    null;

  const companyDomains = parseDomains(
    process.env.SECURE_PUBLISH_COMPANY_DOMAINS ||
      process.env.OAUTH_ALLOWED_DOMAINS ||
      merged.companyDomains ||
      []
  );

  const mock =
    process.env.SECURE_PUBLISH_MOCK === "1" ||
    process.env.SECURE_PUBLISH_MOCK === "true" ||
    Boolean(merged.mock);

  return {
    accountId,
    apiToken,
    kvNamespaceId,
    workerName,
    baseUrl,
    companyDomains,
    mock,
    homeConfigPath: HOME_CONFIG,
    projectConfigPath: path.join(cwd, PROJECT_CONFIG),
  };
}

function parseDomains(v) {
  if (Array.isArray(v)) {
    return v.map((d) => String(d).trim().toLowerCase().replace(/^@/, "")).filter(Boolean);
  }
  return String(v || "")
    .split(",")
    .map((d) => d.trim().toLowerCase().replace(/^@/, ""))
    .filter(Boolean);
}

function readJsonSafe(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

export function configHints(cfg) {
  if (cfg.mock) return [];
  const missing = [];
  if (!cfg.apiToken) missing.push("CLOUDFLARE_API_TOKEN");
  if (!cfg.accountId) missing.push("CLOUDFLARE_ACCOUNT_ID");
  if (!cfg.kvNamespaceId) {
    missing.push("kvNamespaceId (config or SECURE_PUBLISH_KV_NAMESPACE_ID)");
  }
  return missing;
}
