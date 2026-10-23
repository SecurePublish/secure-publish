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
 *
 * Mock mode is env-only (`SECURE_PUBLISH_MOCK=1`). A `mock` key in the
 * project file is ignored (caller prints a warning).
 */
export function loadConfig(cwd = process.cwd()) {
  const home = readJsonSafe(HOME_CONFIG) || {};
  const project = readJsonSafe(path.join(cwd, PROJECT_CONFIG)) || {};
  const merged = { ...home, ...project };

  const companyDomains = parseDomains(
    process.env.SECURE_PUBLISH_COMPANY_DOMAINS ||
      process.env.OAUTH_ALLOWED_DOMAINS ||
      merged.companyDomains ||
      []
  );

  const mock =
    process.env.SECURE_PUBLISH_MOCK === "1" || process.env.SECURE_PUBLISH_MOCK === "true";

  return {
    companyDomains,
    mock,
    ignoredProjectMock: Object.prototype.hasOwnProperty.call(project, "mock"),
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
