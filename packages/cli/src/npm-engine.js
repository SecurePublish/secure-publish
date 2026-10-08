import { CliError } from "./errors.js";

export const MIN_NPM_MAJOR = 10;

/** @param {string | undefined} userAgent */
export function parseNpmMajor(userAgent = process.env.npm_config_user_agent) {
  const m = String(userAgent || "").match(/\bnpm\/(\d+)/);
  return m ? Number(m[1]) : null;
}

/**
 * npx github: on npm 9.2.0 fails during git-dep prepare (workspaces) with
 * exit 1 and no output — our bin never starts. When the bin does run under
 * npm 9 (e.g. `npm exec --package github:… -- securepublish-cli`), fail clearly.
 */
export function assertNpmEngine(userAgent = process.env.npm_config_user_agent) {
  const major = parseNpmMajor(userAgent);
  if (major == null || major >= MIN_NPM_MAJOR) return;
  throw new CliError(
    "npm_engine",
    `Secure Publish requires npm 10 or newer (detected npm ${major}). npm 9 cannot run \`npx --yes github:clovistx/secure-publish\` — git install exits 1 with no output. Upgrade: npm i -g npm@10`
  );
}
