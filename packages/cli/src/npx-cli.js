/** Runnable prefix — npx does not leave `securepublish-cli` on PATH. */
export const NPX_CLI = "npx --yes github:clovistx/secure-publish";

/** @param {string} [rest] subcommand and args */
export function npxCmd(rest = "") {
  const tail = String(rest || "").trim();
  return tail ? `${NPX_CLI} ${tail}` : NPX_CLI;
}
