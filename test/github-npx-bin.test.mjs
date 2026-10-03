/**
 * Ensures agents can run OUR CLI via `npx github:clovistx/secure-publish`
 * (not the unrelated public npm package named secure-publish).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUR_HELP_MARKER = "secure-publish — publish AI HTML dashboards behind company SSO";
const CLI_CMD = "npx --yes github:clovistx/secure-publish";

describe("root package exposes CLI for github npx", () => {
  it("root package.json bin.secure-publish points at packages/cli", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    assert.equal(
      pkg.bin?.["secure-publish"],
      "./packages/cli/bin/secure-publish.js",
      "root must expose secure-publish bin for `npx github:clovistx/secure-publish`"
    );
    // Single bin so npx can resolve without --package name tricks
    assert.deepEqual(Object.keys(pkg.bin), ["secure-publish"]);
  });

  it("resolved bin prints our CLI help (not artelydev/secure-publish)", () => {
    const bin = path.join(root, "packages/cli/bin/secure-publish.js");
    const r = spawnSync(process.execPath, [bin, "help"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(OUR_HELP_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(r.stdout, /Secure publishing of private packages/i);
    assert.doesNotMatch(r.stdout, /dangerousRegistries|Guardian/i);
  });
});

describe("skill documents github CLI command only", () => {
  const skill = fs.readFileSync(
    path.join(root, "skills/secure-publish/SKILL.md"),
    "utf8"
  );

  it("documents the github npx command for login and publish", () => {
    assert.match(skill, new RegExp(`${CLI_CMD.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} login`));
    assert.match(
      skill,
      new RegExp(`${CLI_CMD.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} publish`)
    );
  });

  it("warns against the public npm name; never uses it as the install command", () => {
    assert.match(
      skill,
      /Do \*\*not\*\* run `npm install -g secure-publish` or `npx secure-publish`/
    );
    // No bare install/run that would hit registry artelydev/secure-publish
    assert.doesNotMatch(skill, /(?:^|\n)[^`\n]*(?:npm install -g secure-publish|npx --yes secure-publish\b|npx secure-publish\b)/);
    const runLines = skill
      .split("\n")
      .filter((l) => /^\s*(Then run|npx --yes)/.test(l) || /`(npx|secure-publish)/.test(l));
    for (const line of runLines) {
      if (/Do \*\*not\*\*|not the public npm|different project/.test(line)) continue;
      if (/\bnpx\b/.test(line) || /secure-publish login|secure-publish publish/.test(line)) {
        assert.match(
          line,
          /github:clovistx\/secure-publish/,
          `run instruction must use github install, got: ${line}`
        );
      }
    }
  });

  it("keeps user-facing Portuguese lines unchanged", () => {
    assert.match(
      skill,
      /Vou abrir o login\. Entra com a conta da empresa na página que abrir \(Google, GitHub ou Microsoft\) — a conta fica ligada nesta máquina\./
    );
    assert.match(skill, /Conta ligada\. Publicando em \{host\}, aberto pra empresa\./);
    assert.match(
      skill,
      /Quer restringir a alguém\? Passe os e-mails \(senão fica aberto pra empresa — mesmo domínio de e-mail\)\./
    );
    assert.match(skill, /Publicado pra \*\*toda a empresa\*\*: \{url\}/);
    assert.match(skill, /Publicado só para \{emails\}: \{url\}/);
    assert.match(
      skill,
      /Não consegui publicar agora\. A conta está ligada em \{host\}\. Tenta de novo em instantes\./
    );
  });

  it("does not tell the agent to say token/KV/cookie/device code/session.json", () => {
    const saySection = skill.split("## What you say")[1]?.split("## Access")[0] ?? "";
    assert.doesNotMatch(saySection, /CLOUDFLARE_API_TOKEN|KV|cookie|device code|session\.json/i);
  });
});
