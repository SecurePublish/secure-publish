/**
 * Ensures agents can run OUR CLI via `npx github:clovistx/secure-publish`
 * (not the unrelated public npm package named secure-publish).
 * The binary exposed by that install is `securepublish-cli` only.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN_NAME = "securepublish-cli";
const BIN_REL = `./packages/cli/bin/${BIN_NAME}.js`;
const OUR_HELP_MARKER = `${BIN_NAME} — publish AI HTML dashboards behind company SSO`;
const GITHUB_NPX = "npx --yes github:clovistx/secure-publish";

describe("root package exposes CLI for github npx", () => {
  it(`root package.json bin.${BIN_NAME} points at packages/cli`, () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    assert.equal(
      pkg.bin?.[BIN_NAME],
      BIN_REL,
      `root must expose ${BIN_NAME} bin for \`${GITHUB_NPX}\``
    );
    // Single bin so npx can resolve without --package name tricks
    assert.deepEqual(Object.keys(pkg.bin), [BIN_NAME]);
  });

  it("packages/cli exposes the same single bin name (no sp / secure-publish alias)", () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(root, "packages/cli/package.json"), "utf8")
    );
    assert.equal(pkg.name, BIN_NAME);
    assert.deepEqual(Object.keys(pkg.bin || {}), [BIN_NAME]);
    assert.equal(pkg.bin[BIN_NAME], `./bin/${BIN_NAME}.js`);
  });

  it("resolved bin prints our CLI help (not artelydev/secure-publish)", () => {
    const bin = path.join(root, "packages/cli/bin", `${BIN_NAME}.js`);
    const r = spawnSync(process.execPath, [bin, "help"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(OUR_HELP_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(r.stdout, /Secure publishing of private packages/i);
    assert.doesNotMatch(r.stdout, /dangerousRegistries|Guardian/i);
    assert.doesNotMatch(r.stdout, /\bsp\b/);
    assert.doesNotMatch(r.stdout, /Usage:\s*secure-publish\b/);
  });
});

describe("skill documents securepublish-cli", () => {
  const skill = fs.readFileSync(
    path.join(root, "skills/secure-publish/SKILL.md"),
    "utf8"
  );

  it("documents securepublish-cli for login and publish", () => {
    assert.match(skill, new RegExp(`${BIN_NAME} login`));
    assert.match(skill, new RegExp(`${BIN_NAME} publish`));
  });

  it("documents github npx install; warns against the public npm name", () => {
    assert.match(skill, new RegExp(GITHUB_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(
      skill,
      /Do \*\*not\*\* run `npm install secure-publish`.*`npx secure-publish`/
    );
    // No bare install/run that would hit registry artelydev/secure-publish
    assert.doesNotMatch(
      skill,
      /(?:^|\n)[^`\n]*(?:npm install(?: -g)? secure-publish|npx --yes secure-publish\b|npx secure-publish\b)/
    );
  });

  it("keeps user-facing Portuguese lines unchanged", () => {
    assert.match(
      skill,
      /Vou abrir o login\. Entra com Google na página que abrir — a conta fica ligada nesta máquina\./
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

describe("README documents securepublish-cli", () => {
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");

  it("uses securepublish-cli in CLI examples", () => {
    assert.match(readme, new RegExp(`${BIN_NAME} publish`));
    assert.match(readme, new RegExp(`${BIN_NAME} list`));
    assert.match(readme, new RegExp(`${BIN_NAME} doctor`));
    assert.match(readme, new RegExp(GITHUB_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(readme, /(?:^|\n)\s*secure-publish publish\b/);
    assert.doesNotMatch(readme, /(?:^|\n)\s*sp\s+publish\b/);
    // Warn against the public npm name; never instruct installing/running it
    assert.match(readme, /Do \*\*not\*\*.*`npm install secure-publish`.*`npx secure-publish`/);
    const instructLines = readme
      .split("\n")
      .filter(
        (l) =>
          /^\s*(npm install(?: -g)? secure-publish|npx(?: --yes)? secure-publish)\b/.test(l) ||
          /`(npm install(?: -g)? secure-publish|npx(?: --yes)? secure-publish)`/.test(l)
      );
    for (const line of instructLines) {
      assert.match(
        line,
        /Do \*\*not\*\*|unrelated public package|not the public npm|different project/,
        `must not instruct installing public npm package, got: ${line}`
      );
    }
  });
});
