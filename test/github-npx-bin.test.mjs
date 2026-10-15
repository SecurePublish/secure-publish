/**
 * Ensures agents can run OUR CLI via `npx github:SecurePublish/secure-publish`
 * (not the unrelated public npm package named secure-publish).
 * The binary exposed by that install is `securepublish-cli` only.
 * npx does not leave that bin on PATH — docs must use the full npx form.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN_NAME = "securepublish-cli";
const BIN_REL = `./packages/cli/bin/${BIN_NAME}.cjs`;
const OUR_HELP_MARKER = `${BIN_NAME} — publish AI HTML dashboards behind company SSO`;
const GITHUB_NPX = "npx --yes github:SecurePublish/secure-publish";
const GITHUB_NPX_RE = GITHUB_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const GITHUB_HTTPS = "https://github.com/SecurePublish/secure-publish";

/** Bare `securepublish-cli <sub>` as a runnable line (not prose about the bin name). */
const BARE_CLI_RUN =
  /(?:^|\n)\s*(?:`)?securepublish-cli\s+(?:login|publish|logout|list|revoke|doctor|mock-serve|help)\b/;

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
    // workspaces makes npm 9.2 npx github: run `npx-cli.js install --force`
    // (silent exit 1). Do not add it back.
    assert.equal(pkg.workspaces, undefined);
    assert.match(String(pkg.engines?.node || ""), />=20/);
  });

  it("packages/cli exposes the same single bin name (no sp / secure-publish alias)", () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(root, "packages/cli/package.json"), "utf8")
    );
    assert.equal(pkg.name, BIN_NAME);
    assert.deepEqual(Object.keys(pkg.bin || {}), [BIN_NAME]);
    assert.equal(pkg.bin[BIN_NAME], `./bin/${BIN_NAME}.cjs`);
    assert.match(String(pkg.engines?.node || ""), />=20/);
  });

  it("resolved bin prints our CLI help (not artelydev/secure-publish)", () => {
    const bin = path.join(root, "packages/cli/bin", `${BIN_NAME}.cjs`);
    const r = spawnSync(process.execPath, [bin, "help"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(OUR_HELP_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(r.stdout, /Secure publishing of private packages/i);
    assert.doesNotMatch(r.stdout, /dangerousRegistries|Guardian/i);
    assert.doesNotMatch(r.stdout, /\bsp\b/);
    assert.doesNotMatch(r.stdout, /Usage:\s*secure-publish\b/);
  });
});

describe("skill documents github npx invocations only", () => {
  const skill = fs.readFileSync(
    path.join(root, "skills/secure-publish/SKILL.md"),
    "utf8"
  );

  it("documents full npx github: form for login and publish", () => {
    assert.match(skill, new RegExp(`${GITHUB_NPX_RE} login`));
    assert.match(skill, new RegExp(`${GITHUB_NPX_RE} publish`));
  });

  it("never documents bare securepublish-cli <subcommand> as a runnable command", () => {
    assert.doesNotMatch(
      skill,
      BARE_CLI_RUN,
      "skill must not tell agents to run bare securepublish-cli (npx does not leave it on PATH)"
    );
  });

  it("documents github npx install; warns against the public npm name", () => {
    assert.match(skill, new RegExp(GITHUB_NPX_RE));
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
      /Vou abrir o login\. Na página que abrir, entre com a conta da empresa e digite o código \{user_code\}\./
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

  it("documents Node 22 LTS in Requisitos", () => {
    assert.match(skill, /## Requisitos/);
    assert.match(skill, /Node 22 LTS/);
    assert.match(skill, /`node -v`/);
    assert.match(skill, /nodejs\.org/);
    assert.match(skill, new RegExp(GITHUB_HTTPS.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });
});

describe("README documents github npx invocations", () => {
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");

  it("uses full npx github: form for runnable CLI examples", () => {
    assert.match(readme, new RegExp(`${GITHUB_NPX_RE} publish`));
    assert.match(readme, new RegExp(`${GITHUB_NPX_RE} list`));
    assert.match(readme, new RegExp(`${GITHUB_NPX_RE} doctor`));
    assert.doesNotMatch(
      readme,
      BARE_CLI_RUN,
      "README must not document bare securepublish-cli <subcommand> without npx github:"
    );
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

  it("documents Node 22 LTS in Requisitos", () => {
    assert.match(readme, /## Requisitos/);
    assert.match(readme, /Node 22 LTS/);
    assert.match(readme, /`node -v`/);
    assert.match(readme, /nodejs\.org/);
    assert.match(readme, new RegExp(GITHUB_HTTPS.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });
});

describe("repo identity is SecurePublish/secure-publish", () => {
  const skip = new Set(["node_modules", ".git"]);
  const hits = [];

  function walk(dir) {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (skip.has(ent.name)) continue;
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(p);
        continue;
      }
      const rel = path.relative(root, p);
      // This file names the forbidden strings in the assertion.
      if (rel === "test/github-npx-bin.test.mjs") continue;
      const text = fs.readFileSync(p, "utf8");
      if (/clovistx/i.test(text) || /wises\.com\.br/i.test(text)) {
        hits.push(rel);
      }
    }
  }

  it("has zero clovistx or wises.com.br references", () => {
    walk(root);
    assert.deepEqual(hits, []);
  });

  it("package.json repository/homepage/bugs point at SecurePublish/secure-publish", () => {
    for (const rel of ["package.json", "packages/cli/package.json"]) {
      const pkg = JSON.parse(fs.readFileSync(path.join(root, rel), "utf8"));
      assert.match(pkg.repository.url, /github\.com\/SecurePublish\/secure-publish/);
      assert.equal(pkg.homepage, GITHUB_HTTPS);
      assert.equal(pkg.bugs.url, `${GITHUB_HTTPS}/issues`);
    }
  });
});
