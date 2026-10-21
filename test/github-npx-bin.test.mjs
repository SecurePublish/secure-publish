/**
 * Ensures agents can run OUR CLI via `npx --yes @securepublish/cli@1.0.4`
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
const PKG_NAME = "@securepublish/cli";
const PKG_VERSION = "1.0.4";
const BIN_REL = `packages/cli/bin/${BIN_NAME}.cjs`;
const OUR_HELP_MARKER = `${BIN_NAME} — publish AI HTML dashboards behind company SSO`;
const NPM_NPX = `npx --yes ${PKG_NAME}@${PKG_VERSION}`;
const NPM_NPX_RE = NPM_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const GITHUB_HTTPS = "https://github.com/SecurePublish/secure-publish";
const NPM_REPO_URL = "git+https://github.com/SecurePublish/secure-publish.git";
const GITHUB_CLI_NPX = "npx --yes github:SecurePublish/secure-publish";

/** Bare `securepublish-cli <sub>` as a runnable line (not prose about the bin name). */
const BARE_CLI_RUN =
  /(?:^|\n)\s*(?:`)?securepublish-cli\s+(?:login|publish|logout|list|revoke|doctor|mock-serve|help)\b/;

describe("root package exposes CLI for npm", () => {
  it(`root package.json is ${PKG_NAME} with ${BIN_NAME} bin`, () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    assert.equal(pkg.name, PKG_NAME);
    assert.equal(pkg.version, PKG_VERSION);
    assert.notEqual(pkg.private, true);
    assert.equal(
      pkg.bin?.[BIN_NAME],
      BIN_REL,
      `root must expose ${BIN_NAME} bin for \`${NPM_NPX}\``
    );
    // Single bin so npx can resolve without --package name tricks
    assert.deepEqual(Object.keys(pkg.bin), [BIN_NAME]);
    // workspaces makes npm 9.2 npx github: run `npx-cli.js install --force`
    // (silent exit 1). Do not add it back.
    assert.equal(pkg.workspaces, undefined);
    assert.match(String(pkg.engines?.node || ""), />=20/);
    assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0, "files list required for npm pack");
    assert.ok(pkg.files.some((f) => String(f).includes("packages/cli/bin")));
    assert.ok(pkg.files.some((f) => String(f).includes("packages/cli/src")));
    assert.deepEqual(pkg.publishConfig, { access: "public", provenance: true });
    assert.equal(pkg.repository.url, NPM_REPO_URL);
  });

  it("packages/cli exposes the same scoped name and single bin (no sp / secure-publish alias)", () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(root, "packages/cli/package.json"), "utf8")
    );
    assert.equal(pkg.name, PKG_NAME);
    assert.equal(pkg.version, PKG_VERSION);
    assert.deepEqual(Object.keys(pkg.bin || {}), [BIN_NAME]);
    assert.equal(pkg.bin[BIN_NAME], `./bin/${BIN_NAME}.cjs`);
    assert.match(String(pkg.engines?.node || ""), />=20/);
    assert.equal(pkg.repository.url, NPM_REPO_URL);
    const keywords = pkg.keywords || [];
    assert.equal(keywords.includes("cloudflare"), false);
    assert.equal(keywords.includes("kv"), false);
  });

  it("does not ship Cloudflare KV helpers in the public package", async () => {
    const mod = await import(path.join(root, "packages/cli/src/index.js"));
    for (const name of ["kvPut", "kvDelete", "kvGet", "kvList", "verifyToken"]) {
      assert.equal(name in mod, false, `public entry must not export ${name}`);
    }
    const indexSrc = fs.readFileSync(path.join(root, "packages/cli/src/index.js"), "utf8");
    assert.doesNotMatch(indexSrc, /\bkv(Put|Delete|Get|List)\b/);
    assert.equal(fs.existsSync(path.join(root, "packages/cli/src/cf-api.js")), false);
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
    assert.doesNotMatch(r.stdout, /CLOUDFLARE_API_TOKEN|CLOUDFLARE_ACCOUNT_ID|kvNamespaceId/);
    assert.doesNotMatch(r.stdout, /api\.cloudflare\.com/);
  });
});

describe("skill documents npm package invocations only", () => {
  const skill = fs.readFileSync(
    path.join(root, "skills/secure-publish/SKILL.md"),
    "utf8"
  );

  it("documents full npx @securepublish/cli@1.0.4 form for login and publish", () => {
    assert.match(skill, new RegExp(`${NPM_NPX_RE} login`));
    assert.match(skill, new RegExp(`${NPM_NPX_RE} login --finish`));
    assert.match(skill, new RegExp(`${NPM_NPX_RE} publish`));
    assert.match(skill, new RegExp(`${NPM_NPX_RE} revoke`));
  });

  it("tells the agent to show the code in its own message and skip output wrappers", () => {
    const saySection = skill.split("## What you say")[1]?.split("## Access")[0] ?? "";
    assert.match(saySection, /your own message/i);
    assert.match(saySection, /output-condensing filter or wrapper/i);
    assert.match(saySection, /rtk/i);
    assert.match(saySection, /login --finish/);
  });

  it("never documents github: CLI invocations or bare securepublish-cli <subcommand>", () => {
    assert.doesNotMatch(
      skill,
      new RegExp(GITHUB_CLI_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    );
    assert.doesNotMatch(
      skill,
      BARE_CLI_RUN,
      "skill must not tell agents to run bare securepublish-cli (npx does not leave it on PATH)"
    );
  });

  it("documents npm install; warns against the public npm name secure-publish", () => {
    assert.match(skill, new RegExp(NPM_NPX_RE));
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

  it("describes publish size in plain language without endpoints, env vars, or byte math", () => {
    assert.match(skill, /limite de tamanho por publicação definido pelo serviço/);
    assert.match(skill, /CLI para antes de enviar e diz o que fazer/);
    assert.doesNotMatch(skill, /SECUREPUBLISH_MAX_UPLOAD_BYTES/);
    assert.doesNotMatch(skill, /3145728/);
    assert.doesNotMatch(skill, /GET \/api\/limits/);
    assert.doesNotMatch(skill, /3 \* 1024 \* 1024/);
  });

  it("opens with a trust block (operator, data, install links, code login, security page)", () => {
    const afterFront = skill.replace(/^---[\s\S]*?---\s*/, "");
    const top = afterFront.slice(0, 2500);
    assert.match(top, /Quem opera e para onde vão os dados/);
    assert.match(top, /O Secure Publish é operado por SecurePublish/);
    assert.match(top, /Antes de instalar/);
    assert.match(top, /https:\/\/securepublish\.work\/skill\.md/);
    assert.match(top, /https:\/\/securepublish\.work\/cli/);
    assert.match(top, /https:\/\/www\.npmjs\.com\/package\/@securepublish\/cli/);
    assert.match(top, /unpkg\.com\/browse\/@securepublish\/cli@1\.0\.4/);
    assert.match(top, /Sobre o login por código/);
    assert.match(
      top,
      /O código aparece no seu próprio terminal; digite só em app\.securepublish\.work\/device, depois de entrar com sua conta/
    );
    assert.match(top, /Nunca pedimos esse código por e-mail, chat ou telefone/);
    assert.match(top, /Se alguém te mandar um código, não digite/);
    assert.match(top, /https:\/\/securepublish\.work\/security/);
    assert.match(top, /https:\/\/securepublish\.work\/pt\/seguranca/);
    assert.doesNotMatch(top, /100% seguro/);
    assert.doesNotMatch(top, /\bGoogle\b|\bMicrosoft\b|Cloudflare Access|Entra/);
    assert.doesNotMatch(top, /backup/i);
    assert.doesNotMatch(top, /[A-Za-z0-9._%+-]+@securepublish\.work/);
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

describe("README documents npm package invocations", () => {
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");

  it("uses full npx @securepublish/cli@1.0.4 form for runnable CLI examples", () => {
    assert.match(readme, new RegExp(`${NPM_NPX_RE} login`));
    assert.match(readme, new RegExp(`${NPM_NPX_RE} login --finish`));
    assert.match(readme, new RegExp(`${NPM_NPX_RE} publish`));
    assert.match(readme, new RegExp(`${NPM_NPX_RE} list`));
    assert.match(readme, new RegExp(`${NPM_NPX_RE} doctor`));
    assert.match(readme, new RegExp(`${NPM_NPX_RE} revoke`));
    assert.doesNotMatch(
      readme,
      new RegExp(GITHUB_CLI_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    );
    assert.doesNotMatch(
      readme,
      BARE_CLI_RUN,
      "README must not document bare securepublish-cli <subcommand> without npx @securepublish/cli"
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

  it("describes publish size in plain language without endpoints, env vars, or byte math", () => {
    assert.match(
      readme,
      /publishes an HTML file\. By default, anyone with an email on your company domain can open it/
    );
    assert.match(readme, /per-publish size limit set by the service/);
    assert.match(readme, /If the file is too large, the CLI stops before sending and says what to do/);
    assert.doesNotMatch(readme, /SECUREPUBLISH_MAX_UPLOAD_BYTES/);
    assert.doesNotMatch(readme, /3145728/);
    assert.doesNotMatch(readme, /GET \/api\/limits/);
    assert.doesNotMatch(readme, /3 \* 1024 \* 1024/);
  });

  it("opens with a trust block (operator, data, install links, code login, security page)", () => {
    const top = readme.slice(0, 2800);
    assert.match(top, /Who operates this and where the data goes/);
    assert.match(top, /Secure Publish is operated by SecurePublish/);
    assert.match(top, /Before you install/);
    assert.match(top, /https:\/\/securepublish\.work\/skill\.md/);
    assert.match(top, /https:\/\/securepublish\.work\/cli/);
    assert.match(top, /https:\/\/www\.npmjs\.com\/package\/@securepublish\/cli/);
    assert.match(top, /unpkg\.com\/browse\/@securepublish\/cli@1\.0\.4/);
    assert.match(top, /About code sign-in/);
    assert.match(
      top,
      /The code appears in your own terminal; type it only at app\.securepublish\.work\/device, after you sign in with your account/
    );
    assert.match(top, /We never ask for this code by email, chat, or phone/);
    assert.match(top, /If someone sends you a code, do not type it/);
    assert.match(top, /https:\/\/securepublish\.work\/security/);
    assert.match(top, /https:\/\/securepublish\.work\/pt\/seguranca/);
    assert.doesNotMatch(readme, /100% safe|100% seguro/);
    assert.doesNotMatch(top, /backup/i);
  });

  it("documents Node 22 LTS in Requisitos", () => {
    assert.match(readme, /## Requisitos/);
    assert.match(readme, /Node 22 LTS/);
    assert.match(readme, /`node -v`/);
    assert.match(readme, /nodejs\.org/);
    assert.match(readme, new RegExp(GITHUB_HTTPS.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });
});

describe("npm publish workflow uses Trusted Publishing (OIDC)", () => {
  const workflowDir = path.join(root, ".github/workflows");
  const workflowPath = path.join(workflowDir, "publish.yml");
  const workflow = fs.readFileSync(workflowPath, "utf8");

  it("is named publish.yml (npm Trusted Publisher requires this exact filename)", () => {
    const names = fs.readdirSync(workflowDir);
    assert.ok(names.includes("publish.yml"));
    assert.deepEqual(
      names.filter((n) => /^publish\.(yml|yaml)$/i.test(n)),
      ["publish.yml"]
    );
  });

  it("triggers on release published and v* tags, with OIDC permissions", () => {
    assert.match(workflow, /release:/);
    assert.match(workflow, /types:\s*\n\s*-\s*published/);
    assert.match(workflow, /tags:\s*\n\s*-\s*"v\*"/);
    assert.match(workflow, /contents:\s*read/);
    assert.match(workflow, /id-token:\s*write/);
    assert.match(workflow, /node-version:\s*"22"/);
    assert.match(workflow, /registry-url:\s*"https:\/\/registry\.npmjs\.org"/);
    assert.match(workflow, /npm ci/);
    assert.match(workflow, /npm test/);
    assert.match(workflow, /npm publish --provenance --access public/);
  });

  it("verifies the git tag matches package.json version before publish", () => {
    assert.match(workflow, /Verify tag matches package\.json version/);
    assert.match(workflow, /require\('\.\/package\.json'\)\.version/);
    assert.match(workflow, /github\.event\.release\.tag_name/);
    assert.match(workflow, /GITHUB_REF_NAME/);
    assert.match(workflow, /v\$\{VERSION\}/);
  });

  it("does not commit tokens or secret references", () => {
    assert.doesNotMatch(workflow, /\$\{\{\s*secrets\./);
    assert.doesNotMatch(workflow, /NPM_TOKEN\s*:/);
    assert.doesNotMatch(workflow, /NODE_AUTH_TOKEN\s*:/);
    assert.match(workflow, /NODE_AUTH_TOKEN/);
  });

  it("emits SKILL.md with version + sha256 header as a release artifact", () => {
    assert.match(workflow, /sha256/i);
    assert.match(workflow, /skills\/secure-publish\/SKILL\.md/);
    assert.match(workflow, /actions\/upload-artifact@v4/);
    assert.match(workflow, /skill-md|SKILL\.md/);
    assert.match(workflow, /require\('\.\/package\.json'\)\.version/);
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
