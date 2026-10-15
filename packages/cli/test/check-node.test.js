import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const require = createRequire(import.meta.url);
const { checkNode, MIN_NODE_MAJOR } = require("../src/check-node.cjs");
const bin = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../bin/securepublish-cli.cjs"
);

describe("Node engines check", () => {
  it("accepts Node 20 and 22", () => {
    assert.equal(MIN_NODE_MAJOR, 20);
    assert.equal(checkNode("20.20.2").ok, true);
    assert.equal(checkNode("v22.23.3").ok, true);
  });

  it("rejects older Node with PT and EN lines", () => {
    const r = checkNode("16.20.2");
    assert.equal(r.ok, false);
    assert.match(r.pt, /Node\.js 20 ou mais novo/);
    assert.match(r.pt, /v16\.20\.2/);
    assert.match(r.pt, /node -v/);
    assert.match(r.en, /Node\.js 20 or newer/);
    assert.match(r.en, /v16\.20\.2/);
    assert.match(r.en, /Node 22 LTS/);
  });

  it("bin prints the bilingual message and exits 1 when Node is too old", () => {
    const script = `
      Object.defineProperty(process.versions, "node", { value: "18.20.8" });
      require(${JSON.stringify(bin)});
    `;
    const r = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /Este CLI precisa de Node\.js 20 ou mais novo/);
    assert.match(r.stderr, /This CLI requires Node\.js 20 or newer/);
    assert.match(r.stderr, /v18\.20\.8/);
    assert.equal(r.stdout, "");
  });
});
