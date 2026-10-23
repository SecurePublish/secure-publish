/**
 * Public CLI must not call Cloudflare KV or print token/account/KV config.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main } from "../src/cli.js";

async function withIo(fn) {
  const logs = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a) => logs.push(a.map(String).join(" "));
  console.error = (...a) => logs.push(a.map(String).join(" "));
  try {
    await fn();
    return logs.join("\n");
  } finally {
    console.log = origLog;
    console.error = origErr;
  }
}

describe("public CLI has no Cloudflare KV paths", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let origToken;
  let origAccount;
  let origNs;
  let origOperator;
  let origExitCode;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-nocf-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    origToken = process.env.CLOUDFLARE_API_TOKEN;
    origAccount = process.env.CLOUDFLARE_ACCOUNT_ID;
    origNs = process.env.SECURE_PUBLISH_KV_NAMESPACE_ID;
    origOperator = process.env.SECURE_PUBLISH_OPERATOR;
    origExitCode = process.exitCode;
    delete process.env.CLOUDFLARE_API_TOKEN;
    delete process.env.CLOUDFLARE_ACCOUNT_ID;
    delete process.env.SECURE_PUBLISH_KV_NAMESPACE_ID;
    delete process.env.SECURE_PUBLISH_OPERATOR;
    process.env.HOME = tmp;
    process.chdir(tmp);
    origFetch = globalThis.fetch;
    process.exitCode = 0;
  });

  afterEach(() => {
    process.chdir(origCwd);
    process.env.HOME = origHome;
    if (origToken === undefined) delete process.env.CLOUDFLARE_API_TOKEN;
    else process.env.CLOUDFLARE_API_TOKEN = origToken;
    if (origAccount === undefined) delete process.env.CLOUDFLARE_ACCOUNT_ID;
    else process.env.CLOUDFLARE_ACCOUNT_ID = origAccount;
    if (origNs === undefined) delete process.env.SECURE_PUBLISH_KV_NAMESPACE_ID;
    else process.env.SECURE_PUBLISH_KV_NAMESPACE_ID = origNs;
    if (origOperator === undefined) delete process.env.SECURE_PUBLISH_OPERATOR;
    else process.env.SECURE_PUBLISH_OPERATOR = origOperator;
    globalThis.fetch = origFetch;
    process.exitCode = origExitCode;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("list --remote does not call Cloudflare or require a CF token", async () => {
    process.env.CLOUDFLARE_API_TOKEN = "cf-token-should-not-be-used";
    process.env.CLOUDFLARE_ACCOUNT_ID = "acct";
    process.env.SECURE_PUBLISH_KV_NAMESPACE_ID = "ns";
    globalThis.fetch = async (url) => {
      throw new Error(`fetch should not run for list --remote: ${url}`);
    };
    const out = await withIo(() => main(["list", "--remote"]));
    assert.match(out, /Local registry/);
    assert.doesNotMatch(out, /Remote KV|CLOUDFLARE|api\.cloudflare/i);
  });

  it("doctor --operator does not print Cloudflare token, account, or KV info", async () => {
    process.env.SECURE_PUBLISH_OPERATOR = "1";
    process.env.CLOUDFLARE_API_TOKEN = "cf-token-should-not-be-printed";
    process.env.CLOUDFLARE_ACCOUNT_ID = "acct";
    process.env.SECURE_PUBLISH_KV_NAMESPACE_ID = "ns";
    globalThis.fetch = async (url) => {
      throw new Error(`doctor must not verify a Cloudflare token: ${url}`);
    };
    const out = await withIo(() => main(["doctor", "--operator"]));
    assert.doesNotMatch(out, /CLOUDFLARE_API_TOKEN/);
    assert.doesNotMatch(out, /CLOUDFLARE_ACCOUNT_ID/);
    assert.doesNotMatch(out, /kvNamespaceId/);
    assert.doesNotMatch(out, /dash\.cloudflare\.com/);
    assert.doesNotMatch(out, /Workers KV/);
    assert.match(out, /ainda não entrou nesta máquina|conectado como|mock mode/i);
  });
});
