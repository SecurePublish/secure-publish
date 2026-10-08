/**
 * CLI login prints user_code + URL; logout keeps the file unless 2xx/401.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main } from "../src/cli.js";

function token() {
  return "ab".repeat(32);
}

function sessionPath(dir) {
  return path.join(dir, ".secure-publish", "session.json");
}

function writeSession(dir, extra = {}) {
  const sp = path.join(dir, ".secure-publish");
  fs.mkdirSync(sp, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    sessionPath(dir),
    JSON.stringify({
      publishToken: token(),
      email: "dev@localhost",
      host: "wise.securepublish.work",
      apiBase: "https://app.securepublish.work",
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      ...extra,
    }) + "\n",
    { mode: 0o600 }
  );
}

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

describe("CLI device login / logout", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let origExitCode;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    origExitCode = process.exitCode;
    process.env.HOME = tmp;
    process.chdir(tmp);
    process.exitCode = 0;
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    process.chdir(origCwd);
    process.env.HOME = origHome;
    globalThis.fetch = origFetch;
    process.exitCode = origExitCode;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("login prints user_code and URL with no codes in the URL", async () => {
    const device_code = "cd".repeat(32);
    const user_code = "BCDF-GHJK";
    const verification_url = "https://app.securepublish.work/device";
    globalThis.fetch = async (url, init) => {
      const u = String(url);
      if (u.endsWith("/api/device/code")) {
        return new Response(
          JSON.stringify({
            device_code,
            user_code,
            verification_url,
            expires_in: 600,
            interval: 1,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      if (u.endsWith("/api/device/token")) {
        const body = JSON.parse(init.body);
        assert.equal(body.device_code, device_code);
        assert.equal(body.user_code, undefined);
        return new Response(
          JSON.stringify({
            access_token: token(),
            token_type: "Bearer",
            email: "ana@wises.com.br",
            host: "wise.securepublish.work",
            expires_in: 43200,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      throw new Error(`unexpected fetch ${u}`);
    };

    const logs = await withIo(() => main(["login"]));
    assert.match(
      logs,
      /Pra ligar este computador à sua conta, abra https:\/\/app\.securepublish\.work\/device e digite o código BCDF-GHJK\./
    );
    assert.match(logs, /Só digite se foi você que rodou este comando agora\./);
    assert.equal(logs.includes(device_code), false);
    assert.ok(fs.existsSync(sessionPath(tmp)));
  });

  it("login --lang en prints the English prompt", async () => {
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.endsWith("/api/device/code")) {
        return new Response(
          JSON.stringify({
            device_code: "cd".repeat(32),
            user_code: "LMNP-QRST",
            verification_url: "https://app.securepublish.work/device",
            expires_in: 600,
            interval: 1,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      return new Response(
        JSON.stringify({
          access_token: token(),
          token_type: "Bearer",
          email: "ana@wises.com.br",
          host: "wise.securepublish.work",
          expires_in: 43200,
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };
    const logs = await withIo(() => main(["login", "--lang", "en"]));
    assert.match(
      logs,
      /To connect this computer to your account, open https:\/\/app\.securepublish\.work\/device and enter the code LMNP-QRST\./
    );
    assert.match(logs, /Only enter it if you just ran this command yourself\./);
  });

  it("logout 2xx deletes the file and prints success", async () => {
    writeSession(tmp);
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    const logs = await withIo(() => main(["logout"]));
    assert.match(logs, /Conta desligada nesta máquina/);
    assert.equal(fs.existsSync(sessionPath(tmp)), false);
    assert.equal(process.exitCode || 0, 0);
  });

  it("logout 401 deletes the file and prints success", async () => {
    writeSession(tmp);
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    const logs = await withIo(() => main(["logout"]));
    assert.match(logs, /Conta desligada nesta máquina/);
    assert.equal(fs.existsSync(sessionPath(tmp)), false);
    assert.equal(process.exitCode || 0, 0);
  });

  it("logout 500 keeps the file, prints the error, and exits non-zero", async () => {
    writeSession(tmp);
    globalThis.fetch = async () => new Response("nope", { status: 500 });
    const logs = await withIo(() => main(["logout"]));
    assert.match(
      logs,
      /Não consegui desligar a conta agora\. Ela continua ligada nesta máquina\. Tente de novo em instantes\./
    );
    assert.equal(fs.existsSync(sessionPath(tmp)), true);
    assert.equal(process.exitCode, 1);
  });

  it("logout network error keeps the file and prints the error", async () => {
    writeSession(tmp);
    globalThis.fetch = async () => {
      throw new Error("ECONNRESET");
    };
    const logs = await withIo(() => main(["logout"]));
    assert.match(
      logs,
      /Não consegui desligar a conta agora\. Ela continua ligada nesta máquina\. Tente de novo em instantes\./
    );
    assert.equal(fs.existsSync(sessionPath(tmp)), true);
    assert.equal(process.exitCode, 1);
  });
});
