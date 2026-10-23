/**
 * CLI login is two-step (start exits immediately; --finish polls).
 * logout keeps the file unless 2xx/401.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { main } from "../src/cli.js";

const bin = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../bin/securepublish-cli.cjs"
);

function token() {
  return "ab".repeat(32);
}

function sessionPath(dir) {
  return path.join(dir, ".secure-publish", "session.json");
}

function pendingPath(dir) {
  return path.join(dir, ".secure-publish", "device-pending.json");
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

function writePending(dir, extra = {}) {
  const sp = path.join(dir, ".secure-publish");
  fs.mkdirSync(sp, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    pendingPath(dir),
    JSON.stringify({
      device_code: "cd".repeat(32),
      user_code: "BCDF-GHJK",
      verification_url: "https://app.securepublish.work/device",
      interval: 1,
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
      apiBase: "https://app.securepublish.work",
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

function listen(server) {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", (err) => {
      if (err) reject(err);
      else resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
}

function spawnLogin(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin, ...args], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c) => {
      stdout += c;
    });
    child.stderr.on("data", (c) => {
      stderr += c;
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`login did not exit: stdout=${stdout} stderr=${stderr}`));
    }, 4000);
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

describe("CLI device login / logout", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let origExitCode;
  let origNoBrowser;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    origExitCode = process.exitCode;
    origNoBrowser = process.env.SECURE_PUBLISH_NO_BROWSER;
    process.env.HOME = tmp;
    process.env.SECURE_PUBLISH_NO_BROWSER = "1";
    process.chdir(tmp);
    process.exitCode = 0;
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    process.chdir(origCwd);
    process.env.HOME = origHome;
    if (origNoBrowser === undefined) delete process.env.SECURE_PUBLISH_NO_BROWSER;
    else process.env.SECURE_PUBLISH_NO_BROWSER = origNoBrowser;
    globalThis.fetch = origFetch;
    process.exitCode = origExitCode;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("login (start) prints user_code and URL, persists pending 0600, and does not poll", async () => {
    const device_code = "cd".repeat(32);
    const user_code = "BCDF-GHJK";
    const verification_url = "https://app.securepublish.work/device";
    let tokenHits = 0;
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.endsWith("/api/device/code")) {
        return new Response(
          JSON.stringify({
            device_code,
            user_code,
            verification_url,
            expires_in: 600,
            interval: 30,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      if (u.endsWith("/api/device/token")) {
        tokenHits += 1;
        throw new Error("start must not poll /api/device/token");
      }
      throw new Error(`unexpected fetch ${u}`);
    };

    const logs = await withIo(() => main(["login"]));
    assert.match(
      logs,
      /Para entrar nesta máquina, abra:\nhttps:\/\/app\.securepublish\.work\/device\ne digite este código:\nBCDF-GHJK/
    );
    assert.match(logs, /^https:\/\/app\.securepublish\.work\/device$/m);
    assert.match(logs, /^BCDF-GHJK$/m);
    assert.doesNotMatch(logs, /https:\/\/app\.securepublish\.work\/device[.,]/);
    assert.doesNotMatch(logs, /BCDF-GHJK[.,]/);
    assert.match(logs, /Só digite se foi você que rodou este comando agora\./);
    assert.equal(logs.includes(device_code), false);
    assert.equal(tokenHits, 0);
    assert.equal(fs.existsSync(sessionPath(tmp)), false);
    assert.ok(fs.existsSync(pendingPath(tmp)));
    assert.equal(fs.statSync(pendingPath(tmp)).mode & 0o777, 0o600);
    const pending = JSON.parse(fs.readFileSync(pendingPath(tmp), "utf8"));
    assert.equal(pending.device_code, device_code);
    assert.ok(Date.parse(pending.expiresAt) > Date.now());
    assert.equal(process.exitCode || 0, 0);
  });

  it("login flushes stdout before returning", async () => {
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.endsWith("/api/device/code")) {
        return new Response(
          JSON.stringify({
            device_code: "cd".repeat(32),
            user_code: "BCDF-GHJK",
            verification_url: "https://app.securepublish.work/device",
            expires_in: 600,
            interval: 30,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      throw new Error(`unexpected fetch ${u}`);
    };
    const origWrite = process.stdout.write.bind(process.stdout);
    const writes = [];
    process.stdout.write = (chunk, enc, cb) => {
      const callback = typeof enc === "function" ? enc : cb;
      writes.push({ text: String(chunk), hasCallback: typeof callback === "function" });
      return origWrite(chunk, enc, cb);
    };
    try {
      await withIo(() => main(["login"]));
    } finally {
      process.stdout.write = origWrite;
    }
    assert.ok(
      writes.some((w) => w.hasCallback),
      "expected stdout.write callback so the prompt is flushed before exit"
    );
  });

  it("login --lang en prints the English prompt and exits without waiting", async () => {
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.endsWith("/api/device/code")) {
        return new Response(
          JSON.stringify({
            device_code: "cd".repeat(32),
            user_code: "LMNP-QRST",
            verification_url: "https://app.securepublish.work/device",
            expires_in: 600,
            interval: 30,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      throw new Error(`unexpected fetch ${u}`);
    };
    const logs = await withIo(() => main(["login", "--lang", "en"]));
    assert.match(
      logs,
      /To sign in on this machine, open:\nhttps:\/\/app\.securepublish\.work\/device\nand enter this code:\nLMNP-QRST/
    );
    assert.match(logs, /^https:\/\/app\.securepublish\.work\/device$/m);
    assert.match(logs, /^LMNP-QRST$/m);
    assert.doesNotMatch(logs, /https:\/\/app\.securepublish\.work\/device[.,]/);
    assert.doesNotMatch(logs, /LMNP-QRST[.,]/);
    assert.match(logs, /Only enter it if you just ran this command yourself\./);
    assert.equal(fs.existsSync(sessionPath(tmp)), false);
    assert.equal(process.exitCode || 0, 0);
  });

  it("login --finish stores the session when approved", async () => {
    const device_code = "cd".repeat(32);
    writePending(tmp, { device_code, interval: 1 });
    globalThis.fetch = async (url, init) => {
      const u = String(url);
      assert.equal(u.endsWith("/api/device/token"), true);
      const body = JSON.parse(init.body);
      assert.equal(body.device_code, device_code);
      assert.equal(body.user_code, undefined);
      return new Response(
        JSON.stringify({
          access_token: token(),
          token_type: "Bearer",
          email: "ana@empresa.com",
          host: "wise.securepublish.work",
          expires_in: 43200,
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };
    const logs = await withIo(() => main(["login", "--finish"]));
    assert.match(logs, /email: ana@empresa.com/);
    assert.match(logs, /host: wise.securepublish.work/);
    assert.equal(fs.existsSync(pendingPath(tmp)), false);
    const session = JSON.parse(fs.readFileSync(sessionPath(tmp), "utf8"));
    assert.equal(session.publishToken, token());
    assert.equal(session.email, "ana@empresa.com");
    assert.equal(fs.statSync(sessionPath(tmp)).mode & 0o777, 0o600);
    assert.equal(process.exitCode || 0, 0);
    assert.doesNotMatch(
      logs,
      /app\.securepublish\.work\/app\/hosting\.html/
    );
  });

  it("login --finish with empty host stores the session and tells the user to choose an address (PT/EN)", async () => {
    const noHostPt =
      "Login feito. Falta só um passo, que você faz uma vez só: escolher o endereço da sua empresa, como suaempresa.securepublish.work. Escolha em\nhttps://app.securepublish.work/app/hosting.html\ne depois volte aqui pra publicar.";
    const noHostEn =
      "You're signed in. One step left, and you only do it once: choose your company's address, like yourcompany.securepublish.work. Choose it at\nhttps://app.securepublish.work/app/hosting.html\nthen come back here to publish.";

    const approveEmptyHost = async () => {
      writePending(tmp, { interval: 1 });
      globalThis.fetch = async () =>
        new Response(
          JSON.stringify({
            access_token: token(),
            token_type: "Bearer",
            email: "ana@empresa.com",
            host: "",
            expires_in: 43200,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
    };

    await approveEmptyHost();
    const pt = await withIo(() => main(["login", "--finish"]));
    assert.match(pt, /^host:\s*$/m);
    assert.equal(pt.includes(noHostPt), true);
    assert.doesNotMatch(pt, /https?:\/\/\S+[.,](?:\s|$)/);
    assert.equal(fs.existsSync(sessionPath(tmp)), true);
    assert.equal(process.exitCode || 0, 0);

    process.exitCode = 0;
    await approveEmptyHost();
    const en = await withIo(() => main(["login", "--finish", "--lang", "en"]));
    assert.match(en, /^host:\s*$/m);
    assert.equal(en.includes(noHostEn), true);
    assert.equal(fs.existsSync(sessionPath(tmp)), true);
  });

  it("login --finish stores whitespace-only host as null", async () => {
    writePending(tmp, { interval: 1 });
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          access_token: token(),
          token_type: "Bearer",
          email: "ana@empresa.com",
          host: "  \t  ",
          expires_in: 43200,
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    const logs = await withIo(() => main(["login", "--finish"]));
    assert.match(logs, /^host:\s*$/m);
    assert.match(logs, /app\.securepublish\.work\/app\/hosting\.html/);
    const session = JSON.parse(fs.readFileSync(sessionPath(tmp), "utf8"));
    assert.equal(session.host, null);
  });

  it("login --finish expired uses login_expired and PT/EN messages", async () => {
    writePending(tmp, { expiresAt: new Date(Date.now() - 1000).toISOString() });
    globalThis.fetch = async () => {
      throw new Error("expired pending must not poll");
    };
    const pt = await withIo(() => main(["login", "--finish"]));
    assert.match(pt, /error: login_expired/);
    assert.match(pt, /O pedido de login expirou\. Para começar de novo, rode:/);
    assert.match(pt, /\n[^\n]+ login$/);
    assert.equal(process.exitCode, 1);
    assert.equal(fs.existsSync(pendingPath(tmp)), false);

    process.exitCode = 0;
    writePending(tmp, { expiresAt: new Date(Date.now() - 1000).toISOString() });
    const en = await withIo(() => main(["login", "--finish", "--lang", "en"]));
    assert.match(en, /error: login_expired/);
    assert.match(en, /The sign-in request expired\. To start again, run:/);
    assert.equal(process.exitCode, 1);
  });

  it("login --finish denied uses login_denied", async () => {
    writePending(tmp, { interval: 1 });
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ error: "access_denied" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    const logs = await withIo(() => main(["login", "--finish"]));
    assert.match(logs, /error: login_denied/);
    assert.match(logs, /O login foi recusado no navegador\. Para tentar de novo, rode:/);
    assert.match(logs, /\n[^\n]+ login$/);
    assert.equal(process.exitCode, 1);
    assert.equal(fs.existsSync(pendingPath(tmp)), false);
    assert.equal(fs.existsSync(sessionPath(tmp)), false);

    process.exitCode = 0;
    writePending(tmp, { interval: 1 });
    const en = await withIo(() => main(["login", "--finish", "--lang", "en"]));
    assert.match(en, /error: login_denied/);
    assert.match(en, /Sign-in was denied in the browser\. To try again, run:/);
  });

  it("login --finish with no pending state uses login_no_pending", async () => {
    const logs = await withIo(() => main(["login", "--finish"]));
    assert.match(logs, /error: login_no_pending/);
    assert.match(logs, /Não tem nenhum login em andamento\. Primeiro rode:/);
    assert.match(logs, /Quando aprovar no navegador, rode:/);
    assert.equal(process.exitCode, 1);

    process.exitCode = 0;
    const en = await withIo(() => main(["login", "--finish", "--lang", "en"]));
    assert.match(en, /error: login_no_pending/);
    assert.match(en, /There's no sign-in in progress\. First run:/);
    assert.match(en, /Once you approve it in the browser, run:/);
  });

  it("login --wait keeps the old blocking start+poll behavior", async () => {
    const device_code = "cd".repeat(32);
    globalThis.fetch = async (url, init) => {
      const u = String(url);
      if (u.endsWith("/api/device/code")) {
        return new Response(
          JSON.stringify({
            device_code,
            user_code: "BCDF-GHJK",
            verification_url: "https://app.securepublish.work/device",
            expires_in: 600,
            interval: 1,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      if (u.endsWith("/api/device/token")) {
        assert.equal(JSON.parse(init.body).device_code, device_code);
        return new Response(
          JSON.stringify({
            access_token: token(),
            token_type: "Bearer",
            email: "ana@empresa.com",
            host: "wise.securepublish.work",
            expires_in: 43200,
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      throw new Error(`unexpected fetch ${u}`);
    };
    const logs = await withIo(() => main(["login", "--wait"]));
    assert.match(logs, /e digite este código:\nBCDF-GHJK/);
    assert.match(logs, /email: ana@empresa.com/);
    assert.ok(fs.existsSync(sessionPath(tmp)));
    assert.equal(fs.existsSync(pendingPath(tmp)), false);
    assert.equal(process.exitCode || 0, 0);
  });

  it("spawned login prints, flushes, and exits 0 without waiting on token", async () => {
    const device_code = "ef".repeat(32);
    const user_code = "WXYZ-ABCD";
    let tokenHits = 0;
    const server = http.createServer((req, res) => {
      const url = req.url || "";
      if (url.endsWith("/api/device/code")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            device_code,
            user_code,
            verification_url: "https://app.securepublish.work/device",
            expires_in: 600,
            interval: 30,
          })
        );
        return;
      }
      if (url.endsWith("/api/device/token")) {
        tokenHits += 1;
        return;
      }
      res.writeHead(404);
      res.end();
    });
    const apiBase = await listen(server);
    const started = Date.now();
    try {
      const r = await spawnLogin(["login"], {
        HOME: tmp,
        SECURE_PUBLISH_NO_BROWSER: "1",
        SECURE_PUBLISH_API_BASE: apiBase,
      });
      const elapsed = Date.now() - started;
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /https:\/\/app\.securepublish\.work\/device/);
      assert.match(r.stdout, /^WXYZ-ABCD$/m);
      assert.doesNotMatch(r.stdout, /WXYZ-ABCD[.,]/);
      assert.equal(r.stdout.includes(device_code), false);
      assert.ok(elapsed < 3000, `start blocked too long (${elapsed}ms)`);
      assert.equal(tokenHits, 0);
      assert.ok(fs.existsSync(pendingPath(tmp)));
      assert.equal(fs.existsSync(sessionPath(tmp)), false);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("logout 2xx deletes the file and prints success", async () => {
    writeSession(tmp);
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    const logs = await withIo(() => main(["logout"]));
    assert.match(logs, /Você saiu da conta nesta máquina/);
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
    assert.match(logs, /Você saiu da conta nesta máquina/);
    assert.equal(fs.existsSync(sessionPath(tmp)), false);
    assert.equal(process.exitCode || 0, 0);
  });

  it("logout 500 keeps the file, prints the error, and exits non-zero", async () => {
    writeSession(tmp);
    globalThis.fetch = async () => new Response("nope", { status: 500 });
    const logs = await withIo(() => main(["logout"]));
    assert.match(
      logs,
      /Não consegui sair da conta agora\. Esta máquina continua conectada\. Tente de novo em instantes\./
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
      /Não consegui sair da conta agora\. Esta máquina continua conectada\. Tente de novo em instantes\./
    );
    assert.equal(fs.existsSync(sessionPath(tmp)), true);
    assert.equal(process.exitCode, 1);
  });
});
