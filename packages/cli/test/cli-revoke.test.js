/**
 * CLI revoke: DELETE /api/panels/:id with the device session (not CF KV).
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main, parsePanelRef } from "../src/cli.js";
import { NPX_CLI } from "../src/messages.js";
import { mockPut, mockGet } from "../src/mock-store.js";

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

function writeRegistry(dir, panels) {
  const sp = path.join(dir, ".secure-publish");
  fs.mkdirSync(sp, { recursive: true });
  fs.writeFileSync(
    path.join(sp, "registry.json"),
    JSON.stringify({ panels }, null, 2) + "\n"
  );
}

function readRegistry(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, ".secure-publish", "registry.json"), "utf8"));
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

describe("parsePanelRef", () => {
  it("extracts the first path segment from a published URL", () => {
    assert.equal(
      parsePanelRef("https://wise.securepublish.work/k7f3qx2abc/performance-out-26"),
      "k7f3qx2abc"
    );
    assert.equal(parsePanelRef("https://wise.securepublish.work/k7f3qx2abc"), "k7f3qx2abc");
    assert.equal(
      parsePanelRef("https://wise.securepublish.work/k7f3qx2abc/old-name?x=1"),
      "k7f3qx2abc"
    );
  });

  it("accepts a bare id or a path", () => {
    assert.equal(parsePanelRef("k7f3qx2abc"), "k7f3qx2abc");
    assert.equal(parsePanelRef("/k7f3qx2abc/performance-out-26"), "k7f3qx2abc");
    assert.equal(parsePanelRef(""), "");
    assert.equal(parsePanelRef("   "), "");
  });
});

describe("CLI revoke via session DELETE", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let origToken;
  let origAccount;
  let origNs;
  let calls;
  const panelId = "k7f3qx2abc";

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-revoke-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    origToken = process.env.CLOUDFLARE_API_TOKEN;
    origAccount = process.env.CLOUDFLARE_ACCOUNT_ID;
    origNs = process.env.SECURE_PUBLISH_KV_NAMESPACE_ID;
    delete process.env.CLOUDFLARE_API_TOKEN;
    delete process.env.CLOUDFLARE_ACCOUNT_ID;
    delete process.env.SECURE_PUBLISH_KV_NAMESPACE_ID;
    process.env.HOME = tmp;
    process.chdir(tmp);
    writeSession(tmp);
    writeRegistry(tmp, [
      {
        key: panelId,
        title: "Painel",
        url: `https://wise.securepublish.work/${panelId}/performance-out-26`,
      },
    ]);
    calls = [];
    origFetch = globalThis.fetch;
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
    globalThis.fetch = origFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function mockDeleteResponse(status, body) {
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    };
  }

  it("200 DELETEs the id with the session token and drops the local registry entry", async () => {
    mockDeleteResponse(200, { ok: true });
    const out = await withIo(() => main(["revoke", panelId]));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://app.securepublish.work/api/panels/${panelId}`);
    assert.equal(calls[0].init.method, "DELETE");
    assert.equal(calls[0].init.headers.authorization, `Bearer ${token()}`);
    assert.match(out, new RegExp(`Removed ${panelId}\\.`));
    assert.deepEqual(readRegistry(tmp).panels, []);
    assert.equal(fs.existsSync(sessionPath(tmp)), true);
  });

  it("extracts the panel id from a full published URL", async () => {
    mockDeleteResponse(200, { ok: true });
    await withIo(() =>
      main(["revoke", `https://wise.securepublish.work/${panelId}/performance-out-26`])
    );
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://app.securepublish.work/api/panels/${panelId}`);
    assert.equal(calls[0].init.method, "DELETE");
    assert.deepEqual(readRegistry(tmp).panels, []);
  });

  it("401 tells the user to run login and does not touch the registry", async () => {
    mockDeleteResponse(401, { error: "unauthorized" });
    await assert.rejects(
      () => main(["revoke", panelId]),
      /Sua sessão expirou ou foi encerrada\. Para entrar de novo, rode:\n[^\n]+ login$/
    );
    assert.equal(fs.existsSync(sessionPath(tmp)), false);
    assert.equal(readRegistry(tmp).panels[0].key, panelId);
  });

  it("403 keeps the panel and prints the owner-only message", async () => {
    mockDeleteResponse(403, { error: "forbidden" });
    await assert.rejects(
      () => main(["revoke", panelId]),
      /só quem publicou este link ou o dono da conta da empresa pode removê-lo/
    );
    assert.equal(fs.existsSync(sessionPath(tmp)), true);
    assert.equal(readRegistry(tmp).panels[0].key, panelId);
  });

  it("404 treats the link as already removed and drops the local registry entry", async () => {
    mockDeleteResponse(404, { error: "not_found" });
    const out = await withIo(() => main(["revoke", panelId]));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].init.method, "DELETE");
    assert.match(out, new RegExp(`Removed ${panelId}\\.`));
    assert.deepEqual(readRegistry(tmp).panels, []);
  });

  it("network error does not touch the registry", async () => {
    globalThis.fetch = async () => {
      throw new Error("ECONNRESET");
    };
    await assert.rejects(
      () => main(["revoke", panelId]),
      /Não consegui falar com o Secure Publish\. Verifique a conexão e tente de novo\./
    );
    assert.equal(readRegistry(tmp).panels[0].key, panelId);
  });

  it("without a session asks to run login and does not fetch", async () => {
    fs.rmSync(sessionPath(tmp));
    globalThis.fetch = async () => {
      throw new Error("fetch should not run");
    };
    await assert.rejects(
      () => main(["revoke", panelId]),
      /Você ainda não entrou nesta máquina\. Para entrar, rode:\n[^\n]+ login$/
    );
  });

  it("usage when the id is missing", async () => {
    await assert.rejects(
      () => main(["revoke"]),
      (e) => {
        assert.equal(e.message, `Usage: ${NPX_CLI} revoke <id-or-url>`);
        return true;
      }
    );
  });

  it("mock mode deletes locally without calling the API or needing Cloudflare credentials", async () => {
    const origMock = process.env.SECURE_PUBLISH_MOCK;
    process.env.SECURE_PUBLISH_MOCK = "1";
    mockPut(panelId, { v: 1, html: "<p>x</p>", access: { mode: "company", domains: [] } });
    globalThis.fetch = async () => {
      throw new Error("fetch should not run in mock mode");
    };
    let out;
    try {
      out = await withIo(() => main(["revoke", panelId]));
    } finally {
      if (origMock === undefined) delete process.env.SECURE_PUBLISH_MOCK;
      else process.env.SECURE_PUBLISH_MOCK = origMock;
    }
    assert.equal(mockGet(panelId), null);
    assert.deepEqual(readRegistry(tmp).panels, []);
    assert.match(out, new RegExp(`Removed ${panelId}\\.`));
  });
});
