/**
 * Mock mode is env-only (SECURE_PUBLISH_MOCK=1). A project-file mock key
 * is ignored, warns, and publish still hits the real API.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main } from "../src/cli.js";
import { MESSAGES } from "../src/messages.js";
import { mockList } from "../src/mock-store.js";

const TOKEN = "ab".repeat(32);

function writeSession(dir) {
  const sp = path.join(dir, ".secure-publish");
  fs.mkdirSync(sp, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    path.join(sp, "session.json"),
    JSON.stringify({
      publishToken: TOKEN,
      email: "dev@localhost",
      host: "wise.securepublish.work",
      apiBase: "https://app.securepublish.work",
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
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

function okPublishResponse() {
  return new Response(
    JSON.stringify({
      ok: true,
      id: "k7f3qx2abc",
      url: "https://wise.securepublish.work/k7f3qx2abc",
      host: "wise.securepublish.work",
      title: "dash",
      publishedAt: "2026-10-21T00:00:00Z",
      mode: "company",
      allowlist: [],
    }),
    { status: 201, headers: { "content-type": "application/json" } }
  );
}

describe("mock is env-only", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let origMock;
  let origExitCode;
  let htmlPath;
  let calls;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-mock-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    origMock = process.env.SECURE_PUBLISH_MOCK;
    origExitCode = process.exitCode;
    delete process.env.SECURE_PUBLISH_MOCK;
    process.env.HOME = tmp;
    process.chdir(tmp);
    process.exitCode = 0;
    htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>hi</html>\n");
    calls = [];
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    process.chdir(origCwd);
    process.env.HOME = origHome;
    if (origMock === undefined) delete process.env.SECURE_PUBLISH_MOCK;
    else process.env.SECURE_PUBLISH_MOCK = origMock;
    globalThis.fetch = origFetch;
    process.exitCode = origExitCode;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function mockApi() {
    globalThis.fetch = async (url, init) => {
      const href = String(url);
      if (href.endsWith("/api/limits")) {
        return new Response("nope", { status: 404 });
      }
      calls.push({ url: href, init });
      return okPublishResponse();
    };
  }

  it("project-file mock is ignored, warns, and publish hits the real API with company success", async () => {
    writeSession(tmp);
    fs.writeFileSync(
      path.join(tmp, ".secure-publish.json"),
      JSON.stringify({ mock: true }) + "\n"
    );
    mockApi();
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    assert.match(out, /Ignorei a opção mock do \.secure-publish\.json/);
    assert.match(out, /O modo de teste só liga pela variável SECURE_PUBLISH_MOCK=1/);
    const post = calls.find(
      (c) => c.init?.method === "POST" && String(c.url).endsWith("/api/panels")
    );
    assert.ok(post, "project-file mock must not skip POST /api/panels");
    assert.equal(post.init.headers.authorization, `Bearer ${TOKEN}`);
    assert.match(out, /Publicado pra \*\*toda a empresa\*\*/);
    assert.doesNotMatch(out, /Publicado só nesta máquina/);
    assert.equal(mockList(tmp).length, 0);
  });

  it("project-file mock with --lang en warns in English and still publishes to the server", async () => {
    writeSession(tmp);
    fs.writeFileSync(
      path.join(tmp, ".secure-publish.json"),
      JSON.stringify({ mock: true }) + "\n"
    );
    mockApi();
    const out = await withIo(() =>
      main(["publish", htmlPath, "--title", "Painel", "--lang", "en"])
    );
    assert.equal(out.includes(MESSAGES.ignoredProjectMock.en), true);
    assert.ok(calls.some((c) => c.init?.method === "POST"));
    assert.match(out, /Published for the \*\*whole company\*\*/);
  });

  it("SECURE_PUBLISH_MOCK=1 shows the local-only success line and never the company text", async () => {
    process.env.SECURE_PUBLISH_MOCK = "1";
    globalThis.fetch = async () => {
      throw new Error("env mock must not call the API");
    };
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    assert.equal(out.includes(MESSAGES.mockPublishSuccess.pt), true);
    assert.doesNotMatch(out, /toda a empresa/);
    assert.doesNotMatch(out, /whole company/);
    assert.ok(mockList(tmp).length > 0);
  });

  it("env mock --lang en uses the English local-only line", async () => {
    process.env.SECURE_PUBLISH_MOCK = "1";
    globalThis.fetch = async () => {
      throw new Error("env mock must not call the API");
    };
    const out = await withIo(() =>
      main(["publish", htmlPath, "--title", "Painel", "--lang", "en"])
    );
    assert.equal(out.includes(MESSAGES.mockPublishSuccess.en), true);
    assert.doesNotMatch(out, /toda a empresa/);
    assert.doesNotMatch(out, /whole company/);
  });

  it("publish --mock without the env var does not POST /api/panels and exits 1", async () => {
    writeSession(tmp);
    mockApi();
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel", "--mock"]));
    assert.equal(process.exitCode, 1);
    assert.equal(
      calls.some((c) => c.init?.method === "POST" && String(c.url).endsWith("/api/panels")),
      false,
      "--mock must not POST /api/panels"
    );
    assert.equal(calls.length, 0, "--mock must make zero network calls");
    assert.equal(out, `Erro: ${MESSAGES.removedMockFlag.pt}`);
    assert.doesNotMatch(out, /toda a empresa/);
    assert.equal(mockList(tmp).length, 0);
  });

  it("publish --mock with SECURE_PUBLISH_MOCK=1 still exits 1 and publishes nothing", async () => {
    process.env.SECURE_PUBLISH_MOCK = "1";
    globalThis.fetch = async () => {
      throw new Error("--mock must not call the API even when env mock is on");
    };
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel", "--mock"]));
    assert.equal(process.exitCode, 1);
    assert.equal(out, `Erro: ${MESSAGES.removedMockFlag.pt}`);
    assert.doesNotMatch(out, /toda a empresa|só nesta máquina/);
    assert.equal(mockList(tmp).length, 0);
  });

  it("publish --mock --lang en prints the English error with Error: prefix", async () => {
    writeSession(tmp);
    mockApi();
    const out = await withIo(() =>
      main(["publish", htmlPath, "--title", "Painel", "--mock", "--lang", "en"])
    );
    assert.equal(process.exitCode, 1);
    assert.equal(calls.length, 0);
    assert.equal(out, `Error: ${MESSAGES.removedMockFlag.en}`);
  });
});
