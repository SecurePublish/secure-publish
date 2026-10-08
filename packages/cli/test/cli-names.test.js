/**
 * CLI --name on publish and rename (PATCH name).
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

function writeSession(dir, extra = {}) {
  const sp = path.join(dir, ".secure-publish");
  fs.mkdirSync(sp, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    path.join(sp, "session.json"),
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

describe("CLI named panel links", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let calls;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    process.env.HOME = tmp;
    process.chdir(tmp);
    writeSession(tmp);
    calls = [];
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    process.chdir(origCwd);
    process.env.HOME = origHome;
    globalThis.fetch = origFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("publish --name sends the name as-is and prints the canonical URL", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>hi</html>\n");
    const canon = "https://wise.securepublish.work/k7f3qx2abc/performance-outubro-2026";
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      return new Response(
        JSON.stringify({
          ok: true,
          id: "k7f3qx2abc",
          url: canon,
          path: "/k7f3qx2abc/performance-outubro-2026",
          name: "performance-outubro-2026",
          host: "wise.securepublish.work",
          title: "Painel",
          publishedAt: "2026-10-08T00:00:00Z",
          mode: "company",
          allowlist: [],
        }),
        { status: 201, headers: { "content-type": "application/json" } }
      );
    };

    const out = await withIo(() =>
      main(["publish", htmlPath, "--title", "Painel", "--name", "Performance — Outubro 2026"])
    );
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://app.securepublish.work/api/panels");
    assert.equal(calls[0].init.method, "POST");
    const sent = JSON.parse(calls[0].init.body);
    assert.equal(sent.name, "Performance — Outubro 2026");
    assert.match(out, /https:\/\/wise\.securepublish\.work\/k7f3qx2abc\/performance-outubro-2026/);
  });

  it("rename <url> --name PATCHes the panel id extracted from the URL", async () => {
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      return new Response(
        JSON.stringify({
          id: "k7f3qx2abc",
          name: "performance-out-26",
          path: "/k7f3qx2abc/performance-out-26",
          url: "https://wise.securepublish.work/k7f3qx2abc/performance-out-26",
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    };
    const out = await withIo(() =>
      main([
        "rename",
        "https://wise.securepublish.work/k7f3qx2abc/old-name",
        "--name",
        "performance-out-26",
      ])
    );
    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].url,
      "https://app.securepublish.work/api/panels/k7f3qx2abc/name"
    );
    assert.equal(calls[0].init.method, "PATCH");
    assert.equal(JSON.parse(calls[0].init.body).name, "performance-out-26");
    assert.match(out, /https:\/\/wise\.securepublish\.work\/k7f3qx2abc\/performance-out-26/);
  });

  it("rename --no-name and --name \"\" both clear the name", async () => {
    const run = async (argv) => {
      calls = [];
      globalThis.fetch = async (url, init) => {
        calls.push({ url: String(url), init });
        return new Response(
          JSON.stringify({
            id: "k7f3qx2abc",
            name: null,
            path: "/k7f3qx2abc",
            url: "https://wise.securepublish.work/k7f3qx2abc",
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      };
      await withIo(() => main(argv));
      return JSON.parse(calls[0].init.body);
    };

    const a = await run(["rename", "k7f3qx2abc", "--no-name"]);
    assert.equal(a.name, null);

    const b = await run(["rename", "k7f3qx2abc", "--name", ""]);
    assert.equal(b.name, null);
  });

  it("rename without session uses the existing login error style", async () => {
    fs.rmSync(path.join(tmp, ".secure-publish", "session.json"));
    await assert.rejects(
      () => main(["rename", "k7f3qx2abc", "--name", "x"]),
      /Conta não ligada nesta máquina/
    );
  });
});
