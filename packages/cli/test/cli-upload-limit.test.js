/**
 * publish pre-flight, near-limit warning, and 413 mapping.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main } from "../src/cli.js";
import { resetUploadLimitCache, uploadTooLargeMessage } from "../src/upload-limit.js";

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

describe("CLI publish upload size limit", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let origEnv;
  let calls;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-size-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    origEnv = process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES;
    delete process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES;
    process.env.HOME = tmp;
    process.chdir(tmp);
    writeSession(tmp);
    calls = [];
    origFetch = globalThis.fetch;
    resetUploadLimitCache();
  });

  afterEach(() => {
    process.chdir(origCwd);
    process.env.HOME = origHome;
    if (origEnv === undefined) delete process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES;
    else process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES = origEnv;
    globalThis.fetch = origFetch;
    resetUploadLimitCache();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("uses GET /api/limits when the env var is unset", async () => {
    delete process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES;
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "z".repeat(50));
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/api/limits")) {
        return new Response(JSON.stringify({ maxUploadBytes: 40 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error("POST should not run when /api/limits says the file is over the limit");
    };
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      /too large to publish/i
    );
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://app.securepublish.work/api/limits");
    assert.equal(calls[0].init.method, "GET");
  });

  it("does not upload when the file is over the resolved limit", async () => {
    process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES = "100";
    const htmlPath = path.join(tmp, "dash.html");
    const html = "x".repeat(120);
    fs.writeFileSync(htmlPath, html);
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      throw new Error("fetch should not run for an over-limit file");
    };
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.match(e.message, /too large to publish/i);
        assert.match(e.message, /per-publish upload limit/i);
        assert.equal(e.message, uploadTooLargeMessage(Buffer.byteLength(html), 100));
        return true;
      }
    );
    assert.equal(calls.length, 0);
  });

  it("warns when the file is over 90% of the limit and still publishes", async () => {
    process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES = "1000";
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "y".repeat(901));
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      return okPublishResponse();
    };
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    const post = calls.find((c) => c.init?.method === "POST");
    assert.ok(post, "expected POST /api/panels");
    assert.equal(post.url, "https://app.securepublish.work/api/panels");
    assert.match(out, /^warn:/m);
    assert.match(out, /wise\.securepublish\.work\/k7f3qx2abc/);
  });

  it("publishes a file under 90% of the limit without a size warning", async () => {
    process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES = "1000";
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>hi</html>\n");
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      return okPublishResponse();
    };
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    const post = calls.find((c) => c.init?.method === "POST");
    assert.ok(post);
    assert.doesNotMatch(out, /warn:.*MB/);
    assert.match(out, /wise\.securepublish\.work\/k7f3qx2abc/);
  });

  it("maps a 413 from the server to the same too-large message", async () => {
    process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES = "10000";
    const html = "<html>small</html>\n";
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, html);
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (init?.method === "POST") {
        return new Response(JSON.stringify({ error: "payload_too_large" }), {
          status: 413,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("unexpected", { status: 500 });
    };
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.equal(
          e.message,
          uploadTooLargeMessage(Buffer.byteLength(html), 10000)
        );
        assert.doesNotMatch(e.message, /Não consegui publicar agora/);
        return true;
      }
    );
    const post = calls.filter((c) => c.init?.method === "POST");
    assert.equal(post.length, 1);
  });

  it("prefers maxUploadBytes from a 413 body when the server limit changed", async () => {
    process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES = "10000";
    const html = "<html>small</html>\n";
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, html);
    globalThis.fetch = async (_url, init) => {
      if (init?.method === "POST") {
        return new Response(JSON.stringify({ error: "payload_too_large", maxUploadBytes: 512 }), {
          status: 413,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("unexpected", { status: 500 });
    };
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.equal(e.message, uploadTooLargeMessage(Buffer.byteLength(html), 512));
        return true;
      }
    );
  });
});
