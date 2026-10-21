/**
 * publish: server-owned size pre-check, fallback upload, 413 display, sanitization.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main } from "../src/cli.js";
import { SIZE_REFUSED_MESSAGE } from "../src/upload-limit.js";

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

function expectedPayload(html, extra = {}) {
  return JSON.stringify({ html, title: "Painel", ...extra });
}

describe("CLI publish upload size limit", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let origEnv;
  let origOperator;
  let origToken;
  let origAccount;
  let origNs;
  let calls;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-size-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    origEnv = process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES;
    origOperator = process.env.SECURE_PUBLISH_OPERATOR;
    origToken = process.env.CLOUDFLARE_API_TOKEN;
    origAccount = process.env.CLOUDFLARE_ACCOUNT_ID;
    origNs = process.env.SECURE_PUBLISH_KV_NAMESPACE_ID;
    delete process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES;
    delete process.env.SECURE_PUBLISH_OPERATOR;
    delete process.env.CLOUDFLARE_API_TOKEN;
    delete process.env.CLOUDFLARE_ACCOUNT_ID;
    delete process.env.SECURE_PUBLISH_KV_NAMESPACE_ID;
    process.env.HOME = tmp;
    process.chdir(tmp);
    writeSession(tmp);
    calls = [];
    origFetch = globalThis.fetch;
  });

  afterEach(() => {
    process.chdir(origCwd);
    process.env.HOME = origHome;
    if (origEnv === undefined) delete process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES;
    else process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES = origEnv;
    if (origOperator === undefined) delete process.env.SECURE_PUBLISH_OPERATOR;
    else process.env.SECURE_PUBLISH_OPERATOR = origOperator;
    if (origToken === undefined) delete process.env.CLOUDFLARE_API_TOKEN;
    else process.env.CLOUDFLARE_API_TOKEN = origToken;
    if (origAccount === undefined) delete process.env.CLOUDFLARE_ACCOUNT_ID;
    else process.env.CLOUDFLARE_ACCOUNT_ID = origAccount;
    if (origNs === undefined) delete process.env.SECURE_PUBLISH_KV_NAMESPACE_ID;
    else process.env.SECURE_PUBLISH_KV_NAMESPACE_ID = origNs;
    globalThis.fetch = origFetch;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("blocks the upload and prints the server message when the request body is over upload.maxBytes", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    const html = "z".repeat(80);
    fs.writeFileSync(htmlPath, html);
    const payload = expectedPayload(html);
    const payloadBytes = Buffer.byteLength(payload, "utf8");
    const serverMessage = "Este arquivo passa do limite do serviço. Comprima as imagens.";
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/api/limits")) {
        return new Response(
          JSON.stringify({
            upload: { maxBytes: payloadBytes - 1, message: serverMessage },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      throw new Error("POST should not run when /api/limits says the body is over the limit");
    };
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.equal(e.message, serverMessage);
        assert.doesNotMatch(e.message, /too large to publish/i);
        assert.doesNotMatch(e.message, /3145728|3 MB|SECUREPUBLISH/);
        return true;
      }
    );
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://app.securepublish.work/api/limits");
    assert.equal(calls[0].init.method, "GET");
    assert.equal(calls[0].init.headers["accept-language"], "pt");
  });

  it("compares the JSON request body size, not the HTML file size alone", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    const html = "z".repeat(20);
    fs.writeFileSync(htmlPath, html);
    const payload = expectedPayload(html);
    const htmlBytes = Buffer.byteLength(html, "utf8");
    const payloadBytes = Buffer.byteLength(payload, "utf8");
    assert.ok(payloadBytes > htmlBytes);
    const serverMessage = "O corpo da publicação passa do limite.";
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/api/limits")) {
        return new Response(
          JSON.stringify({
            upload: { maxBytes: htmlBytes + 1, message: serverMessage },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      throw new Error("POST should not run: JSON body exceeds maxBytes even if HTML does not");
    };
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.equal(e.message, serverMessage);
        return true;
      }
    );
    assert.equal(calls.filter((c) => c.init?.method === "POST").length, 0);
  });

  it("sends Accept-Language from --lang on GET /api/limits", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>hi</html>\n");
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/api/limits")) {
        return new Response(
          JSON.stringify({ upload: { maxBytes: 1_000_000, message: "too big" } }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      return okPublishResponse();
    };
    await withIo(() => main(["publish", htmlPath, "--title", "Painel", "--lang", "en"]));
    const limits = calls.find((c) => String(c.url).endsWith("/api/limits"));
    assert.ok(limits);
    assert.equal(limits.init.headers["accept-language"], "en");
  });

  it("uploads anyway when upload.message is empty or missing (never a blank error)", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    const html = "z".repeat(80);
    fs.writeFileSync(htmlPath, html);
    const payloadBytes = Buffer.byteLength(expectedPayload(html), "utf8");

    const run = async (upload) => {
      calls = [];
      globalThis.fetch = async (url, init) => {
        calls.push({ url: String(url), init });
        if (String(url).endsWith("/api/limits")) {
          return new Response(JSON.stringify({ upload }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return okPublishResponse();
      };
      return withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    };

    const missing = await run({ maxBytes: payloadBytes - 1 });
    assert.match(missing, /wise\.securepublish\.work\/k7f3qx2abc/);
    assert.doesNotMatch(missing, /^Error:\s*$/m);
    assert.ok(calls.some((c) => c.init?.method === "POST"));

    const empty = await run({ maxBytes: payloadBytes - 1, message: "" });
    assert.match(empty, /wise\.securepublish\.work\/k7f3qx2abc/);
    assert.doesNotMatch(empty, /^Error:\s*$/m);
    assert.ok(calls.some((c) => c.init?.method === "POST"));
  });

  it("skips the pre-check for the old {maxUploadBytes} shape and uploads", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>hi</html>\n");
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/api/limits")) {
        return new Response(JSON.stringify({ maxUploadBytes: 1 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return okPublishResponse();
    };
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    const post = calls.find((c) => c.init?.method === "POST");
    assert.ok(post, "expected POST /api/panels");
    assert.match(out, /wise\.securepublish\.work\/k7f3qx2abc/);
  });

  it("uploads anyway when /api/limits fails or times out", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>hi</html>\n");
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/api/limits")) {
        throw new Error("ECONNRESET");
      }
      return okPublishResponse();
    };
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    const post = calls.find((c) => c.init?.method === "POST");
    assert.ok(post, "expected POST /api/panels after limits failure");
    assert.equal(post.url, "https://app.securepublish.work/api/panels");
    assert.match(out, /wise\.securepublish\.work\/k7f3qx2abc/);
    assert.doesNotMatch(out, /^warn:/m);
  });

  it("ignores SECUREPUBLISH_MAX_UPLOAD_BYTES and does not warn at 90%", async () => {
    process.env.SECUREPUBLISH_MAX_UPLOAD_BYTES = "10";
    const htmlPath = path.join(tmp, "dash.html");
    const html = "y".repeat(200);
    fs.writeFileSync(htmlPath, html);
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/api/limits")) {
        throw new Error("limits down");
      }
      return okPublishResponse();
    };
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    const post = calls.find((c) => c.init?.method === "POST");
    assert.ok(post);
    assert.equal(JSON.parse(post.init.body).html, html);
    assert.doesNotMatch(out, /warn:.*MB/);
    assert.match(out, /wise\.securepublish\.work\/k7f3qx2abc/);
  });

  it("prints the server message field unchanged on a 413 JSON body", async () => {
    const html = "<html>small</html>\n";
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, html);
    const serverMessage = "O serviço recusou: arquivo acima do limite. Diminua as imagens.";
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/api/limits")) {
        return new Response(
          JSON.stringify({ upload: { maxBytes: 10_000_000, message: "unused precheck" } }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      }
      if (init?.method === "POST") {
        return new Response(JSON.stringify({ error: "payload_too_large", message: serverMessage }), {
          status: 413,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("unexpected", { status: 500 });
    };
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.equal(e.message, serverMessage);
        assert.doesNotMatch(e.message, /too large to publish/i);
        assert.doesNotMatch(e.message, /Não consegui publicar agora/);
        return true;
      }
    );
    const post = calls.filter((c) => c.init?.method === "POST");
    assert.equal(post.length, 1);
  });

  it("uses a generic size line when a 413 has no JSON, empty message, or HTML", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>small</html>\n");

    const publish413 = async (body, contentType, extraFlags = []) => {
      globalThis.fetch = async (url, init) => {
        if (String(url).endsWith("/api/limits")) throw new Error("limits down");
        if (init?.method === "POST") {
          return new Response(body, {
            status: 413,
            headers: { "content-type": contentType },
          });
        }
        return new Response("unexpected", { status: 500 });
      };
      try {
        await main(["publish", htmlPath, "--title", "Painel", ...extraFlags]);
        throw new Error("expected publish to fail");
      } catch (e) {
        return e.message;
      }
    };

    assert.equal(await publish413("Payload Too Large", "text/plain"), SIZE_REFUSED_MESSAGE.pt);
    assert.equal(
      await publish413(JSON.stringify({ message: "" }), "application/json"),
      SIZE_REFUSED_MESSAGE.pt
    );
    const htmlDump = "<!DOCTYPE html><html><body><h1>413</h1>" + "y".repeat(400) + "</body></html>";
    const fromHtml = await publish413(htmlDump, "text/html");
    assert.equal(fromHtml, SIZE_REFUSED_MESSAGE.pt);
    assert.doesNotMatch(fromHtml, /<!DOCTYPE|<html|<h1/i);
    assert.equal(
      await publish413("Payload Too Large", "text/plain", ["--lang", "en"]),
      SIZE_REFUSED_MESSAGE.en
    );
  });

  it("sanitizes 413 server text (ANSI/control stripped, length capped)", async () => {
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>small</html>\n");
    const injected = "ok\x1b[31mX\x1b[0m\x07" + "W".repeat(600);
    globalThis.fetch = async (url, init) => {
      if (String(url).endsWith("/api/limits")) {
        throw new Error("limits down");
      }
      return new Response(JSON.stringify({ message: injected }), {
        status: 413,
        headers: { "content-type": "application/json" },
      });
    };
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.equal(e.message.includes("\x1b"), false);
        assert.equal(e.message.includes("\x07"), false);
        assert.equal(e.message.length, 500);
        assert.match(e.message, /^okX/);
        return true;
      }
    );
  });

  it("does not write Cloudflare KV even with --operator and a Cloudflare token", async () => {
    process.env.CLOUDFLARE_API_TOKEN = "cf-token-should-not-be-used";
    process.env.CLOUDFLARE_ACCOUNT_ID = "acct";
    process.env.SECURE_PUBLISH_KV_NAMESPACE_ID = "ns";
    const htmlPath = path.join(tmp, "dash.html");
    fs.writeFileSync(htmlPath, "<html>hi</html>\n");
    globalThis.fetch = async (url, init) => {
      const href = String(url);
      calls.push({ url: href, init });
      if (href.includes("api.cloudflare.com")) {
        throw new Error("public CLI must not write Cloudflare KV");
      }
      if (href.endsWith("/api/limits")) {
        return new Response("nope", { status: 404 });
      }
      return okPublishResponse();
    };
    const out = await withIo(() =>
      main(["publish", htmlPath, "--title", "Painel", "--operator"])
    );
    assert.equal(
      calls.some((c) => String(c.url).includes("api.cloudflare.com")),
      false
    );
    const post = calls.find((c) => c.init?.method === "POST");
    assert.ok(post);
    assert.equal(post.url, "https://app.securepublish.work/api/panels");
    assert.match(out, /wise\.securepublish\.work\/k7f3qx2abc/);
  });
});
