/**
 * Server is the session-expiry authority: local expiresAt must not drop the
 * token. 401 tells the user to log in again. 409 no_host is a distinct
 * hosting-address message (not the generic retry line).
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main } from "../src/cli.js";

const TOKEN = "ab".repeat(32);

const SESSION_EXPIRED_PT =
  "Sua sessão expirou ou foi encerrada. Rode npx --yes @securepublish/cli@1.0.4 login para entrar de novo.";
const SESSION_EXPIRED_EN =
  "Your session expired or was ended. Run npx --yes @securepublish/cli@1.0.4 login to sign in again.";
const NO_HOST_PUBLISH_PT =
  "Ainda não publiquei: sua empresa não tem um endereço no Secure Publish. Escolha um em https://app.securepublish.work/app/hosting.html e tente publicar de novo. Isso só precisa ser feito uma vez.";
const NO_HOST_PUBLISH_EN =
  "Not published yet: your company doesn't have a Secure Publish address. Choose one at https://app.securepublish.work/app/hosting.html and try publishing again. You only need to do this once.";

function sessionPath(dir) {
  return path.join(dir, ".secure-publish", "session.json");
}

function writeSession(dir, extra = {}) {
  const sp = path.join(dir, ".secure-publish");
  fs.mkdirSync(sp, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    sessionPath(dir),
    JSON.stringify({
      publishToken: TOKEN,
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

describe("CLI session expiry is server-authoritative", () => {
  let tmp;
  let origHome;
  let origCwd;
  let origFetch;
  let origExitCode;
  let htmlPath;
  let calls;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sp-cli-session-"));
    origHome = process.env.HOME;
    origCwd = process.cwd();
    origExitCode = process.exitCode;
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
    globalThis.fetch = origFetch;
    process.exitCode = origExitCode;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function mockApi(handler) {
    globalThis.fetch = async (url, init) => {
      const href = String(url);
      if (href.endsWith("/api/limits")) {
        return new Response("nope", { status: 404 });
      }
      calls.push({ url: href, init });
      return handler(href, init);
    };
  }

  it("sends a token whose saved expiresAt is in the past", async () => {
    writeSession(tmp, { expiresAt: new Date(Date.now() - 60_000).toISOString() });
    mockApi(() => okPublishResponse());
    const out = await withIo(() => main(["publish", htmlPath, "--title", "Painel"]));
    const post = calls.find(
      (c) => c.init?.method === "POST" && String(c.url).endsWith("/api/panels")
    );
    assert.ok(post, "expired local expiresAt must not drop the token before POST");
    assert.equal(post.init.headers.authorization, `Bearer ${TOKEN}`);
    assert.match(out, /wise\.securepublish\.work\/k7f3qx2abc/);
    assert.equal(fs.existsSync(sessionPath(tmp)), true);
  });

  it("publish 401 maps to the login-again message in PT and EN, not the generic retry", async () => {
    writeSession(tmp);
    mockApi(
      () =>
        new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        })
    );
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.equal(e.message, SESSION_EXPIRED_PT);
        assert.doesNotMatch(e.message, /Tenta de novo em instantes/);
        return true;
      }
    );
    assert.equal(fs.existsSync(sessionPath(tmp)), false);

    writeSession(tmp);
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel", "--lang", "en"]),
      (e) => {
        assert.equal(e.message, SESSION_EXPIRED_EN);
        assert.doesNotMatch(e.message, /Try again in a moment/);
        assert.doesNotMatch(e.message, /Tenta de novo em instantes/);
        return true;
      }
    );
  });

  it("rename 401 maps to the login-again message in PT and EN", async () => {
    writeSession(tmp);
    mockApi(
      () =>
        new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        })
    );
    await assert.rejects(
      () => main(["rename", "k7f3qx2abc", "--name", "x"]),
      (e) => {
        assert.equal(e.message, SESSION_EXPIRED_PT);
        assert.doesNotMatch(e.message, /Tenta de novo em instantes/);
        return true;
      }
    );

    writeSession(tmp);
    await assert.rejects(
      () => main(["rename", "k7f3qx2abc", "--name", "x", "--lang", "en"]),
      (e) => {
        assert.equal(e.message, SESSION_EXPIRED_EN);
        return true;
      }
    );
  });

  it("revoke 401 maps to the login-again message in PT and EN", async () => {
    writeSession(tmp);
    mockApi(
      () =>
        new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        })
    );
    await assert.rejects(
      () => main(["revoke", "k7f3qx2abc"]),
      (e) => {
        assert.equal(e.message, SESSION_EXPIRED_PT);
        assert.doesNotMatch(e.message, /Tenta de novo em instantes/);
        return true;
      }
    );

    writeSession(tmp);
    await assert.rejects(
      () => main(["revoke", "k7f3qx2abc", "--lang", "en"]),
      (e) => {
        assert.equal(e.message, SESSION_EXPIRED_EN);
        return true;
      }
    );
  });

  it("non-401 publish/rename errors keep the generic retry message", async () => {
    writeSession(tmp);
    mockApi(
      () =>
        new Response(JSON.stringify({ error: "server_error", host: "wise.securepublish.work" }), {
          status: 500,
          headers: { "content-type": "application/json" },
        })
    );
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      /Não consegui publicar agora\. A conta está ligada em wise\.securepublish\.work\. Tenta de novo em instantes\./
    );
    assert.equal(fs.existsSync(sessionPath(tmp)), true);

    await assert.rejects(
      () => main(["rename", "k7f3qx2abc", "--name", "x"]),
      /Não consegui alterar o nome agora\. A conta está ligada em wise\.securepublish\.work\. Tenta de novo em instantes\./
    );
  });

  it("publish 409 no_host is the hosting-address message in PT and EN, not the generic retry", async () => {
    writeSession(tmp);
    mockApi(
      () =>
        new Response(JSON.stringify({ error: "no_host" }), {
          status: 409,
          headers: { "content-type": "application/json" },
        })
    );
    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel"]),
      (e) => {
        assert.equal(e.message, NO_HOST_PUBLISH_PT);
        assert.doesNotMatch(e.message, /Tenta de novo em instantes/);
        return true;
      }
    );
    assert.equal(fs.existsSync(sessionPath(tmp)), true);

    await assert.rejects(
      () => main(["publish", htmlPath, "--title", "Painel", "--lang", "en"]),
      (e) => {
        assert.equal(e.message, NO_HOST_PUBLISH_EN);
        assert.doesNotMatch(e.message, /Tenta de novo em instantes/);
        return true;
      }
    );
  });

  it("rename 409 no_host uses the same hosting-address message", async () => {
    writeSession(tmp);
    mockApi(
      () =>
        new Response(JSON.stringify({ error: "no_host" }), {
          status: 409,
          headers: { "content-type": "application/json" },
        })
    );
    await assert.rejects(() => main(["rename", "k7f3qx2abc", "--name", "x"]), (e) => {
      assert.equal(e.message, NO_HOST_PUBLISH_PT);
      return true;
    });
  });

  it("logout still POSTs /api/session/revoke with a past local expiresAt", async () => {
    writeSession(tmp, { expiresAt: new Date(Date.now() - 60_000).toISOString() });
    mockApi(() => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const logs = await withIo(() => main(["logout"]));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://app.securepublish.work/api/session/revoke");
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers.authorization, `Bearer ${TOKEN}`);
    assert.match(logs, /Conta desligada nesta máquina/);
    assert.equal(fs.existsSync(sessionPath(tmp)), false);
  });
});
