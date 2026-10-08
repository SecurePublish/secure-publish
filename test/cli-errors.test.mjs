/**
 * CLI user-facing output: npx github: command form + stable stderr error codes.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN = path.join(root, "packages/cli/bin/securepublish-cli.js");
const GITHUB_NPX = "npx --yes github:clovistx/secure-publish";
const BARE_CLI_RUN =
  /(?:^|\n)\s*(?:`)?securepublish-cli\s+(?:login|publish|logout|list|revoke|doctor|mock-serve|help|status)\b/;

function tmpHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sp-home-"));
}

function writeSession(home, extra = {}) {
  const dir = path.join(home, ".secure-publish");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const session = {
    publishToken: "ab".repeat(32),
    email: "ana@empresa.com",
    host: "wise.securepublish.work",
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    ...extra,
  };
  fs.writeFileSync(path.join(dir, "session.json"), JSON.stringify(session, null, 2));
}

function writeHtml(dir, name, contents) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, contents);
  return p;
}

function runCli(args, { home, env = {}, cwd } = {}) {
  const h = home || tmpHome();
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      cwd: cwd || root,
      env: {
        ...process.env,
        HOME: h,
        SECURE_PUBLISH_MOCK: "",
        SECURE_PUBLISH_OPERATOR: "",
        SECURE_PUBLISH_NO_BROWSER: "1",
        ...env,
      },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 20000);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

function assertErrorCode(r, code) {
  assert.notEqual(r.status, 0, `expected non-zero exit, stdout=${r.stdout} stderr=${r.stderr}`);
  assert.match(
    r.stderr,
    new RegExp(`^error: ${code}$`, "m"),
    `expected error: ${code} in stderr:\n${r.stderr}`
  );
}

function assertNoBareCli(text, label) {
  assert.doesNotMatch(text, BARE_CLI_RUN, `${label} must not tell users to run bare securepublish-cli`);
}

function startApi(handler) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      Promise.resolve(handler(req, res)).catch(() => {
        res.statusCode = 500;
        res.end("{}");
      });
    });
    server.listen(0, "127.0.0.1", async () => {
      const { port } = server.address();
      resolve({ server, port, base: `http://127.0.0.1:${port}` });
    });
  });
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    return {};
  }
}

describe("CLI prints npx github: form (never bare securepublish-cli <sub>)", async () => {
  it("publish usage line uses npx form", async () => {
    const r = await runCli(["publish"]);
    assertErrorCode(r, "usage");
    assert.match(r.stderr, new RegExp(`${GITHUB_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} publish`));
    assertNoBareCli(r.stderr, "publish usage");
  });

  it("not-logged-in publish tells user to npx login", async () => {
    const home = tmpHome();
    const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
    const r = await runCli(["publish", file], { home });
    assertErrorCode(r, "not_logged_in");
    assert.match(r.stderr, /Conta não ligada nesta máquina/);
    assert.match(r.stderr, new RegExp(`${GITHUB_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} login`));
    assertNoBareCli(r.stderr, "not logged in");
  });

  it("doctor next-step lines use npx form", async () => {
    const r = await runCli(["doctor"]);
    assertErrorCode(r, "not_logged_in");
    assert.match(r.stdout, /Status: conta não ligada nesta máquina/);
    assert.match(r.stdout, new RegExp(`Next: ${GITHUB_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} login`));
    assertNoBareCli(`${r.stdout}\n${r.stderr}`, "doctor");
  });

  it("revoke usage uses npx form", async () => {
    const r = await runCli(["revoke"]);
    assertErrorCode(r, "usage");
    assert.match(r.stderr, new RegExp(`${GITHUB_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} revoke`));
    assertNoBareCli(r.stderr, "revoke usage");
  });
});

describe("CLI failure paths print stable error codes on stderr", async () => {
  it("file_not_found", async () => {
    const home = tmpHome();
    const r = await runCli(["publish", path.join(home, "missing.html")], { home });
    assertErrorCode(r, "file_not_found");
    assert.match(r.stderr, /File not found:/);
  });

  it("file_empty", async () => {
    const home = tmpHome();
    const file = writeHtml(home, "empty.html", "  \n");
    const r = await runCli(["publish", file], { home });
    assertErrorCode(r, "file_empty");
    assert.match(r.stderr, /HTML file is empty/);
  });

  it("not_html", async () => {
    const home = tmpHome();
    const file = writeHtml(home, "notes.txt", "just a plain text dashboard idea");
    const r = await runCli(["publish", file], { home });
    assertErrorCode(r, "not_html");
    assert.match(r.stderr, /not HTML|não é HTML|not html/i);
  });

  it("invalid_email when --to has no valid address", async () => {
    const home = tmpHome();
    const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
    const r = await runCli(["publish", file, "--to", "not-an-email"], { home });
    assertErrorCode(r, "invalid_email");
    assert.match(r.stderr, /Inclua pelo menos um e-mail/);
  });

  it("invalid_email when --to mixes garbage with a real address", async () => {
    const home = tmpHome();
    const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
    const r = await runCli(["publish", file, "--to", "ana@empresa.com,nope"], { home });
    assertErrorCode(r, "invalid_email");
  });

  it("session_expired maps Worker 401 unauthorized", async () => {
    const api = await startApi(async (req, res) => {
      if (req.url === "/api/panels" && req.method === "POST") {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const home = tmpHome();
      writeSession(home, { apiBase: api.base });
      const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
      const r = await runCli(["publish", file], {
        home,
        env: { SECURE_PUBLISH_API_BASE: api.base },
      });
      assertErrorCode(r, "session_expired");
      assert.match(r.stderr, /Sessão expirada|Conta não ligada/i);
    } finally {
      api.server.close();
    }
  });

  it("no_host maps Worker 409 no_host", async () => {
    const api = await startApi(async (req, res) => {
      if (req.url === "/api/panels" && req.method === "POST") {
        res.writeHead(409, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "no_host" }));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const home = tmpHome();
      writeSession(home, { apiBase: api.base, host: "" });
      const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
      const r = await runCli(["publish", file], {
        home,
        env: { SECURE_PUBLISH_API_BASE: api.base },
      });
      assertErrorCode(r, "no_host");
    } finally {
      api.server.close();
    }
  });

  it("html_too_large maps Worker 413 html_too_large", async () => {
    const api = await startApi(async (req, res) => {
      if (req.url === "/api/panels" && req.method === "POST") {
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "html_too_large" }));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const home = tmpHome();
      writeSession(home, { apiBase: api.base });
      const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
      const r = await runCli(["publish", file], {
        home,
        env: { SECURE_PUBLISH_API_BASE: api.base },
      });
      assertErrorCode(r, "html_too_large");
    } finally {
      api.server.close();
    }
  });

  it("network_error when the API is unreachable", async () => {
    const home = tmpHome();
    const dead = "http://127.0.0.1:59999";
    writeSession(home, { apiBase: dead });
    const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
    const r = await runCli(["publish", file], {
      home,
      env: { SECURE_PUBLISH_API_BASE: dead },
    });
    assertErrorCode(r, "network_error");
    assert.match(r.stderr, /Não consegui publicar agora/);
  });

  it("unknown Worker JSON error code is printed verbatim", async () => {
    const api = await startApi(async (req, res) => {
      if (req.url === "/api/panels" && req.method === "POST") {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "upstream_down" }));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const home = tmpHome();
      writeSession(home, { apiBase: api.base });
      const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
      const r = await runCli(["publish", file], {
        home,
        env: { SECURE_PUBLISH_API_BASE: api.base },
      });
      assertErrorCode(r, "upstream_down");
      assert.match(r.stderr, /Não consegui publicar agora/);
    } finally {
      api.server.close();
    }
  });

  it("company_requires_work_domain maps Worker 400 and prints npx --to form", async () => {
    const api = await startApi(async (req, res) => {
      if (req.url === "/api/panels" && req.method === "POST") {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "company_requires_work_domain" }));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const home = tmpHome();
      writeSession(home, { apiBase: api.base });
      const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
      const r = await runCli(["publish", file], {
        home,
        env: { SECURE_PUBLISH_API_BASE: api.base },
      });
      assertErrorCode(r, "company_requires_work_domain");
      assert.match(
        r.stderr,
        /npx --yes github:clovistx\/secure-publish publish .+ --to /
      );
      assert.match(r.stderr, /--to/);
      assertNoBareCli(r.stderr, "company_requires_work_domain");
    } finally {
      api.server.close();
    }
  });

  it("server_error when the Worker fails without a JSON error code", async () => {
    const api = await startApi(async (req, res) => {
      if (req.url === "/api/panels" && req.method === "POST") {
        res.writeHead(503, { "content-type": "text/plain" });
        res.end("nope");
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const home = tmpHome();
      writeSession(home, { apiBase: api.base });
      const file = writeHtml(home, "panel.html", "<html><body>ok</body></html>");
      const r = await runCli(["publish", file], {
        home,
        env: { SECURE_PUBLISH_API_BASE: api.base },
      });
      assertErrorCode(r, "server_error");
      assert.match(r.stderr, /Não consegui publicar agora/);
    } finally {
      api.server.close();
    }
  });

  it("login network_error when device/code cannot be reached", async () => {
    const r = await runCli(["login"], {
      env: { SECURE_PUBLISH_API_BASE: "http://127.0.0.1:59999" },
    });
    assertErrorCode(r, "network_error");
  });

  it("login server_error when device/code is not ok", async () => {
    const api = await startApi(async (req, res) => {
      res.writeHead(500, { "content-type": "text/plain" });
      res.end("nope");
    });
    try {
      const r = await runCli(["login"], {
        env: { SECURE_PUBLISH_API_BASE: api.base },
      });
      assertErrorCode(r, "server_error");
    } finally {
      api.server.close();
    }
  });

  it("login expired_token maps Worker poll error", async () => {
    const api = await startApi(async (req, res) => {
      if (req.url === "/api/device/code" && req.method === "POST") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            device_code: "ab".repeat(32),
            verification_url: "http://127.0.0.1/auth/google?device=x",
            expires_in: 600,
            interval: 0,
          })
        );
        return;
      }
      if (req.url === "/api/device/token" && req.method === "POST") {
        await readJson(req);
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "expired_token" }));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    try {
      const r = await runCli(["login"], {
        env: { SECURE_PUBLISH_API_BASE: api.base },
      });
      assertErrorCode(r, "expired_token");
    } finally {
      api.server.close();
    }
  });

  it("status is an alias of doctor and reports not_logged_in", async () => {
    const r = await runCli(["status"]);
    assertErrorCode(r, "not_logged_in");
    assert.match(r.stdout, /Status: conta não ligada nesta máquina/);
  });

  it("unknown_command", async () => {
    const r = await runCli(["frobnicate"]);
    assertErrorCode(r, "unknown_command");
  });

  it("reserved_slug Worker code passes through verbatim", async () => {
    const { codeFromApiError } = await import(
      "../packages/cli/src/errors.js"
    );
    assert.equal(codeFromApiError("reserved_slug", 400), "reserved_slug");
  });

  it("npm_engine when npm_config_user_agent is npm 9", async () => {
    const r = await runCli(["help"], {
      env: { npm_config_user_agent: "npm/9.2.0 node/v20.19.0 linux x64 workspaces/false" },
    });
    assertErrorCode(r, "npm_engine");
    assert.match(r.stderr, /npm 10/);
    assert.match(r.stderr, /npm i -g npm@10/);
  });
});
