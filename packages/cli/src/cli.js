import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import http from "node:http";
import { spawn } from "node:child_process";
import { loadConfig, configHints } from "./config.js";
import { loadRegistry, upsertPanel, removePanel } from "./registry.js";
import { kvPut, kvGet, kvDelete, kvList, verifyToken } from "./cf-api.js";
import { mockPut, mockGet, mockDelete, mockList } from "./mock-store.js";
import {
  parseToFlag,
  buildAccessMeta,
  checkPanelAccess,
  accessDeniedMessage,
  publishSuccessMessage,
  normalizeDomains,
} from "./acl.js";

const CLI = "securepublish-cli";

const HELP = `
${CLI} — publish AI HTML dashboards behind company SSO

Auth model:
  The URL path is the panel id (KV lookup only) — NOT a credential.
  Viewers must sign in (Cloudflare Access or Worker OAuth), then pass
  the panel ACL:
    default (no --to)  company-wide = same email *domain* as the tenant
                       (OAUTH_ALLOWED_DOMAINS / companyDomains).
                       NOT Workspace/Entra/GitHub Org membership (later).
    --to a@x,b@y       explicit email allowlist (still requires SSO)

Usage:
  ${CLI} login
  ${CLI} publish <file.html> [--title "..."] [--name "..."] [--to email,email] [--mock]
  ${CLI} rename <id-or-url> --name <text>
  ${CLI} rename <id-or-url> --no-name
  ${CLI} logout
  ${CLI} list [--remote]
  ${CLI} revoke <key>
  ${CLI} doctor
  ${CLI} mock-serve [--port 8787]
  ${CLI} help

Sign in with Google via \`login\`. Publish uses that account.
Do not set CLOUDFLARE_API_TOKEN for publish.

Operator only (\`--operator\` or SECURE_PUBLISH_OPERATOR=1) still writes KV directly:
  CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID
  SECURE_PUBLISH_KV_NAMESPACE_ID
  SECURE_PUBLISH_BASE_URL
  SECURE_PUBLISH_COMPANY_DOMAINS
  SECURE_PUBLISH_MOCK=1
  OAUTH_ALLOWED_DOMAINS
  SECURE_PUBLISH_API_BASE   default https://app.securepublish.work

Config files (optional):
  ./.secure-publish.json
  ~/.secure-publish/config.json
`.trim();

function generateKey() {
  return crypto.randomBytes(12).toString("hex");
}

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--title" || a === "-t") {
      args.flags.title = argv[++i] ?? "";
    } else if (a === "--name") {
      args.flags.name = argv[++i] ?? "";
    } else if (a === "--no-name") {
      args.flags.noName = true;
    } else if (a === "--to") {
      args.flags.to = argv[++i] ?? "";
    } else if (a === "--remote") {
      args.flags.remote = true;
    } else if (a === "--mock") {
      args.flags.mock = true;
    } else if (a === "--port") {
      args.flags.port = argv[++i] ?? "8787";
    } else if (a === "--lang") {
      args.flags.lang = argv[++i] ?? "pt";
    } else if (a === "--help" || a === "-h") {
      args.flags.help = true;
    } else if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("-")) {
        args.flags[key] = next;
        i++;
      } else {
        args.flags[key] = true;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function requireCf(cfg) {
  const missing = configHints(cfg);
  if (missing.length) {
    throw new Error(
      `Missing config: ${missing.join(", ")}\nRun: ${CLI} doctor`
    );
  }
}

function publicUrl(cfg, key) {
  if (cfg.mock) {
    const port = process.env.SECURE_PUBLISH_MOCK_PORT || "8787";
    return `http://127.0.0.1:${port}/${key}`;
  }
  const base = (cfg.baseUrl || `https://${cfg.workerName || "secure-publish"}.workers.dev`).replace(
    /\/$/,
    ""
  );
  return `${base}/${key}`;
}


async function appendKvIndex(cfg, indexKey, panelId) {
  let list = [];
  try {
    const raw = await kvGet({
      accountId: cfg.accountId,
      namespaceId: cfg.kvNamespaceId,
      token: cfg.apiToken,
      key: indexKey,
    });
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) list = parsed.map(String);
    }
  } catch {
    /* empty / missing index */
  }
  if (!list.includes(panelId)) list.push(panelId);
  await kvPut({
    accountId: cfg.accountId,
    namespaceId: cfg.kvNamespaceId,
    token: cfg.apiToken,
    key: indexKey,
    value: JSON.stringify(list),
  });
}

function encodeRecord({ html, title, access, publishedAt, publisherEmail }) {
  const rec = {
    v: 1,
    title,
    publishedAt,
    access,
    html,
  };
  if (publisherEmail) rec.publisherEmail = publisherEmail;
  return JSON.stringify(rec);
}

function decodeRecord(raw) {
  if (raw == null) return null;
  if (typeof raw === "object") return raw;
  const text = String(raw);
  try {
    const j = JSON.parse(text);
    if (j && typeof j.html === "string") return j;
  } catch {
    /* legacy raw HTML */
  }
  return { v: 0, html: text, access: { mode: "company", domains: [] } };
}


function sessionFile() {
  return path.join(os.homedir(), ".secure-publish", "session.json");
}

function apiBaseOf(cfg) {
  return String(
    process.env.SECURE_PUBLISH_API_BASE || cfg?.apiBase || "https://app.securepublish.work"
  ).replace(/\/$/, "");
}

function operatorMode(flags) {
  return Boolean(
    flags?.operator ||
      process.env.SECURE_PUBLISH_OPERATOR === "1" ||
      process.env.SECURE_PUBLISH_OPERATOR === "true"
  );
}

/** Local publish credential. Mode 0600. Never log the secret. */
function readPublishSession() {
  try {
    const raw = JSON.parse(fs.readFileSync(sessionFile(), "utf8"));
    const publishToken = String(raw?.publishToken || "").trim();
    if (!/^[a-f0-9]{64}$/.test(publishToken)) return null;
    if (raw.expiresAt && Date.parse(raw.expiresAt) <= Date.now()) return null;
    return {
      publishToken,
      email: raw.email || null,
      host: raw.host || null,
      apiBase: raw.apiBase || null,
      expiresAt: raw.expiresAt || null,
    };
  } catch {
    return null;
  }
}

function writePublishSession(session) {
  const file = sessionFile();
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(session, null, 2) + "\n", { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
}

function clearPublishSession() {
  try {
    fs.unlinkSync(sessionFile());
  } catch {
    /* absent */
  }
}

function openLoginUrl(url) {
  const cmd = process.platform === "darwin" ? "open" : "xdg-open";
  try {
    const child = spawn(cmd, [url], { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    /* caller prints the url */
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function cmdLogin(cfg) {
  const apiBase = apiBaseOf(cfg);
  const startRes = await fetch(`${apiBase}/api/device/code`, {
    method: "POST",
    headers: { accept: "application/json" },
  });
  const start = await startRes.json().catch(() => ({}));
  if (!startRes.ok || !start.verification_url || !start.device_code) {
    throw new Error("Não consegui abrir o login agora. Tenta de novo em instantes.");
  }
  console.log(start.verification_url);
  openLoginUrl(start.verification_url);
  const interval = Math.max(1, Number(start.interval) || 2) * 1000;
  const deadline = Date.now() + (Number(start.expires_in) || 600) * 1000;
  while (Date.now() < deadline) {
    await sleep(interval);
    const pollRes = await fetch(`${apiBase}/api/device/token`, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/json" },
      body: JSON.stringify({ device_code: start.device_code }),
    });
    const poll = await pollRes.json().catch(() => ({}));
    if (pollRes.ok && poll.access_token) {
      const expiresIn = Number(poll.expires_in) || 0;
      writePublishSession({
        publishToken: poll.access_token,
        email: poll.email || null,
        host: poll.host || null,
        apiBase,
        expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
      });
      if (poll.email) console.log(`email: ${poll.email}`);
      if (poll.host) console.log(`host: ${poll.host}`);
      else console.log("host:");
      return;
    }
    if (poll.error === "authorization_pending") continue;
    throw new Error("Não consegui ligar a conta agora. Tenta de novo em instantes.");
  }
  throw new Error("Não consegui ligar a conta agora. Tenta de novo em instantes.");
}

async function cmdLogout(cfg) {
  const session = readPublishSession();
  if (session?.publishToken) {
    const apiBase = (session.apiBase || apiBaseOf(cfg)).replace(/\/$/, "");
    try {
      await fetch(`${apiBase}/api/session/revoke`, {
        method: "POST",
        headers: { authorization: `Bearer ${session.publishToken}`, accept: "application/json" },
      });
    } catch {
      /* still drop the local file */
    }
  }
  clearPublishSession();
  console.log("Conta desligada nesta máquina.");
}

async function publishViaAccount(filePath, html, flags, cfg, toEmails) {
  const session = readPublishSession();
  if (!session) {
    throw new Error(`Conta não ligada nesta máquina. Rode ${CLI} login.`);
  }
  const apiBase = (session.apiBase || apiBaseOf(cfg)).replace(/\/$/, "");
  const title =
    flags.title || path.basename(filePath, path.extname(filePath)) || "untitled";
  const body = { html, title };
  if (toEmails.length) body.to = toEmails;
  if (typeof flags.name === "string" && flags.name !== "") body.name = flags.name;
  const res = await fetch(`${apiBase}/api/panels`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      authorization: `Bearer ${session.publishToken}`,
    },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  const host = data.host || session.host || "";
  if (!res.ok) {
    if (res.status === 401) clearPublishSession();
    const where = host ? ` A conta está ligada em ${host}.` : "";
    throw new Error(`Não consegui publicar agora.${where} Tenta de novo em instantes.`);
  }
  if (!data.url || !data.id) {
    throw new Error(
      `Não consegui publicar agora.${host ? ` A conta está ligada em ${host}.` : ""} Tenta de novo em instantes.`
    );
  }
  const lang = flags.lang === "en" ? "en" : "pt";
  const entry = {
    key: data.id,
    title: data.title || title,
    sourcePath: filePath,
    publishedAt: data.publishedAt || new Date().toISOString(),
    url: data.url,
    access: {
      mode: data.mode || (toEmails.length ? "allowlist" : "company"),
      emails: data.allowlist || toEmails,
    },
    mock: false,
  };
  upsertPanel(entry);
  console.log(
    publishSuccessMessage(
      { mode: entry.access.mode, url: data.url, emails: data.allowlist || toEmails },
      lang
    )
  );
  console.log(`key:    ${data.id}`);
  console.log(`title:  ${entry.title}`);
  console.log(`host:   ${data.host || host}`);
  return entry;
}

async function cmdPublish(fileArg, flags, cfg) {
  if (!fileArg) {
    throw new Error(
      `Usage: ${CLI} publish <file.html> [--title "..."] [--name "..."] [--to email,email]`
    );
  }
  const filePath = path.resolve(fileArg);
  if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
  const html = fs.readFileSync(filePath, "utf8");
  if (!html.trim()) throw new Error("HTML file is empty");

  const useMock = Boolean(flags.mock || cfg.mock);
  const useOperator = operatorMode(flags);
  const toEmails = parseToFlag(flags.to);
  if (flags.to !== undefined && flags.to !== true && toEmails.length === 0) {
    throw new Error(
      "Inclua pelo menos um e-mail em --to (ex.: --to ana@empresa.com)"
    );
  }

  const access = buildAccessMeta({
    toEmails,
    companyDomains: cfg.companyDomains,
  });

  if (!useMock && !useOperator) {
    return publishViaAccount(filePath, html, flags, cfg, toEmails);
  }
  if (!useMock) requireCf(cfg);

  if (access.mode === "company" && !access.domains.length && !useMock) {
    process.stderr.write(
      "warn: company-wide publish without companyDomains / OAUTH_ALLOWED_DOMAINS — edge will fail closed until domains are set.\n"
    );
  }

  const key = generateKey();
  const title =
    flags.title ||
    path.basename(filePath, path.extname(filePath)) ||
    "untitled";
  const publishedAt = new Date().toISOString();
  const publisherEmail = (
    process.env.SECURE_PUBLISH_PUBLISHER_EMAIL ||
    flags.publisher ||
    ""
  )
    .trim()
    .toLowerCase();
  const record = {
    v: 1,
    title,
    publishedAt,
    access,
    html,
  };
  if (publisherEmail) record.publisherEmail = publisherEmail;

  const lang = flags.lang === "en" ? "en" : "pt";

  if (useMock) {
    process.stderr.write(
      `Publishing ${path.basename(filePath)} → mock KV key ${key}…\n`
    );
    mockPut(key, record);
    if (publisherEmail) {
      const pubIdx = `idx:pub:${publisherEmail}`;
      const prev = mockGet(pubIdx);
      const list = Array.isArray(prev) ? prev.map(String) : [];
      if (!list.includes(key)) list.push(key);
      mockPut(pubIdx, list);
      const dom = publisherEmail.split("@")[1];
      if (dom) {
        const dIdx = `idx:domain:${dom}`;
        const dprev = mockGet(dIdx);
        const dlist = Array.isArray(dprev) ? dprev.map(String) : [];
        if (!dlist.includes(key)) dlist.push(key);
        mockPut(dIdx, dlist);
      }
    }
  } else {
    process.stderr.write(
      `Publishing ${path.basename(filePath)} → KV key ${key}…\n`
    );
    await kvPut({
      accountId: cfg.accountId,
      namespaceId: cfg.kvNamespaceId,
      token: cfg.apiToken,
      key,
      value: encodeRecord(record),
    });
    // Console API indexes (compatible with packages/edge/src/kv.js)
    if (publisherEmail) {
      await appendKvIndex(cfg, `idx:pub:${publisherEmail}`, key);
      const dom = publisherEmail.split("@")[1];
      if (dom) await appendKvIndex(cfg, `idx:domain:${dom}`, key);
    } else if (access.mode === "company" && access.domains?.[0]) {
      await appendKvIndex(cfg, `idx:domain:${access.domains[0]}`, key);
    }
  }

  const url = publicUrl({ ...cfg, mock: useMock }, key);
  const entry = {
    key,
    title,
    sourcePath: filePath,
    publishedAt,
    url,
    access,
    mock: useMock,
  };
  upsertPanel(entry);

  console.log(publishSuccessMessage({ mode: access.mode, url, emails: toEmails }, lang));
  console.log(`key:    ${key}`);
  console.log(`title:  ${title}`);
  console.log(
    `access: ${
      access.mode === "allowlist"
        ? `allowlist (${toEmails.join(", ")})`
        : `company (email domain: ${(access.domains.length ? access.domains : cfg.companyDomains).join(", ") || "(set OAUTH_ALLOWED_DOMAINS)"})`
    }`
  );
  console.log(
    "note:   URL identifies the panel; viewer needs SSO, then domain/allowlist ACL. Not org membership (V1)."
  );
  return entry;
}

async function cmdList(flags, cfg) {
  const reg = loadRegistry();
  console.log("Local registry (.secure-publish/registry.json):");
  if (!reg.panels.length) {
    console.log("  (empty)");
  } else {
    for (const p of reg.panels) {
      const mode = p.access?.mode || "?";
      console.log(
        `  ${p.key}  [${mode}]  ${p.title || "-"}  ${p.url || ""}  ${p.publishedAt || ""}`
      );
    }
  }

  if (flags.remote) {
    if (cfg.mock || flags.mock) {
      console.log("\nMock KV keys:");
      const keys = mockList();
      if (!keys.length) console.log("  (empty)");
      else for (const k of keys) console.log(`  ${k}`);
      return;
    }
    requireCf(cfg);
    console.log("\nRemote KV keys:");
    const keys = await kvList({
      accountId: cfg.accountId,
      namespaceId: cfg.kvNamespaceId,
      token: cfg.apiToken,
    });
    if (!keys.length) console.log("  (empty)");
    else for (const k of keys) console.log(`  ${k}`);
  }
}

/** First path segment of a panel URL or a bare id. */
export function parsePanelRef(ref) {
  const raw = String(ref || "").trim();
  if (!raw) return "";
  try {
    if (/^https?:\/\//i.test(raw)) {
      const u = new URL(raw);
      const parts = u.pathname.split("/").filter(Boolean);
      return parts[0] || "";
    }
  } catch {
    /* fall through */
  }
  const parts = raw.replace(/^\//, "").split("/").filter(Boolean);
  return parts[0] || "";
}

async function cmdRename(ref, flags, cfg) {
  const usage = `Usage: ${CLI} rename <id-or-url> --name <text>`;
  if (!ref) throw new Error(usage);
  const clear = flags.noName === true || flags.name === "";
  if (!clear && typeof flags.name !== "string") throw new Error(usage);

  const session = readPublishSession();
  if (!session) {
    throw new Error(`Conta não ligada nesta máquina. Rode ${CLI} login.`);
  }

  const id = parsePanelRef(ref);
  if (!id) throw new Error(usage);

  const apiBase = (session.apiBase || apiBaseOf(cfg)).replace(/\/$/, "");
  const res = await fetch(`${apiBase}/api/panels/${encodeURIComponent(id)}/name`, {
    method: "PATCH",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      authorization: `Bearer ${session.publishToken}`,
    },
    body: JSON.stringify({ name: clear ? null : flags.name }),
  });
  const data = await res.json().catch(() => ({}));
  const host = data.host || session.host || "";
  if (!res.ok) {
    if (res.status === 401) clearPublishSession();
    const where = host ? ` A conta está ligada em ${host}.` : "";
    throw new Error(`Não consegui alterar o nome agora.${where} Tenta de novo em instantes.`);
  }
  if (!data.url) {
    throw new Error(
      `Não consegui alterar o nome agora.${host ? ` A conta está ligada em ${host}.` : ""} Tenta de novo em instantes.`
    );
  }
  console.log(data.url);
  return data;
}

async function cmdRevoke(key, cfg, flags) {
  if (!key) throw new Error(`Usage: ${CLI} revoke <key>`);
  const useMock = Boolean(flags.mock || cfg.mock);

  process.stderr.write(`Revoking ${key}…\n`);
  if (useMock) {
    mockDelete(key);
  } else {
    requireCf(cfg);
    try {
      await kvDelete({
        accountId: cfg.accountId,
        namespaceId: cfg.kvNamespaceId,
        token: cfg.apiToken,
        key,
      });
    } catch (err) {
      if (err.status !== 404) throw err;
      process.stderr.write("KV key already absent (404).\n");
    }
  }

  const removed = removePanel(key);
  console.log(
    removed
      ? `Revoked ${key} (store + local registry).`
      : `Revoked ${key} from store (not in local registry).`
  );
}

async function cmdDoctor(cfg) {
  if (!cfg.mock && !operatorMode({})) {
    const lines = [`${CLI} doctor`, "─────────────────────"];
    const session = readPublishSession();
    if (session) {
      lines.push(`Status: conta ligada${session.email ? " (" + session.email + ")" : ""}.`);
      if (session.host) lines.push(`host: ${session.host}`);
      lines.push(`Next: ${CLI} publish <file.html>`);
    } else {
      lines.push("Status: conta não ligada nesta máquina.");
      lines.push(`Next: ${CLI} login`);
    }
    console.log(lines.join("\n"));
    return session ? 0 : 1;
  }
  const lines = [];
  lines.push(`${CLI} doctor`);
  lines.push("─────────────────────");
  lines.push(`Node:                 ${process.version}`);
  lines.push(`mock mode:            ${cfg.mock ? "ON" : "off"}`);
  lines.push(
    `CLOUDFLARE_API_TOKEN: ${
      cfg.apiToken ? "set (" + cfg.apiToken.slice(0, 6) + "…)" : "MISSING"
    }`
  );
  lines.push(`CLOUDFLARE_ACCOUNT_ID: ${cfg.accountId || "MISSING"}`);
  lines.push(`kvNamespaceId:        ${cfg.kvNamespaceId || "MISSING"}`);
  lines.push(
    `baseUrl:              ${
      cfg.baseUrl || "(not set — will use workers.dev pattern)"
    }`
  );
  lines.push(`workerName:           ${cfg.workerName}`);
  lines.push(
    `companyDomains:       ${
      cfg.companyDomains.length
        ? cfg.companyDomains.join(", ")
        : "(none — set SECURE_PUBLISH_COMPANY_DOMAINS / OAUTH_ALLOWED_DOMAINS)"
    }`
  );
  lines.push(`home config:          ${cfg.homeConfigPath}`);
  lines.push(`project config:       ${cfg.projectConfigPath}`);

  const missing = configHints(cfg);
  if (cfg.mock) {
    lines.push("");
    lines.push("Status: mock mode — Cloudflare not required.");
    lines.push("Next: npm run e2e:mock  OR  publish … --mock && mock-serve");
  } else if (missing.length) {
    lines.push("");
    lines.push(`Status: incomplete — missing ${missing.join(", ")}`);
    lines.push("");
    lines.push("Next steps (no secrets in git / chat):");
    if (!cfg.apiToken) {
      lines.push("  1. Ask John/ops for CLOUDFLARE_API_TOKEN (Workers KV Edit).");
      lines.push("     export CLOUDFLARE_API_TOKEN=…   # never commit");
    }
    if (!cfg.accountId) {
      lines.push("  2. export CLOUDFLARE_ACCOUNT_ID=…  (dash.cloudflare.com)");
    }
    if (!cfg.kvNamespaceId) {
      lines.push("  3. export SECURE_PUBLISH_KV_NAMESPACE_ID=…  (or wrangler kv namespace list)");
    }
    lines.push("  Or copy .env.example → .env / ~/.secure-publish/config.json");
    lines.push("  Without a token yet: SECURE_PUBLISH_MOCK=1 for local E2E.");
    if (!cfg.baseUrl) {
      lines.push("");
      lines.push("  Wildcard LIVE — set BASE_URL:");
      lines.push("    export SECURE_PUBLISH_BASE_URL=https://demo.securepublish.work");
      lines.push("  Or tenant: https://{slug}.securepublish.work  — docs/DEPLOY-WILDCARD.md");
      lines.push("  Fallback: https://secure-publish.clovist.workers.dev");
    }
  } else {
    lines.push("");
    lines.push("Status: config looks complete. Verifying token…");
    try {
      const v = await verifyToken(cfg.apiToken);
      lines.push(`Token verify: OK (${v.result?.status || "active"})`);
      lines.push("");
      lines.push(`Next: ${CLI} publish examples/panel-vendas.html --title \"…\"`);
      if (!cfg.baseUrl) {
        lines.push("  Tip: set SECURE_PUBLISH_BASE_URL=https://demo.securepublish.work");
      }
    } catch (err) {
      lines.push(`Token verify: FAILED — ${err.message}`);
      lines.push("Next: ask John to rotate/reissue CLOUDFLARE_API_TOKEN (KV Edit scope).");
    }
  }

  lines.push("");
  lines.push("ACL reminder (V1 Lock A):");
  lines.push("  Default publish = company email *domain* after SSO.");
  lines.push("  --to = explicit email allowlist.");
  lines.push("  Does NOT check Workspace / Entra / GitHub Org membership.");
  lines.push("  Panel URLs are NOT credentials — SSO session required.");
  lines.push("  Wildcard *.securepublish.work: LIVE — docs/DEPLOY-WILDCARD.md");

  console.log(lines.join("\n"));
  return cfg.mock || missing.length === 0 ? 0 : 1;
}

/**
 * Local mock edge: SSO simulated via X-Mock-User: email@domain
 * (or ?as=email). Demonstrates domain / --to ACL without Cloudflare.
 */
async function cmdMockServe(flags, cfg) {
  const port = Number(flags.port || process.env.SECURE_PUBLISH_MOCK_PORT || 8787);
  const companyDomains = normalizeDomains(
    cfg.companyDomains.length
      ? cfg.companyDomains
      : process.env.SECURE_PUBLISH_COMPANY_DOMAINS ||
          process.env.OAUTH_ALLOWED_DOMAINS ||
          "empresa.com"
  );

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    const parts = url.pathname.split("/").filter(Boolean);

    if (parts.length === 0) {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end(
        [
          "Secure Publish mock edge",
          "",
          "Pass viewer as header X-Mock-User: you@empresa.com",
          "or query ?as=you@empresa.com",
          `Company domains (V1): ${companyDomains.join(", ")}`,
          "GET /{panel-id}",
          "",
        ].join("\n")
      );
      return;
    }

    if (parts[0] === "_auth" || parts[0] === "health") {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end("ok\n");
      return;
    }

    const panelId = parts[0];
    if (!/^[0-9a-f]{24}$/i.test(panelId)) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("Not found — invalid or unknown panel id.\n");
      return;
    }

    const record = mockGet(panelId);
    if (!record) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("Not found — invalid or unknown panel id.\n");
      return;
    }

    const email = (
      req.headers["x-mock-user"] ||
      url.searchParams.get("as") ||
      ""
    )
      .toString()
      .trim()
      .toLowerCase();

    if (!email) {
      res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
      res.end(
        "Unauthorized — SSO required.\n" +
          "Mock: send X-Mock-User: you@empresa.com (simulates signed-in session).\n"
      );
      return;
    }

    const decoded = decodeRecord(record);
    const acl = checkPanelAccess(
      { email },
      decoded.access,
      { companyDomains }
    );
    if (!acl.ok) {
      const body = accessDeniedMessage(acl.reason, "pt") + "\n";
      res.writeHead(403, {
        "content-type": "text/plain; charset=utf-8",
        "x-secure-publish-acl": acl.reason || "denied",
      });
      res.end(body);
      return;
    }

    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
      "x-secure-publish": "mock-sso",
      "x-secure-publish-user": email,
    });
    res.end(decoded.html);
  });

  await new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", (err) => (err ? reject(err) : resolve()));
  });
  console.log(
    `${CLI} mock-serve on http://127.0.0.1:${port} (domains: ${companyDomains.join(", ")})`
  );
  console.log("Header X-Mock-User simulates SSO session. Ctrl+C to stop.");
  return server;
}

export async function main(argv) {
  const args = parseArgs(argv);
  const cmd = args._[0];

  if (!cmd || args.flags.help || cmd === "help" || cmd === "--help") {
    console.log(HELP);
    return;
  }

  const cfg = loadConfig();
  if (args.flags.mock) cfg.mock = true;

  switch (cmd) {
    case "login":
      await cmdLogin(cfg);
      break;
    case "logout":
      await cmdLogout(cfg);
      break;
    case "publish":
      await cmdPublish(args._[1], args.flags, cfg);
      break;
    case "rename":
      await cmdRename(args._[1], args.flags, cfg);
      break;
    case "list":
      await cmdList(args.flags, cfg);
      break;
    case "revoke":
      await cmdRevoke(args._[1], cfg, args.flags);
      break;
    case "doctor": {
      const code = await cmdDoctor(cfg);
      if (code) process.exitCode = code;
      break;
    }
    case "mock-serve":
      await cmdMockServe(args.flags, cfg);
      // keep process alive
      await new Promise(() => {});
      break;
    default:
      throw new Error(`Unknown command: ${cmd}\n\n${HELP}`);
  }
}
