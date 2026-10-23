import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import http from "node:http";
import { spawn } from "node:child_process";
import { loadConfig } from "./config.js";
import { loadRegistry, upsertPanel, removePanel } from "./registry.js";
import { mockPut, mockGet, mockDelete, mockList } from "./mock-store.js";
import {
  parseToFlag,
  buildAccessMeta,
  checkPanelAccess,
  accessDeniedMessage,
  publishSuccessMessage,
  normalizeDomains,
} from "./acl.js";
import {
  acceptLanguageHeader,
  fetchUploadLimit,
  isOverUploadLimit,
  sanitizeServerText,
  serverSizeErrorMessage,
} from "./upload-limit.js";
import { message, loginFailMessage, NPX_CLI, thrownErrorLine } from "./messages.js";

/** Sarah-final CLI login copy. Swap these strings only. */
const LOGIN_PROMPT = {
  pt: [
    "Para entrar nesta máquina, abra:",
    "{url}",
    "e digite este código:",
    "{user_code}",
    "Só digite se foi você que rodou este comando agora.",
  ],
  en: [
    "To sign in on this machine, open:",
    "{url}",
    "and enter this code:",
    "{user_code}",
    "Only enter it if you just ran this command yourself.",
  ],
};

function cliLang(flags) {
  return flags?.lang === "en" ? "en" : "pt";
}

const HELP = `
Secure Publish CLI — publish AI HTML dashboards behind company SSO

Auth model:
  The URL path is the panel id — NOT a credential.
  Viewers must sign in, then pass the panel ACL:
    default (no --to)  company-wide = same email *domain* as the account
    --to a@x,b@y       explicit email allowlist (still requires sign-in)

Usage:
  ${NPX_CLI} login
  ${NPX_CLI} login --finish
  ${NPX_CLI} login --wait
  ${NPX_CLI} publish <file.html> [--title "..."] [--name "..."] [--to email,email]
  ${NPX_CLI} rename <id-or-url> --name <text>
  ${NPX_CLI} rename <id-or-url> --no-name
  ${NPX_CLI} logout
  ${NPX_CLI} list
  ${NPX_CLI} revoke <id-or-url>
  ${NPX_CLI} doctor
  ${NPX_CLI} mock-serve [--port 8787]
  ${NPX_CLI} help

Run \`${NPX_CLI} login\` to print the URL and code (it flushes and exits at once), enter the code in the browser, then \`${NPX_CLI} login --finish\`. Publishing and revoke use that account. \`${NPX_CLI} login --wait\` keeps the old blocking flow.
Only the person who published a link or the company account owner can revoke it.

Optional:
  SECURE_PUBLISH_API_BASE   default https://app.securepublish.work
  SECURE_PUBLISH_MOCK=1     local mock store (no upload to the service)

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
    } else if (a === "--mock" || a.startsWith("--mock=")) {
      args.flags.removedMock = true;
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


function sessionDir() {
  return path.join(os.homedir(), ".secure-publish");
}

function sessionFile() {
  return path.join(sessionDir(), "session.json");
}

function pendingFile() {
  return path.join(sessionDir(), "device-pending.json");
}

function writeJson0600(file, data) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
}

function apiBaseOf(cfg) {
  return String(
    process.env.SECURE_PUBLISH_API_BASE || cfg?.apiBase || "https://app.securepublish.work"
  ).replace(/\/$/, "");
}

/** Local publish credential. Mode 0600. Never log the secret. */
function readPublishSession() {
  try {
    const raw = JSON.parse(fs.readFileSync(sessionFile(), "utf8"));
    const publishToken = String(raw?.publishToken || "").trim();
    if (!/^[a-f0-9]{64}$/.test(publishToken)) return null;
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
  writeJson0600(sessionFile(), session);
}

function writePendingDevice(pending) {
  writeJson0600(pendingFile(), pending);
}

function readPendingDevice() {
  try {
    const raw = JSON.parse(fs.readFileSync(pendingFile(), "utf8"));
    const device_code = String(raw?.device_code || "").trim();
    if (!device_code) return null;
    return {
      device_code,
      user_code: raw.user_code || null,
      verification_url: raw.verification_url || null,
      interval: raw.interval,
      expiresAt: raw.expiresAt || null,
      apiBase: raw.apiBase || null,
    };
  } catch {
    return null;
  }
}

function clearPendingDevice() {
  try {
    fs.unlinkSync(pendingFile());
  } catch {
    /* absent */
  }
}

function clearPublishSession() {
  try {
    fs.unlinkSync(sessionFile());
  } catch {
    /* absent */
  }
}

function openLoginUrl(url) {
  if (process.env.SECURE_PUBLISH_NO_BROWSER === "1") return;
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

function flushStream(stream) {
  return new Promise((resolve) => {
    if (!stream || typeof stream.write !== "function" || stream.destroyed) {
      resolve();
      return;
    }
    stream.write("", "utf8", () => resolve());
  });
}

/** Wait until stdout/stderr have drained so wrappers see the code before exit. */
async function flushStdio() {
  await flushStream(process.stdout);
  await flushStream(process.stderr);
}

function apiErrorCode(data) {
  return typeof data?.error === "string" ? data.error : "";
}

function throwIfNoHost(data, lang, key = "noHostPublish") {
  if (apiErrorCode(data) !== "no_host") return;
  throw new Error(message(key, lang));
}

function throwIfSessionUnauthorized(status, lang) {
  if (status !== 401) return;
  clearPublishSession();
  throw new Error(message("sessionExpired", lang));
}

function loginFail(code, lang) {
  const resolved = ["login_failed", "login_expired", "login_denied", "login_no_pending"].includes(
    code
  )
    ? code
    : "login_failed";
  console.error(`error: ${resolved}`);
  console.error(loginFailMessage(resolved, lang));
  process.exitCode = 1;
}

async function cmdLogin(cfg, flags = {}) {
  if (flags.finish) {
    await cmdLoginFinish(cfg, flags);
    return;
  }
  await cmdLoginStart(cfg, flags);
  if (process.exitCode) return;
  if (flags.wait) await cmdLoginFinish(cfg, flags);
}

async function cmdLoginStart(cfg, flags = {}) {
  const apiBase = apiBaseOf(cfg);
  const lang = cliLang(flags);
  let startRes;
  try {
    startRes = await fetch(`${apiBase}/api/device/code`, {
      method: "POST",
      headers: { accept: "application/json" },
    });
  } catch {
    loginFail("login_failed", lang);
    return;
  }
  const start = await startRes.json().catch(() => ({}));
  if (!startRes.ok || !start.verification_url || !start.device_code || !start.user_code) {
    loginFail("login_failed", lang);
    return;
  }
  writePendingDevice({
    device_code: start.device_code,
    user_code: start.user_code,
    verification_url: start.verification_url,
    interval: Math.max(1, Number(start.interval) || 2),
    expiresAt: new Date(Date.now() + (Number(start.expires_in) || 600) * 1000).toISOString(),
    apiBase,
  });
  for (const line of LOGIN_PROMPT[lang]) {
    console.log(
      line.replace("{url}", start.verification_url).replace("{user_code}", start.user_code)
    );
  }
  openLoginUrl(start.verification_url);
  await flushStdio();
}

async function cmdLoginFinish(cfg, flags = {}) {
  const lang = cliLang(flags);
  const pending = readPendingDevice();
  if (!pending?.device_code) {
    loginFail("login_no_pending", lang);
    return;
  }
  const expiresAtMs = Date.parse(pending.expiresAt);
  if (Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now()) {
    clearPendingDevice();
    loginFail("login_expired", lang);
    return;
  }
  const apiBase = String(pending.apiBase || apiBaseOf(cfg)).replace(/\/$/, "");
  let interval = Math.max(1, Number(pending.interval) || 2) * 1000;
  const deadline = Number.isFinite(expiresAtMs) ? expiresAtMs : Date.now() + 600_000;

  while (Date.now() < deadline) {
    await sleep(interval);
    if (Date.now() >= deadline) break;
    let pollRes;
    let poll;
    try {
      pollRes = await fetch(`${apiBase}/api/device/token`, {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify({ device_code: pending.device_code }),
      });
      poll = await pollRes.json().catch(() => ({}));
    } catch {
      loginFail("login_failed", lang);
      return;
    }
    if (pollRes.ok && poll.access_token) {
      const expiresIn = Number(poll.expires_in) || 0;
      const host = String(poll.host || "").trim() || null;
      writePublishSession({
        publishToken: poll.access_token,
        email: poll.email || null,
        host,
        apiBase,
        expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString(),
      });
      clearPendingDevice();
      if (poll.email) console.log(`email: ${poll.email}`);
      if (host) console.log(`host: ${host}`);
      else {
        console.log("host:");
        console.log(message("noHostLogin", lang));
      }
      return;
    }
    if (poll.error === "authorization_pending") continue;
    if (poll.error === "slow_down") {
      interval += 5000;
      continue;
    }
    if (poll.error === "access_denied") {
      clearPendingDevice();
      loginFail("login_denied", lang);
      return;
    }
    if (poll.error === "expired_token") {
      clearPendingDevice();
      loginFail("login_expired", lang);
      return;
    }
    clearPendingDevice();
    loginFail("login_failed", lang);
    return;
  }
  clearPendingDevice();
  loginFail("login_expired", lang);
}

async function cmdLogout(cfg, flags = {}) {
  const lang = cliLang(flags);
  const session = readPublishSession();
  if (session?.publishToken) {
    const apiBase = (session.apiBase || apiBaseOf(cfg)).replace(/\/$/, "");
    let status;
    try {
      const res = await fetch(`${apiBase}/api/session/revoke`, {
        method: "POST",
        headers: { authorization: `Bearer ${session.publishToken}`, accept: "application/json" },
      });
      status = res.status;
    } catch {
      console.log(message("logoutKeepLocal", lang));
      process.exitCode = 1;
      return;
    }
    if (!((status >= 200 && status < 300) || status === 401)) {
      console.log(message("logoutKeepLocal", lang));
      process.exitCode = 1;
      return;
    }
  }
  clearPublishSession();
  console.log(message("logoutDone", lang));
}

async function publishViaAccount(filePath, html, flags, cfg, toEmails) {
  const session = readPublishSession();
  if (!session) {
    throw new Error(message("notLoggedIn", cliLang(flags)));
  }
  const apiBase = (session.apiBase || apiBaseOf(cfg)).replace(/\/$/, "");
  const title =
    flags.title || path.basename(filePath, path.extname(filePath)) || "untitled";
  const body = { html, title };
  if (toEmails.length) body.to = toEmails;
  if (typeof flags.name === "string" && flags.name !== "") body.name = flags.name;
  const payload = JSON.stringify(body);
  const lang = cliLang(flags);
  const limit = await fetchUploadLimit({ apiBase, lang });
  // upload.maxBytes is the decoded HTML limit, not the JSON envelope.
  if (
    limit &&
    isOverUploadLimit(Buffer.byteLength(body.html, "utf8"), limit.maxBytes)
  ) {
    throw new Error(sanitizeServerText(limit.message));
  }
  const res = await fetch(`${apiBase}/api/panels`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "accept-language": acceptLanguageHeader(lang),
      "content-type": "application/json",
      authorization: `Bearer ${session.publishToken}`,
    },
    body: payload,
  });
  const raw = await res.text();
  let data = {};
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = {};
  }
  const host = data.host || session.host || "";
  if (res.status === 413) {
    throw new Error(serverSizeErrorMessage(raw, lang));
  }
  throwIfNoHost(data, lang, "noHostPublish");
  throwIfSessionUnauthorized(res.status, lang);
  if (!res.ok) {
    throw new Error(message("publishRetry", lang, host));
  }
  if (!data.url || !data.id) {
    throw new Error(message("publishRetry", lang, host));
  }
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
  printCopyValue("key:", data.id);
  console.log(`title:  ${entry.title}`);
  console.log(`host:   ${data.host || host}`);
  return entry;
}

async function cmdPublish(fileArg, flags, cfg) {
  if (!fileArg) {
    throw new Error(
      `Usage: ${NPX_CLI} publish <file.html> [--title "..."] [--name "..."] [--to email,email]`
    );
  }
  const filePath = path.resolve(fileArg);
  if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
  const html = fs.readFileSync(filePath, "utf8");
  if (!html.trim()) throw new Error("HTML file is empty");

  const useMock = Boolean(cfg.mock);
  const toEmails = parseToFlag(flags.to);
  if (flags.to !== undefined && flags.to !== true && toEmails.length === 0) {
    throw new Error(message("missingToEmail", cliLang(flags)));
  }

  const access = buildAccessMeta({
    toEmails,
    companyDomains: cfg.companyDomains,
  });

  if (!useMock) {
    return publishViaAccount(filePath, html, flags, cfg, toEmails);
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

  console.log(message("mockPublishSuccess", lang));
  printCopyValue("key:", key);
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

  if (flags.remote && cfg.mock) {
    console.log("\nMock store keys:");
    const keys = mockList();
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
  const usage = `Usage: ${NPX_CLI} rename <id-or-url> --name <text>`;
  if (!ref) throw new Error(usage);
  const clear = flags.noName === true || flags.name === "";
  if (!clear && typeof flags.name !== "string") throw new Error(usage);

  const session = readPublishSession();
  if (!session) {
    throw new Error(message("notLoggedIn", cliLang(flags)));
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
  const lang = cliLang(flags);
  throwIfNoHost(data, lang, "noHostRename");
  throwIfSessionUnauthorized(res.status, lang);
  if (!res.ok) {
    throw new Error(message("renameRetry", lang, host));
  }
  if (!data.url) {
    throw new Error(message("renameRetry", lang, host));
  }
  console.log(data.url);
  return data;
}

function printCopyValue(label, value) {
  console.log(label);
  console.log(value);
}

async function cmdRevoke(ref, cfg, flags) {
  const usage = `Usage: ${NPX_CLI} revoke <id-or-url>`;
  if (!ref) throw new Error(usage);

  const id = parsePanelRef(ref);
  if (!id) throw new Error(usage);

  const useMock = Boolean(cfg.mock);
  if (useMock) {
    mockDelete(id);
    removePanel(id);
    printCopyValue("Removed:", id);
    return;
  }

  const session = readPublishSession();
  if (!session) {
    throw new Error(message("notLoggedIn", cliLang(flags)));
  }

  const apiBase = (session.apiBase || apiBaseOf(cfg)).replace(/\/$/, "");
  let res;
  try {
    res = await fetch(`${apiBase}/api/panels/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${session.publishToken}`,
      },
    });
  } catch {
    throw new Error(message("revokeNetwork", cliLang(flags)));
  }

  const lang = cliLang(flags);
  throwIfSessionUnauthorized(res.status, lang);
  if (res.status === 403) {
    throw new Error(message("revokeForbidden", lang));
  }
  if (res.status !== 200 && res.status !== 404) {
    throw new Error(message("revokeRetry", lang));
  }

  removePanel(id);
  printCopyValue("Removed:", id);
}

async function cmdDoctor(cfg, flags = {}) {
  const lang = cliLang(flags);
  const lines = ["Secure Publish CLI", "─────────────────────"];
  if (cfg.mock) {
    lines.push("Status: mock mode.");
    lines.push(`Next: ${NPX_CLI} publish <file.html>`);
    console.log(lines.join("\n"));
    return 0;
  }
  const session = readPublishSession();
  if (session) {
    lines.push(message("doctorSignedIn", lang, session.email || ""));
    if (session.host) lines.push(`host: ${session.host}`);
    lines.push(`Next: ${NPX_CLI} publish <file.html>`);
  } else {
    lines.push(message("doctorNotSignedIn", lang));
    lines.push(`Next: ${NPX_CLI} login`);
  }
  console.log(lines.join("\n"));
  return session ? 0 : 1;
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
    `Secure Publish CLI mock-serve on http://127.0.0.1:${port} (domains: ${companyDomains.join(", ")})`
  );
  console.log("Header X-Mock-User simulates SSO session. Ctrl+C to stop.");
  return server;
}

export async function main(argv) {
  const args = parseArgs(argv);
  const lang = cliLang(args.flags);
  if (args.flags.removedMock) {
    console.error(thrownErrorLine(new Error(message("removedMockFlag", lang)), lang));
    process.exitCode = 1;
    return;
  }
  const cmd = args._[0];

  if (!cmd || args.flags.help || cmd === "help" || cmd === "--help") {
    console.log(HELP);
    return;
  }

  const cfg = loadConfig();
  if (cfg.ignoredProjectMock) {
    console.error(message("ignoredProjectMock", lang));
  }

  switch (cmd) {
    case "login":
      await cmdLogin(cfg, args.flags);
      break;
    case "logout":
      await cmdLogout(cfg, args.flags);
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
      const code = await cmdDoctor(cfg, args.flags);
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
