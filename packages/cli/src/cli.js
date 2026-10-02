import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import http from "node:http";
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

const HELP = `
secure-publish — publish AI HTML dashboards behind company SSO

Auth model:
  The URL path is the panel id (KV lookup only) — NOT a credential.
  Viewers must sign in (Cloudflare Access or Worker OAuth), then pass
  the panel ACL:
    default (no --to)  company-wide = same email *domain* as the tenant
                       (OAUTH_ALLOWED_DOMAINS / companyDomains).
                       NOT Workspace/Entra/GitHub Org membership (later).
    --to a@x,b@y       explicit email allowlist (still requires SSO)

Usage:
  secure-publish publish <file.html> [--title "..."] [--to email,email] [--mock]
  secure-publish list [--remote]
  secure-publish revoke <key>
  secure-publish doctor
  secure-publish mock-serve [--port 8787]
  secure-publish help

Environment:
  CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID
  SECURE_PUBLISH_KV_NAMESPACE_ID
  SECURE_PUBLISH_BASE_URL
  SECURE_PUBLISH_COMPANY_DOMAINS   tenant email domains (comma-separated)
  SECURE_PUBLISH_MOCK=1           local mock KV (no Cloudflare)
  OAUTH_ALLOWED_DOMAINS           same meaning on the Worker

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
      `Missing config: ${missing.join(", ")}\nRun: secure-publish doctor`
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

async function cmdPublish(fileArg, flags, cfg) {
  if (!fileArg) {
    throw new Error(
      'Usage: secure-publish publish <file.html> [--title "..."] [--to email,email]'
    );
  }
  const filePath = path.resolve(fileArg);
  if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
  const html = fs.readFileSync(filePath, "utf8");
  if (!html.trim()) throw new Error("HTML file is empty");

  const useMock = Boolean(flags.mock || cfg.mock);
  if (!useMock) requireCf(cfg);

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

async function cmdRevoke(key, cfg, flags) {
  if (!key) throw new Error("Usage: secure-publish revoke <key>");
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
  const lines = [];
  lines.push("secure-publish doctor");
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
  } else if (missing.length) {
    lines.push("");
    lines.push(`Status: incomplete — missing ${missing.join(", ")}`);
    lines.push("Create ~/.secure-publish/config.json or .secure-publish.json");
  } else {
    lines.push("");
    lines.push("Status: config looks complete. Verifying token…");
    try {
      const v = await verifyToken(cfg.apiToken);
      lines.push(`Token verify: OK (${v.result?.status || "active"})`);
    } catch (err) {
      lines.push(`Token verify: FAILED — ${err.message}`);
    }
  }

  lines.push("");
  lines.push("ACL reminder (V1 Lock A):");
  lines.push("  Default publish = company email *domain* after SSO.");
  lines.push("  --to = explicit email allowlist.");
  lines.push("  Does NOT check Workspace / Entra / GitHub Org membership.");
  lines.push("  Panel URLs are NOT credentials — SSO session required.");

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
    `secure-publish mock-serve on http://127.0.0.1:${port} (domains: ${companyDomains.join(", ")})`
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
    case "publish":
      await cmdPublish(args._[1], args.flags, cfg);
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
