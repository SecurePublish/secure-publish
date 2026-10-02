/**
 * End-to-end mock: publish company + allowlist, mock-serve, curl ACL cases.
 * Writes E2E-MOCK.txt at repo root.
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bin = path.join(root, "packages/cli/bin/secure-publish.js");
const outFile = path.join(root, "E2E-MOCK.txt");
const log = [];

function note(s) {
  log.push(s);
  process.stdout.write(s + "\n");
}

function run(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [bin, ...args], {
      cwd: root,
      env: { ...process.env, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`exit ${code}\n${stderr}\n${stdout}`));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

async function curl(url, headers = {}) {
  const res = await fetch(url, { headers, redirect: "manual" });
  const body = await res.text();
  return { status: res.status, body: body.slice(0, 400), headers: Object.fromEntries(res.headers) };
}

const env = {
  SECURE_PUBLISH_MOCK: "1",
  SECURE_PUBLISH_COMPANY_DOMAINS: "empresa.com",
  SECURE_PUBLISH_MOCK_PORT: "18791",
};

// clean mock store
const mockDir = path.join(root, ".secure-publish/mock-kv");
fs.rmSync(mockDir, { recursive: true, force: true });
fs.rmSync(path.join(root, ".secure-publish/registry.json"), { force: true });

note("=== Secure Publish E2E mock ===");
note(`when: ${new Date().toISOString()}`);
note("V1 Lock A: default = company email domain after SSO; --to = email allowlist.");
note("NOT Workspace/Entra/GitHub Org membership.");
note("");

const pubCompany = await run(
  ["publish", "examples/panel-vendas.html", "--title", "Painel Vendas Q3", "--mock"],
  env
);
note("--- publish company (no --to) ---");
note(pubCompany.stderr.trim());
note(pubCompany.stdout.trim());
const companyKey = pubCompany.stdout.match(/key:\s+(\S+)/)?.[1];
if (!companyKey) throw new Error("no company key");

const pubTo = await run(
  [
    "publish",
    "examples/panel-ops.html",
    "--title",
    "Ops",
    "--to",
    "ana@empresa.com,bia@empresa.com",
    "--mock",
  ],
  env
);
note("");
note("--- publish --to ---");
note(pubTo.stderr.trim());
note(pubTo.stdout.trim());
const toKey = pubTo.stdout.match(/key:\s+(\S+)/)?.[1];
if (!toKey) throw new Error("no --to key");

const server = spawn(
  process.execPath,
  [bin, "mock-serve", "--port", "18791"],
  { cwd: root, env: { ...process.env, ...env } }
);
let ready = "";
await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error("mock-serve timeout\n" + ready)), 8000);
  server.stdout.on("data", (d) => {
    ready += d.toString();
    if (ready.includes("mock-serve")) {
      clearTimeout(t);
      resolve();
    }
  });
  server.stderr.on("data", (d) => {
    ready += d.toString();
  });
  server.on("exit", (c) => {
    clearTimeout(t);
    reject(new Error("server exited " + c + " " + ready));
  });
});
note("");
note("--- mock-serve ---");
note(ready.trim());

const base = "http://127.0.0.1:18791";
const cases = [
  ["company no session", `${base}/${companyKey}`, {}, 403],
  ["company same domain", `${base}/${companyKey}`, { "X-Mock-User": "ana@empresa.com" }, 200],
  ["company other domain", `${base}/${companyKey}`, { "X-Mock-User": "ana@gmail.com" }, 403],
  ["allowlist listed", `${base}/${toKey}`, { "X-Mock-User": "ana@empresa.com" }, 200],
  ["allowlist same domain but not listed", `${base}/${toKey}`, { "X-Mock-User": "carla@empresa.com" }, 403],
  ["allowlist other domain", `${base}/${toKey}`, { "X-Mock-User": "ana@gmail.com" }, 403],
  ["unknown id", `${base}/deadbeefdeadbeefdeadbeef`, { "X-Mock-User": "ana@empresa.com" }, 404],
];

note("");
note("--- ACL cases ---");
let failed = 0;
for (const [name, url, headers, expect] of cases) {
  const r = await curl(url, headers);
  const ok = r.status === expect;
  if (!ok) failed++;
  const acl = r.headers["x-secure-publish-acl"] || "";
  note(
    `${ok ? "PASS" : "FAIL"}  ${name}  got ${r.status} expected ${expect}${acl ? "  acl=" + acl : ""}`
  );
  if (!ok || r.status !== 200) {
    note("      body: " + r.body.replace(/\n/g, " ").slice(0, 180));
  }
}

server.kill("SIGTERM");

note("");
note(failed === 0 ? "RESULT: ALL PASS" : `RESULT: ${failed} FAILED`);
fs.writeFileSync(outFile, log.join("\n") + "\n", "utf8");
note(`wrote ${outFile}`);
if (failed) process.exit(1);
