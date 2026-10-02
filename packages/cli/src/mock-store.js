import fs from "node:fs";
import path from "node:path";

const DIR = ".secure-publish/mock-kv";

function kvDir(cwd = process.cwd()) {
  return path.join(cwd, DIR);
}

function keyPath(key, cwd = process.cwd()) {
  return path.join(kvDir(cwd), `${key}.json`);
}

export function mockPut(key, record, cwd = process.cwd()) {
  fs.mkdirSync(kvDir(cwd), { recursive: true });
  fs.writeFileSync(keyPath(key, cwd), JSON.stringify(record, null, 2) + "\n", "utf8");
}

export function mockGet(key, cwd = process.cwd()) {
  const file = keyPath(key, cwd);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function mockDelete(key, cwd = process.cwd()) {
  const file = keyPath(key, cwd);
  if (fs.existsSync(file)) fs.unlinkSync(file);
}

export function mockList(cwd = process.cwd()) {
  const dir = kvDir(cwd);
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.replace(/\.json$/, ""));
}
