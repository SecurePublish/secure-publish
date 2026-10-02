import fs from "node:fs";
import path from "node:path";

const REGISTRY_DIR = ".secure-publish";
const REGISTRY_FILE = "registry.json";

function registryPath(cwd = process.cwd()) {
  return path.join(cwd, REGISTRY_DIR, REGISTRY_FILE);
}

export function loadRegistry(cwd = process.cwd()) {
  const file = registryPath(cwd);
  try {
    if (!fs.existsSync(file)) return { panels: [] };
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!Array.isArray(data.panels)) data.panels = [];
    return data;
  } catch {
    return { panels: [] };
  }
}

export function saveRegistry(data, cwd = process.cwd()) {
  const dir = path.join(cwd, REGISTRY_DIR);
  fs.mkdirSync(dir, { recursive: true });
  const file = registryPath(cwd);
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n", "utf8");
  return file;
}

export function upsertPanel(entry, cwd = process.cwd()) {
  const reg = loadRegistry(cwd);
  const idx = reg.panels.findIndex((p) => p.key === entry.key);
  if (idx >= 0) reg.panels[idx] = { ...reg.panels[idx], ...entry };
  else reg.panels.push(entry);
  saveRegistry(reg, cwd);
  return reg;
}

export function removePanel(key, cwd = process.cwd()) {
  const reg = loadRegistry(cwd);
  const before = reg.panels.length;
  reg.panels = reg.panels.filter((p) => p.key !== key);
  saveRegistry(reg, cwd);
  return before !== reg.panels.length;
}
