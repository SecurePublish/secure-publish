/**
 * Named panel links: 10-char codes, name normalization, canonical redirects,
 * access-before-301, panel-path headers, PATCH name, API path field.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import worker from "../src/worker.js";
import {
  PANEL_CODE_ALPHABET,
  PANEL_ID_RE,
  generatePanelCode,
  normalizePanelName,
  panelPath,
} from "../src/kv.js";
import { mintSessionCookie } from "../src/sso.js";

function memoryKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, String(value));
    },
    async delete(key) {
      store.delete(key);
    },
    async list({ prefix = "", limit = 1000 } = {}) {
      const keys = [...store.keys()]
        .filter((k) => k.startsWith(prefix))
        .sort()
        .map((name) => ({ name }));
      return { keys: keys.slice(0, limit), list_complete: true };
    },
    _store: store,
  };
}

const CODE = "k7f3qx2abc";
const LEGACY = "aaaaaaaaaaaaaaaaaaaaaaaa";
const NAME = "performance-out-26";
const HTML = "<html>named-panel</html>";
const OWNER = "ana@wises.com.br";
const VIEWER = "bob@wises.com.br";
const PANEL_404 = "Not found — invalid or unknown panel id.";

function namedRecord(extra = {}) {
  return {
    v: 1,
    title: "Performance Outubro",
    publishedAt: "2026-10-08T12:00:00Z",
    publisherEmail: OWNER,
    access: { mode: "allowlist", emails: [OWNER] },
    html: HTML,
    name: NAME,
    ...extra,
  };
}

function tenantKv(record, id = CODE) {
  return memoryKv({
    [id]: JSON.stringify(record),
    [`idx:pub:${OWNER}`]: JSON.stringify([id]),
    "host:sub:wise": OWNER,
    [`tenant:user:${OWNER}`]: JSON.stringify({
      email: OWNER,
      slug: "wise",
      host: "wise.securepublish.work",
    }),
  });
}

function oauthEnv(panels, extra = {}) {
  return {
    PANELS: panels,
    SESSION_SECRET: "test-session-secret-at-least-32-chars!!",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
    OAUTH_ALLOWED_DOMAINS: "wises.com.br",
    ...extra,
  };
}

function bypassEnv(panels) {
  return {
    PANELS: panels,
    SSO_DEV_BYPASS: "1",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
    OAUTH_ALLOWED_DOMAINS: "localhost",
  };
}

async function cookieFor(env, email) {
  const setCookie = await mintSessionCookie(
    {
      email,
      provider: "google",
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    env.SESSION_SECRET,
    env,
    "https://app.securepublish.work/_auth/callback/google"
  );
  return setCookie.split(";")[0];
}

function panelReq(path, { cookie, host = "wise.securepublish.work" } = {}) {
  const headers = { Host: host };
  if (cookie) headers.Cookie = cookie;
  return new Request(`https://${host}${path}`, { headers, redirect: "manual" });
}

function assertPanelPathHeaders(res) {
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  assert.equal(res.headers.get("x-robots-tag"), "noindex, nofollow");
}

describe("panel code generation", () => {
  it("alphabet is lowercase base32 and codes are 10 chars from getRandomValues via byte & 31", () => {
    assert.equal(PANEL_CODE_ALPHABET, "abcdefghijklmnopqrstuvwxyz234567");
    assert.equal(PANEL_CODE_ALPHABET.length, 32);

    const orig = crypto.getRandomValues;
    crypto.getRandomValues = (arr) => {
      const src = [0, 1, 31, 32, 33, 255, 64, 65, 7, 8];
      for (let i = 0; i < 10; i++) arr[i] = src[i];
      return arr;
    };
    try {
      const code = generatePanelCode();
      assert.equal(code.length, 10);
      const expected = [0, 1, 31, 32, 33, 255, 64, 65, 7, 8]
        .map((b) => PANEL_CODE_ALPHABET[b & 31])
        .join("");
      assert.equal(code, expected);
      assert.match(code, /^[abcdefghijklmnopqrstuvwxyz234567]{10}$/);
    } finally {
      crypto.getRandomValues = orig;
    }
  });

  it("source maps bytes with & 31 and does not use Math.random or %", () => {
    const src = fs.readFileSync(
      fileURLToPath(new URL("../src/kv.js", import.meta.url)),
      "utf8"
    );
    const fn = src.slice(
      src.indexOf("export function generatePanelCode"),
      src.indexOf("export function generatePanelCode") + 500
    );
    assert.match(fn, /getRandomValues/);
    assert.match(fn, /&\s*31/);
    assert.doesNotMatch(fn, /Math\.random/);
    assert.doesNotMatch(fn, /%\s*32/);
  });

  it("PANEL_ID_RE accepts 10-char codes and legacy 24-hex", () => {
    assert.equal(PANEL_ID_RE.test(CODE), true);
    assert.equal(PANEL_ID_RE.test(LEGACY), true);
    assert.equal(PANEL_ID_RE.test("ABCDEF2345"), true);
    assert.equal(PANEL_ID_RE.test("a7k2m9"), false);
    assert.equal(PANEL_ID_RE.test("api"), false);
    assert.equal(PANEL_ID_RE.test("auth"), false);
    assert.equal(PANEL_ID_RE.test("_auth"), false);
    assert.equal(PANEL_ID_RE.test("assets"), false);
  });
});

describe("normalizePanelName", () => {
  it("normalizes Performance — Outubro 2026", () => {
    assert.equal(
      normalizePanelName("Performance — Outubro 2026"),
      "performance-outubro-2026"
    );
  });

  it("strips accents", () => {
    assert.equal(normalizePanelName("São Paulo — Relatório"), "sao-paulo-relatorio");
    assert.equal(normalizePanelName("Ação / Relatório"), "acao-relatorio");
  });

  it("cuts 61+ chars at a hyphen boundary when possible", () => {
    const input =
      "aaaaaaaaaa-bbbbbbbbbb-cccccccccc-dddddddddd-eeeeeeeeee-ffffffff";
    const out = normalizePanelName(input);
    assert.ok(out.length <= 60);
    assert.equal(out, "aaaaaaaaaa-bbbbbbbbbb-cccccccccc-dddddddddd-eeeeeeeeee");
    assert.equal(normalizePanelName("a".repeat(61)), "a".repeat(60));
  });

  it("all-symbols and empty become null", () => {
    assert.equal(normalizePanelName("!!! ---"), null);
    assert.equal(normalizePanelName("@@@"), null);
    assert.equal(normalizePanelName(""), null);
    assert.equal(normalizePanelName("   "), null);
    assert.equal(normalizePanelName(null), null);
  });

  it("trims leading/trailing hyphens and lowercases", () => {
    assert.equal(normalizePanelName("-Hello--World-"), "hello-world");
  });
});

describe("named panel serving", () => {
  it("legacy 24-hex still served at /{24hex} and /{24hex}/{name}", async () => {
    const panels = tenantKv(namedRecord(), LEGACY);
    const env = oauthEnv(panels);
    const cookie = await cookieFor(env, OWNER);

    const bare = await worker.fetch(panelReq(`/${LEGACY}`, { cookie }), env);
    assert.equal(bare.status, 200);
    assert.equal(await bare.text(), HTML);
    assertPanelPathHeaders(bare);
    assert.equal(bare.headers.get("cache-control"), "no-store");

    const named = await worker.fetch(
      panelReq(`/${LEGACY}/${NAME}`, { cookie }),
      env
    );
    assert.equal(named.status, 200);
    assert.equal(await named.text(), HTML);
  });

  it("/{code} serves the panel with no redirect even when named", async () => {
    const env = oauthEnv(tenantKv(namedRecord()));
    const cookie = await cookieFor(env, OWNER);
    const res = await worker.fetch(panelReq(`/${CODE}`, { cookie }), env);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("location"), null);
    assert.equal(await res.text(), HTML);
    assertPanelPathHeaders(res);
  });

  it("wrong/old name 301s to a relative canonical path only after access passes", async () => {
    const env = oauthEnv(tenantKv(namedRecord()));
    const cookie = await cookieFor(env, OWNER);

    const res = await worker.fetch(
      panelReq(`/${CODE}/old-or-wrong`, { cookie }),
      env
    );
    assert.equal(res.status, 301);
    assert.equal(res.headers.get("location"), `/${CODE}/${NAME}`);
    assert.ok(!/^https?:/i.test(res.headers.get("location")));
    assert.equal(res.headers.get("cache-control"), "private, no-store");
    assertPanelPathHeaders(res);
    const loc = res.headers.get("location");
    assert.ok(!loc.includes("old-or-wrong"));
    assert.ok(!loc.includes("http"));
  });

  it("no-name panel: /{code}/anything 301s to /{code}", async () => {
    const env = oauthEnv(tenantKv(namedRecord({ name: null })));
    const cookie = await cookieFor(env, OWNER);
    const res = await worker.fetch(
      panelReq(`/${CODE}/leftover`, { cookie }),
      env
    );
    assert.equal(res.status, 301);
    assert.equal(res.headers.get("location"), `/${CODE}`);
    assert.equal(res.headers.get("cache-control"), "private, no-store");
    assertPanelPathHeaders(res);
  });

  it("signed-in without access: /{code}/wrong-name is the same 403 as /{code}; no Location; name not in body", async () => {
    const env = oauthEnv(tenantKv(namedRecord()));
    const cookie = await cookieFor(env, VIEWER);

    const withName = await worker.fetch(
      panelReq(`/${CODE}/wrong-name`, { cookie }),
      env
    );
    const bare = await worker.fetch(panelReq(`/${CODE}`, { cookie }), env);

    assert.equal(withName.status, 403);
    assert.equal(bare.status, 403);
    const bodyNamed = await withName.text();
    const bodyBare = await bare.text();
    assert.equal(bodyNamed, bodyBare);
    assert.equal(withName.headers.get("location"), null);
    assert.equal(bare.headers.get("location"), null);
    assert.ok(!bodyNamed.includes(NAME));
    assert.ok(!bodyNamed.includes("performance"));
    assertPanelPathHeaders(withName);
    assertPanelPathHeaders(bare);
  });

  it("unauthenticated: login redirect may carry requested path, never the current name", async () => {
    const env = oauthEnv(tenantKv(namedRecord()));
    const res = await worker.fetch(
      panelReq(`/${CODE}/wrong-name`),
      env
    );
    assert.equal(res.status, 302);
    const loc = res.headers.get("location") || "";
    const body = await res.text();
    assert.match(loc, /\/_auth\/login/);
    assert.ok(loc.includes("wrong-name") || loc.includes(encodeURIComponent("/" + CODE + "/wrong-name")) || loc.includes(`/${CODE}/wrong-name`));
    assert.ok(!loc.includes(NAME), `current name leaked in Location: ${loc}`);
    assert.ok(!body.includes(NAME));
    assertPanelPathHeaders(res);
  });

  it("unknown code 404 is identical to today", async () => {
    const env = oauthEnv(tenantKv(namedRecord()));
    const cookie = await cookieFor(env, OWNER);
    const res = await worker.fetch(
      panelReq("/zzzzz23456", { cookie }),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(await res.text(), PANEL_404);
    assertPanelPathHeaders(res);
  });

  it("headers present on 200/301/302/403/404 panel paths", async () => {
    const env = oauthEnv(tenantKv(namedRecord()));
    const cookie = await cookieFor(env, OWNER);
    const statuses = {};

    const ok = await worker.fetch(panelReq(`/${CODE}/${NAME}`, { cookie }), env);
    statuses[200] = ok;
    const redir = await worker.fetch(panelReq(`/${CODE}/nope`, { cookie }), env);
    statuses[301] = redir;
    const login = await worker.fetch(panelReq(`/${CODE}`), env);
    statuses[302] = login;
    const denied = await worker.fetch(
      panelReq(`/${CODE}`, { cookie: await cookieFor(env, VIEWER) }),
      env
    );
    statuses[403] = denied;
    const missing = await worker.fetch(panelReq("/yyyyy23456", { cookie }), env);
    statuses[404] = missing;

    assert.equal(ok.status, 200);
    assert.equal(redir.status, 301);
    assert.equal(login.status, 302);
    assert.equal(denied.status, 403);
    assert.equal(missing.status, 404);
    for (const res of Object.values(statuses)) assertPanelPathHeaders(res);
  });

  it("does not shadow /_auth, /auth, /api", async () => {
    const env = oauthEnv(tenantKv(namedRecord()));
    const providers = await worker.fetch(
      new Request("https://wise.securepublish.work/auth/providers", {
        headers: { Host: "wise.securepublish.work" },
        redirect: "manual",
      }),
      env
    );
    assert.equal(providers.status, 200);
    const body = await providers.json();
    assert.ok(Array.isArray(body.providers));

    const api = await worker.fetch(
      new Request("https://wise.securepublish.work/api/me", {
        headers: { Host: "wise.securepublish.work" },
        redirect: "manual",
      }),
      env
    );
    assert.notEqual(api.status, 200);
    assert.notEqual(await api.text(), HTML);

    const authLogin = await worker.fetch(
      new Request("https://wise.securepublish.work/_auth/login", {
        headers: { Host: "wise.securepublish.work" },
        redirect: "manual",
      }),
      env
    );
    assert.notEqual(authLogin.status, 404);
    assert.notEqual(await authLogin.text(), PANEL_404);
  });
});

describe("POST/GET/PATCH panel name + path", () => {
  it("POST /api/panels accepts name, returns canonical url, path, normalized name, 10-char id", async () => {
    const panels = memoryKv({
      [`tenant:user:dev@localhost`]: JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
      "host:sub:wise": "dev@localhost",
    });
    const env = bypassEnv(panels);
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: {
          Origin: "https://app.securepublish.work",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          html: "<p>x</p>",
          title: "Performance",
          name: "Performance — Outubro 2026",
        }),
      }),
      env
    );
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.match(body.id, /^[abcdefghijklmnopqrstuvwxyz234567]{10}$/);
    assert.equal(body.name, "performance-outubro-2026");
    assert.equal(body.path, `/${body.id}/performance-outubro-2026`);
    assert.equal(
      body.url,
      `https://wise.securepublish.work/${body.id}/performance-outubro-2026`
    );
    const stored = JSON.parse(panels._store.get(body.id));
    assert.equal(stored.name, "performance-outubro-2026");
  });

  it("GET /api/panels items include name, canonical url, and path", async () => {
    const panels = memoryKv({
      [CODE]: JSON.stringify(
        namedRecord({
          publisherEmail: "dev@localhost",
          access: { mode: "company", domains: ["localhost"] },
        })
      ),
      "idx:pub:dev@localhost": JSON.stringify([CODE]),
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
    });
    const env = bypassEnv(panels);
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels?scope=mine", {
        headers: { Origin: "https://app.securepublish.work" },
      }),
      env
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    const p = body.panels.find((x) => x.id === CODE);
    assert.ok(p);
    assert.equal(p.name, NAME);
    assert.equal(p.path, `/${CODE}/${NAME}`);
    assert.equal(p.url, `https://wise.securepublish.work/${CODE}/${NAME}`);
  });

  it("GET path for legacy unnamed 24-hex is /{24hex}", async () => {
    const panels = memoryKv({
      [LEGACY]: JSON.stringify({
        v: 1,
        title: "Old",
        publishedAt: "2026-01-01T00:00:00Z",
        publisherEmail: "dev@localhost",
        access: { mode: "company", domains: ["localhost"] },
        html: "<p>old</p>",
      }),
      "idx:pub:dev@localhost": JSON.stringify([LEGACY]),
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
    });
    const env = bypassEnv(panels);
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels?scope=mine", {
        headers: { Origin: "https://app.securepublish.work" },
      }),
      env
    );
    const p = (await res.json()).panels.find((x) => x.id === LEGACY);
    assert.ok(p);
    assert.equal(p.name, null);
    assert.equal(p.path, `/${LEGACY}`);
    assert.equal(p.url, `https://wise.securepublish.work/${LEGACY}`);
  });

  it("PATCH /api/panels/:id/name is publisher only and returns id, name, url, path", async () => {
    const panels = tenantKv(namedRecord({ name: "old-name" }), CODE);
    const env = oauthEnv(panels);
    const ownerCookie = await cookieFor(env, OWNER);
    const otherCookie = await cookieFor(env, VIEWER);

    const forbidden = await worker.fetch(
      new Request(`https://app.securepublish.work/api/panels/${CODE}/name`, {
        method: "PATCH",
        headers: {
          Origin: "https://app.securepublish.work",
          "content-type": "application/json",
          Cookie: otherCookie,
        },
        body: JSON.stringify({ name: "hacked" }),
      }),
      env
    );
    assert.equal(forbidden.status, 403);
    const stored = JSON.parse(panels._store.get(CODE));
    assert.equal(stored.name, "old-name");

    const ok = await worker.fetch(
      new Request(`https://app.securepublish.work/api/panels/${CODE}/name`, {
        method: "PATCH",
        headers: {
          Origin: "https://app.securepublish.work",
          "content-type": "application/json",
          Cookie: ownerCookie,
        },
        body: JSON.stringify({ name: "Performance — Outubro 2026" }),
      }),
      env
    );
    assert.equal(ok.status, 200);
    const body = await ok.json();
    assert.equal(body.id, CODE);
    assert.equal(body.name, "performance-outubro-2026");
    assert.equal(body.path, `/${CODE}/performance-outubro-2026`);
    assert.equal(
      body.url,
      `https://wise.securepublish.work/${CODE}/performance-outubro-2026`
    );
  });

  it("PATCH name null or empty removes it", async () => {
    const panels = tenantKv(namedRecord(), CODE);
    const env = oauthEnv(panels);
    const cookie = await cookieFor(env, OWNER);

    const cleared = await worker.fetch(
      new Request(`https://app.securepublish.work/api/panels/${CODE}/name`, {
        method: "PATCH",
        headers: {
          Origin: "https://app.securepublish.work",
          "content-type": "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ name: "" }),
      }),
      env
    );
    assert.equal(cleared.status, 200);
    const body = await cleared.json();
    assert.equal(body.name, null);
    assert.equal(body.path, `/${CODE}`);
    assert.equal(JSON.parse(panels._store.get(CODE)).name, undefined);

    await panels.put(CODE, JSON.stringify(namedRecord()));
    const clearedNull = await worker.fetch(
      new Request(`https://app.securepublish.work/api/panels/${CODE}/name`, {
        method: "PATCH",
        headers: {
          Origin: "https://app.securepublish.work",
          "content-type": "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ name: null }),
      }),
      env
    );
    assert.equal(clearedNull.status, 200);
    assert.equal((await clearedNull.json()).name, null);
  });

  it("panelPath helper", () => {
    assert.equal(panelPath(CODE, NAME), `/${CODE}/${NAME}`);
    assert.equal(panelPath(CODE, null), `/${CODE}`);
    assert.equal(panelPath(LEGACY, null), `/${LEGACY}`);
  });
});
