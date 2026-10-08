/**
 * viewers[] is publisher-only PII. Colleagues on company scope get views + path,
 * never viewers. Legacy records without publisherEmail never get viewers.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { mintSessionCookie } from "../src/sso.js";
import { isPanelPublisher } from "../src/api.js";

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

const ANA = "ana@wises.com.br";
const BRUNO = "bruno@wises.com.br";
const ANA_PANEL = "aaaaaaaaaaaaaaaaaaaaaaaa";
const LEGACY_PANEL = "bbbbbbbbbbbbbbbbbbbbbbbb";
const HTML = "<html>privacy</html>";

function oauthEnv(panels) {
  return {
    PANELS: panels,
    SESSION_SECRET: "test-session-secret-at-least-32-chars!!",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
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

function apiHeaders(cookie) {
  return { Origin: "https://app.securepublish.work", Cookie: cookie };
}

function seed() {
  const panels = memoryKv({
    [ANA_PANEL]: JSON.stringify({
      v: 1,
      title: "Ana Co",
      name: "ana-co",
      publishedAt: "2026-10-08T12:00:00Z",
      publisherEmail: "Ana@Wises.com.br",
      access: { mode: "company", domains: ["wises.com.br"] },
      html: HTML,
    }),
    [LEGACY_PANEL]: JSON.stringify({
      v: 1,
      title: "Legacy Co",
      publishedAt: "2026-01-01T00:00:00Z",
      access: { mode: "company", domains: ["wises.com.br"] },
      html: HTML,
    }),
    [`view:${ANA_PANEL}`]: JSON.stringify({
      count: 4,
      byEmail: {
        "bob@wises.com.br": {
          first: "2026-10-07T00:47:12.000Z",
          last: "2026-10-08T13:07:00.000Z",
        },
      },
    }),
    [`view:${LEGACY_PANEL}`]: JSON.stringify({
      count: 2,
      byEmail: {
        "eve@wises.com.br": {
          first: "2026-10-01T00:00:00.000Z",
          last: "2026-10-01T00:00:00.000Z",
        },
      },
    }),
    [`idx:pub:${ANA}`]: JSON.stringify([ANA_PANEL]),
    "idx:domain:wises.com.br": JSON.stringify([ANA_PANEL, LEGACY_PANEL]),
    [`tenant:user:${ANA}`]: JSON.stringify({
      email: ANA,
      slug: "wise",
      host: "wise.securepublish.work",
    }),
  });
  return panels;
}

async function listPanels(env, cookie, scope) {
  const res = await worker.fetch(
    new Request(`https://app.securepublish.work/api/panels?scope=${scope}`, {
      headers: apiHeaders(cookie),
    }),
    env
  );
  assert.equal(res.status, 200);
  return res.json();
}

describe("isPanelPublisher", () => {
  it("matches normalized lowercase emails only when both are present", () => {
    assert.equal(isPanelPublisher("Ana@Wises.com.br", "ana@wises.com.br"), true);
    assert.equal(isPanelPublisher("bruno@wises.com.br", "ana@wises.com.br"), false);
    assert.equal(isPanelPublisher("ana@wises.com.br", ""), false);
    assert.equal(isPanelPublisher("ana@wises.com.br", null), false);
    assert.equal(isPanelPublisher("", "ana@wises.com.br"), false);
  });
});

describe("GET /api/panels viewers is publisher-only", () => {
  it("scope=company: colleague gets views and path but no viewers key on someone else's panel", async () => {
    const env = oauthEnv(seed());
    const body = await listPanels(env, await cookieFor(env, BRUNO), "company");
    const p = body.panels.find((x) => x.id === ANA_PANEL);
    assert.ok(p);
    assert.equal(p.views, 4);
    assert.equal(p.path, `/${ANA_PANEL}/ana-co`);
    assert.equal("viewers" in p, false);
    assert.equal(p.viewers, undefined);
  });

  it("publisher gets viewers on their own panel in both scopes", async () => {
    const env = oauthEnv(seed());
    const cookie = await cookieFor(env, ANA);

    const mine = await listPanels(env, cookie, "mine");
    const mineP = mine.panels.find((x) => x.id === ANA_PANEL);
    assert.ok(mineP);
    assert.equal(mineP.views, 4);
    assert.ok(Array.isArray(mineP.viewers));
    assert.equal(mineP.viewers[0].email, "bob@wises.com.br");
    assert.equal(mineP.path, `/${ANA_PANEL}/ana-co`);

    const company = await listPanels(env, cookie, "company");
    const coP = company.panels.find((x) => x.id === ANA_PANEL);
    assert.ok(coP);
    assert.ok(Array.isArray(coP.viewers));
    assert.equal(coP.viewers.length, 1);
    assert.equal(coP.views, 4);
  });

  it("legacy panel without publisherEmail never returns viewers", async () => {
    const env = oauthEnv(seed());
    for (const email of [ANA, BRUNO]) {
      const body = await listPanels(env, await cookieFor(env, email), "company");
      const p = body.panels.find((x) => x.id === LEGACY_PANEL);
      assert.ok(p, `expected legacy panel for ${email}`);
      assert.equal(p.publisherEmail, null);
      assert.equal(typeof p.views, "number");
      assert.equal(p.views, 2);
      assert.ok(p.path);
      assert.equal("viewers" in p, false);
      assert.equal(p.viewers, undefined);
    }
  });
});
