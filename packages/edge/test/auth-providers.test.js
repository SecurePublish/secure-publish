/**
 * GET /auth/providers must never fall through to panel-id 404 on the app host.
 * Console signup/login (api.js mountIdpButtons) uses this to pick SSO buttons.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

const PANEL_404 = "Not found — invalid or unknown panel id.";
const APP = "https://app.securepublish.work";
const CONSOLE_ORIGIN = "https://app.securepublish.work";

function memoryKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value) {
      store.set(key, value);
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
  };
}

function googleOnlyEnv() {
  return {
    PANELS: memoryKv(),
    SESSION_SECRET: "test-session-secret-at-least-32-chars!!",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN,
  };
}

function appRequest(path, { method = "GET", headers = {}, body } = {}) {
  const init = {
    method,
    headers: { Origin: CONSOLE_ORIGIN, ...headers },
    redirect: "manual",
  };
  if (body !== undefined) init.body = body;
  return new Request(`${APP}${path}`, init);
}

describe("GET /auth/providers on app host", () => {
  it("returns 200 JSON { providers: ['google'] } when only Google is configured", async () => {
    const res = await worker.fetch(appRequest("/auth/providers"), googleOnlyEnv());
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") || "", /application\/json/);
    assert.deepEqual(await res.json(), { providers: ["google"] });
  });

  it("includes CORS credentials headers the console expects", async () => {
    const res = await worker.fetch(appRequest("/auth/providers"), googleOnlyEnv());
    assert.equal(res.headers.get("Access-Control-Allow-Origin"), CONSOLE_ORIGIN);
    assert.equal(res.headers.get("Access-Control-Allow-Credentials"), "true");
  });

  it("adds github and microsoft only when both client id and secret exist", async () => {
    const env = {
      ...googleOnlyEnv(),
      GITHUB_CLIENT_ID: "gh-id",
      GITHUB_CLIENT_SECRET: "gh-secret",
      MICROSOFT_CLIENT_ID: "ms-id",
      MICROSOFT_CLIENT_SECRET: "ms-secret",
    };
    const res = await worker.fetch(appRequest("/auth/providers"), env);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), {
      providers: ["google", "github", "microsoft"],
    });
  });

  it("omits github when only the client id is set (secret missing)", async () => {
    const env = {
      ...googleOnlyEnv(),
      GITHUB_CLIENT_ID: "gh-id-only",
    };
    const res = await worker.fetch(appRequest("/auth/providers"), env);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { providers: ["google"] });
  });

  it("does not return the panel-id 404 body", async () => {
    const res = await worker.fetch(appRequest("/auth/providers"), googleOnlyEnv());
    const text = await res.clone().text();
    assert.notEqual(text, PANEL_404);
    assert.notEqual(res.status, 404);
  });
});

describe("documented /auth/* and /api/* on app host are not swallowed by panel 404", () => {
  const PANEL_ID = "aaaaaaaaaaaaaaaaaaaaaaaa";

  /**
   * Every path in docs/API-CONTRACT.md, plus GET /auth/providers and the
   * OAuth callbacks pinned to app.securepublish.work.
   */
  const documented = [
    { method: "GET", path: "/api/me" },
    { method: "POST", path: "/api/panels", headers: { "content-type": "application/json" }, body: "{}" },
    { method: "POST", path: "/api/device/code" },
    { method: "POST", path: "/api/device/token", headers: { "content-type": "application/json" }, body: "{}" },
    { method: "POST", path: "/api/device/bind", headers: { "content-type": "application/json" }, body: "{}" },
    { method: "POST", path: "/api/session/revoke" },
    { method: "GET", path: "/api/panels?scope=mine" },
    { method: "GET", path: "/api/panels?scope=company" },
    {
      method: "PATCH",
      path: `/api/panels/${PANEL_ID}/access`,
      headers: { "content-type": "application/json" },
      body: "{}",
    },
    { method: "PUT", path: "/api/hosting/subdomain", headers: { "content-type": "application/json" }, body: "{}" },
    { method: "PUT", path: "/api/hosting/custom", headers: { "content-type": "application/json" }, body: "{}" },
    { method: "DELETE", path: "/api/hosting/custom" },
    { method: "POST", path: "/api/hosting/custom/verify" },
    { method: "GET", path: "/auth/google" },
    { method: "GET", path: "/auth/microsoft" },
    { method: "GET", path: "/auth/github" },
    { method: "GET", path: "/auth/logout" },
    { method: "POST", path: "/auth/logout" },
    { method: "GET", path: "/auth/providers" },
    { method: "GET", path: "/_auth/callback/google" },
    { method: "GET", path: "/_auth/callback/github" },
    { method: "GET", path: "/_auth/callback/microsoft" },
  ];

  it("lists every documented console route (guards against missing a contract path)", () => {
    assert.equal(documented.length, 22);
  });

  it("none of the documented app-host routes return the panel 404", async () => {
    const env = googleOnlyEnv();
    const failures = [];
    for (const route of documented) {
      const res = await worker.fetch(
        appRequest(route.path, {
          method: route.method,
          headers: route.headers,
          body: route.body,
        }),
        env
      );
      const text = await res.text();
      if (text === PANEL_404 || text.trim() === PANEL_404) {
        failures.push(`${route.method} ${route.path} → ${res.status} panel 404`);
      }
    }
    assert.equal(
      failures.length,
      0,
      `panel 404 swallowed:\n${failures.join("\n")}`
    );
  });
});
