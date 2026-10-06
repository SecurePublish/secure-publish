/**
 * P0: Domain-scoped session cookie must authorize panel hosts (*.securepublish.work).
 * Repro: logged-in console cookie present → panel must not 302 to /_auth/login.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { mintSessionCookie, readSessionCookie } from "../src/sso.js";

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
      return { keys: keys.slice(0, limit), list_complete: true, cursor: undefined };
    },
    _store: store,
  };
}

const PANEL_ID = "aaaaaaaaaaaaaaaaaaaaaaaa";
const PANEL_HTML = "<html>panel-session-ok</html>";
const EMAIL = "marcus@wises.com.br";

function oauthEnv(panels) {
  return {
    PANELS: panels,
    SESSION_SECRET: "test-session-secret-at-least-32-chars!!",
    GOOGLE_CLIENT_ID: "gid",
    GOOGLE_CLIENT_SECRET: "gsecret",
    CONSOLE_ORIGIN: "https://app.securepublish.work",
    OAUTH_ALLOWED_DOMAINS: "wises.com.br",
  };
}

async function mintAppSession(env, email = EMAIL) {
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
  assert.match(
    setCookie,
    /Domain=\.securepublish\.work/i,
    "console login must mint Domain-scoped cookie"
  );
  assert.match(setCookie, /SameSite=Lax/i);
  return setCookie.split(";")[0];
}

describe("P0 panel host accepts Domain-scoped SSO cookie", () => {
  it("wise.securepublish.work panel does not redirect to login when Domain cookie is sent", async () => {
    const panels = memoryKv({
      [PANEL_ID]: JSON.stringify({
        v: 1,
        title: "Ops",
        publishedAt: "2026-10-06T12:00:00Z",
        publisherEmail: EMAIL,
        access: { mode: "company", domains: ["wises.com.br"] },
        html: PANEL_HTML,
      }),
      "host:sub:wise": EMAIL,
    });
    const env = oauthEnv(panels);
    const cookiePair = await mintAppSession(env);

    const res = await worker.fetch(
      new Request(`https://wise.securepublish.work/${PANEL_ID}`, {
        headers: {
          Host: "wise.securepublish.work",
          Cookie: cookiePair,
        },
        redirect: "manual",
      }),
      env
    );

    assert.notEqual(res.status, 302, "must not redirect to Entrar-para-ver login");
    const location = res.headers.get("location") || "";
    assert.ok(
      !location.includes("/_auth/login"),
      `unexpected login redirect: ${location}`
    );
    assert.equal(res.status, 200);
    assert.equal(await res.text(), PANEL_HTML);
  });

  it("readSessionCookie accepts a valid Domain cookie when an invalid sibling is listed first", async () => {
    const env = oauthEnv(memoryKv());
    const cookiePair = await mintAppSession(env);
    const raw = `secure_publish_session=e30.deadbeef; ${cookiePair}`;
    const session = await readSessionCookie(
      new Request("https://wise.securepublish.work/x", {
        headers: { Cookie: raw, Host: "wise.securepublish.work" },
      }),
      env.SESSION_SECRET
    );
    assert.ok(session, "must not first-match reject when a later cookie verifies");
    assert.equal(session.email, EMAIL);
  });

  it("OAuth start on panel host bounces to app.securepublish.work (Domain mint host)", async () => {
    const env = oauthEnv(memoryKv());
    const res = await worker.fetch(
      new Request(
        "https://wise.securepublish.work/_auth/start/google?return_to=%2Fabc",
        { headers: { Host: "wise.securepublish.work" }, redirect: "manual" }
      ),
      env
    );
    assert.equal(res.status, 302);
    const loc = res.headers.get("location") || "";
    assert.match(loc, /^https:\/\/app\.securepublish\.work\/_auth\/start\/google/);
    assert.match(loc, /return_to=/);
  });

  it("without cookie, panel still redirects to /_auth/login (no QA bypass)", async () => {
    const panels = memoryKv({
      [PANEL_ID]: JSON.stringify({
        v: 1,
        title: "Ops",
        publishedAt: "2026-10-06T12:00:00Z",
        publisherEmail: EMAIL,
        access: { mode: "company", domains: ["wises.com.br"] },
        html: PANEL_HTML,
      }),
      "host:sub:wise": EMAIL,
    });
    const env = oauthEnv(panels);
    const res = await worker.fetch(
      new Request(`https://wise.securepublish.work/${PANEL_ID}`, {
        headers: { Host: "wise.securepublish.work" },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 302);
    assert.match(res.headers.get("location") || "", /\/_auth\/login/);
  });
});
