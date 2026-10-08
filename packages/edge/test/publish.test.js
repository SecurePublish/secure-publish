/**
 * POST /api/panels — account owner only.
 * Browser cookie stays HttpOnly. Publish credential is Authorization: Bearer.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
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
    async list() {
      return {
        keys: [...store.keys()].sort().map((name) => ({ name })),
        list_complete: true,
      };
    },
    _store: store,
  };
}

const bypassEnv = (panels) => ({
  PANELS: panels,
  SSO_DEV_BYPASS: "1",
  CONSOLE_ORIGIN: "https://console.pages.dev",
  OAUTH_ALLOWED_DOMAINS: "localhost",
});

async function issuePublishToken(panels) {
  const env = bypassEnv(panels);
  const started = await worker.fetch(
    new Request("https://app.securepublish.work/api/device/code", { method: "POST" }),
    env
  );
  assert.equal(started.status, 200);
  const start = await started.json();
  assert.match(start.device_code, /^[a-f0-9]{64}$/);
  assert.match(start.user_code, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
  assert.equal(start.verification_url, "https://app.securepublish.work/device");
  assert.equal(start.verification_url.includes(start.device_code), false);
  assert.equal(start.verification_url.includes(start.user_code), false);

  const pending = await worker.fetch(
    new Request("https://app.securepublish.work/api/device/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: start.device_code }),
    }),
    env
  );
  assert.equal(pending.status, 400);
  assert.equal((await pending.json()).error, "authorization_pending");

  const bound = await worker.fetch(
    new Request("https://app.securepublish.work/api/device/bind", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user_code: start.user_code }),
    }),
    env
  );
  assert.equal(bound.status, 200);

  const again = await worker.fetch(
    new Request("https://app.securepublish.work/api/device/bind", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user_code: start.user_code }),
    }),
    env
  );
  assert.equal(again.status, 404);
  assert.equal((await again.json()).error, "device_code_invalid");

  const polled = await worker.fetch(
    new Request("https://app.securepublish.work/api/device/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: start.device_code }),
    }),
    env
  );
  assert.equal(polled.status, 200);
  assert.equal(polled.headers.get("set-cookie"), null);
  const body = await polled.json();
  assert.equal(body.token_type, "Bearer");
  assert.equal(body.email, "dev@localhost");
  assert.match(body.access_token, /^[a-f0-9]{64}$/);
  assert.ok(body.expires_in > 0 && body.expires_in <= 60 * 60 * 12);

  const replay = await worker.fetch(
    new Request("https://app.securepublish.work/api/device/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: start.device_code }),
    }),
    env
  );
  assert.equal(replay.status, 400);
  assert.equal((await replay.json()).error, "expired_token");
  return body.access_token;
}

describe("POST /api/panels", () => {
  it("rejects publish with no session and no Authorization", async () => {
    const env = {
      PANELS: memoryKv(),
      CONSOLE_ORIGIN: "https://console.pages.dev",
    };
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ html: "<p>x</p>" }),
      }),
      env
    );
    assert.equal(res.status, 401);
  });

  it("no host → 409 no_host (does not invent a url)", async () => {
    const env = bypassEnv(memoryKv());
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ html: "<p>hi</p>", title: "Painel" }),
      }),
      env
    );
    assert.equal(res.status, 409);
    const body = await res.json();
    assert.equal(body.error, "no_host");
    assert.equal(body.url, undefined);
  });

  it("signed-in owner publishes company HTML on the tenant host", async () => {
    const panels = memoryKv();
    const env = bypassEnv(panels);
    const claim = await worker.fetch(
      new Request("https://app.securepublish.work/api/hosting/subdomain", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug: "wise" }),
      }),
      env
    );
    assert.equal(claim.status, 200);

    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          html: "<html>horas</html>",
          title: "Horas setembro",
          publisherEmail: "other@evil.test",
        }),
      }),
      env
    );
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.match(body.id, /^[abcdefghijklmnopqrstuvwxyz234567]{10}$/);
    assert.equal(body.path, `/${body.id}`);
    assert.equal(body.name, null);
    assert.equal(body.url, `https://wise.securepublish.work/${body.id}`);
    assert.equal(body.host, "wise.securepublish.work");
    assert.equal(body.mode, "company");
    assert.deepEqual(body.allowlist, []);
    const stored = JSON.parse(panels._store.get(body.id));
    assert.equal(stored.publisherEmail, "dev@localhost");
    assert.equal(stored.html, "<html>horas</html>");
    assert.equal(stored.access.mode, "company");
    assert.deepEqual(stored.access.domains, ["localhost"]);
    assert.equal(stored.title, "Horas setembro");
  });

  it("optional to becomes an allowlist", async () => {
    const panels = memoryKv({
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
      "host:sub:wise": "dev@localhost",
    });
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          html: "<p>only</p>",
          to: ["Ana@Wises.com.br", "bia@wises.com.br"],
        }),
      }),
      bypassEnv(panels)
    );
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.mode, "allowlist");
    assert.deepEqual(body.allowlist, ["ana@wises.com.br", "bia@wises.com.br"]);
  });

  it("rejects empty html and oversized html", async () => {
    const panels = memoryKv({
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        host: "wise.securepublish.work",
        slug: "wise",
      }),
    });
    const env = bypassEnv(panels);
    const missing = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ html: "  " }),
      }),
      env
    );
    assert.equal(missing.status, 400);
    assert.equal((await missing.json()).error, "missing_html");

    const huge = "x".repeat(Math.floor(1.5 * 1024 * 1024) + 1);
    const over = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ html: huge }),
      }),
      env
    );
    assert.equal(over.status, 413);
    assert.equal((await over.json()).error, "html_too_large");
  });

  it("Authorization bearer publishes as the account owner and is revocable", async () => {
    const panels = memoryKv({
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
      "host:sub:wise": "dev@localhost",
    });
    const token = await issuePublishToken(panels);
    const locked = { PANELS: panels, CONSOLE_ORIGIN: "https://console.pages.dev" };
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ html: "<p>via account</p>", title: "Setembro" }),
      }),
      locked
    );
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.url, `https://wise.securepublish.work/${body.id}`);
    const stored = JSON.parse(panels._store.get(body.id));
    assert.equal(stored.publisherEmail, "dev@localhost");

    const revoked = await worker.fetch(
      new Request("https://app.securepublish.work/api/session/revoke", {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
      }),
      locked
    );
    assert.equal(revoked.status, 200);
    const after = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ html: "<p>again</p>" }),
      }),
      locked
    );
    assert.equal(after.status, 401);
  });

});

describe("Bearer precedence over session cookie", () => {
  const CONSOLE = "https://app.securepublish.work";
  const SECRET = "test-secret-test-secret-test-secret";

  function cookieEnv(panels) {
    return {
      PANELS: panels,
      SESSION_SECRET: SECRET,
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      CONSOLE_ORIGIN: CONSOLE,
      OAUTH_ALLOWED_DOMAINS: "wises.com.br",
    };
  }

  async function cookieHeader(env, email = "ana@wises.com.br") {
    const setCookie = await mintSessionCookie(
      {
        email,
        provider: "google",
        exp: Math.floor(Date.now() / 1000) + 600,
      },
      env.SESSION_SECRET,
      env,
      `${CONSOLE}/_auth/callback/google`
    );
    return setCookie.split(";")[0];
  }

  it("(a) valid Bearer + valid cookie → identity from Bearer", async () => {
    const panels = memoryKv({
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
      "host:sub:wise": "dev@localhost",
    });
    const token = await issuePublishToken(panels);
    const env = cookieEnv(panels);
    const cookie = await cookieHeader(env);
    const res = await worker.fetch(
      new Request(`${CONSOLE}/api/panels`, {
        method: "POST",
        headers: {
          Origin: CONSOLE,
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
          cookie,
        },
        body: JSON.stringify({ html: "<p>via bearer</p>" }),
      }),
      env
    );
    assert.equal(res.status, 201);
    const body = await res.json();
    const stored = JSON.parse(panels._store.get(body.id));
    assert.equal(stored.publisherEmail, "dev@localhost");
  });

  it("(b) invalid Bearer + valid cookie → 401", async () => {
    const panels = memoryKv();
    const env = cookieEnv(panels);
    const cookie = await cookieHeader(env);
    const res = await worker.fetch(
      new Request(`${CONSOLE}/api/me`, {
        headers: {
          Origin: CONSOLE,
          authorization: `Bearer ${"a".repeat(64)}`,
          cookie,
        },
      }),
      env
    );
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "unauthorized");
  });

  it("(c) no Bearer + valid cookie → cookie works", async () => {
    const panels = memoryKv();
    const env = cookieEnv(panels);
    const cookie = await cookieHeader(env);
    const res = await worker.fetch(
      new Request(`${CONSOLE}/api/me`, {
        headers: { Origin: CONSOLE, cookie },
      }),
      env
    );
    assert.equal(res.status, 200);
    assert.equal((await res.json()).email, "ana@wises.com.br");
  });

  it("(d) invalid Bearer on a mutation with valid cookie and Origin/JSON → 401", async () => {
    const panels = memoryKv();
    const env = cookieEnv(panels);
    const cookie = await cookieHeader(env);
    const res = await worker.fetch(
      new Request(`${CONSOLE}/api/panels`, {
        method: "POST",
        headers: {
          Origin: CONSOLE,
          cookie,
          "content-type": "application/json",
          authorization: `Bearer ${"b".repeat(64)}`,
        },
        body: JSON.stringify({ html: "<p>nope</p>" }),
      }),
      env
    );
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "unauthorized");
  });
});

function seedOwnedPanel(panels, id, email) {
  const domain = email.split("@")[1];
  panels._store.set(
    id,
    JSON.stringify({
      v: 1,
      title: "panel",
      publishedAt: "2026-01-01T00:00:00.000Z",
      publisherEmail: email,
      access: { mode: "company", domains: [domain] },
      html: "<p>x</p>",
    })
  );
}

function overwritePubtokEmail(panels, email) {
  for (const [key, value] of panels._store.entries()) {
    if (!key.startsWith("pubtok:") || key.startsWith("pubtok-idx:")) continue;
    const rec = JSON.parse(value);
    rec.email = email;
    panels._store.set(key, JSON.stringify(rec));
    return;
  }
  throw new Error("missing pubtok");
}

describe("CLI Bearer is limited to POST /api/panels and PATCH …/name", () => {
  const CONSOLE = "https://app.securepublish.work";
  const SECRET = "test-secret-test-secret-test-secret";
  const PANEL_ID = "k7f3qx2abc";

  function cookieEnv(panels) {
    return {
      PANELS: panels,
      SESSION_SECRET: SECRET,
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      CONSOLE_ORIGIN: CONSOLE,
      OAUTH_ALLOWED_DOMAINS: "wises.com.br",
    };
  }

  async function cookieHeader(env, email = "ana@wises.com.br") {
    const setCookie = await mintSessionCookie(
      {
        email,
        provider: "google",
        exp: Math.floor(Date.now() / 1000) + 600,
      },
      env.SESSION_SECRET,
      env,
      `${CONSOLE}/_auth/callback/google`
    );
    return setCookie.split(";")[0];
  }

  function ownerTenant() {
    return memoryKv({
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
      "host:sub:wise": "dev@localhost",
    });
  }

  it("valid Bearer on PATCH …/access → 401 even with cookie + Origin/JSON", async () => {
    const panels = ownerTenant();
    seedOwnedPanel(panels, PANEL_ID, "ana@wises.com.br");
    const token = await issuePublishToken(panels);
    const env = cookieEnv(panels);
    const cookie = await cookieHeader(env);
    const res = await worker.fetch(
      new Request(`${CONSOLE}/api/panels/${PANEL_ID}/access`, {
        method: "PATCH",
        headers: {
          Origin: CONSOLE,
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
          cookie,
        },
        body: JSON.stringify({ mode: "allowlist", allowlist: ["bia@wises.com.br"] }),
      }),
      env
    );
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "unauthorized");
    const stored = JSON.parse(panels._store.get(PANEL_ID));
    assert.equal(stored.access.mode, "company");
  });

  it("valid Bearer on POST /api/device/bind → 401 even with cookie + Origin/JSON", async () => {
    const panels = memoryKv();
    const token = await issuePublishToken(panels);
    const env = cookieEnv(panels);
    const cookie = await cookieHeader(env);
    const started = await worker.fetch(
      new Request(`${CONSOLE}/api/device/code`, { method: "POST" }),
      env
    );
    assert.equal(started.status, 200);
    const { user_code } = await started.json();
    const res = await worker.fetch(
      new Request(`${CONSOLE}/api/device/bind`, {
        method: "POST",
        headers: {
          Origin: CONSOLE,
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
          cookie,
        },
        body: JSON.stringify({ user_code }),
      }),
      env
    );
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "unauthorized");
  });

  it("valid Bearer still works on POST /api/panels and PATCH …/name", async () => {
    const panels = ownerTenant();
    seedOwnedPanel(panels, PANEL_ID, "dev@localhost");
    const token = await issuePublishToken(panels);
    const env = cookieEnv(panels);

    const published = await worker.fetch(
      new Request(`${CONSOLE}/api/panels`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ html: "<p>cli publish</p>" }),
      }),
      env
    );
    assert.equal(published.status, 201);
    const publishedBody = await published.json();
    assert.equal(
      JSON.parse(panels._store.get(publishedBody.id)).publisherEmail,
      "dev@localhost"
    );

    const renamed = await worker.fetch(
      new Request(`${CONSOLE}/api/panels/${PANEL_ID}/name`, {
        method: "PATCH",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ name: "Performance Outubro" }),
      }),
      env
    );
    assert.equal(renamed.status, 200);
    const renamedBody = await renamed.json();
    assert.equal(renamedBody.name, "performance-outubro");
    assert.equal(renamedBody.path, `/${PANEL_ID}/performance-outubro`);
  });

  it("POST /api/session/revoke with valid Bearer → 2xx, then token 401 on POST /api/panels", async () => {
    const panels = ownerTenant();
    const token = await issuePublishToken(panels);
    const env = cookieEnv(panels);

    const revoked = await worker.fetch(
      new Request(`${CONSOLE}/api/session/revoke`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
      }),
      env
    );
    assert.ok(revoked.status >= 200 && revoked.status < 300);

    const after = await worker.fetch(
      new Request(`${CONSOLE}/api/panels`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ html: "<p>again</p>" }),
      }),
      env
    );
    assert.equal(after.status, 401);
  });

  it("Bearer stored email with uppercase/spaces resolves to lowercase trimmed publisherEmail", async () => {
    const panels = memoryKv({
      "tenant:user:ana@wises.com.br": JSON.stringify({
        email: "ana@wises.com.br",
        slug: "wise",
        host: "wise.securepublish.work",
      }),
      "host:sub:wise": "ana@wises.com.br",
    });
    const token = await issuePublishToken(panels);
    overwritePubtokEmail(panels, "  Ana@Wises.com.br  ");
    const env = cookieEnv(panels);
    const res = await worker.fetch(
      new Request(`${CONSOLE}/api/panels`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ html: "<p>norm</p>" }),
      }),
      env
    );
    assert.equal(res.status, 201);
    const body = await res.json();
    const stored = JSON.parse(panels._store.get(body.id));
    assert.equal(stored.publisherEmail, "ana@wises.com.br");
  });
});
