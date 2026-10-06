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
    new Request("https://worker.test/api/device/code", { method: "POST" }),
    env
  );
  assert.equal(started.status, 200);
  const start = await started.json();
  assert.match(start.device_code, /^[a-f0-9]{64}$/);
  assert.match(
    start.verification_url,
    /^https:\/\/app\.securepublish\.work\/_auth\/login\?device=[a-f0-9]{64}$/
  );

  const pending = await worker.fetch(
    new Request("https://worker.test/api/device/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: start.device_code }),
    }),
    env
  );
  assert.equal(pending.status, 400);
  assert.equal((await pending.json()).error, "authorization_pending");

  const bound = await worker.fetch(
    new Request("https://worker.test/api/device/bind", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: start.device_code }),
    }),
    env
  );
  assert.equal(bound.status, 200);

  const again = await worker.fetch(
    new Request("https://worker.test/api/device/bind", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_code: start.device_code }),
    }),
    env
  );
  assert.equal(again.status, 400);

  const polled = await worker.fetch(
    new Request("https://worker.test/api/device/token", {
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
    new Request("https://worker.test/api/device/token", {
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
      new Request("https://worker.test/api/panels", {
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
      new Request("https://worker.test/api/panels", {
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
      new Request("https://worker.test/api/hosting/subdomain", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ slug: "wise" }),
      }),
      env
    );
    assert.equal(claim.status, 200);

    const res = await worker.fetch(
      new Request("https://worker.test/api/panels", {
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
    assert.match(body.id, /^[0-9a-f]{24}$/);
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
      new Request("https://worker.test/api/panels", {
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
      new Request("https://worker.test/api/panels", {
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
      new Request("https://worker.test/api/panels", {
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

  it("bearer for another account than the cookie is forbidden", async () => {
    const panels = memoryKv();
    const token = await issuePublishToken(panels);
    const env = {
      PANELS: panels,
      SESSION_SECRET: "test-secret-test-secret-test-secret",
      GOOGLE_CLIENT_ID: "google-client",
      GOOGLE_CLIENT_SECRET: "google-secret",
      CONSOLE_ORIGIN: "https://app.securepublish.work",
    };
    const setCookie = await mintSessionCookie(
      {
        email: "ana@wises.com.br",
        provider: "google",
        exp: Math.floor(Date.now() / 1000) + 600,
      },
      env.SESSION_SECRET,
      env,
      "https://app.securepublish.work/api/panels"
    );
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/panels", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
          cookie: setCookie.split(";")[0],
        },
        body: JSON.stringify({ html: "<p>nope</p>" }),
      }),
      env
    );
    assert.equal(res.status, 403);
  });
});
