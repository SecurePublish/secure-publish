/**
 * Fail-closed host ↔ publisher binding (Marcus / host swap).
 * Old slug without lock must 404 before SSO; current slug + matching publisher works.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker, { assertPanelHostBinding } from "../src/worker.js";
import { claimSubdomain } from "../src/kv.js";

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
const PANEL_HTML = "<html>bound</html>";

function panelRecord(publisherEmail = "dev@localhost") {
  return {
    v: 1,
    title: "Bound",
    publishedAt: "2026-10-02T15:00:00-03:00",
    publisherEmail,
    access: { mode: "company", domains: ["localhost"] },
    html: PANEL_HTML,
  };
}

function req(url, host) {
  const headers = {};
  if (host) headers.Host = host;
  return new Request(url, { headers });
}

describe("assertPanelHostBinding — unit", () => {
  it("workers.dev / localhost skip lock (interim)", async () => {
    const env = { PANELS: memoryKv() };
    const record = panelRecord();
    for (const host of [
      "secure-publish.clovis.workers.dev",
      "localhost",
      "127.0.0.1",
    ]) {
      const r = await assertPanelHostBinding(req(`https://${host}/${PANEL_ID}`, host), env, record);
      assert.equal(r.ok, true, host);
    }
  });

  it("reserved product hosts skip subdomain lock", async () => {
    const env = { PANELS: memoryKv() };
    for (const host of [
      "app.securepublish.work",
      "www.securepublish.work",
      "securepublish.work",
    ]) {
      const r = await assertPanelHostBinding(
        req(`https://${host}/${PANEL_ID}`, host),
        env,
        panelRecord()
      );
      assert.equal(r.ok, true, host);
    }
  });

  it("missing host:sub lock → deny", async () => {
    const env = { PANELS: memoryKv() };
    const r = await assertPanelHostBinding(
      req(`https://oldslug.securepublish.work/${PANEL_ID}`, "oldslug.securepublish.work"),
      env,
      panelRecord()
    );
    assert.equal(r.ok, false);
    assert.equal(r.status, 404);
  });

  it("lock owner mismatch → deny", async () => {
    const env = {
      PANELS: memoryKv({ "host:sub:wise": "other@acme.example" }),
    };
    const r = await assertPanelHostBinding(
      req(`https://wise.securepublish.work/${PANEL_ID}`, "wise.securepublish.work"),
      env,
      panelRecord("dev@localhost")
    );
    assert.equal(r.ok, false);
    assert.equal(r.status, 404);
  });

  it("lock owner match (case-insensitive) → ok", async () => {
    const env = {
      PANELS: memoryKv({ "host:sub:wise": "Dev@Localhost" }),
    };
    const r = await assertPanelHostBinding(
      req(`https://wise.securepublish.work/${PANEL_ID}`, "wise.securepublish.work"),
      env,
      panelRecord("dev@localhost")
    );
    assert.equal(r.ok, true);
  });

  it("custom host: publisher must match host:custom lock", async () => {
    const env = {
      PANELS: memoryKv({ "host:custom:dash.acme.example": "dev@localhost" }),
    };
    const ok = await assertPanelHostBinding(
      req("https://dash.acme.example/" + PANEL_ID, "dash.acme.example"),
      env,
      panelRecord("dev@localhost")
    );
    assert.equal(ok.ok, true);

    const bad = await assertPanelHostBinding(
      req("https://dash.acme.example/" + PANEL_ID, "dash.acme.example"),
      env,
      panelRecord("other@acme.example")
    );
    assert.equal(bad.ok, false);
    assert.equal(bad.status, 404);
  });

  it("legacy panel without publisherEmail → deny on bound host", async () => {
    const env = {
      PANELS: memoryKv({ "host:sub:wise": "dev@localhost" }),
    };
    const r = await assertPanelHostBinding(
      req(`https://wise.securepublish.work/${PANEL_ID}`, "wise.securepublish.work"),
      env,
      { ...panelRecord(), publisherEmail: "" }
    );
    assert.equal(r.ok, false);
  });
});

describe("panel serve — fail-closed host binding", () => {
  it("old slug without lock → 404 before SSO (no OAuth redirect)", async () => {
    const env = {
      PANELS: memoryKv({
        [PANEL_ID]: JSON.stringify(panelRecord()),
      }),
      // no SSO_DEV_BYPASS — if we reached SSO we'd get 403/redirect, not clean 404
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
    };
    const res = await worker.fetch(
      req(`https://zombie.securepublish.work/${PANEL_ID}`, "zombie.securepublish.work"),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(res.headers.get("location"), null);
    const body = await res.text();
    assert.match(
      body,
      /Não achamos este dashboard\. O link pode estar errado ou ter sido removido\./
    );
    assert.match(body, /We couldn't find this dashboard/);
    assert.equal(body.toLowerCase().includes("host not bound"), false);
  });

  it("current slug + matching publisher → 200 HTML", async () => {
    const kv = memoryKv({
      [PANEL_ID]: JSON.stringify(panelRecord("dev@localhost")),
      "host:sub:wise": "dev@localhost",
    });
    const env = {
      PANELS: kv,
      SSO_DEV_BYPASS: "1",
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
    };
    const res = await worker.fetch(
      req(`https://wise.securepublish.work/${PANEL_ID}`, "wise.securepublish.work"),
      env
    );
    assert.equal(res.status, 200);
    assert.equal(await res.text(), PANEL_HTML);
  });

  it("workers.dev serves by panel id without subdomain lock", async () => {
    const env = {
      PANELS: memoryKv({
        [PANEL_ID]: JSON.stringify(panelRecord()),
      }),
      SSO_DEV_BYPASS: "1",
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
    };
    const res = await worker.fetch(
      req(`https://secure-publish.example.workers.dev/${PANEL_ID}`, "secure-publish.example.workers.dev"),
      env
    );
    assert.equal(res.status, 200);
  });

  it("after claimSubdomain swap: old slug 404, new slug 200", async () => {
    const kv = memoryKv({
      [PANEL_ID]: JSON.stringify(panelRecord("dev@localhost")),
    });
    const first = await claimSubdomain(kv, "oldslug", "dev@localhost");
    assert.equal(first.ok, true);
    const second = await claimSubdomain(kv, "newslug", "dev@localhost");
    assert.equal(second.ok, true);
    assert.equal(await kv.get("host:sub:oldslug"), null);
    assert.equal(await kv.get("host:sub:newslug"), "dev@localhost");

    const env = {
      PANELS: kv,
      SSO_DEV_BYPASS: "1",
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
    };

    const dead = await worker.fetch(
      req(`https://oldslug.securepublish.work/${PANEL_ID}`, "oldslug.securepublish.work"),
      env
    );
    assert.equal(dead.status, 404);

    const live = await worker.fetch(
      req(`https://newslug.securepublish.work/${PANEL_ID}`, "newslug.securepublish.work"),
      env
    );
    assert.equal(live.status, 200);
    assert.equal(await live.text(), PANEL_HTML);
  });

  it("custom host: verified + matching publisher → 200; mismatch → 404", async () => {
    const kv = memoryKv({
      [PANEL_ID]: JSON.stringify(panelRecord("dev@localhost")),
      "host:custom:dash.acme.example": "dev@localhost",
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        customHostname: "dash.acme.example",
        customVerified: true,
        slug: "wise",
        host: "wise.securepublish.work",
      }),
    });
    const env = {
      PANELS: kv,
      SSO_DEV_BYPASS: "1",
      CONSOLE_ORIGIN: "https://console.pages.dev",
      OAUTH_ALLOWED_DOMAINS: "localhost",
    };

    const ok = await worker.fetch(
      req(`https://dash.acme.example/${PANEL_ID}`, "dash.acme.example"),
      env
    );
    assert.equal(ok.status, 200);

    // Same host lock, but panel owned by someone else → 404 fail-closed
    const otherId = "bbbbbbbbbbbbbbbbbbbbbbbb";
    await kv.put(
      otherId,
      JSON.stringify({
        ...panelRecord("other@acme.example"),
        access: { mode: "company", domains: ["localhost"] },
      })
    );
    const bad = await worker.fetch(
      req(`https://dash.acme.example/${otherId}`, "dash.acme.example"),
      env
    );
    assert.equal(bad.status, 404);
  });
});

/**
 * Claim-blocked infra hosts (api/admin/auth/login/cname) are NOT product hosts.
 * Without a host:sub lock they must 404 fail-closed — never skip binding (that
 * would serve any panel on api.securepublish.work) and never OAuth-redirect
 * toward serving the HTML.
 */
describe("claim-reserved infra hosts — fail-closed panel serve", () => {
  const INFRA_HOSTS = ["api", "admin", "auth", "login", "cname"];

  for (const slug of INFRA_HOSTS) {
    it(`${slug}.securepublish.work/{id} → 404, not HTML, no login redirect`, async () => {
      const env = {
        PANELS: memoryKv({
          [PANEL_ID]: JSON.stringify(panelRecord()),
        }),
        CONSOLE_ORIGIN: "https://console.pages.dev",
        OAUTH_ALLOWED_DOMAINS: "localhost",
      };
      const host = `${slug}.securepublish.work`;
      const res = await worker.fetch(req(`https://${host}/${PANEL_ID}`, host), env);
      assert.equal(res.status, 404);
      assert.equal(res.headers.get("location"), null);
      const body = await res.text();
      assert.equal(body.includes(PANEL_HTML), false);
      assert.match(body, /Não achamos este dashboard/);
      assert.equal(body.toLowerCase().includes("host not bound"), false);
    });
  }

  it("api.securepublish.work does not skip host binding the way app. does", async () => {
    const env = { PANELS: memoryKv() };
    const api = await assertPanelHostBinding(
      req(`https://api.securepublish.work/${PANEL_ID}`, "api.securepublish.work"),
      env,
      panelRecord()
    );
    assert.equal(api.ok, false);
    assert.equal(api.status, 404);

    const app = await assertPanelHostBinding(
      req(`https://app.securepublish.work/${PANEL_ID}`, "app.securepublish.work"),
      env,
      panelRecord()
    );
    assert.equal(app.ok, true);
  });
});

describe("claimSubdomain — reserved_slug (direct)", () => {
  it("APP is reserved; KV unchanged", async () => {
    const kv = memoryKv();
    const result = await claimSubdomain(kv, "APP", "dev@localhost");
    assert.equal(result.ok, false);
    assert.equal(result.status, 400);
    assert.equal(result.error, "reserved_slug");
    assert.equal(await kv.get("host:sub:app"), null);
    assert.equal(await kv.get("tenant:user:dev@localhost"), null);
  });

  it("wise remains claimable", async () => {
    const kv = memoryKv();
    const result = await claimSubdomain(kv, "wise", "dev@localhost");
    assert.equal(result.ok, true);
    assert.equal(result.host, "wise.securepublish.work");
  });

  it("reserved claim does not drop an existing tenant slug", async () => {
    const kv = memoryKv();
    const first = await claimSubdomain(kv, "wise", "dev@localhost");
    assert.equal(first.ok, true);
    const blocked = await claimSubdomain(kv, "app", "dev@localhost");
    assert.equal(blocked.ok, false);
    assert.equal(blocked.error, "reserved_slug");
    assert.equal(await kv.get("host:sub:wise"), "dev@localhost");
    assert.equal(await kv.get("host:sub:app"), null);
    const tenant = JSON.parse(await kv.get("tenant:user:dev@localhost"));
    assert.equal(tenant.slug, "wise");
  });
});

