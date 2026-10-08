/**
 * Self-service orgs get an automatic <label>.securepublish.work host.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { mintSessionCookie } from "../src/sso.js";
import {
  autoHostLabel,
  ensureAutoHost,
  ensureOrgMembership,
  getTenant,
} from "../src/kv.js";
import { memoryKv, oauthEnv } from "./helpers.js";

const APP = "https://app.securepublish.work";
const CLOVIS = "clovis@furk.tech";
const TEAMMATE = "x@furk.tech";

function subdomainKeys(kv) {
  return [...kv._store.keys()].filter((k) => k.startsWith("host:sub:")).sort();
}

async function sessionCookie(env, email) {
  const setCookie = await mintSessionCookie(
    {
      email,
      provider: "google",
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    env.SESSION_SECRET,
    env,
    `${APP}/_auth/callback/google`
  );
  return setCookie.split(";")[0];
}

function delayKv(base, ms = 8) {
  const pause = () => new Promise((r) => setTimeout(r, ms));
  return {
    async get(key) {
      if (/^(host:sub:|orghost:)/.test(String(key))) await pause();
      return base.get(key);
    },
    async put(key, value, options) {
      if (/^(host:sub:|orghost:)/.test(String(key))) await pause();
      return base.put(key, value, options);
    },
    async delete(key) {
      return base.delete(key);
    },
    _store: base._store,
  };
}

describe("autoHostLabel", () => {
  it("uses the first label of the registrable domain", () => {
    assert.equal(autoHostLabel("clovis@furk.tech"), "furk");
    assert.equal(autoHostLabel("x@empresa1.com.br"), "empresa1");
    assert.equal(autoHostLabel("x@mail.acme.co.uk"), "acme");
    assert.equal(autoHostLabel("hi@app.io"), "app");
  });
});

describe("ensureAutoHost", () => {
  it("assigns furk.securepublish.work for a furk.tech org", async () => {
    const kv = memoryKv();
    const result = await ensureOrgMembership(kv, CLOVIS);
    assert.equal(result.ok, true);
    const tenant = await getTenant(kv, CLOVIS);
    assert.equal(tenant.slug, "furk");
    assert.equal(tenant.host, "furk.securepublish.work");
    assert.equal(await kv.get("host:sub:furk"), CLOVIS);
    assert.equal(await kv.get("orghost:furk.tech"), "furk");
  });

  it("uses a -2 suffix when the label is taken or reserved", async () => {
    const taken = memoryKv({ "host:sub:furk": "other@evil.example" });
    await ensureOrgMembership(taken, CLOVIS);
    const takenTenant = await getTenant(taken, CLOVIS);
    assert.equal(takenTenant.slug, "furk-2");
    assert.equal(takenTenant.host, "furk-2.securepublish.work");
    assert.equal(await taken.get("host:sub:furk"), "other@evil.example");
    assert.equal(await taken.get("host:sub:furk-2"), CLOVIS);

    const reserved = memoryKv();
    await ensureOrgMembership(reserved, "hi@app.io");
    const reservedTenant = await getTenant(reserved, "hi@app.io");
    assert.equal(reservedTenant.slug, "app-2");
    assert.equal(await reserved.get("host:sub:app"), null);
    assert.equal(await reserved.get("host:sub:app-2"), "hi@app.io");
  });

  it("does not change an org that already has a host", async () => {
    const kv = memoryKv({
      "org:furk.tech": JSON.stringify({
        v: 1,
        domain: "furk.tech",
        createdBy: CLOVIS,
        createdAt: "2026-01-01T00:00:00.000Z",
      }),
      [`tenant:user:${CLOVIS}`]: JSON.stringify({
        email: CLOVIS,
        domain: "furk.tech",
        slug: "custom",
        host: "custom.securepublish.work",
      }),
      "host:sub:custom": CLOVIS,
    });
    await ensureOrgMembership(kv, CLOVIS);
    const tenant = await getTenant(kv, CLOVIS);
    assert.equal(tenant.slug, "custom");
    assert.equal(tenant.host, "custom.securepublish.work");
    assert.equal(await kv.get("host:sub:furk"), null);
    assert.equal(await kv.get("host:sub:custom"), CLOVIS);
  });

  it("does not assign a host to a personal email", async () => {
    const kv = memoryKv();
    await ensureOrgMembership(kv, "eve@gmail.com");
    const tenant = await getTenant(kv, "eve@gmail.com");
    assert.equal(tenant?.slug, undefined);
    assert.equal(tenant?.host, undefined);
    assert.equal(subdomainKeys(kv).length, 0);
    assert.equal(await kv.get("orghost:gmail.com"), null);

    const after = await ensureAutoHost(kv, "eve@gmail.com");
    assert.equal(after?.slug, undefined);
    assert.equal(subdomainKeys(kv).length, 0);
  });

  it("concurrent assignment for the same org yields a single host", async () => {
    const base = memoryKv();
    const kv = delayKv(base);
    await Promise.all([
      ensureOrgMembership(kv, CLOVIS),
      ensureOrgMembership(kv, TEAMMATE),
    ]);
    const a = await getTenant(base, CLOVIS);
    const b = await getTenant(base, TEAMMATE);
    assert.equal(a.slug, "furk");
    assert.equal(b.slug, "furk");
    assert.equal(a.host, "furk.securepublish.work");
    assert.equal(b.host, "furk.securepublish.work");
    assert.deepEqual(subdomainKeys(base), ["host:sub:furk"]);
    const lock = await base.get("host:sub:furk");
    assert.ok(lock === CLOVIS || lock === TEAMMATE);
    assert.equal(await base.get("orghost:furk.tech"), "furk");
  });
});

describe("GET /api/me lazy auto-host", () => {
  it("assigns a host to an existing hostless org and is idempotent", async () => {
    const kv = memoryKv({
      "org:furk.tech": JSON.stringify({
        v: 1,
        domain: "furk.tech",
        createdBy: CLOVIS,
        createdAt: "2026-10-08T00:00:00.000Z",
      }),
      [`tenant:user:${CLOVIS}`]: JSON.stringify({
        email: CLOVIS,
        domain: "furk.tech",
      }),
    });
    const env = oauthEnv(kv);
    const cookie = await sessionCookie(env, CLOVIS);
    const first = await worker.fetch(
      new Request(`${APP}/api/me`, { headers: { Cookie: cookie } }),
      env
    );
    assert.equal(first.status, 200);
    const body = await first.json();
    assert.equal(body.host, "furk.securepublish.work");
    assert.equal(await kv.get("host:sub:furk"), CLOVIS);

    const second = await worker.fetch(
      new Request(`${APP}/api/me`, { headers: { Cookie: cookie } }),
      env
    );
    assert.equal(second.status, 200);
    assert.equal((await second.json()).host, "furk.securepublish.work");
    assert.deepEqual(subdomainKeys(kv), ["host:sub:furk"]);
    assert.equal((await getTenant(kv, CLOVIS)).slug, "furk");

    const pub = await worker.fetch(
      new Request(`${APP}/api/panels`, {
        method: "POST",
        headers: {
          Origin: APP,
          Cookie: cookie,
          "content-type": "application/json",
        },
        body: JSON.stringify({ html: "<p>hi</p>" }),
      }),
      env
    );
    assert.equal(pub.status, 201);
    const published = await pub.json();
    assert.equal(published.host, "furk.securepublish.work");
    assert.match(published.url, /^https:\/\/furk\.securepublish\.work\//);
  });
});
