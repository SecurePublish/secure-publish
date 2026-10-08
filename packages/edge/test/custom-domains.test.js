import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { UNKNOWN_PANEL_BODY } from "../src/worker.js";
import { syncCustomHostname, recheckAllCustomHostnames } from "../src/custom-domain.js";
import { mintSessionCookie } from "../src/sso.js";
import {
  memoryKv,
  PANEL_ID,
  CF_ZONE_ID,
  CF_SAAS_TOKEN,
  panelRecord,
  enabledEnv,
  oauthEnv,
  installCfFetchMock,
  tenantSnapshot,
} from "./helpers.js";

const HOST = "dashboards.example.com";
const PANEL_HTML = "<html>bound</html>";

function kvWithSubAndPanel() {
  return memoryKv({
    [PANEL_ID]: JSON.stringify(panelRecord()),
    "host:sub:wise": "dev@localhost",
    "tenant:user:dev@localhost": JSON.stringify({
      email: "dev@localhost",
      slug: "wise",
      host: "wise.securepublish.work",
    }),
    [`idx:pub:dev@localhost`]: JSON.stringify([PANEL_ID]),
  });
}

function putCustom(env, hostname = HOST) {
  return worker.fetch(
    new Request("https://app.securepublish.work/api/hosting/custom", {
      method: "PUT",
      headers: {
        Origin: "https://app.securepublish.work",
        "content-type": "application/json",
      },
      body: JSON.stringify({ hostname }),
    }),
    env
  );
}

function verify(env) {
  return worker.fetch(
    new Request("https://app.securepublish.work/api/hosting/custom/verify", {
      method: "POST",
      headers: { Origin: "https://app.securepublish.work" },
    }),
    env
  );
}

describe("CUSTOM_DOMAINS_ENABLED flag", () => {
  it("PUT returns 403 custom_domains_disabled and writes nothing when flag is off", async () => {
    const kv = kvWithSubAndPanel();
    const env = enabledEnv(kv, { CUSTOM_DOMAINS_ENABLED: "false" });
    const res = await putCustom(env);
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "custom_domains_disabled");
    assert.equal(await kv.get(`host:custom:${HOST}`), null);
    assert.equal(JSON.parse(await kv.get("tenant:user:dev@localhost")).customHostname, undefined);
  });

  it("verify returns 403 custom_domains_disabled when flag is off", async () => {
    const kv = kvWithSubAndPanel();
    const env = enabledEnv(kv, { CUSTOM_DOMAINS_ENABLED: "false" });
    const res = await verify(env);
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "custom_domains_disabled");
  });

  it("/api/me never includes records (or cname.securepublish.work) when flag is off", async () => {
    const kv = kvWithSubAndPanel();
    await kv.put(`host:custom:${HOST}`, "dev@localhost");
    await kv.put(
      "tenant:user:dev@localhost",
      JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
        customHostname: HOST,
        customVerified: false,
        customStatus: "pending_dns",
        customVerifyToken: "a".repeat(64),
      })
    );
    const env = enabledEnv(kv, { CUSTOM_DOMAINS_ENABLED: "false" });
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/me", {
        headers: { Origin: "https://app.securepublish.work" },
      }),
      env
    );
    const body = await res.json();
    assert.equal(body.customDomainsEnabled, false);
    assert.equal(body.customRecords, undefined);
    assert.equal(body.customStatus, undefined);
    assert.equal(JSON.stringify(body).includes("cname.securepublish.work"), false);
  });
});

describe("PUT /api/hosting/custom — validation before KV/CF", () => {
  let mock;
  afterEach(() => mock?.restore());

  it("rejects reserved / apex / IP / garbage with no KV write", async () => {
    mock = installCfFetchMock();
    const cases = [
      ["app.securepublish.work.", "reserved_hostname"],
      ["APP.SecurePublish.WORK", "reserved_hostname"],
      ["x.pages.dev.", "reserved_hostname"],
      ["example.com", "apex_domain_not_supported"],
      ["suaempresa.com.br", "apex_domain_not_supported"],
      ["10.0.0.1", "invalid_hostname"],
      ["[::1]", "invalid_hostname"],
      ["com.br", "invalid_hostname"],
    ];
    for (const [hostname, error] of cases) {
      const kv = kvWithSubAndPanel();
      const env = enabledEnv(kv);
      const cfBefore = mock.calls.filter((c) => c.url.includes("api.cloudflare.com")).length;
      const res = await putCustom(env, hostname);
      assert.equal(res.status, 400, hostname);
      assert.equal((await res.json()).error, error, hostname);
      assert.equal([...kv._store.keys()].filter((k) => k.startsWith("host:custom:")).length, 0);
      const cfAfter = mock.calls.filter((c) => c.url.includes("api.cloudflare.com")).length;
      assert.equal(cfAfter, cfBefore, hostname);
    }
  });

  it("accepts dashboards.example.com and IDN; claim makes no Cloudflare call", async () => {
    mock = installCfFetchMock();
    const kv = kvWithSubAndPanel();
    const env = enabledEnv(kv);
    const res = await putCustom(env, "dashboards.example.com");
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.customHostname, "dashboards.example.com");
    assert.equal(body.status, "pending_dns");
    assert.equal(body.records[0].type, "CNAME");
    assert.equal(body.records[0].name, "dashboards");
    assert.equal(body.records[0].value, "cname.securepublish.work");
    assert.equal(body.records[1].type, "TXT");
    assert.equal(body.records[1].name, "_secure-publish.dashboards");
    assert.match(body.records[1].value, /^sp-verify=[0-9a-f]{64}$/);
    assert.equal(await kv.get("host:custom:dashboards.example.com"), null);
    assert.equal(
      mock.calls.filter((c) => c.url.includes("api.cloudflare.com")).length,
      0
    );

    const idn = await putCustom(env, "share.münchen.de");
    assert.equal(idn.status, 200);
    const idnBody = await idn.json();
    assert.match(idnBody.customHostname, /^share\.xn--/);
  });

  it("hostname locked by another account → 409", async () => {
    const kv = kvWithSubAndPanel();
    await kv.put(`host:custom:${HOST}`, "other@acme.example");
    const env = enabledEnv(kv);
    const res = await putCustom(env);
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, "hostname_taken");
  });

  it("new claim replaces previous pending hostname and deletes its CF hostname without locking the new host", async () => {
    mock = installCfFetchMock();
    const kv = kvWithSubAndPanel();
    await kv.put("host:custom:old.example.com", "dev@localhost");
    await kv.put(
      "tenant:user:dev@localhost",
      JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
        customHostname: "old.example.com",
        customVerified: false,
        customStatus: "issuing_cert",
        customVerifyToken: "b".repeat(64),
        customCfId: "cf-old",
      })
    );
    const env = enabledEnv(kv);
    const res = await putCustom(env, "share.wises.com.br");
    assert.equal(res.status, 200);
    assert.equal(await kv.get("host:custom:old.example.com"), null);
    assert.equal(await kv.get("host:custom:share.wises.com.br"), null);
    const del = mock.calls.find(
      (c) => c.method === "DELETE" && c.url.includes("cf-old")
    );
    assert.ok(del);
    assert.equal(
      mock.calls.filter((c) => c.method === "POST" && c.url.includes("custom_hostnames")).length,
      0
    );
    const tenant = JSON.parse(await kv.get("tenant:user:dev@localhost"));
    assert.equal(tenant.customCfId, null);
    assert.equal(JSON.stringify(await res.json()).includes(CF_SAAS_TOKEN), false);
  });
});

describe("POST /api/hosting/custom/verify", () => {
  let mock;
  afterEach(() => mock?.restore());

  async function claimedEnv(txtRecords, cfOpts = {}) {
    mock = installCfFetchMock({ txtRecords, ...cfOpts });
    const kv = kvWithSubAndPanel();
    const env = enabledEnv(kv);
    const claimed = await putCustom(env);
    const token = (await claimed.json()).records[1].value;
    return { env, kv, token };
  }

  it("TXT missing → 200 pending_dns; no CF create", async () => {
    const { env } = await claimedEnv([]);
    const res = await verify(env);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, "pending_dns");
    assert.equal(body.customHostname, HOST);
    assert.equal(body.records[0].name, "dashboards");
    assert.equal(
      mock.calls.filter((c) => c.url.includes("api.cloudflare.com")).length,
      0
    );
  });

  it("creates CF hostname only after TXT matches; POST body is exact", async () => {
    const { env, token } = await claimedEnv(null, {
      hostnameStatus: "pending",
      sslStatus: "pending_validation",
    });
    mock.restore();
    mock = installCfFetchMock({
      txtRecords: [token],
      hostnameStatus: "pending",
      sslStatus: "pending_validation",
    });
    const res = await verify(env);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).status, "pending_dns");
    const post = mock.calls.find(
      (c) => c.method === "POST" && c.url.includes(`/zones/${CF_ZONE_ID}/custom_hostnames`)
    );
    assert.ok(post);
    assert.deepEqual(JSON.parse(post.init.body), {
      hostname: HOST,
      ssl: {
        method: "http",
        type: "dv",
        settings: { min_tls_version: "1.2" },
      },
    });
    assert.match(post.init.headers.Authorization, /^Bearer /);
  });

  it("hostname active + ssl pending → issuing_cert", async () => {
    const { env, kv, token } = await claimedEnv([""]);
    mock.restore();
    mock = installCfFetchMock({
      txtRecords: [token],
      hostnameStatus: "active",
      sslStatus: "pending_issuance",
    });
    const res = await verify(env);
    assert.equal((await res.json()).status, "issuing_cert");
    const tenant = JSON.parse(await kv.get("tenant:user:dev@localhost"));
    assert.equal(tenant.customVerified, false);
    assert.equal(tenant.host, "wise.securepublish.work");
    assert.equal(await kv.get(`host:custom:${HOST}`), null);
  });

  it("both active + TXT ok → active, serving host switches, token kept", async () => {
    const { env, kv, token } = await claimedEnv([]);
    mock.restore();
    mock = installCfFetchMock({ txtRecords: [token] });
    const res = await verify(env);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, "active");
    assert.equal(body.customHostname, HOST);
    const tenant = JSON.parse(await kv.get("tenant:user:dev@localhost"));
    assert.equal(tenant.customVerified, true);
    assert.equal(tenant.customStatus, "active");
    assert.equal(tenant.host, HOST);
    assert.ok(tenant.customVerifyToken);
    assert.ok(tenant.customCfId);
    assert.equal(await kv.get(`host:custom:${HOST}`), "dev@localhost");
    const lockPuts = kv._puts.filter((p) => p.key === `host:custom:${HOST}`);
    assert.ok(lockPuts.length);
    assert.equal(lockPuts.at(-1).options.expirationTtl, undefined);
  });

  it("CF API error → 502 cloudflare_error, never fake success, token not in body", async () => {
    const { env, token } = await claimedEnv([]);
    mock.restore();
    mock = installCfFetchMock({ txtRecords: [token], createError: true });
    const res = await verify(env);
    assert.equal(res.status, 502);
    const body = await res.json();
    assert.equal(body.error, "cloudflare_error");
    assert.equal(JSON.stringify(body).includes(CF_SAAS_TOKEN), false);
  });
});

describe("/api/me custom domain fields", () => {
  it("includes customDomainsEnabled, customStatus, customRecords when flag on and claim exists", async () => {
    const kv = kvWithSubAndPanel();
    const env = enabledEnv(kv);
    await putCustom(env);
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/me", {
        headers: { Origin: "https://app.securepublish.work" },
      }),
      env
    );
    const body = await res.json();
    assert.equal(body.customDomainsEnabled, true);
    assert.equal(body.customStatus, "pending_dns");
    assert.equal(body.customHostname, HOST);
    assert.equal(body.customVerified, false);
    assert.equal(body.host, "wise.securepublish.work");
    assert.ok(Array.isArray(body.customRecords));
    assert.equal(body.customRecords[0].name, "dashboards");
  });
});

describe("DELETE /api/hosting/custom", () => {
  let mock;
  afterEach(() => mock?.restore());

  it("owner deletes CF hostname, lock, and claim fields (including verified)", async () => {
    mock = installCfFetchMock();
    const kv = kvWithSubAndPanel();
    await kv.put(`host:custom:${HOST}`, "dev@localhost");
    await kv.put(
      "tenant:user:dev@localhost",
      JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: HOST,
        customHostname: HOST,
        customVerified: true,
        customStatus: "active",
        customVerifyToken: "c".repeat(64),
        customCfId: "cf-hn-1",
      })
    );
    const env = enabledEnv(kv);
    const res = await worker.fetch(
      new Request("https://app.securepublish.work/api/hosting/custom", {
        method: "DELETE",
        headers: { Origin: "https://app.securepublish.work" },
      }),
      env
    );
    assert.equal(res.status, 200);
    assert.equal(await kv.get(`host:custom:${HOST}`), null);
    const tenant = JSON.parse(await kv.get("tenant:user:dev@localhost"));
    assert.equal(tenant.customHostname, null);
    assert.equal(tenant.customCfId, null);
    assert.equal(tenant.host, "wise.securepublish.work");
    assert.ok(mock.calls.some((c) => c.method === "DELETE"));
  });
});

describe("serving & routing", () => {
  it("unknown host 404 bytes identical to unknown panel", async () => {
    const kv = kvWithSubAndPanel();
    const env = enabledEnv(kv);
    const unknownPanel = await worker.fetch(
      new Request(`https://wise.securepublish.work/ffffffffffffffffffffffff`, {
        headers: { Host: "wise.securepublish.work" },
      }),
      env
    );
    const unknownHost = await worker.fetch(
      new Request(`https://evil.example.com/${PANEL_ID}`, {
        headers: { Host: "evil.example.com" },
      }),
      env
    );
    assert.equal(unknownPanel.status, 404);
    assert.equal(await unknownPanel.text(), UNKNOWN_PANEL_BODY);
    assert.equal(unknownHost.status, 404);
    assert.equal(await unknownHost.text(), UNKNOWN_PANEL_BODY);
  });

  it("unverified / pending / issuing_cert / records_missing custom host → identical 404", async () => {
    for (const status of ["pending_dns", "issuing_cert", "records_missing"]) {
      const kv = kvWithSubAndPanel();
      await kv.put(`host:custom:${HOST}`, "dev@localhost");
      await kv.put(
        "tenant:user:dev@localhost",
        JSON.stringify({
          email: "dev@localhost",
          slug: "wise",
          host: "wise.securepublish.work",
          customHostname: HOST,
          customVerified: status === "records_missing" ? false : false,
          customStatus: status,
          customCfId: "cf-1",
        })
      );
      const env = enabledEnv(kv);
      const res = await worker.fetch(
        new Request(`https://${HOST}/${PANEL_ID}`, { headers: { Host: HOST } }),
        env
      );
      assert.equal(res.status, 404, status);
      assert.equal(await res.text(), UNKNOWN_PANEL_BODY, status);
    }
  });

  it("active verified custom host serves panel with same ACL", async () => {
    const kv = kvWithSubAndPanel();
    await kv.put(`host:custom:${HOST}`, "dev@localhost");
    await kv.put(
      "tenant:user:dev@localhost",
      JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: HOST,
        customHostname: HOST,
        customVerified: true,
        customStatus: "active",
      })
    );
    const env = enabledEnv(kv);
    const res = await worker.fetch(
      new Request(`https://${HOST}/${PANEL_ID}`, { headers: { Host: HOST } }),
      env
    );
    assert.equal(res.status, 200);
    assert.equal(await res.text(), PANEL_HTML);
  });

  it("CF status alone (verified false) never serves", async () => {
    const kv = kvWithSubAndPanel();
    await kv.put(`host:custom:${HOST}`, "dev@localhost");
    await kv.put(
      "tenant:user:dev@localhost",
      JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        customHostname: HOST,
        customVerified: false,
        customStatus: "pending_dns",
        customCfId: "cf-active-at-cloudflare",
      })
    );
    const env = enabledEnv(kv);
    const res = await worker.fetch(
      new Request(`https://${HOST}/${PANEL_ID}`, { headers: { Host: HOST } }),
      env
    );
    assert.equal(res.status, 404);
    assert.equal(await res.text(), UNKNOWN_PANEL_BODY);
  });

  it("old subdomain 301 uses KV customHostname, not request Host; panel paths only", async () => {
    const kv = kvWithSubAndPanel();
    await kv.put(`host:custom:${HOST}`, "dev@localhost");
    await kv.put(
      "tenant:user:dev@localhost",
      JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: HOST,
        customHostname: HOST,
        customVerified: true,
        customStatus: "active",
      })
    );
    const env = enabledEnv(kv);
    const res = await worker.fetch(
      new Request(`https://wise.securepublish.work/${PANEL_ID}`, {
        headers: { Host: "wise.securepublish.work" },
        redirect: "manual",
      }),
      env
    );
    assert.equal(res.status, 301);
    assert.equal(res.headers.get("location"), `https://${HOST}/${PANEL_ID}`);
    assert.equal(res.headers.get("cache-control"), "private, no-store");

    const spoof = await worker.fetch(
      new Request(`https://evil.example/${PANEL_ID}`, {
        headers: { Host: "wise.securepublish.work" },
        redirect: "manual",
      }),
      env
    );
    assert.equal(spoof.headers.get("location"), `https://${HOST}/${PANEL_ID}`);
  });

  it("10-char code paths including /{code}/{name} 301 to the custom host", async () => {
    const code = "k7f3qx2abc";
    const kv = memoryKv({
      [code]: JSON.stringify(panelRecord()),
      "host:sub:wise": "dev@localhost",
      [`host:custom:${HOST}`]: "dev@localhost",
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: HOST,
        customHostname: HOST,
        customVerified: true,
        customStatus: "active",
      }),
    });
    const env = enabledEnv(kv);
    for (const path of [`/${code}`, `/${code}/performance-out-26`]) {
      const res = await worker.fetch(
        new Request(`https://wise.securepublish.work${path}`, {
          headers: { Host: "wise.securepublish.work" },
          redirect: "manual",
        }),
        env
      );
      assert.equal(res.status, 301, path);
      assert.equal(res.headers.get("location"), `https://${HOST}${path}`, path);
      assert.equal(res.headers.get("cache-control"), "private, no-store", path);
    }
  });

  it("no 301 unless status active", async () => {
    const kv = kvWithSubAndPanel();
    await kv.put(`host:custom:${HOST}`, "dev@localhost");
    await kv.put(
      "tenant:user:dev@localhost",
      JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
        customHostname: HOST,
        customVerified: false,
        customStatus: "issuing_cert",
      })
    );
    const env = enabledEnv(kv);
    const res = await worker.fetch(
      new Request(`https://wise.securepublish.work/${PANEL_ID}`, {
        headers: { Host: "wise.securepublish.work" },
        redirect: "manual",
      }),
      env
    );
    assert.notEqual(res.status, 301);
    assert.equal(res.status, 200);
  });
});

describe("TXT recheck — verify and cron share one function", () => {
  let mock;
  afterEach(() => mock?.restore());

  function activeTenantKv() {
    const kv = kvWithSubAndPanel();
    kv.put(
      `host:custom:${HOST}`,
      "dev@localhost"
    );
    kv.put(
      "tenant:user:dev@localhost",
      JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: HOST,
        customHostname: HOST,
        customVerified: true,
        customStatus: "active",
        customVerifyToken: "d".repeat(64),
        customCfId: "cf-hn-1",
      })
    );
    return kv;
  }

  it("verify on active domain with TXT removed → records_missing; custom 404; subdomain serves, no 301; lock kept", async () => {
    mock = installCfFetchMock({ txtRecords: [] });
    const kv = memoryKv({
      [PANEL_ID]: JSON.stringify(panelRecord()),
      "host:sub:wise": "dev@localhost",
      [`host:custom:${HOST}`]: "dev@localhost",
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: HOST,
        customHostname: HOST,
        customVerified: true,
        customStatus: "active",
        customVerifyToken: "d".repeat(64),
        customCfId: "cf-hn-1",
      }),
    });
    const env = enabledEnv(kv);
    const res = await verify(env);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).status, "records_missing");
    assert.equal(await kv.get(`host:custom:${HOST}`), "dev@localhost");
    const tenant = JSON.parse(await kv.get("tenant:user:dev@localhost"));
    assert.equal(tenant.customVerified, false);
    assert.equal(tenant.customStatus, "records_missing");
    assert.equal(tenant.host, "wise.securepublish.work");

    const custom = await worker.fetch(
      new Request(`https://${HOST}/${PANEL_ID}`, { headers: { Host: HOST } }),
      env
    );
    assert.equal(custom.status, 404);
    assert.equal(await custom.text(), UNKNOWN_PANEL_BODY);

    const sub = await worker.fetch(
      new Request(`https://wise.securepublish.work/${PANEL_ID}`, {
        headers: { Host: "wise.securepublish.work" },
        redirect: "manual",
      }),
      env
    );
    assert.notEqual(sub.status, 301);
    assert.equal(sub.status, 200);
    assert.equal(await sub.text(), PANEL_HTML);
  });

  it("cron path and verify path produce the same KV state on TXT loss", async () => {
    mock = installCfFetchMock({ txtRecords: [] });
    const base = {
      [PANEL_ID]: JSON.stringify(panelRecord()),
      "host:sub:wise": "dev@localhost",
      [`host:custom:${HOST}`]: "dev@localhost",
    };
    const tenant = {
      email: "dev@localhost",
      slug: "wise",
      host: HOST,
      customHostname: HOST,
      customVerified: true,
      customStatus: "active",
      customVerifyToken: "d".repeat(64),
      customCfId: "cf-hn-1",
    };
    const kvA = memoryKv({
      ...base,
      "tenant:user:dev@localhost": JSON.stringify(tenant),
    });
    const kvB = memoryKv({
      ...base,
      "tenant:user:dev@localhost": JSON.stringify(tenant),
    });
    const envA = enabledEnv(kvA);
    const envB = enabledEnv(kvB);
    await verify(envA);
    await recheckAllCustomHostnames(envB);
    assert.deepEqual(
      tenantSnapshot(await kvA.get("tenant:user:dev@localhost")),
      tenantSnapshot(await kvB.get("tenant:user:dev@localhost"))
    );
    assert.equal(await kvA.get(`host:custom:${HOST}`), "dev@localhost");
    assert.equal(await kvB.get(`host:custom:${HOST}`), "dev@localhost");
  });

  it("verify restores records_missing when TXT and CF SSL are ok again", async () => {
    const token = "d".repeat(64);
    mock = installCfFetchMock({ txtRecords: [`sp-verify=${token}`] });
    const kv = memoryKv({
      [PANEL_ID]: JSON.stringify(panelRecord()),
      "host:sub:wise": "dev@localhost",
      [`host:custom:${HOST}`]: "dev@localhost",
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: "wise.securepublish.work",
        customHostname: HOST,
        customVerified: false,
        customStatus: "records_missing",
        customVerifyToken: token,
        customCfId: "cf-hn-1",
      }),
    });
    const env = enabledEnv(kv);
    const res = await verify(env);
    assert.equal((await res.json()).status, "active");
    const tenant = JSON.parse(await kv.get("tenant:user:dev@localhost"));
    assert.equal(tenant.customVerified, true);
    assert.equal(tenant.customStatus, "active");
    assert.equal(tenant.host, HOST);
  });

  it("syncCustomHostname is the function both paths call (TXT loss)", async () => {
    mock = installCfFetchMock({ txtRecords: [] });
    const kv = memoryKv({
      [`host:custom:${HOST}`]: "dev@localhost",
      "tenant:user:dev@localhost": JSON.stringify({
        email: "dev@localhost",
        slug: "wise",
        host: HOST,
        customHostname: HOST,
        customVerified: true,
        customStatus: "active",
        customVerifyToken: "d".repeat(64),
        customCfId: "cf-hn-1",
      }),
    });
    const env = enabledEnv(kv);
    const tenant = JSON.parse(await kv.get("tenant:user:dev@localhost"));
    const out = await syncCustomHostname(env, tenant, { createCfIfMissing: false });
    assert.equal(out.status, "records_missing");
  });
});

describe("pending claims do not lock a hostname", () => {
  let mock;
  afterEach(() => mock?.restore());

  const ALICE = "alice@wises.com.br";
  const BOB = "bob@wises.com.br";

  function twoAccountKv() {
    return memoryKv({
      [PANEL_ID]: JSON.stringify(
        panelRecord(ALICE, { access: { mode: "company", domains: ["wises.com.br"] } })
      ),
      "host:sub:alice": ALICE,
      "host:sub:bob": BOB,
      [`tenant:user:${ALICE}`]: JSON.stringify({
        email: ALICE,
        slug: "alice",
        host: "alice.securepublish.work",
      }),
      [`tenant:user:${BOB}`]: JSON.stringify({
        email: BOB,
        slug: "bob",
        host: "bob.securepublish.work",
      }),
    });
  }

  async function cookieFor(env, email) {
    const setCookie = await mintSessionCookie(
      { email, provider: "google", exp: Math.floor(Date.now() / 1000) + 3600 },
      env.SESSION_SECRET,
      env,
      "https://app.securepublish.work/_auth/callback/google"
    );
    return setCookie.split(";")[0];
  }

  function claimAs(env, cookie, hostname = HOST) {
    return worker.fetch(
      new Request("https://app.securepublish.work/api/hosting/custom", {
        method: "PUT",
        headers: {
          Origin: "https://app.securepublish.work",
          "content-type": "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ hostname }),
      }),
      env
    );
  }

  function verifyAs(env, cookie) {
    return worker.fetch(
      new Request("https://app.securepublish.work/api/hosting/custom/verify", {
        method: "POST",
        headers: {
          Origin: "https://app.securepublish.work",
          Cookie: cookie,
          "content-type": "application/json",
        },
        body: "{}",
      }),
      env
    );
  }

  it("(a) A claims and disappears; B claims the same host, verifies with B's token, reaches active", async () => {
    mock = installCfFetchMock();
    const kv = twoAccountKv();
    const env = oauthEnv(kv);
    const aliceCookie = await cookieFor(env, ALICE);
    const bobCookie = await cookieFor(env, BOB);

    const aClaim = await claimAs(env, aliceCookie);
    assert.equal(aClaim.status, 200);
    await aClaim.json();
    assert.equal(await kv.get(`host:custom:${HOST}`), null);
    const aliceTenant = JSON.parse(await kv.get(`tenant:user:${ALICE}`));
    assert.equal(aliceTenant.customHostname, HOST);
    assert.ok(aliceTenant.customVerifyToken);

    const bClaim = await claimAs(env, bobCookie);
    assert.equal(bClaim.status, 200);
    const bBody = await bClaim.json();
    const bToken = bBody.records[1].value;
    assert.equal(await kv.get(`host:custom:${HOST}`), null);
    const bobTenant = JSON.parse(await kv.get(`tenant:user:${BOB}`));
    assert.notEqual(bobTenant.customVerifyToken, aliceTenant.customVerifyToken);

    mock.restore();
    mock = installCfFetchMock({ txtRecords: [bToken] });
    const bVerify = await verifyAs(env, bobCookie);
    assert.equal(bVerify.status, 200);
    assert.equal((await bVerify.json()).status, "active");
    assert.equal(await kv.get(`host:custom:${HOST}`), BOB);
    const bobAfter = JSON.parse(await kv.get(`tenant:user:${BOB}`));
    assert.equal(bobAfter.customStatus, "active");
    assert.equal(bobAfter.customVerified, true);
  });

  it("(b) after B is active, A's verify is hostname_taken with no CF create and lock unchanged", async () => {
    mock = installCfFetchMock();
    const kv = twoAccountKv();
    const env = oauthEnv(kv);
    const aliceCookie = await cookieFor(env, ALICE);
    const bobCookie = await cookieFor(env, BOB);

    await (await claimAs(env, aliceCookie)).json();
    const bClaim = await claimAs(env, bobCookie);
    const bToken = (await bClaim.json()).records[1].value;
    mock.restore();
    mock = installCfFetchMock({ txtRecords: [bToken] });
    assert.equal((await verifyAs(env, bobCookie)).status, 200);
    assert.equal(await kv.get(`host:custom:${HOST}`), BOB);

    const cfBefore = mock.calls.filter(
      (c) => c.method === "POST" && c.url.includes("custom_hostnames")
    ).length;

    const aVerify = await verifyAs(env, aliceCookie);
    assert.equal(aVerify.status, 409);
    assert.equal((await aVerify.json()).error, "hostname_taken");
    assert.equal(await kv.get(`host:custom:${HOST}`), BOB);
    const cfAfter = mock.calls.filter(
      (c) => c.method === "POST" && c.url.includes("custom_hostnames")
    ).length;
    assert.equal(cfAfter, cfBefore);
  });

  it("(c) claim PUT for a host already locked by another account gives hostname_taken", async () => {
    const kv = twoAccountKv();
    await kv.put(`host:custom:${HOST}`, BOB);
    const env = oauthEnv(kv);
    const aliceCookie = await cookieFor(env, ALICE);
    const res = await claimAs(env, aliceCookie);
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, "hostname_taken");
    assert.equal(await kv.get(`host:custom:${HOST}`), BOB);
    const aliceTenant = JSON.parse(await kv.get(`tenant:user:${ALICE}`));
    assert.notEqual(aliceTenant.customHostname, HOST);
  });
});

