import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkPanelAccess, normalizeEmails, normalizeDomains } from "../src/acl.js";
import {
  accessToApiMode,
  accessToAllowlist,
  buildAccessFromPatch,
  formatPublishedLabel,
  viewsToApi,
  PANEL_ID_RE,
} from "../src/kv.js";
import { consoleOrigins, corsHeaders } from "../src/api.js";

describe("ACL Lock A — company = email domain", () => {
  it("allows same domain for company mode", () => {
    const r = checkPanelAccess(
      { email: "ana@acme.example" },
      { mode: "company", domains: ["acme.example"] },
      {}
    );
    assert.equal(r.ok, true);
  });

  it("denies other domain for company mode", () => {
    const r = checkPanelAccess(
      { email: "x@other.com" },
      { mode: "company", domains: ["acme.example"] },
      {}
    );
    assert.equal(r.ok, false);
    assert.equal(r.reason, "domain_not_allowed");
  });

  it("treats org alias as company (domain)", () => {
    const r = checkPanelAccess(
      { email: "ana@acme.example" },
      { mode: "org", domains: ["acme.example"] },
      {}
    );
    assert.equal(r.ok, true);
  });

  it("allowlist requires exact email", () => {
    const ok = checkPanelAccess(
      { email: "ana@acme.example" },
      { mode: "allowlist", emails: ["ana@acme.example"] },
      {}
    );
    assert.equal(ok.ok, true);
    const no = checkPanelAccess(
      { email: "bruno@acme.example" },
      { mode: "allowlist", emails: ["ana@acme.example"] },
      {}
    );
    assert.equal(no.ok, false);
    assert.equal(no.reason, "not_on_allowlist");
  });

  it("falls back to env company domains", () => {
    const r = checkPanelAccess(
      { email: "ana@acme.example" },
      { mode: "company", domains: [] },
      { OAUTH_ALLOWED_DOMAINS: "acme.example" }
    );
    assert.equal(r.ok, true);
  });
});

describe("normalize helpers", () => {
  it("normalizes emails", () => {
    assert.deepEqual(normalizeEmails([" Ana@X.COM ", "ana@x.com", "bad"]), [
      "ana@x.com",
    ]);
  });
  it("normalizes domains", () => {
    assert.deepEqual(normalizeDomains("@Acme.Example, acme.example"), ["acme.example"]);
  });
});

describe("API shape helpers", () => {
  it("maps access to contract mode/allowlist", () => {
    assert.equal(accessToApiMode({ mode: "org" }), "company");
    assert.equal(accessToApiMode({ mode: "allowlist" }), "allowlist");
    assert.deepEqual(accessToAllowlist({ mode: "allowlist", emails: ["a@b.com"] }), [
      "a@b.com",
    ]);
    assert.deepEqual(accessToAllowlist({ mode: "company", domains: ["b.com"] }), []);
  });

  it("buildAccessFromPatch sets domain from publisher for company", () => {
    const a = buildAccessFromPatch({ mode: "company" }, "eu@acme.example");
    assert.equal(a.mode, "company");
    assert.deepEqual(a.domains, ["acme.example"]);
    const b = buildAccessFromPatch(
      { mode: "allowlist", allowlist: ["x@acme.example"] },
      "eu@acme.example"
    );
    assert.equal(b.mode, "allowlist");
    assert.deepEqual(b.emails, ["x@acme.example"]);
  });

  it("panel id is 24 hex", () => {
    assert.equal(PANEL_ID_RE.test("a".repeat(24)), true);
    assert.equal(PANEL_ID_RE.test("a7k2m9"), false);
  });

  it("viewsToApi formats viewers", () => {
    const { views, viewers } = viewsToApi({
      count: 2,
      byEmail: {
        "ana@acme.example": {
          first: "2026-10-02T03:19:00-03:00",
          last: "2026-10-02T03:41:00-03:00",
        },
      },
    });
    assert.equal(views, 2);
    assert.equal(viewers.length, 1);
    assert.equal(viewers[0].email, "ana@acme.example");
    assert.ok(viewers[0].first);
    assert.ok(viewers[0].last);
  });

  it("formatPublishedLabel returns a local Sao Paulo label without timezone suffix", () => {
    const label = formatPublishedLabel("2026-10-02T03:18:00.000Z");
    assert.equal(label, "02/10/2026 · 00:18");
    assert.ok(!label.includes("BRT"));
  });
});

describe("CORS — exact CONSOLE_ORIGIN + credentials", () => {
  it("parses origins", () => {
    assert.deepEqual(
      consoleOrigins({ CONSOLE_ORIGIN: "https://a.pages.dev, https://b.example/" }),
      ["https://a.pages.dev", "https://b.example"]
    );
  });

  it("reflects only allowlisted Origin", () => {
    const env = { CONSOLE_ORIGIN: "https://console.pages.dev" };
    const ok = corsHeaders(
      new Request("https://worker.example/api/me", {
        headers: { Origin: "https://console.pages.dev" },
      }),
      env
    );
    assert.equal(ok["Access-Control-Allow-Origin"], "https://console.pages.dev");
    assert.equal(ok["Access-Control-Allow-Credentials"], "true");

    const bad = corsHeaders(
      new Request("https://worker.example/api/me", {
        headers: { Origin: "https://evil.example" },
      }),
      env
    );
    assert.equal(bad["Access-Control-Allow-Origin"], undefined);
  });
});
