import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  validateCustomHostname,
  normalizeCustomHostname,
  customDnsRecords,
} from "../src/hostname.js";

describe("normalizeCustomHostname", () => {
  it("trims, lowercases, strips trailing dots", () => {
    assert.equal(
      normalizeCustomHostname("  Dashboards.Example.COM. ").hostname,
      "dashboards.example.com"
    );
  });

  it("IDN to punycode via new URL", () => {
    const r = normalizeCustomHostname("bücher.example.com");
    assert.equal(r.ok, true);
    assert.equal(r.hostname, "xn--bcher-kva.example.com");
  });

  it("rejects port, path, userinfo", () => {
    for (const h of [
      "dashboards.example.com:443",
      "dashboards.example.com/path",
      "user@dashboards.example.com",
      "user:pass@dashboards.example.com",
      "dashboards.example.com/foo?x=1",
    ]) {
      assert.equal(validateCustomHostname(h).error, "invalid_hostname", h);
    }
  });
});

describe("validateCustomHostname — claim rules", () => {
  it("app.securepublish.work. is reserved", () => {
    const r = validateCustomHostname("app.securepublish.work.");
    assert.equal(r.ok, false);
    assert.equal(r.error, "reserved_hostname");
  });

  it("APP.SecurePublish.WORK is reserved", () => {
    const r = validateCustomHostname("APP.SecurePublish.WORK");
    assert.equal(r.ok, false);
    assert.equal(r.error, "reserved_hostname");
  });

  it("x.pages.dev. is reserved", () => {
    const r = validateCustomHostname("x.pages.dev.");
    assert.equal(r.ok, false);
    assert.equal(r.error, "reserved_hostname");
  });

  it("workers.dev and pages.dev suffixes are reserved (endsWith, not includes)", () => {
    assert.equal(validateCustomHostname("foo.workers.dev").error, "reserved_hostname");
    assert.equal(validateCustomHostname("notworkers.dev").error, "apex_domain_not_supported");
    assert.equal(validateCustomHostname("evilpages.dev").error, "apex_domain_not_supported");
  });

  it("example.com is apex_domain_not_supported", () => {
    const r = validateCustomHostname("example.com");
    assert.equal(r.ok, false);
    assert.equal(r.error, "apex_domain_not_supported");
  });

  it("suaempresa.com.br is apex_domain_not_supported", () => {
    const r = validateCustomHostname("suaempresa.com.br");
    assert.equal(r.ok, false);
    assert.equal(r.error, "apex_domain_not_supported");
  });

  it("bare public suffix com.br is invalid_hostname", () => {
    const r = validateCustomHostname("com.br");
    assert.equal(r.ok, false);
    assert.equal(r.error, "invalid_hostname");
  });

  it("IPv4 and IPv6 literals are invalid_hostname", () => {
    assert.equal(validateCustomHostname("10.0.0.1").error, "invalid_hostname");
    assert.equal(validateCustomHostname("[::1]").error, "invalid_hostname");
    assert.equal(validateCustomHostname("::1").error, "invalid_hostname");
  });

  it("garbage is invalid_hostname", () => {
    for (const h of ["", " ", "...", "not a host", "***", "http://example.com"]) {
      assert.equal(validateCustomHostname(h).error, "invalid_hostname", JSON.stringify(h));
    }
  });

  it("dashboards.example.com is ok", () => {
    const r = validateCustomHostname("dashboards.example.com");
    assert.equal(r.ok, true);
    assert.equal(r.hostname, "dashboards.example.com");
  });

  it("IDN subdomain of an ICANN domain is ok", () => {
    const r = validateCustomHostname("share.münchen.de");
    assert.equal(r.ok, true);
    assert.match(r.hostname, /^share\.xn--/);
  });
});

describe("customDnsRecords — names relative to eTLD+1", () => {
  it("share.example.com → share and _secure-publish.share", () => {
    const recs = customDnsRecords("share.example.com", "abc");
    assert.deepEqual(recs, [
      { type: "CNAME", name: "share", value: "cname.securepublish.work" },
      { type: "TXT", name: "_secure-publish.share", value: "sp-verify=abc" },
    ]);
  });

  it("a.b.example.co.uk → a.b", () => {
    const recs = customDnsRecords("a.b.example.co.uk", "tok");
    assert.equal(recs[0].name, "a.b");
    assert.equal(recs[1].name, "_secure-publish.a.b");
  });
});
