import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { unquoteTxt, txtMatchesVerify, lookupTxt } from "../src/dns.js";

describe("unquoteTxt", () => {
  it("strips surrounding quotes from DoH data", () => {
    assert.equal(unquoteTxt('"sp-verify=a@b.com"'), "sp-verify=a@b.com");
  });

  it("concatenates adjacent quoted chunks", () => {
    assert.equal(unquoteTxt('"sp-verify=""a@b.com"'), "sp-verify=a@b.com");
  });

  it("passes through bare strings", () => {
    assert.equal(unquoteTxt("sp-verify=a@b.com"), "sp-verify=a@b.com");
  });
});

describe("txtMatchesVerify", () => {
  it("exact match", () => {
    assert.equal(txtMatchesVerify(["sp-verify=dev@localhost"], "sp-verify=dev@localhost"), true);
  });

  it("whitespace-separated tokens", () => {
    assert.equal(
      txtMatchesVerify(["other sp-verify=dev@localhost trailing"], "sp-verify=dev@localhost"),
      true
    );
  });

  it("rejects prefix email spoof", () => {
    assert.equal(
      txtMatchesVerify(["sp-verify=dev@localhost.evil"], "sp-verify=dev@localhost"),
      false
    );
  });

  it("rejects mismatch", () => {
    assert.equal(txtMatchesVerify(["sp-verify=other@x.com"], "sp-verify=dev@localhost"), false);
  });

  it("empty records", () => {
    assert.equal(txtMatchesVerify([], "sp-verify=dev@localhost"), false);
  });
});

describe("lookupTxt", () => {
  it("parses DoH JSON Answer type 16 with quoted data", async () => {
    const fakeFetch = async () =>
      new Response(
        JSON.stringify({
          Status: 0,
          Answer: [
            {
              name: "_secure-publish.dash.acme.example.",
              type: 16,
              TTL: 60,
              data: '"sp-verify=dev@localhost"',
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/dns-json" } }
      );
    const r = await lookupTxt("_secure-publish.dash.acme.example", fakeFetch);
    assert.equal(r.ok, true);
    assert.deepEqual(r.records, ["sp-verify=dev@localhost"]);
  });

  it("returns empty records when no Answer", async () => {
    const fakeFetch = async () =>
      new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
    const r = await lookupTxt("_secure-publish.missing.example", fakeFetch);
    assert.equal(r.ok, true);
    assert.deepEqual(r.records, []);
  });

  it("dns_lookup_failed on HTTP error", async () => {
    const fakeFetch = async () => new Response("nope", { status: 500 });
    const r = await lookupTxt("x.example", fakeFetch);
    assert.equal(r.ok, false);
    assert.equal(r.error, "dns_lookup_failed");
  });
});
