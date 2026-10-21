/**
 * Upload size limit: env → GET /api/limits → fallback, plus user-facing copy.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_MAX_UPLOAD_BYTES,
  formatMb,
  isNearUploadLimit,
  isOverUploadLimit,
  isSizeTooLargeResponse,
  nearLimitWarning,
  parsePositiveInt,
  resetUploadLimitCache,
  resolveMaxUploadBytes,
  uploadTooLargeMessage,
} from "../src/upload-limit.js";

describe("DEFAULT_MAX_UPLOAD_BYTES", () => {
  it("is 3 MiB in bytes (3 * 1024 * 1024)", () => {
    assert.equal(DEFAULT_MAX_UPLOAD_BYTES, 3 * 1024 * 1024);
    assert.equal(DEFAULT_MAX_UPLOAD_BYTES, 3145728);
  });
});

describe("parsePositiveInt", () => {
  it("accepts a positive integer string", () => {
    assert.equal(parsePositiveInt("3145728"), 3145728);
    assert.equal(parsePositiveInt(" 100 "), 100);
  });

  it("rejects missing, zero, negative, and non-integers", () => {
    assert.equal(parsePositiveInt(undefined), null);
    assert.equal(parsePositiveInt(""), null);
    assert.equal(parsePositiveInt("0"), null);
    assert.equal(parsePositiveInt("-1"), null);
    assert.equal(parsePositiveInt("1.5"), null);
    assert.equal(parsePositiveInt("nope"), null);
  });
});

describe("formatMb", () => {
  it("prints bytes as MB using 1024 * 1024", () => {
    assert.equal(formatMb(3 * 1024 * 1024), "3.0");
    assert.equal(formatMb(Math.round(2.6 * 1024 * 1024)), "2.6");
  });
});

describe("over / near / under limit", () => {
  const limit = 1000;

  it("treats a file over the limit as over, not near", () => {
    assert.equal(isOverUploadLimit(1001, limit), true);
    assert.equal(isNearUploadLimit(1001, limit), false);
  });

  it("treats a file over 90% of the limit as near, not over", () => {
    assert.equal(isOverUploadLimit(901, limit), false);
    assert.equal(isNearUploadLimit(901, limit), true);
    assert.equal(isNearUploadLimit(1000, limit), true);
  });

  it("treats a file at or under 90% as under the warning", () => {
    assert.equal(isOverUploadLimit(900, limit), false);
    assert.equal(isNearUploadLimit(900, limit), false);
    assert.equal(isOverUploadLimit(1, limit), false);
  });
});

describe("uploadTooLargeMessage", () => {
  it("states the per-publish limit, file size, limit in MB, and practical tips", () => {
    const msg = uploadTooLargeMessage(Math.round(2.6 * 1024 * 1024), 3 * 1024 * 1024);
    assert.match(msg, /too large to publish/i);
    assert.match(msg, /per-publish upload limit/i);
    assert.match(msg, /2\.6 MB/);
    assert.match(msg, /3\.0 MB/);
    assert.match(msg, /Compress/i);
    assert.match(msg, /fewer images/i);
    assert.match(msg, /Move large images/i);
    assert.match(msg, /Split/i);
  });
});

describe("nearLimitWarning", () => {
  it("warns without saying the publish was blocked", () => {
    const msg = nearLimitWarning(901, 1000);
    assert.match(msg, /^warn:/);
    assert.match(msg, /MB/);
    assert.doesNotMatch(msg, /too large to publish/i);
  });
});

describe("isSizeTooLargeResponse", () => {
  it("maps HTTP 413 as size-too-large", () => {
    assert.equal(isSizeTooLargeResponse({ status: 413 }, {}), true);
  });

  it("maps known size-too-large error bodies even without 413", () => {
    assert.equal(
      isSizeTooLargeResponse({ status: 400 }, { error: "payload_too_large" }),
      true
    );
    assert.equal(
      isSizeTooLargeResponse({ status: 400 }, { error: "size_too_large" }),
      true
    );
  });

  it("does not map unrelated errors", () => {
    assert.equal(isSizeTooLargeResponse({ status: 401 }, { error: "unauthorized" }), false);
    assert.equal(isSizeTooLargeResponse({ status: 500 }, { error: "internal" }), false);
    assert.equal(isSizeTooLargeResponse({ status: 200 }, {}), false);
  });
});

describe("resolveMaxUploadBytes", () => {
  beforeEach(() => {
    resetUploadLimitCache();
  });

  afterEach(() => {
    resetUploadLimitCache();
  });

  it("uses SECUREPUBLISH_MAX_UPLOAD_BYTES when set and does not fetch", async () => {
    let fetches = 0;
    const n = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: { SECUREPUBLISH_MAX_UPLOAD_BYTES: "12345" },
      fetchImpl: async () => {
        fetches += 1;
        throw new Error("should not fetch");
      },
    });
    assert.equal(n, 12345);
    assert.equal(fetches, 0);
  });

  it("ignores an invalid env var and falls through", async () => {
    const n = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: { SECUREPUBLISH_MAX_UPLOAD_BYTES: "nope" },
      fetchImpl: async () =>
        new Response(JSON.stringify({ maxUploadBytes: 999 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(n, 999);
  });

  it("uses GET /api/limits maxUploadBytes when the env var is unset", async () => {
    let url;
    const n = await resolveMaxUploadBytes({
      apiBase: "https://app.example/",
      env: {},
      fetchImpl: async (u) => {
        url = String(u);
        return new Response(JSON.stringify({ maxUploadBytes: 1500000 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    assert.equal(url, "https://app.example/api/limits");
    assert.equal(n, 1500000);
  });

  it("falls back to 3145728 when /api/limits is missing (404)", async () => {
    const n = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: {},
      fetchImpl: async () => new Response("nope", { status: 404 }),
    });
    assert.equal(n, DEFAULT_MAX_UPLOAD_BYTES);
  });

  it("falls back to 3145728 when /api/limits fails or returns invalid JSON", async () => {
    const failed = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: {},
      fetchImpl: async () => {
        throw new Error("ECONNRESET");
      },
    });
    assert.equal(failed, DEFAULT_MAX_UPLOAD_BYTES);

    resetUploadLimitCache();
    const badJson = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: {},
      fetchImpl: async () =>
        new Response("not-json", {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(badJson, DEFAULT_MAX_UPLOAD_BYTES);

    resetUploadLimitCache();
    const badValue = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: {},
      fetchImpl: async () =>
        new Response(JSON.stringify({ maxUploadBytes: 0 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(badValue, DEFAULT_MAX_UPLOAD_BYTES);
  });

  it("falls back to 3145728 when there is no apiBase (no hard dependency)", async () => {
    const n = await resolveMaxUploadBytes({
      env: {},
      fetchImpl: async () => {
        throw new Error("should not fetch");
      },
    });
    assert.equal(n, DEFAULT_MAX_UPLOAD_BYTES);
  });

  it("caches GET /api/limits for the rest of the run", async () => {
    let fetches = 0;
    const fetchImpl = async () => {
      fetches += 1;
      return new Response(JSON.stringify({ maxUploadBytes: 42 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    const a = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: {},
      fetchImpl,
    });
    const b = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: {},
      fetchImpl,
    });
    assert.equal(a, 42);
    assert.equal(b, 42);
    assert.equal(fetches, 1);
  });

  it("aborts a slow /api/limits request and falls back", async () => {
    const n = await resolveMaxUploadBytes({
      apiBase: "https://app.example",
      env: {},
      timeoutMs: 20,
      fetchImpl: (_url, init) =>
        new Promise((_, reject) => {
          init.signal.addEventListener("abort", () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            reject(err);
          });
        }),
    });
    assert.equal(n, DEFAULT_MAX_UPLOAD_BYTES);
  });
});
