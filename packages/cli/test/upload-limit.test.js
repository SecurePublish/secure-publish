/**
 * Server-owned upload limit: fetch /api/limits, skip legacy shape, sanitize.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  LIMITS_FETCH_TIMEOUT_MS,
  SERVER_TEXT_MAX_CHARS,
  fetchUploadLimit,
  isOverUploadLimit,
  sanitizeServerText,
  serverSizeErrorMessage,
} from "../src/upload-limit.js";

describe("LIMITS_FETCH_TIMEOUT_MS", () => {
  it("is 3 seconds", () => {
    assert.equal(LIMITS_FETCH_TIMEOUT_MS, 3000);
  });
});

describe("isOverUploadLimit", () => {
  it("is over only when the request body is strictly larger than maxBytes", () => {
    assert.equal(isOverUploadLimit(101, 100), true);
    assert.equal(isOverUploadLimit(100, 100), false);
    assert.equal(isOverUploadLimit(1, 100), false);
  });
});

describe("sanitizeServerText", () => {
  it("strips ANSI and other control characters", () => {
    const raw = "hello\x1b[31mRED\x1b[0m\x07\x08world\r\nnext";
    const out = sanitizeServerText(raw);
    assert.equal(out.includes("\x1b"), false);
    assert.equal(out.includes("\x07"), false);
    assert.equal(out.includes("\x08"), false);
    assert.equal(out.includes("\r"), false);
    assert.match(out, /hello/);
    assert.match(out, /RED/);
    assert.match(out, /world/);
    assert.match(out, /next/);
  });

  it("caps length at ~500 characters", () => {
    const out = sanitizeServerText("A".repeat(800));
    assert.equal(out.length, SERVER_TEXT_MAX_CHARS);
    assert.equal(SERVER_TEXT_MAX_CHARS, 500);
  });

  it("stringifies non-strings safely", () => {
    assert.equal(sanitizeServerText(undefined), "");
    assert.equal(sanitizeServerText(null), "");
  });
});

describe("serverSizeErrorMessage", () => {
  it("prints the JSON message field unchanged (aside from sanitizing)", () => {
    const msg = "Este arquivo passa do limite. Comprima as imagens.";
    assert.equal(
      serverSizeErrorMessage(JSON.stringify({ message: msg, error: "payload_too_large" })),
      msg
    );
  });

  it("prints raw response text when the 413 body is not JSON", () => {
    assert.equal(serverSizeErrorMessage("Payload Too Large"), "Payload Too Large");
  });

  it("prints raw JSON when the object has no message string", () => {
    const raw = JSON.stringify({ error: "payload_too_large" });
    assert.equal(serverSizeErrorMessage(raw), raw);
  });

  it("sanitizes JSON message and raw text", () => {
    const injected = "x\x1b[31mY\x1b[0m" + "Z".repeat(600);
    const fromJson = serverSizeErrorMessage(JSON.stringify({ message: injected }));
    assert.equal(fromJson.includes("\x1b"), false);
    assert.equal(fromJson.length, 500);
    const fromRaw = serverSizeErrorMessage("\x1b[0m" + "Q".repeat(10));
    assert.equal(fromRaw, "Q".repeat(10));
  });
});

describe("fetchUploadLimit", () => {
  it("reads upload.maxBytes and upload.message from GET /api/limits", async () => {
    let url;
    let init;
    const limit = await fetchUploadLimit({
      apiBase: "https://app.example/",
      lang: "en",
      fetchImpl: async (u, opts) => {
        url = String(u);
        init = opts;
        return new Response(
          JSON.stringify({
            upload: { maxBytes: 1500000, message: "too big — compress images" },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    });
    assert.equal(url, "https://app.example/api/limits");
    assert.equal(init.method, "GET");
    assert.equal(init.headers.accept, "application/json");
    assert.equal(init.headers["accept-language"], "en");
    assert.equal(limit.maxBytes, 1500000);
    assert.equal(limit.message, "too big — compress images");
  });

  it("sends Accept-Language from --lang (default pt)", async () => {
    let init;
    await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async (_u, opts) => {
        init = opts;
        return new Response(JSON.stringify({ upload: { maxBytes: 1, message: "x" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    assert.equal(init.headers["accept-language"], "pt");
  });

  it("skips pre-check when the response is the legacy {maxUploadBytes} shape", async () => {
    const limit = await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async () =>
        new Response(JSON.stringify({ maxUploadBytes: 3145728 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(limit, null);
  });

  it("returns null when /api/limits fails, 404s, or returns invalid JSON", async () => {
    const failed = await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async () => {
        throw new Error("ECONNRESET");
      },
    });
    assert.equal(failed, null);

    const missing = await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async () => new Response("nope", { status: 404 }),
    });
    assert.equal(missing, null);

    const badJson = await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async () =>
        new Response("not-json", {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(badJson, null);

    const badValue = await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async () =>
        new Response(JSON.stringify({ upload: { maxBytes: 0, message: "x" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(badValue, null);
  });

  it("returns null when there is no apiBase", async () => {
    const n = await fetchUploadLimit({
      fetchImpl: async () => {
        throw new Error("should not fetch");
      },
    });
    assert.equal(n, null);
  });

  it("aborts a slow /api/limits request and returns null", async () => {
    const n = await fetchUploadLimit({
      apiBase: "https://app.example",
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
    assert.equal(n, null);
  });
});
