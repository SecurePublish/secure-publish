/**
 * Server-owned upload limit: fetch /api/limits, skip legacy shape, sanitize.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  LIMITS_FETCH_TIMEOUT_MS,
  SERVER_TEXT_MAX_CHARS,
  SIZE_REFUSED_MESSAGE,
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
  it("is over only when the HTML UTF-8 size is strictly larger than maxBytes", () => {
    assert.equal(isOverUploadLimit(101, 100), true);
    assert.equal(isOverUploadLimit(100, 100), false);
    assert.equal(isOverUploadLimit(1, 100), false);
    assert.equal(isOverUploadLimit(3145728, 3145728), false);
    assert.equal(isOverUploadLimit(3145729, 3145728), true);
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

  it("strips C1 controls including CSI (U+009B)", () => {
    const raw = "ok\u0080\u009b[31mRED\u009c\u009fend";
    const out = sanitizeServerText(raw);
    assert.equal(out.includes("\u0080"), false);
    assert.equal(out.includes("\u009b"), false);
    assert.equal(out.includes("\u009c"), false);
    assert.equal(out.includes("\u009f"), false);
    assert.match(out, /ok/);
    assert.match(out, /end/);
  });

  it("strips bidi controls (U+202A–U+202E, U+2066–U+2069)", () => {
    const raw = "https://safe.example/\u202e\u202amalicious\u202c \u2066hidden\u2069";
    const out = sanitizeServerText(raw);
    for (const ch of [
      "\u202a",
      "\u202b",
      "\u202c",
      "\u202d",
      "\u202e",
      "\u2066",
      "\u2067",
      "\u2068",
      "\u2069",
    ]) {
      assert.equal(out.includes(ch), false, `expected ${JSON.stringify(ch)} stripped`);
    }
    assert.match(out, /https:\/\/safe\.example\//);
    assert.match(out, /malicious/);
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

  it("uses a short generic line when the 413 has no usable JSON message", () => {
    assert.equal(
      SIZE_REFUSED_MESSAGE.pt,
      "O servidor recusou o arquivo por ser grande demais. Diminua o arquivo e tente de novo."
    );
    assert.equal(
      SIZE_REFUSED_MESSAGE.en,
      "The server rejected this file as too large. Make it smaller and try again."
    );
    assert.equal(serverSizeErrorMessage("Payload Too Large"), SIZE_REFUSED_MESSAGE.pt);
    assert.equal(serverSizeErrorMessage("Payload Too Large", "en"), SIZE_REFUSED_MESSAGE.en);
    assert.equal(
      serverSizeErrorMessage(JSON.stringify({ error: "payload_too_large" })),
      SIZE_REFUSED_MESSAGE.pt
    );
    assert.equal(
      serverSizeErrorMessage(JSON.stringify({ message: "" })),
      SIZE_REFUSED_MESSAGE.pt
    );
    assert.equal(
      serverSizeErrorMessage(JSON.stringify({ message: "   " })),
      SIZE_REFUSED_MESSAGE.pt
    );
  });

  it("never dumps HTML from a 413 body", () => {
    const html = "<!DOCTYPE html><html><body>" + "x".repeat(600) + "</body></html>";
    const out = serverSizeErrorMessage(html);
    assert.equal(out, SIZE_REFUSED_MESSAGE.pt);
    assert.doesNotMatch(out, /<!DOCTYPE|<html|<body/i);
    assert.ok(out.length < 200);
  });

  it("sanitizes a usable JSON message and does not fall back", () => {
    const injected = "x\x1b[31mY\x1b[0m" + "Z".repeat(600);
    const fromJson = serverSizeErrorMessage(JSON.stringify({ message: injected }));
    assert.equal(fromJson.includes("\x1b"), false);
    assert.equal(fromJson.length, 500);
    assert.match(fromJson, /^xY/);
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

  it("skips pre-check when upload.message is missing or empty", async () => {
    const missing = await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async () =>
        new Response(JSON.stringify({ upload: { maxBytes: 10 } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(missing, null);

    const empty = await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async () =>
        new Response(JSON.stringify({ upload: { maxBytes: 10, message: "" } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(empty, null);

    const blank = await fetchUploadLimit({
      apiBase: "https://app.example",
      fetchImpl: async () =>
        new Response(JSON.stringify({ upload: { maxBytes: 10, message: "   " } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    assert.equal(blank, null);
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
