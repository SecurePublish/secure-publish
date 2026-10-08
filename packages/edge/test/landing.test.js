/**
 * Worker origin landing (GET /) is shown in the browser — publish hint must be npx.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/worker.js";

const GITHUB_NPX = "npx --yes github:clovistx/secure-publish";
const BARE_CLI_RUN =
  /(?:^|\n)\s*(?:`)?securepublish-cli\s+(?:login|publish|logout|list|revoke|doctor|mock-serve|help|status)\b/;

describe("Worker GET / publish hint", () => {
  it("tells humans to run npx github: publish, not bare securepublish-cli", async () => {
    const res = await worker.fetch(
      new Request("https://secure-publish.clovist.workers.dev/"),
      {
        PANELS: {
          async get() {
            return null;
          },
        },
      }
    );
    assert.equal(res.status, 404);
    const text = await res.text();
    assert.match(text, new RegExp(`${GITHUB_NPX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} publish`));
    assert.doesNotMatch(text, BARE_CLI_RUN);
    assert.doesNotMatch(text, /Publish: securepublish-cli /);
  });
});
