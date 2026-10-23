import assert from "node:assert/strict";
import test from "node:test";
import { parseRuntimeUrl, scanRuntimeUrl } from "../src/runtime.js";
import { runRules } from "../src/rules.js";
import { hangingFetch } from "./helpers.js";

const emptyProject = { files: [], allPaths: [], packageJson: null, providers: { auth: [], payments: [], ai: [], database: [], observability: ["sentry"] } };

function fakeResponse({ url, status = 200, headers = {} }) {
  return { url, status, headers: new Headers(headers), body: null };
}

test("an http URL that redirects to https counts as HTTPS and uses the final headers", async () => {
  const runtime = await scanRuntimeUrl("http://app.example.com", {
    fetchImpl: async () => fakeResponse({
      url: "https://app.example.com/",
      headers: { "strict-transport-security": "max-age=63072000", "x-content-type-options": "nosniff" },
    }),
  });
  assert.equal(runtime.https, true);
  assert.equal(runtime.redirectedToHttps, true);
  assert.ok(!runtime.missingHeaders.includes("strict-transport-security"));
  assert.ok(runtime.missingHeaders.includes("content-security-policy"));

  const { findings } = runRules(emptyProject, { focus: "all", runtime, dataInventory: [] });
  assert.ok(!findings.some((finding) => finding.title === "Production URL is not using HTTPS"));
});

test("an unreachable URL reports the error, not a wall of missing headers", async () => {
  const runtime = await scanRuntimeUrl("https://down.example.com", {
    fetchImpl: async () => { throw new TypeError("fetch failed", { cause: new Error("getaddrinfo ENOTFOUND down.example.com") }); },
  });
  assert.equal(runtime.reachable, false);
  assert.match(runtime.error, /ENOTFOUND/);

  const { findings } = runRules(emptyProject, { focus: "all", runtime, dataInventory: [] });
  assert.ok(!findings.some((finding) => finding.id === "HEADERS_HTTPS_RUNTIME"));
});

test("runtime scan times out instead of hanging", async () => {
  const runtime = await scanRuntimeUrl("https://slow.example.com", {
    timeoutMs: 20,
    fetchImpl: hangingFetch,
  });
  assert.equal(runtime.reachable, false);
  assert.match(runtime.error, /timed out after 20ms/);
});

test("parseRuntimeUrl rejects non-URLs and non-http schemes", () => {
  assert.throws(() => parseRuntimeUrl("example.com"), /Invalid --url/);
  assert.throws(() => parseRuntimeUrl("file:///etc/passwd"), /Only http/);
  assert.equal(parseRuntimeUrl("https://example.com"), "https://example.com/");
});
