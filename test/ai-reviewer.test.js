import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildAiReviewInput, redactSecrets, resolveAiReviewConfig, runAiReview } from "../src/ai-reviewer.js";

const audit = {
  project: {
    root: "/tmp/demo-app",
    framework: "nextjs",
    language: "typescript",
    providers: { auth: ["custom_jwt"], payments: ["stripe"], ai: ["openai"], database: [], observability: [] },
  },
  runtime: null,
  summary: { total: 2, critical: 1, high: 1, medium: 0, low: 0, info: 0 },
  dataInventory: [{ dataType: "Email", source: "login form", storedIn: "database", sharedWith: ["Stripe"], risk: "Medium" }],
  findings: [
    {
      id: "SECRET",
      title: "Secret exposed",
      severity: "critical",
      category: "secrets",
      file: ".env",
      line: 1,
      confidence: "high",
      evidence: "OPENAI_API_KEY=sk_test_secret_should_not_leave",
      risk: "Credential abuse",
      recommendation: "Rotate key",
      standards: ["OWASP"],
    },
    {
      id: "IDOR",
      title: "IDOR risk",
      severity: "high",
      category: "authorization",
      file: "app/api/projects/[id]/route.ts",
      confidence: "medium",
      evidence: "Query by id without user scope",
      risk: "Data exposure",
      recommendation: "Scope queries",
      standards: [],
    },
  ],
};

test("resolveAiReviewConfig requires local key and model", () => {
  assert.equal(resolveAiReviewConfig({ env: {} }).enabled, false);
  assert.equal(resolveAiReviewConfig({ env: { AUDITSAAS_AI_REVIEW: "false" } }).reason, "disabled");

  const config = resolveAiReviewConfig({
    env: { AUDITSAAS_LLM_API_KEY: "key", AUDITSAAS_LLM_MODEL: "model" },
  });

  assert.equal(config.enabled, true);
  assert.equal(config.baseUrl, "https://api.openai.com/v1");
});

test("buildAiReviewInput redacts secret-like evidence and keeps compact scanner context", () => {
  const input = buildAiReviewInput(audit, { projectName: "Demo" });

  assert.equal(input.project.name, "Demo");
  assert.equal(input.findings.length, 2);
  assert.match(input.findings[0].evidence, /\[REDACTED\]/);
  assert.doesNotMatch(JSON.stringify(input), /sk_test_secret_should_not_leave/);
});

test("redactSecrets removes common token shapes", () => {
  assert.equal(redactSecrets("token=abc123456789xyz"), "[REDACTED]");
});

test("runAiReview writes markdown and json from an OpenAI-compatible response", async () => {
  const outDir = path.join(os.tmpdir(), `auditsaas-ai-review-${Date.now()}`);
  const review = await runAiReview({
    audit,
    outDir,
    projectName: "Demo",
    env: { AUDITSAAS_LLM_API_KEY: "local-key", AUDITSAAS_LLM_MODEL: "test-model", AUDITSAAS_LLM_BASE_URL: "https://llm.example/v1" },
    fetchImpl: async (url, options) => {
      assert.equal(url, "https://llm.example/v1/chat/completions");
      const body = JSON.parse(options.body);
      assert.equal(body.model, "test-model");
      assert.doesNotMatch(body.messages[1].content, /sk_test_secret_should_not_leave/);
      return {
        ok: true,
        json: async () => ({ choices: [{ message: { content: "# Executive Summary\nReview looks good.\n\n# Top Risks\nFix secrets first." } }] }),
      };
    },
  });

  assert.equal(review.status, "completed");
  assert.equal(review.model, "test-model");
  assert.match(await fs.readFile(path.join(outDir, "ai-review.md"), "utf8"), /Fix secrets first/);
  assert.match(await fs.readFile(path.join(outDir, "ai-review.json"), "utf8"), /test-model/);
});
