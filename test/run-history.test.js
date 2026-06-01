import assert from "node:assert/strict";
import test from "node:test";
import { formatRunHistoryEntry } from "../src/run-history.js";

test("formatRunHistoryEntry appends a readable scan summary", () => {
  const entry = formatRunHistoryEntry({
    runId: "run_123",
    projectName: "Billing API",
    target: "/apps/billing-api",
    focus: "security",
    url: "https://billing.example.com",
    reportPath: "/apps/billing-api/audit-output",
    summary: { total: 5, critical: 1, high: 2, medium: 1, low: 1, info: 0 },
  });

  assert.match(entry, /## .* - Billing API/);
  assert.match(entry, /- Run ID: run_123/);
  assert.match(entry, /- Findings: 5 total, 1 critical, 2 high, 1 medium, 1 low, 0 info/);
});
