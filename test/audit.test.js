import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { auditProject } from "../src/index.js";

test("audits vulnerable fixture and writes deliverables", async () => {
  const outDir = path.join(os.tmpdir(), `saas-audit-${Date.now()}`);
  const target = path.resolve("test/fixtures/vulnerable-app");
  const result = await auditProject({ target, outDir });

  assert.ok(result.summary.total > 5);
  assert.ok(result.findings.some((finding) => finding.id === "PAYMENT_STRIPE_WEBHOOK_SIGNATURE_MISSING"));
  assert.ok(result.findings.some((finding) => finding.id === "AUTHZ_IDOR_POSSIBLE"));
  assert.ok(result.findings.some((finding) => finding.id === "AI_FRONTEND_OR_UNBOUNDED"));
  assert.ok(result.dataInventory.length > 0);

  const report = await fs.readFile(path.join(outDir, "audit-report.md"), "utf8");
  const privacy = await fs.readFile(path.join(outDir, "privacy-policy-draft.md"), "utf8");
  const findings = JSON.parse(await fs.readFile(path.join(outDir, "findings.json"), "utf8"));

  assert.match(report, /AI SaaS Security, Privacy & Scalability Audit/);
  assert.match(privacy, /Privacy Policy Draft/);
  assert.equal(findings.length, result.findings.length);
});
