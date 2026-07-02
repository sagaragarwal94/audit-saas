import fs from "node:fs/promises";
import path from "node:path";
import { collectProject } from "./scanner.js";
import { runRules } from "./rules.js";
import { scanRuntimeUrl } from "./runtime.js";
import { buildDataInventory, buildPrivacyPolicy } from "./privacy.js";
import { writeReports } from "./reports.js";

export async function auditProject({ target, outDir, focus = "all", url }) {
  const startedAt = Date.now();
  const project = await collectProject(target);
  const runtime = url ? await scanRuntimeUrl(url) : null;
  const dataInventory = buildDataInventory(project);
  const findings = runRules(project, { focus, runtime, dataInventory });
  const privacyPolicy = buildPrivacyPolicy(project, dataInventory);
  const summary = summarize(findings);
  const durationMs = Date.now() - startedAt;

  await fs.mkdir(outDir, { recursive: true });
  await writeReports({
    outDir,
    project,
    runtime,
    findings,
    summary,
    dataInventory,
    privacyPolicy
  });

  return {
    outDir: path.resolve(outDir),
    project,
    runtime,
    findings,
    summary,
    dataInventory,
    filesScanned: project.files.length,
    durationMs
  };
}

function summarize(findings) {
  return {
    total: findings.length,
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    low: findings.filter((finding) => finding.severity === "low").length,
    info: findings.filter((finding) => finding.severity === "info").length
  };
}
