import fs from "node:fs/promises";
import path from "node:path";
import { loadConfig, UsageError } from "./config.js";
import { addFingerprints, applyBaseline, applySuppressions, loadBaseline, sortFindings, summarize } from "./findings.js";
import { collectProject } from "./scanner.js";
import { runRules } from "./rules.js";
import { scanRuntimeUrl } from "./runtime.js";
import { buildDataInventory, buildPrivacyPolicy } from "./privacy.js";
import { writeReports } from "./reports.js";

export { loadConfig } from "./config.js";

export async function auditProject({ target, outDir, focus, url, config, configPath, baseline, projectName, toolVersion }) {
  const startedAt = Date.now();
  await assertScanTarget(target);
  const resolvedConfig = config || await loadConfig(target, configPath);
  const effectiveFocus = focus || resolvedConfig.focus || "all";

  const project = await collectProject(target, { ignorePaths: resolvedConfig.ignorePaths });
  const runtime = url ? await scanRuntimeUrl(url) : null;
  const dataInventory = buildDataInventory(project);
  const { findings: rawFindings, errors } = runRules(project, { focus: effectiveFocus, runtime, dataInventory });
  const fingerprinted = addFingerprints(sortFindings(rawFindings));
  const { findings: unsuppressed, suppressed } = applySuppressions(fingerprinted, project, resolvedConfig);
  const { findings, unchanged, exported } = applyBaseline(unsuppressed, baseline ? await loadBaseline(baseline) : null);
  const privacyPolicy = buildPrivacyPolicy(project, dataInventory);
  const summary = { ...summarize(findings), suppressed: suppressed.length, baselined: unchanged.length };
  const durationMs = Date.now() - startedAt;

  await fs.mkdir(outDir, { recursive: true });
  await writeReports({
    outDir,
    project,
    projectName: projectName || path.basename(project.root),
    toolVersion,
    runtime,
    findings,
    exportedFindings: exported,
    suppressed,
    summary,
    dataInventory,
    privacyPolicy
  });

  return {
    outDir: path.resolve(outDir),
    project,
    runtime,
    findings,
    suppressed,
    summary,
    errors,
    dataInventory,
    config: resolvedConfig,
    focus: effectiveFocus,
    filesScanned: project.files.length,
    durationMs
  };
}

export async function assertScanTarget(target) {
  let stat;
  try {
    stat = await fs.stat(target);
  } catch {
    throw new UsageError(`Scan target does not exist: ${target}`);
  }
  if (!stat.isDirectory()) throw new UsageError(`Scan target is not a directory: ${target}`);
}
