import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { runAiReview } from "./ai-reviewer.js";
import { FOCUS_VALUES, SEVERITIES, UsageError, loadConfig, validateFailOn, validateFocus } from "./config.js";
import { countAtOrAbove } from "./findings.js";
import { assertScanTarget, auditProject } from "./index.js";
import { loadRuleCatalog } from "./rule-catalog.js";
import { parseRuntimeUrl } from "./runtime.js";
import { appendRunHistory } from "./run-history.js";
import { color, severityColor, severityLabel, formatDuration, padRight } from "./tty.js";

const CLI_VERSION = readCliVersion();

const SCAN_OPTIONS = {
  name: { type: "string" },
  "project-name": { type: "string" },
  "app-name": { type: "string" },
  "out-dir": { type: "string" },
  output: { type: "string" },
  focus: { type: "string" },
  url: { type: "string" },
  "ai-model": { type: "string" },
  "no-ai-review": { type: "boolean" },
  "fail-on": { type: "string" },
  baseline: { type: "string" },
  config: { type: "string" },
  json: { type: "boolean" },
  "no-history": { type: "boolean" },
  help: { type: "boolean", short: "h" }
};

const RULES_OPTIONS = {
  json: { type: "boolean" },
  help: { type: "boolean", short: "h" }
};

// Exit codes: 0 = success, 1 = findings at/above --fail-on (or an internal
// error), 2 = usage/config error. Scripts and CI can tell "the scan found
// something" apart from "the scan never ran".
export async function runCli(argv) {
  const [, , command = "help", ...rest] = argv;

  if (command === "version" || command === "--version" || command === "-v") {
    console.log(CLI_VERSION);
    return;
  }

  if (command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  if (command === "rules") {
    listRules(parseCommandArgs(rest, RULES_OPTIONS));
    return;
  }

  if (command !== "scan") {
    throw new UsageError(`Unknown command "${command}".`);
  }

  const { values, positionals } = parseCommandArgs(rest, SCAN_OPTIONS);
  if (values.help) {
    printHelp();
    return;
  }
  if (positionals.length > 1) throw new UsageError(`Expected one scan path, got ${positionals.length}: ${positionals.join(" ")}`);
  await scan(values, positionals[0] || ".");
}

function parseCommandArgs(args, options) {
  try {
    return parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (error) {
    throw new UsageError(error.message);
  }
}

async function scan(options, targetArg) {
  const target = path.resolve(process.cwd(), targetArg);
  const outDir = path.resolve(process.cwd(), options["out-dir"] || options.output || "audit-output");
  const projectName = options.name || options["project-name"] || options["app-name"] || path.basename(target);
  if (options.focus !== undefined) validateFocus(options.focus);
  if (options["fail-on"] !== undefined) validateFailOn(options["fail-on"]);
  if (options.url !== undefined) parseRuntimeUrl(options.url);
  await assertScanTarget(target);

  // With --json, stdout carries only the machine-readable result.
  const log = options.json ? (...args) => console.error(...args) : (...args) => console.log(...args);
  const config = await loadConfig(target, options.config);
  const failOn = options["fail-on"] || config.failOn || "none";
  const runId = `local_${Date.now().toString(36)}`;

  log(color.dim(`Scanning ${target} ...`));
  if (config.path) log(color.dim(`Using config ${config.path}`));

  const result = await auditProject({
    target,
    outDir,
    focus: options.focus,
    url: options.url,
    config,
    baseline: options.baseline ? path.resolve(process.cwd(), options.baseline) : undefined,
    projectName,
    toolVersion: CLI_VERSION
  });

  const aiReview = await runAiReview({
    audit: result,
    outDir: result.outDir,
    projectName,
    modelOverride: options["ai-model"],
    disabled: options["no-ai-review"],
  });

  if (!options["no-history"]) {
    try {
      await appendRunHistory({
        projectDir: target,
        runId,
        projectName,
        target,
        focus: result.focus,
        url: options.url,
        summary: result.summary,
        reportPath: result.outDir,
      });
    } catch (error) {
      log(color.yellow(`Warning: could not write auditsaas-run-history.md (${error.message}). Use --no-history to skip it.`));
    }
  }

  const failing = countAtOrAbove(result.findings, failOn);
  if (options.json) {
    console.log(JSON.stringify({
      version: CLI_VERSION,
      target,
      outDir: result.outDir,
      focus: result.focus,
      failOn,
      failed: failing > 0 || (failOn !== "none" && result.errors.length > 0),
      summary: result.summary,
      filesScanned: result.filesScanned,
      durationMs: result.durationMs,
      errors: result.errors,
      aiReview: { status: aiReview.status, model: aiReview.model || null },
      findings: result.findings
    }, null, 2));
  } else {
    printSummary(result, aiReview, options);
  }

  for (const error of result.errors) log(color.yellow(`Warning: rule ${error.ruleId} failed and was skipped: ${error.message}`));
  if (failing > 0) {
    log(color.red(`\n${failing} finding(s) at or above "${failOn}" severity (--fail-on ${failOn}).`));
    process.exitCode = 1;
  }
  // A gate that silently skipped a rule isn't a passing gate.
  if (failOn !== "none" && result.errors.length > 0) {
    log(color.red(`\n${result.errors.length} rule(s) crashed, so the --fail-on ${failOn} check is incomplete.`));
    process.exitCode = 1;
  }
}

function printSummary(result, aiReview, options) {
  const { summary, filesScanned, durationMs, findings } = result;

  console.log("");
  console.log(color.bold("AuditSaas scan complete"));
  console.log(color.dim(`${filesScanned} files scanned in ${formatDuration(durationMs)}`));
  console.log("");

  if (summary.total === 0) {
    console.log(color.green("No findings for the selected focus. Nice."));
  } else {
    const bands = SEVERITIES
      .filter((severity) => summary[severity] > 0)
      .map((severity) => severityLabel(severity, summary[severity]));
    console.log(`${color.bold(String(summary.total))} findings: ${bands.join("  ")}`);
    console.log("");
    printCategoryTable(findings);
    printTopFindings(findings);
  }

  const hidden = [
    summary.suppressed ? `${summary.suppressed} suppressed` : "",
    summary.baselined ? `${summary.baselined} in baseline` : ""
  ].filter(Boolean);
  if (hidden.length) console.log(color.dim(`\nNot shown: ${hidden.join(", ")}`));

  console.log("");
  console.log(`${color.bold("AI review:")} ${aiReview.status}${aiReview.model ? ` (${aiReview.model})` : ""}`);
  console.log(`${color.bold("Reports:")} ${result.outDir}`);
  if (options.url) {
    console.log(color.dim(`Runtime headers checked against: ${options.url}`));
  }
}

function printTopFindings(findings) {
  const top = findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").slice(0, 10);
  if (top.length === 0) return;
  console.log("");
  console.log(color.bold("Top findings"));
  for (const finding of top) {
    const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "project-wide";
    console.log(`  ${severityColor(finding.severity, finding.severity.toUpperCase().padEnd(8))} ${finding.title}`);
    console.log(color.dim(`           ${location}  ${finding.id}`));
  }
  const remaining = findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").length - top.length;
  if (remaining > 0) console.log(color.dim(`  ...and ${remaining} more in audit-report.md`));
}

function printCategoryTable(findings) {
  const byCategory = new Map();
  for (const finding of findings) {
    const row = byCategory.get(finding.category) || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    row[finding.severity] = (row[finding.severity] || 0) + 1;
    row.total += 1;
    byCategory.set(finding.category, row);
  }

  const categories = [...byCategory.keys()].sort((a, b) => byCategory.get(b).total - byCategory.get(a).total);
  const nameWidth = Math.max(...categories.map((name) => name.length), "category".length) + 2;

  console.log(color.dim(`${padRight("category", nameWidth)}critical  high  medium  low  info`));
  for (const category of categories) {
    const row = byCategory.get(category);
    console.log(
      `${padRight(category, nameWidth)}${padRight(row.critical || "-", 10)}${padRight(row.high || "-", 6)}${padRight(row.medium || "-", 8)}${padRight(row.low || "-", 5)}${row.info || "-"}`
    );
  }
}

function listRules({ values }) {
  if (values.help) {
    printHelp();
    return;
  }
  const rules = [...loadRuleCatalog().values()].sort((a, b) => a.category.localeCompare(b.category) || a.id.localeCompare(b.id));
  if (values.json) {
    console.log(JSON.stringify(rules, null, 2));
    return;
  }
  const idWidth = Math.max(...rules.map((rule) => rule.id.length)) + 2;
  let category = "";
  for (const rule of rules) {
    if (rule.category !== category) {
      category = rule.category;
      console.log(`\n${color.bold(category)}`);
    }
    console.log(`  ${padRight(rule.id, idWidth)}${severityColor(rule.severity, padRight(rule.severity, 9))}${color.dim(rule.title || "")}`);
  }
  console.log(color.dim(`\n${rules.length} rules. Details: https://auditsaas.org/rules`));
}

function readCliVersion() {
  try {
    const packagePath = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    return JSON.parse(readFileSync(packagePath, "utf8")).version || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function printHelp() {
  console.log(`${color.bold("AuditSaas")} ${color.dim(`v${CLI_VERSION}`)} — local security, privacy, AI, and payments audit CLI

${color.bold("Usage")}
  saas-audit scan [path] [options]
  saas-audit rules [--json]
  saas-audit --version

${color.bold("Scan options")}
  --name "My App"                Project name used in reports
  --out-dir ./audit-output       Where to write report files (default: ./audit-output)
  --focus <area>                 ${FOCUS_VALUES.join("|")} (default: all)
  --url https://app.example.com  Also check HTTPS and security headers on a live URL
  --fail-on <severity>           Exit 1 if any finding is at/above ${SEVERITIES.join("|")}|none (default: none)
  --baseline findings.json       Only report findings not present in a previous scan's findings.json
  --config .auditsaas.json       Config file (default: <path>/.auditsaas.json if present)
  --json                         Print the result as JSON on stdout (logs go to stderr)
  --no-history                   Don't append to auditsaas-run-history.md in the scanned project
  --ai-model <model>             Override the AI review model
  --no-ai-review                 Skip the optional AI second-pass review

${color.bold("Suppressing findings")}
  // auditsaas-ignore RULE_ID -- reason     on the line, or the line above
  // auditsaas-ignore-file RULE_ID          anywhere in a file
  .auditsaas.json: { "ignorePaths": ["test/fixtures/**"], "ignoreRules": ["RULE_ID"], "failOn": "high" }

${color.bold("Environment")}
  AUDITSAAS_LLM_API_KEY=<provider-key>
  AUDITSAAS_LLM_MODEL=<openai-compatible-model>
  AUDITSAAS_LLM_BASE_URL=https://api.openai.com/v1
  AUDITSAAS_LLM_TIMEOUT_MS=120000
  AUDITSAAS_AI_REVIEW=true|false
  NO_COLOR=1                     Disable colored terminal output

${color.bold("Exit codes")}
  0 success · 1 findings at/above --fail-on, or an internal error · 2 invalid usage or config

${color.bold("Examples")}
  saas-audit scan .
  saas-audit scan . --focus ai
  saas-audit scan . --fail-on high --no-history
  saas-audit scan . --url https://app.example.com
`);
}
