import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runAiReview } from "./ai-reviewer.js";
import { auditProject } from "./index.js";
import { appendRunHistory } from "./run-history.js";
import { color, severityLabel, formatDuration, padRight } from "./tty.js";

const CLI_VERSION = readCliVersion();

export async function runCli(argv) {
  const [, , command = "help", targetArg = "."] = argv;

  if (command === "version" || command === "--version" || command === "-v") {
    console.log(CLI_VERSION);
    return;
  }

  if (command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  if (command !== "scan") {
    throw new Error(`Unknown command "${command}". Run: saas-audit help`);
  }

  await scan(argv, targetArg);
}

async function scan(argv, targetArg) {
  const options = parseOptions(argv.slice(4));
  const target = path.resolve(process.cwd(), targetArg);
  const outDir = path.resolve(process.cwd(), options.outDir || "audit-output");
  const projectName = options.name || options.projectName || path.basename(target);
  const focus = options.focus || "all";
  const runId = `local_${Date.now().toString(36)}`;

  console.log(color.dim(`Scanning ${target} ...`));

  const result = await auditProject({
    target,
    outDir,
    focus,
    url: options.url,
  });

  const aiReview = await runAiReview({
    audit: result,
    outDir: result.outDir,
    projectName,
    modelOverride: options.aiModel,
    disabled: options.noAiReview,
  });

  await appendRunHistory({
    projectDir: target,
    runId,
    projectName,
    target,
    focus,
    url: options.url,
    summary: result.summary,
    reportPath: result.outDir,
  });

  printSummary(result, aiReview, options);
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
    const bands = ["critical", "high", "medium", "low", "info"]
      .filter((severity) => summary[severity] > 0)
      .map((severity) => severityLabel(severity, summary[severity]));
    console.log(`${color.bold(String(summary.total))} findings: ${bands.join("  ")}`);
    console.log("");
    printCategoryTable(findings);
  }

  console.log("");
  console.log(`${color.bold("AI review:")} ${aiReview.status}${aiReview.model ? ` (${aiReview.model})` : ""}`);
  console.log(`${color.bold("Reports:")} ${result.outDir}`);
  if (options.url) {
    console.log(color.dim(`Runtime headers checked against: ${options.url}`));
  }
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

function parseOptions(args) {
  const options = {};
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--out-dir" || arg === "--output") options.outDir = args[++i];
    else if (arg === "--focus") options.focus = args[++i];
    else if (arg === "--url") options.url = args[++i];
    else if (arg === "--name" || arg === "--project-name" || arg === "--app-name") options.name = args[++i];
    else if (arg === "--ai-model") options.aiModel = args[++i];
    else if (arg === "--no-ai-review") options.noAiReview = true;
    else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
  }
  return options;
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
  saas-audit --version
  saas-audit scan <path> [options]

${color.bold("Options")}
  --name "My App"              Project name used in reports
  --out-dir ./audit-output     Where to write report files (default: ./audit-output)
  --focus security|privacy|payments|ai|all   Limit which rule categories run (default: all)
  --url https://app.example.com   Also check HTTPS and security headers on a live URL
  --ai-model gpt-4.1-mini       Override the AI review model
  --no-ai-review                 Skip the optional AI second-pass review

${color.bold("Environment")}
  AUDITSAAS_LLM_API_KEY=<your-local-llm-key>
  AUDITSAAS_LLM_MODEL=<openai-compatible-model>
  AUDITSAAS_LLM_BASE_URL=https://api.openai.com/v1
  AUDITSAAS_AI_REVIEW=true|false
  NO_COLOR=1                     Disable colored terminal output

${color.bold("Examples")}
  saas-audit scan .
  saas-audit scan . --focus ai
  saas-audit scan . --url https://app.example.com
`);
}
