import path from "node:path";
import { runAiReview } from "./ai-reviewer.js";
import { auditProject } from "./index.js";
import { appendRunHistory } from "./run-history.js";
import {
  apiBase,
  clearCredentials,
  completeRun,
  createDevice,
  getDeviceId,
  hashProjectPath,
  pollDeviceToken,
  readCredentials,
  startRun,
  updateRun,
  whoami,
  writeCredentials,
} from "./cli-license.js";

export async function runCli(argv) {
  const [, , command = "help", targetArg = "."] = argv;

  if (command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  if (command === "login") return login();
  if (command === "logout") return logout();
  if (command === "whoami") return printWhoami();
  if (command !== "scan") {
    throw new Error(`Unknown command "${command}". Run: saas-audit help`);
  }

  await scan(argv, targetArg);
}

async function login() {
  const existing = await readCredentials();
  if (existing?.licenseToken) {
    console.log(`Already connected. Run \`saas-audit whoami\` to inspect this device, or \`saas-audit logout\` to reconnect.`);
    return;
  }

  const deviceId = await getDeviceId();
  const device = await createDevice(deviceId);
  if (device.licenseToken) {
    await writeCredentials({
      licenseToken: device.licenseToken,
      userId: device.userId,
      email: device.email,
      plan: device.plan,
      deviceId,
      apiBase: apiBase(),
    });
    console.log(`Connected as ${device.email || device.userId}. Plan: ${device.plan}.`);
    return;
  }

  console.log("Open this URL to connect the Gravel CLI:");
  console.log(device.verificationUrl);
  console.log(`Code: ${device.userCode}`);
  console.log("Waiting for approval...");

  const deadline = new Date(device.expiresAt).getTime();
  while (Date.now() < deadline) {
    const result = await pollDeviceToken(device.deviceCode);
    if (result.licenseToken) {
      await writeCredentials({
        licenseToken: result.licenseToken,
        userId: result.userId,
        email: result.email,
        plan: result.plan,
        deviceId,
        apiBase: apiBase(),
      });
      console.log(`Connected as ${result.email || result.userId}. Plan: ${result.plan}.`);
      return;
    }
    await wait(2500);
  }

  throw new Error("Login expired. Run `saas-audit login` again.");
}

async function logout() {
  await clearCredentials();
  console.log("Gravel CLI credentials removed.");
}

async function printWhoami() {
  const credentials = await requireCredentials();
  const remote = await whoami(credentials).catch(() => null);
  console.log(`API: ${apiBase()}`);
  console.log(`Token source: ${credentials.source}`);
  console.log(`Account: ${remote?.user?.email || credentials.email || "unknown"}`);
  console.log(`Plan: ${remote?.subscription?.entitlement || credentials.plan || "free"}`);
  console.log(`Free run used: ${remote?.trial?.completed ? "yes" : "no"}`);
}

async function scan(argv, targetArg) {
  const credentials = await requireCredentials();
  const options = parseOptions(argv.slice(4));
  const target = path.resolve(process.cwd(), targetArg);
  const outDir = path.resolve(process.cwd(), options.outDir || "audit-output");
  const projectName = options.name || options.projectName || path.basename(target);
  const focus = options.focus || "all";

  const started = await startRun(credentials, {
    projectName,
    projectPathHash: hashProjectPath(target),
    source: "cli",
  }).catch((error) => {
    if (error.status === 402) {
      throw new Error(`${error.message}\nUpgrade: ${absoluteUrl(error.data?.checkoutUrl || "/billing?plan=pro")}`);
    }
    throw error;
  });
  const runId = started.run.id;

  await updateRun(credentials, runId, {
    status: "running",
    percentComplete: 18,
    currentStep: "Collecting project files",
  });

  const result = await auditProject({
    target,
    outDir,
    focus,
    url: options.url,
  });

  await updateRun(credentials, runId, {
    status: "running",
    percentComplete: 78,
    currentStep: "Reviewing audit findings",
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

  await completeRun(credentials, runId, {
    findingsCount: result.summary.total,
    findingsSummary: result.summary,
    findings: result.findings,
    reportPath: result.outDir,
    aiReviewStatus: aiReview.status,
    aiReviewSummary: aiReview.summary,
    aiReviewModel: aiReview.model,
    aiReviewGeneratedAt: aiReview.generatedAt,
  });

  console.log("AI SaaS audit complete.");
  console.log(`Project: ${result.project.root}`);
  console.log(`Findings: ${result.summary.total} total, ${result.summary.critical} critical, ${result.summary.high} high`);
  console.log(`AI review: ${aiReview.status}${aiReview.model ? ` (${aiReview.model})` : ""}`);
  console.log(`Reports: ${result.outDir}`);
}

async function requireCredentials() {
  const credentials = await readCredentials();
  if (!credentials?.licenseToken) {
    throw new Error("Run `saas-audit login` before scanning. Set GRAVEL_API_BASE if your Gravel app is not local.");
  }
  return credentials;
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

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function absoluteUrl(value) {
  try {
    return new URL(value).toString();
  } catch {
    return new URL(value, apiBase()).toString();
  }
}

function printHelp() {
  console.log(`Gravel Audit CLI

Usage:
  saas-audit login
  saas-audit logout
  saas-audit whoami
  saas-audit scan <path> [--name "My App"] [--out-dir ./audit-output] [--focus security|privacy|payments|ai|all] [--url https://app.example.com] [--ai-model gpt-4.1-mini] [--no-ai-review]

Environment:
  GRAVEL_API_BASE=http://127.0.0.1:4000
  GRAVEL_LICENSE_TOKEN=<token>
  GRAVEL_LLM_API_KEY=<your-local-llm-key>
  GRAVEL_LLM_MODEL=<openai-compatible-model>
  GRAVEL_LLM_BASE_URL=https://api.openai.com/v1
  GRAVEL_AI_REVIEW=true|false

Examples:
  saas-audit login
  saas-audit scan .
  saas-audit scan . --focus ai
  saas-audit scan . --url https://app.example.com
`);
}
