import fs from "node:fs/promises";
import path from "node:path";
import { severityRank } from "./findings.js";
import { redactSecrets } from "./redact.js";

export { redactSecrets } from "./redact.js";

const DEFAULT_BASE_URL = "https://api.openai.com/v1";
const DEFAULT_TIMEOUT_MS = 120_000;

export function resolveAiReviewConfig({ env = process.env, modelOverride, disabled = false } = {}) {
  if (disabled || isFalse(env.AUDITSAAS_AI_REVIEW)) return { enabled: false, reason: "disabled" };

  const apiKey = env.AUDITSAAS_LLM_API_KEY || "";
  const model = modelOverride || env.AUDITSAAS_LLM_MODEL || "";
  const baseUrl = env.AUDITSAAS_LLM_BASE_URL || "";
  if (!model) return { enabled: false, reason: "missing_config" };
  // A hosted default endpoint always needs a real key. An explicit base URL
  // usually means a local model server (Ollama, LM Studio, ...) that does
  // not require one.
  if (!apiKey && !baseUrl) return { enabled: false, reason: "missing_config" };

  const timeoutMs = Number.parseInt(env.AUDITSAAS_LLM_TIMEOUT_MS || "", 10);
  return {
    enabled: true,
    apiKey: apiKey || "local",
    model,
    baseUrl: baseUrl || DEFAULT_BASE_URL,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS,
  };
}

export async function runAiReview({ audit, outDir, projectName, modelOverride, disabled = false, env = process.env, fetchImpl = fetch }) {
  const config = resolveAiReviewConfig({ env, modelOverride, disabled });
  if (!config.enabled) {
    return { status: "skipped", reason: config.reason, summary: "AI review skipped because local LLM config is not enabled." };
  }

  const generatedAt = new Date().toISOString();
  try {
    const reviewInput = buildAiReviewInput(audit, { projectName });
    const content = await requestOpenAiCompatibleReview({ config, reviewInput, fetchImpl });
    const review = {
      status: "completed",
      model: config.model,
      generatedAt,
      summary: summarizeReview(content),
      content,
    };
    await writeAiReviewFiles(outDir, review, reviewInput);
    return { ...review, reportPath: path.join(path.resolve(outDir), "ai-review.md") };
  } catch (error) {
    const review = {
      status: "failed",
      model: config.model,
      generatedAt,
      summary: "AI review failed. Deterministic audit reports were still generated.",
      error: error.message,
    };
    await writeAiReviewFiles(outDir, review, null);
    return { ...review, reportPath: path.join(path.resolve(outDir), "ai-review.md") };
  }
}

export function buildAiReviewInput(audit, { projectName } = {}) {
  const findings = [...audit.findings]
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 20)
    .map((finding) => ({
      id: finding.id,
      title: redactSecrets(finding.title),
      severity: finding.severity,
      category: finding.category,
      file: finding.file || "project-wide",
      line: finding.line || null,
      confidence: finding.confidence,
      evidence: redactSecrets(finding.evidence || "Pattern-based finding").slice(0, 700),
      risk: redactSecrets(finding.risk || "").slice(0, 900),
      recommendation: redactSecrets(finding.recommendation || "").slice(0, 900),
      standards: finding.standards || [],
    }));

  return {
    project: {
      name: projectName || path.basename(audit.project.root),
      framework: audit.project.framework,
      language: audit.project.language,
      providers: audit.project.providers,
    },
    summary: audit.summary,
    runtime: audit.runtime ? {
      url: audit.runtime.url,
      reachable: audit.runtime.reachable,
      https: audit.runtime.https,
      status: audit.runtime.status,
      missingHeaders: audit.runtime.missingHeaders || [],
    } : null,
    dataInventory: audit.dataInventory.slice(0, 20).map((item) => ({
      dataType: redactSecrets(item.dataType),
      source: redactSecrets(item.source),
      storedIn: redactSecrets(item.storedIn),
      sharedWith: item.sharedWith,
      risk: item.risk,
    })),
    findings,
  };
}

async function requestOpenAiCompatibleReview({ config, reviewInput, fetchImpl }) {
  const messages = [
    {
      role: "system",
      content: "You are AuditSaas's senior SaaS security audit reviewer. Review deterministic scanner output. Do not claim to have seen full source code. Be concise, practical, and specific.",
    },
    {
      role: "user",
      content: `Review this local scanner output and return Markdown with sections: Executive Summary, Top Risks, Likely False Positives, Fix Order, Launch Readiness Verdict.\n\n${JSON.stringify(reviewInput, null, 2)}`,
    },
  ];

  let { response, data } = await postChatCompletion({ config, fetchImpl, body: { model: config.model, temperature: 0.2, messages } });
  // Reasoning models reject any non-default temperature; retry once without it.
  if (!response.ok && /temperature/i.test(errorMessage(data))) {
    ({ response, data } = await postChatCompletion({ config, fetchImpl, body: { model: config.model, messages } }));
  }
  if (!response.ok) throw new Error(errorMessage(data) || `LLM request failed with ${response.status}`);

  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error("LLM response did not include review content");
  return redactSecrets(content);
}

async function postChatCompletion({ config, fetchImpl, body }) {
  const timeoutMs = config.timeoutMs || DEFAULT_TIMEOUT_MS;
  let response;
  try {
    response = await fetchImpl(chatCompletionsUrl(config.baseUrl), {
      method: "POST",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch (error) {
    if (error?.name === "TimeoutError") throw new Error(`LLM request timed out after ${timeoutMs}ms (set AUDITSAAS_LLM_TIMEOUT_MS to raise it)`);
    throw new Error(`Could not reach LLM endpoint ${config.baseUrl}: ${error?.cause?.message || error?.message || error}`);
  }
  const data = await response.json().catch(() => ({}));
  return { response, data };
}

function errorMessage(data) {
  return data?.error?.message || data?.message || "";
}

async function writeAiReviewFiles(outDir, review, reviewInput) {
  await fs.mkdir(outDir, { recursive: true });
  await Promise.all([
    fs.writeFile(path.join(outDir, "ai-review.md"), renderAiReviewMarkdown(review)),
    fs.writeFile(path.join(outDir, "ai-review.json"), `${JSON.stringify({ ...review, reviewInput }, null, 2)}\n`),
  ]);
}

function renderAiReviewMarkdown(review) {
  if (review.status === "completed") {
    return `# AuditSaas AI Audit Review\n\nModel: ${review.model}\nGenerated: ${review.generatedAt}\n\n${review.content}\n`;
  }

  return `# AuditSaas AI Audit Review\n\nStatus: ${review.status}\nModel: ${review.model || "not configured"}\nGenerated: ${review.generatedAt || new Date().toISOString()}\n\n${review.summary}\n${review.error ? `\nError: ${review.error}\n` : ""}`;
}

function summarizeReview(content) {
  return content
    .split(/\r?\n/)
    .map((line) => line.replace(/^#+\s*/, "").trim())
    .filter(Boolean)
    .slice(0, 3)
    .join(" ")
    .slice(0, 600);
}

function chatCompletionsUrl(baseUrl) {
  const trimmed = String(baseUrl || DEFAULT_BASE_URL).replace(/\/$/, "");
  return trimmed.endsWith("/chat/completions") ? trimmed : `${trimmed}/chat/completions`;
}

function isFalse(value) {
  return /^(0|false|off|no)$/i.test(String(value || ""));
}
