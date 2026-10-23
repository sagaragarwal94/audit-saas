import fs from "node:fs/promises";
import path from "node:path";
import { SEVERITIES } from "./config.js";

export async function writeReports(payload) {
  const files = {
    "audit-report.md": renderAuditReport(payload),
    "findings.json": `${JSON.stringify(payload.exportedFindings || payload.findings, null, 2)}\n`,
    "findings.sarif.json": `${JSON.stringify(renderSarif({ ...payload, findings: payload.exportedFindings || payload.findings }), null, 2)}\n`,
    "priority-action-plan.md": renderActionPlan(payload.findings),
    "privacy-policy-draft.md": payload.privacyPolicy,
    "data-inventory.md": renderDataInventory(payload.dataInventory),
    "production-readiness-checklist.md": renderProductionChecklist(payload)
  };

  await Promise.all(Object.entries(files).map(([name, content]) => fs.writeFile(path.join(payload.outDir, name), content)));
}

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
// GitHub code scanning buckets results by this numeric score (>=9 critical,
// >=7 high, >=4 medium, otherwise low).
const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };
const RULES_PAGE = "https://auditsaas.org/rules";

export function renderSarif({ findings, project, toolVersion }) {
  const ruleIds = [...new Set(findings.map((finding) => finding.id))];
  const ruleIndex = new Map(ruleIds.map((id, index) => [id, index]));
  // Code scanning drops results without a location, so project-wide
  // findings are anchored to the manifest when there is one.
  const fallbackUri = project?.packageJson ? "package.json" : null;

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "AuditSaas",
            ...(toolVersion ? { version: toolVersion, semanticVersion: toolVersion } : {}),
            informationUri: "https://auditsaas.org",
            rules: ruleIds.map((id) => {
              const finding = findings.find((item) => item.id === id);
              return {
                id,
                name: id,
                shortDescription: { text: finding.title },
                fullDescription: { text: finding.risk || finding.title },
                help: {
                  text: finding.recommendation || "",
                  markdown: `${finding.recommendation || ""}${finding.codeExample ? `\n\n\`\`\`ts\n${finding.codeExample}\n\`\`\`` : ""}`
                },
                helpUri: `${RULES_PAGE}#${id}`,
                defaultConfiguration: { level: SARIF_LEVEL[finding.severity] || "warning" },
                properties: {
                  category: finding.category,
                  standards: finding.standards || [],
                  tags: ["security", finding.category],
                  "security-severity": SECURITY_SEVERITY[finding.severity] || "5.5"
                }
              };
            })
          }
        },
        automationDetails: { id: "auditsaas/" },
        results: findings.map((finding) => {
          const uri = finding.file ? finding.file.replaceAll("\\", "/") : fallbackUri;
          return {
            ruleId: finding.id,
            ruleIndex: ruleIndex.get(finding.id),
            level: SARIF_LEVEL[finding.severity] || "warning",
            message: { text: `${finding.title}${finding.file ? "" : " (project-wide)"}. ${finding.recommendation || ""}`.trim() },
            locations: uri
              ? [
                  {
                    physicalLocation: {
                      artifactLocation: { uri },
                      region: { startLine: finding.line || 1 }
                    }
                  }
                ]
              : [],
            partialFingerprints: { "auditsaasFingerprint/v1": finding.fingerprint },
            ...(finding.baselineState ? { baselineState: finding.baselineState } : {}),
            properties: { confidence: finding.confidence, severity: finding.severity }
          };
        })
      }
    ]
  };
}

function renderAuditReport({ project, projectName, toolVersion, runtime, findings, suppressed = [], summary, dataInventory }) {
  const grouped = groupBySeverity(findings);
  return `# AI SaaS Security, Privacy & Scalability Audit

## Executive Summary

Project: ${projectName || path.basename(project.root)} (\`${project.root}\`)
Generated: ${new Date().toISOString()}${toolVersion ? ` by AuditSaas v${toolVersion}` : ""}

Detected stack:

- Framework: ${project.framework}
- Language: ${project.language}
- Auth: ${project.providers.auth.join(", ") || "not detected"}
- Payments: ${project.providers.payments.join(", ") || "not detected"}
- AI: ${project.providers.ai.join(", ") || "not detected"}
- Database: ${project.providers.database.join(", ") || "not detected"}
- Observability: ${project.providers.observability.join(", ") || "not detected"}

Overall findings: ${summary.total} total, ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.info} info.${summary.suppressed ? ` ${summary.suppressed} suppressed by config or \`auditsaas-ignore\` comments (listed at the end).` : ""}${summary.baselined ? ` ${summary.baselined} already present in the baseline and not shown.` : ""}

${runtime ? renderRuntimeSummary(runtime) : "Runtime URL scan was not requested. Run with `--url https://your-app.com` to check HTTPS and response security headers."}

## Critical Issues

${renderFindings(grouped.critical)}

## High Priority Issues

${renderFindings(grouped.high)}

## Medium Priority Issues

${renderFindings(grouped.medium)}

## Low Priority Issues

${renderFindings(grouped.low)}

## Informational

${renderFindings(grouped.info)}

## Data Collection Inventory

${renderInventoryTable(dataInventory)}

## Privacy Policy Draft Summary

A draft privacy policy was generated in \`privacy-policy-draft.md\`. It is based on detected data collection, storage, third-party processors, AI usage, payments, cookies, analytics, and logging. Have it reviewed by a qualified legal professional before publication.

## Post-Deploy Monitoring Plan

Add alerts for failed login spikes, repeated 401/403 responses, sequential ID access attempts, AI spend spikes, high token usage, unusual data exports, payment webhook failures, admin access from unknown locations, error-rate spikes, and database latency spikes.

## Production Readiness

Review \`production-readiness-checklist.md\` for launch gating items.
${renderSuppressed(suppressed)}`;
}

function renderSuppressed(suppressed) {
  if (suppressed.length === 0) return "";
  return `
## Suppressed Findings

These matched a rule but were suppressed. Re-check them when the surrounding code changes.

| Rule | Location | Suppressed by |
|---|---|---|
${suppressed.map((finding) => `| ${finding.id} | ${escapeTable(finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "project-wide")} | ${finding.suppressedBy} |`).join("\n")}
`;
}

function renderRuntimeSummary(runtime) {
  if (!runtime.reachable) return `Runtime URL scan failed for ${runtime.url}: ${runtime.error || "unknown error"}.`;
  return `Runtime URL: ${runtime.url}${runtime.finalUrl && runtime.finalUrl !== runtime.url ? ` (redirected to ${runtime.finalUrl})` : ""}

- HTTPS: ${runtime.https ? (runtime.redirectedToHttps ? "yes (HTTP redirects to HTTPS)" : "yes") : "no"}
- Status: ${runtime.status}
- Missing security headers: ${runtime.missingHeaders.length ? runtime.missingHeaders.join(", ") : "none detected"}`;
}

function renderFindings(findings) {
  if (!findings || findings.length === 0) return "No findings in this severity band.";
  return findings.map((finding, index) => `### ${index + 1}. ${finding.title}

- Severity: ${finding.severity}
- Category: ${finding.category}
- File: ${finding.file || "project-wide"}
- Line: ${finding.line || "n/a"}
- Confidence: ${finding.confidence}
- Standards: ${finding.standards?.join("; ") || "n/a"}
- Evidence: ${finding.evidence ? `\`${String(finding.evidence).replaceAll("`", "'")}\`` : "Pattern-based finding"}
- Fingerprint: ${finding.fingerprint || "n/a"}

Risk:
${finding.risk}

Recommendation:
${finding.recommendation}

${finding.codeExample ? `Example:\n\n\`\`\`ts\n${finding.codeExample}\n\`\`\`\n` : ""}`).join("\n");
}

function renderActionPlan(findings) {
  const critical = findings.filter((finding) => finding.severity === "critical");
  const high = findings.filter((finding) => finding.severity === "high");
  const medium = findings.filter((finding) => finding.severity === "medium");
  return `# Prioritized Action Plan

## Fix Immediately

${renderActionItems(critical)}

## Fix Before Public Launch

${renderActionItems(high)}

## Improve Before Scaling

${renderActionItems(medium)}

## Ongoing Hardening

- Add CI secret scanning, dependency scanning, and custom audit rules.
- Review reports after every major auth, payments, AI, or database change.
- Add post-deploy anomaly detection and cost alerts.
`;
}

function renderActionItems(findings) {
  if (findings.length === 0) return "- No items in this band.";
  return findings.map((finding) => `- [ ] ${finding.title}${finding.file ? ` (${finding.file}${finding.line ? `:${finding.line}` : ""})` : ""}: ${finding.recommendation}`).join("\n");
}

function renderDataInventory(dataInventory) {
  return `# Data Inventory

${renderInventoryTable(dataInventory)}
`;
}

function renderInventoryTable(dataInventory) {
  if (dataInventory.length === 0) return "No data collection points were detected by the scanner.";
  return `| Data Type | Source | Stored In | Shared With | Risk | Evidence |
|---|---|---|---|---|---|
${dataInventory.map((item) => `| ${escapeTable(item.dataType)} | ${escapeTable(item.source)} | ${escapeTable(item.storedIn)} | ${escapeTable(item.sharedWith.join(", ") || "unknown/none detected")} | ${item.risk} | ${escapeTable(item.evidenceFiles.join(", "))} |`).join("\n")}`;
}

function renderProductionChecklist({ runtime }) {
  return `# Production Readiness Checklist

- [ ] Authentication requires secure password hashing or trusted provider-managed auth.
- [ ] Login and password reset flows are rate limited.
- [ ] Sessions expire and logout invalidates active sessions where applicable.
- [ ] Cookies use HttpOnly, Secure, and SameSite controls.
- [ ] All sensitive database queries are scoped by user, org, or tenant.
- [ ] API routes validate input and return minimal response DTOs.
- [ ] Stripe/payment webhooks verify signatures and are idempotent.
- [ ] OpenAI/AI calls run server-side behind auth, quota, token caps, and rate limits.
- [ ] Secrets are server-side only and real .env files are not committed.
- [ ] Logs redact passwords, tokens, cookies, prompts, payment payloads, and request bodies.
- [ ] HTTPS is enforced for app URLs, OAuth callbacks, and webhooks.
- [ ] Security headers are configured: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- [ ] Privacy policy has been reviewed and published.
- [ ] Alerts exist for failed login spikes, 401/403 spikes, sequential ID probing, AI spend spikes, webhook failures, admin actions, error spikes, and database latency.

${renderRuntimeChecklistNote(runtime)}
`;
}

function renderRuntimeChecklistNote(runtime) {
  if (!runtime) return "Runtime header scan not run. Use `--url` to verify deployed security headers.";
  if (!runtime.reachable) return `Runtime scan target ${runtime.url} could not be reached (${runtime.error || "unknown error"}); headers were not checked.`;
  return `Runtime scan target: ${runtime.finalUrl || runtime.url}\n\nMissing runtime headers: ${runtime.missingHeaders.join(", ") || "none detected"}`;
}

function groupBySeverity(findings) {
  return Object.fromEntries(SEVERITIES.map((severity) => [severity, findings.filter((finding) => finding.severity === severity)]));
}

function escapeTable(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}
