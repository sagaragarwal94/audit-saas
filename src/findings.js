import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { SEVERITIES, UsageError } from "./config.js";

const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((severity, index) => [severity, index]));
const LINE_DIRECTIVE = /auditsaas-ignore(?!-file)\b([^\n]*)/;
const FILE_DIRECTIVE = /auditsaas-ignore-file\b([^\n]*)/g;

export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? SEVERITIES.length;
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) =>
    severityRank(a.severity) - severityRank(b.severity) ||
    (a.file || "").localeCompare(b.file || "") ||
    (a.line || 0) - (b.line || 0) ||
    a.id.localeCompare(b.id)
  );
}

// Stable across unrelated edits: keyed on rule, file, and the matched line's
// text rather than its line number, so inserting code above a finding
// doesn't turn it into a "new" finding against a baseline. Identical
// matches in one file are disambiguated by occurrence order.
export function addFingerprints(findings) {
  const seen = new Map();
  return findings.map((finding) => {
    const evidence = String(finding.evidence || "").replace(/\s+/g, " ").trim();
    const base = createHash("sha256")
      .update([finding.id, finding.file || "", finding.title || "", evidence].join("\u0000"))
      .digest("hex")
      .slice(0, 16);
    const occurrence = (seen.get(base) || 0) + 1;
    seen.set(base, occurrence);
    return { ...finding, fingerprint: occurrence === 1 ? base : `${base}:${occurrence}` };
  });
}

// Inline: `// auditsaas-ignore RULE_ID -- reason` on the finding's line or the
// line above. File-wide: `auditsaas-ignore-file RULE_ID` anywhere in the file.
// With no rule IDs, a directive suppresses every rule. Config `ignoreRules`
// drops a rule project-wide.
export function applySuppressions(findings, project, config = {}) {
  const ignoredRules = new Set(config.ignoreRules || []);
  const filesByPath = new Map(project.files.map((file) => [file.relativePath, file]));
  const fileDirectiveCache = new Map();
  const kept = [];
  const suppressed = [];

  for (const finding of findings) {
    let reason = null;
    if (ignoredRules.has(finding.id)) {
      reason = "config";
    } else if (finding.file && filesByPath.has(finding.file)) {
      const file = filesByPath.get(finding.file);
      if (!fileDirectiveCache.has(file.relativePath)) fileDirectiveCache.set(file.relativePath, fileDirectives(file.content));
      if (matchesDirective(fileDirectiveCache.get(file.relativePath), finding.id)) {
        reason = "file-directive";
      } else if (finding.line && lineSuppresses(file.content, finding.line, finding.id)) {
        reason = "inline-directive";
      }
    }
    if (reason) suppressed.push({ ...finding, suppressedBy: reason });
    else kept.push(finding);
  }

  return { findings: kept, suppressed };
}

function fileDirectives(content) {
  if (!content.includes("auditsaas-ignore-file")) return [];
  return [...content.matchAll(FILE_DIRECTIVE)].map((match) => directiveRuleIds(match[1]));
}

function lineSuppresses(content, line, ruleId) {
  if (!content.includes("auditsaas-ignore")) return false;
  const lines = content.split(/\r?\n/);
  return [lines[line - 1], lines[line - 2]].some((text) => {
    const match = text?.match(LINE_DIRECTIVE);
    return match ? matchesDirective([directiveRuleIds(match[1])], ruleId) : false;
  });
}

function directiveRuleIds(rest) {
  const beforeReason = rest.split("--")[0];
  return beforeReason.match(/\b[A-Z][A-Z0-9_]{2,}\b/g) || [];
}

function matchesDirective(directives, ruleId) {
  return directives.some((ids) => ids.length === 0 || ids.includes(ruleId));
}

export async function loadBaseline(file) {
  let parsed;
  try {
    parsed = JSON.parse(await fs.readFile(file, "utf8"));
  } catch (error) {
    throw new UsageError(`Could not read baseline ${file}: ${error.message}`);
  }
  const list = Array.isArray(parsed) ? parsed : parsed?.findings;
  if (!Array.isArray(list)) throw new UsageError(`Baseline ${file} must be a findings.json array from a previous scan`);
  const fingerprints = new Set(list.map((finding) => finding?.fingerprint).filter(Boolean));
  if (list.length > 0 && fingerprints.size === 0) {
    throw new UsageError(`Baseline ${file} has no fingerprints; regenerate it with auditsaas >= 0.2.0`);
  }
  return fingerprints;
}

// Splits findings into new ones (reported, counted, gated on) and unchanged
// ones. Both still go into findings.json/SARIF, tagged with SARIF's
// baselineState, so the latest output can be reused as the next baseline
// without losing the entries it already covered.
export function applyBaseline(findings, fingerprints) {
  if (!fingerprints) return { findings, unchanged: [], exported: findings };
  const tagged = findings.map((finding) => ({
    ...finding,
    baselineState: fingerprints.has(finding.fingerprint) ? "unchanged" : "new"
  }));
  return {
    findings: tagged.filter((finding) => finding.baselineState === "new"),
    unchanged: tagged.filter((finding) => finding.baselineState === "unchanged"),
    exported: tagged
  };
}

export function summarize(findings) {
  const summary = { total: findings.length };
  for (const severity of SEVERITIES) summary[severity] = findings.filter((finding) => finding.severity === severity).length;
  return summary;
}

export function countAtOrAbove(findings, threshold) {
  if (!threshold || threshold === "none") return 0;
  const limit = severityRank(threshold);
  return findings.filter((finding) => severityRank(finding.severity) <= limit).length;
}
