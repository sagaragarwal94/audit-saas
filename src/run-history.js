import fs from "node:fs/promises";
import path from "node:path";

export async function appendRunHistory({ projectDir, runId, projectName, target, focus, url, summary, reportPath }) {
  await fs.mkdir(projectDir, { recursive: true });
  await fs.appendFile(
    path.join(projectDir, "auditsaas-run-history.md"),
    formatRunHistoryEntry({ runId, projectName, target, focus, url, summary, reportPath }),
  );
}

export function formatRunHistoryEntry({ runId, projectName, target, focus, url, summary = {}, reportPath }) {
  const completedAt = new Date().toISOString();
  return `\n## ${completedAt} - ${projectName || "Untitled project"}\n\n` +
    `- Run ID: ${runId || "local"}\n` +
    `- Project path: ${target || "unknown"}\n` +
    `- Focus: ${focus || "all"}\n` +
    `- Runtime URL: ${url || "not scanned"}\n` +
    `- Report path: ${reportPath || "audit-output"}\n` +
    `- Findings: ${summary.total || 0} total, ${summary.critical || 0} critical, ${summary.high || 0} high, ${summary.medium || 0} medium, ${summary.low || 0} low, ${summary.info || 0} info\n`;
}
