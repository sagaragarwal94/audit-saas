#!/usr/bin/env node
// Regenerates the rule listing in site/rules.html from rules/*.md so the
// public site never becomes a third, hand-maintained copy of the catalog
// (the other two -- rules/*.md and src/rules.js -- are kept in sync by
// test/rule-parity.test.js). Run via `npm run build:rules-page`.

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const rulesDir = path.join(root, "rules");
const rulesPagePath = path.join(root, "site", "rules.html");

const START_MARKER = "<!-- RULES:START -->";
const END_MARKER = "<!-- RULES:END -->";

function readCategoryFiles() {
  return readdirSync(rulesDir)
    .filter((name) => name.endsWith(".md") && name !== "README.md")
    .sort();
}

function parseCategoryFile(fileName) {
  const content = readFileSync(path.join(rulesDir, fileName), "utf8");
  const [heading, ...rest] = content.split(/\r?\n/);
  const title = heading.replace(/^#\s*/, "").replace(/\s*Rules\s*$/i, "").trim();

  const blocks = rest.join("\n").split(/^##\s+/m).slice(1);
  const rules = blocks.map((block) => parseRuleBlock(block)).filter(Boolean);

  return { title, rules };
}

function parseRuleBlock(block) {
  const [heading = "", ...rest] = block.split(/\r?\n/);
  const id = heading.trim();
  if (!id) return null;

  const fields = {};
  let current = "";
  for (const line of rest) {
    const match = line.match(/^\*\*(Title|Category|Severity|Risk|Recommendation|Standards|Code Example):\*\*\s*(.*)$/);
    if (match) {
      current = match[1].toLowerCase().replace(/\s+/g, "");
      fields[current] = match[2].trim();
    } else if (current && line.trim()) {
      fields[current] = `${fields[current]}\n${line.trim()}`.trim();
    }
  }

  return { id, severity: fields.severity || "medium", risk: fields.risk || "", fix: fields.recommendation || "" };
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// Preserve inline `code` spans after escaping the rest of the text.
function inlineMarkdown(value) {
  return escapeHtml(value).replace(/`([^`]+)`/g, "<code>$1</code>");
}

function renderRule(rule) {
  return `        <div class="rule"><div class="rule-head"><h3>${rule.id}</h3><span class="sev ${rule.severity}">${rule.severity}</span></div><p><strong>Risk:</strong> ${inlineMarkdown(rule.risk)}</p><p><strong>Fix:</strong> ${inlineMarkdown(rule.fix)}</p></div>`;
}

function renderCategory({ title, rules }) {
  return [`      <div class="category">`, `        <h2>${escapeHtml(title)}</h2>`, ...rules.map(renderRule), `      </div>`].join("\n");
}

function main() {
  const categories = readCategoryFiles().map(parseCategoryFile).filter((category) => category.rules.length > 0);
  const totalRules = categories.reduce((sum, category) => sum + category.rules.length, 0);

  const body = categories.map(renderCategory).join("\n\n");
  const generated = `${START_MARKER}\n${body}\n      ${END_MARKER}`;

  const page = readFileSync(rulesPagePath, "utf8");
  const startIndex = page.indexOf(START_MARKER);
  const endIndex = page.indexOf(END_MARKER);
  if (startIndex === -1 || endIndex === -1) {
    throw new Error(`Could not find ${START_MARKER} / ${END_MARKER} markers in ${rulesPagePath}`);
  }

  const updated = page.slice(0, startIndex) + generated + page.slice(endIndex + END_MARKER.length);
  writeFileSync(rulesPagePath, updated);

  console.log(`Wrote ${totalRules} rules across ${categories.length} categories to ${path.relative(root, rulesPagePath)}`);
}

main();
