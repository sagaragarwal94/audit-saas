import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const catalogDir = path.join(root, "rules");

export function loadRuleCatalog(dir = catalogDir) {
  if (!existsSync(dir)) return new Map();

  const entries = readMarkdownFiles(dir)
    .flatMap((file) => parseRuleFile(file, readFileSync(file, "utf8")))
    .map((rule) => [rule.id, rule]);

  return new Map(entries);
}

function readMarkdownFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return readMarkdownFiles(fullPath);
    return entry.isFile() && entry.name.endsWith(".md") ? [fullPath] : [];
  });
}

function parseRuleFile(file, content) {
  const category = path.basename(file, ".md");
  const blocks = content.split(/^##\s+/m).slice(1);
  return blocks.map((block) => parseRuleBlock(category, block)).filter(Boolean);
}

function parseRuleBlock(category, block) {
  const [heading = "", ...rest] = block.split(/\r?\n/);
  const id = heading.trim();
  if (!id) return null;

  const fields = {};
  let current = "";
  for (const line of rest) {
    const match = line.match(/^\*\*(Title|Category|Severity|Risk|Recommendation|Standards|Code Example):\*\*\s*(.*)$/);
    if (match) {
      current = camelCase(match[1]);
      fields[current] = match[2].trim();
    } else if (current && line.trim()) {
      fields[current] = `${fields[current]}\n${line.trim()}`.trim();
    }
  }

  return {
    id,
    title: fields.title,
    category: fields.category || category,
    severity: fields.severity,
    risk: fields.risk,
    recommendation: fields.recommendation,
    standards: splitList(fields.standards),
    codeExample: fields.codeExample,
  };
}

function splitList(value = "") {
  if (!value || value.toLowerCase() === "none") return [];
  return value.split(";").map((item) => item.trim()).filter(Boolean);
}

function camelCase(value) {
  return value.toLowerCase().replace(/\s+([a-z])/g, (_, letter) => letter.toUpperCase());
}
