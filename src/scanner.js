import fs from "node:fs/promises";
import path from "node:path";

const IGNORE_DIRS = new Set([".git", "node_modules", ".next", "dist", "build", "coverage", ".turbo", ".vercel", "audit-output", "test-output"]);
const TEXT_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".env", ".local", ".prisma", ".sql", ".md", ".yml", ".yaml"]);

export async function collectProject(root) {
  const files = await walk(root);
  const packageJson = await readJson(path.join(root, "package.json"));
  const textFiles = [];

  for (const file of files) {
    if (!isTextFile(file)) continue;
    const content = await safeRead(file);
    if (content == null) continue;
    textFiles.push({
      path: file,
      relativePath: path.relative(root, file),
      content,
      ext: path.extname(file),
      classification: classifyFile(path.relative(root, file), content)
    });
  }

  return {
    root,
    packageJson,
    files: textFiles,
    providers: detectProviders(textFiles, packageJson),
    framework: detectFramework(textFiles, packageJson),
    language: textFiles.some((file) => file.ext === ".ts" || file.ext === ".tsx") ? "typescript" : "javascript"
  };
}

async function walk(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.isDirectory() && IGNORE_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await walk(fullPath));
    else files.push(fullPath);
  }
  return files;
}

async function safeRead(file) {
  try {
    const stat = await fs.stat(file);
    if (stat.size > 750_000) return null;
    return await fs.readFile(file, "utf8");
  } catch {
    return null;
  }
}

async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return null;
  }
}

function isTextFile(file) {
  const base = path.basename(file);
  if (base.startsWith(".env")) return true;
  if (["Dockerfile", "Procfile"].includes(base)) return true;
  return TEXT_EXTENSIONS.has(path.extname(file));
}

function classifyFile(relativePath, content) {
  const normalized = relativePath.replaceAll("\\", "/");
  const labels = [];
  if (/app\/api\/|pages\/api\/|routes\/api\/|server\/api\//.test(normalized)) labels.push("api_route");
  if (/middleware\.(t|j)s$/.test(normalized)) labels.push("middleware");
  if (/webhook|stripe|paddle|lemonsqueezy/i.test(normalized + content)) labels.push("payment");
  if (/openai|anthropic|gemini|langchain|ai\/react|generateText|streamText/i.test(content)) labels.push("ai");
  if (/auth|session|jwt|clerk|nextauth|supabase\.auth|firebase\/auth/i.test(normalized + content)) labels.push("auth");
  if (/schema\.prisma|drizzle|migration|CREATE TABLE|ALTER TABLE/i.test(normalized + content)) labels.push("database");
  if (/\.env/.test(normalized)) labels.push("environment");
  if (/logger|logtail|sentry|datadog|axiom|console\./i.test(normalized + content)) labels.push("logging");
  if (/form|input|textarea|upload|localStorage|sessionStorage|cookies/i.test(content)) labels.push("data_collection");
  if (/next\.config|vercel\.json|netlify\.toml|docker-compose|Dockerfile/i.test(normalized)) labels.push("config");
  if (labels.length === 0) labels.push("source");
  return labels;
}

function detectProviders(files, packageJson) {
  const haystack = [
    JSON.stringify(packageJson || {}),
    ...files.map((file) => `${file.relativePath}\n${file.content}`)
  ].join("\n").toLowerCase();
  return {
    auth: pick(haystack, [["clerk", "clerk"], ["next-auth", "nextauth"], ["@auth/", "authjs"], ["supabase.auth", "supabase"], ["firebase/auth", "firebase"], ["jwt", "custom_jwt"]]),
    payments: pick(haystack, [["stripe", "stripe"], ["paddle", "paddle"], ["lemonsqueezy", "lemonsqueezy"]]),
    ai: pick(haystack, [["openai", "openai"], ["@ai-sdk/openai", "vercel_ai_sdk"], ["anthropic", "anthropic"], ["gemini", "gemini"], ["langchain", "langchain"]]),
    database: pick(haystack, [["prisma", "prisma"], ["drizzle", "drizzle"], ["supabase", "supabase"], ["mongoose", "mongodb"], ["postgres", "postgres"], ["mysql", "mysql"]]),
    observability: pick(haystack, [["sentry", "sentry"], ["datadog", "datadog"], ["axiom", "axiom"], ["posthog", "posthog"], ["opentelemetry", "opentelemetry"]])
  };
}

function detectFramework(files, packageJson) {
  const deps = { ...(packageJson?.dependencies || {}), ...(packageJson?.devDependencies || {}) };
  if (deps.next || files.some((file) => file.relativePath.startsWith("app/"))) return "nextjs";
  if (deps["@remix-run/node"]) return "remix";
  if (deps.express) return "express";
  if (deps.fastify) return "fastify";
  return "unknown";
}

function pick(haystack, patterns) {
  return [...new Set(patterns.filter(([pattern]) => haystack.includes(pattern)).map(([, provider]) => provider))];
}
