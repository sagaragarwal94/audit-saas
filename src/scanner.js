import fs from "node:fs/promises";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { compileGlobs } from "./config.js";

const IGNORE_DIRS = new Set([
  ".git", "node_modules", ".next", "dist", "build", "coverage", ".turbo", ".vercel", "audit-output", "test-output",
  ".svelte-kit", ".nuxt", ".output", ".cache", ".parcel-cache", ".yarn", ".pnpm-store", ".terraform", ".serverless",
  ".expo", ".angular", ".docusaurus", "storybook-static", "vendor", ".venv", "venv", "__pycache__"
]);
const TEXT_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro",
  ".json", ".env", ".local", ".prisma", ".sql", ".graphql", ".gql", ".md", ".yml", ".yaml", ".toml",
  ".html", ".htm", ".tf", ".tfvars", ".sh", ".bak", ".backup", ".old"
]);
const MAX_FILE_BYTES = 750_000;
const MINIFIED_LINE_LENGTH = 5_000;

export function isLockfile(relativePath) {
  return /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/.test(relativePath);
}
const READ_CONCURRENCY = 32;

export async function collectProject(root, { ignorePaths = [] } = {}) {
  const isIgnored = compileGlobs(ignorePaths);
  const skipped = { ignored: 0, tooLarge: 0, binary: 0, unreadable: 0 };
  const allPaths = await walk(root, root, isIgnored, skipped);
  const packageJson = await readJson(path.join(root, "package.json"));
  const gitIgnored = getGitIgnoredSet(root);
  const isGitIgnored = (relativePath) => {
    if (!gitIgnored) return false;
    if (gitIgnored.has(relativePath)) return true;
    // `--directory` collapses wholly-ignored dirs to one "dir/" entry.
    const parts = relativePath.split("/");
    for (let i = 1; i < parts.length; i += 1) {
      if (gitIgnored.has(`${parts.slice(0, i).join("/")}/`)) return true;
    }
    return false;
  };

  const candidates = allPaths.filter(isTextFile);
  const contents = await mapLimit(candidates, READ_CONCURRENCY, (file) => safeRead(file, skipped));
  const textFiles = [];
  candidates.forEach((file, index) => {
    const content = contents[index];
    if (content == null) return;
    const relativePath = toPosix(path.relative(root, file));
    textFiles.push({
      path: file,
      relativePath,
      content,
      ext: path.extname(file).toLowerCase(),
      classification: classifyFile(relativePath, content),
      minified: /\.min\.(js|css)$/i.test(relativePath) || hasLongLine(content),
      gitIgnored: isGitIgnored(relativePath)
    });
  });

  return {
    root,
    packageJson,
    files: textFiles,
    allPaths: allPaths.map((file) => toPosix(path.relative(root, file))),
    isGitIgnored,
    skipped,
    providers: detectProviders(textFiles, packageJson),
    framework: detectFramework(textFiles, packageJson),
    language: textFiles.some((file) => /\.(ts|tsx|mts|cts)$/.test(file.ext)) ? "typescript" : "javascript"
  };
}

function getGitIgnoredSet(root) {
  try {
    // --directory lists node_modules/ once instead of every file inside it.
    const output = execFileSync("git", ["-C", root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 64 * 1024 * 1024
    });
    return new Set(output.split("\n").filter(Boolean).map(toPosix));
  } catch {
    return null;
  }
}

// Regular files only: symlinks are skipped so a link to `/` or a sibling repo
// can't blow up the walk or pull unrelated code into the report.
async function walk(root, dir, isIgnored, skipped) {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    skipped.unreadable += 1;
    return [];
  }
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      if (isIgnored(toPosix(path.relative(root, fullPath)))) {
        skipped.ignored += 1;
        continue;
      }
      files.push(...await walk(root, fullPath, isIgnored, skipped));
    } else if (entry.isFile()) {
      if (isIgnored(toPosix(path.relative(root, fullPath)))) {
        skipped.ignored += 1;
        continue;
      }
      files.push(fullPath);
    }
  }
  return files;
}

async function safeRead(file, skipped) {
  try {
    const stat = await fs.stat(file);
    if (stat.size > MAX_FILE_BYTES) {
      skipped.tooLarge += 1;
      return null;
    }
    const content = await fs.readFile(file, "utf8");
    if (content.includes("\u0000")) {
      skipped.binary += 1;
      return null;
    }
    return content;
  } catch {
    skipped.unreadable += 1;
    return null;
  }
}

function hasLongLine(content) {
  let start = 0;
  while (start < content.length) {
    const end = content.indexOf("\n", start);
    const stop = end === -1 ? content.length : end;
    if (stop - start > MINIFIED_LINE_LENGTH) return true;
    start = stop + 1;
  }
  return false;
}

async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return null;
  }
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function isTextFile(file) {
  const base = path.basename(file);
  if (base.startsWith(".env")) return true;
  if (["Dockerfile", "Procfile", "Containerfile"].includes(base) || /^Dockerfile\./.test(base) || /\.dockerfile$/i.test(base)) return true;
  return TEXT_EXTENSIONS.has(path.extname(file).toLowerCase());
}

function toPosix(value) {
  return value.replaceAll("\\", "/");
}

function classifyFile(relativePath, content) {
  const labels = [];
  if (isApiRoutePath(relativePath)) labels.push("api_route");
  if (/middleware\.(t|j)s$/.test(relativePath)) labels.push("middleware");
  if (/webhook|stripe|paddle|lemonsqueezy/i.test(relativePath + content)) labels.push("payment");
  if (/openai|anthropic|gemini|langchain|ai\/react|generateText|streamText/i.test(content)) labels.push("ai");
  if (/auth|session|jwt|clerk|nextauth|supabase\.auth|firebase\/auth|login|sign-?in|sign-?up|register|password/i.test(relativePath + content)) labels.push("auth");
  if (/schema\.prisma|drizzle|migration|CREATE TABLE|ALTER TABLE/i.test(relativePath + content)) labels.push("database");
  if (/(^|\/)\.env/.test(relativePath)) labels.push("environment");
  if (/logger|logtail|sentry|datadog|axiom|console\./i.test(relativePath + content)) labels.push("logging");
  if (/form|input|textarea|upload|localStorage|sessionStorage|cookies/i.test(content)) labels.push("data_collection");
  if (/next\.config|vercel\.json|netlify\.toml|docker-compose|compose\.ya?ml|Dockerfile/i.test(relativePath)) labels.push("config");
  if (labels.length === 0) labels.push("source");
  return labels;
}

// Next.js pages/app API dirs and app-router route handlers, Nuxt server/api,
// SvelteKit +server endpoints, and Vercel's root-level api/ functions.
function isApiRoutePath(relativePath) {
  return /(app\/api|pages\/api|routes\/api|server\/api)\//.test(relativePath) ||
    /^api\//.test(relativePath) ||
    /(^|\/)app\/(.*\/)?route\.(t|j)s$/.test(relativePath) ||
    /(^|\/)src\/routes\/(.*\/)?\+server\.(t|j)s$/.test(relativePath);
}

function detectProviders(files, packageJson) {
  const haystack = [
    JSON.stringify(packageJson || {}),
    ...files.filter((file) => file.ext !== ".md" && file.ext !== ".mdx").map((file) => `${file.relativePath}\n${file.content}`)
  ].join("\n").toLowerCase();
  return {
    auth: pick(haystack, [["clerk", "clerk"], ["next-auth", "nextauth"], ["@auth/", "authjs"], ["better-auth", "better_auth"], ["lucia", "lucia"], ["supabase.auth", "supabase"], ["firebase/auth", "firebase"], ["jwt", "custom_jwt"]]),
    payments: pick(haystack, [["stripe", "stripe"], ["paddle", "paddle"], ["lemonsqueezy", "lemonsqueezy"], ["polar.sh", "polar"]]),
    ai: pick(haystack, [["openai", "openai"], ["@ai-sdk/", "vercel_ai_sdk"], ["anthropic", "anthropic"], ["gemini", "gemini"], ["langchain", "langchain"], ["mistral", "mistral"], ["groq", "groq"]]),
    database: pick(haystack, [["prisma", "prisma"], ["drizzle", "drizzle"], ["supabase", "supabase"], ["mongoose", "mongodb"], ["postgres", "postgres"], ["mysql", "mysql"]]),
    observability: pick(haystack, [["sentry", "sentry"], ["datadog", "datadog"], ["axiom", "axiom"], ["posthog", "posthog"], ["opentelemetry", "opentelemetry"]])
  };
}

function detectFramework(files, packageJson) {
  const deps = { ...(packageJson?.dependencies || {}), ...(packageJson?.devDependencies || {}) };
  if (deps.next || files.some((file) => file.relativePath.startsWith("app/"))) return "nextjs";
  if (deps["@remix-run/node"] || deps["@react-router/node"]) return "remix";
  if (deps.nuxt) return "nuxt";
  if (deps["@sveltejs/kit"]) return "sveltekit";
  if (deps.astro) return "astro";
  if (deps.hono) return "hono";
  if (deps.express) return "express";
  if (deps.fastify) return "fastify";
  return "unknown";
}

function pick(haystack, patterns) {
  return [...new Set(patterns.filter(([pattern]) => haystack.includes(pattern)).map(([, provider]) => provider))];
}
