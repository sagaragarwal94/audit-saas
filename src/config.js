import fs from "node:fs/promises";
import path from "node:path";

export const CONFIG_FILENAME = ".auditsaas.json";
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const FOCUS_VALUES = ["all", "security", "privacy", "payments", "ai"];

const KNOWN_KEYS = new Set(["$schema", "ignorePaths", "ignoreRules", "failOn", "focus"]);

export class UsageError extends Error {}

// Loads `.auditsaas.json` from the scanned project (or an explicit --config
// path). A missing default config is fine; a missing explicit one, or a
// malformed one, is a usage error so CI fails loudly instead of silently
// scanning with no suppressions.
export async function loadConfig(target, explicitPath) {
  const file = explicitPath ? path.resolve(explicitPath) : path.join(target, CONFIG_FILENAME);
  let raw;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (error) {
    if (!explicitPath && error.code === "ENOENT") return { path: null, ignorePaths: [], ignoreRules: [] };
    throw new UsageError(`Could not read config file ${file}: ${error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new UsageError(`Config file ${file} is not valid JSON: ${error.message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new UsageError(`Config file ${file} must contain a JSON object`);
  }

  const unknown = Object.keys(parsed).filter((key) => !KNOWN_KEYS.has(key));
  if (unknown.length) throw new UsageError(`Unknown key(s) in ${file}: ${unknown.join(", ")}`);

  const config = {
    path: file,
    ignorePaths: stringList(parsed.ignorePaths, "ignorePaths", file),
    ignoreRules: stringList(parsed.ignoreRules, "ignoreRules", file),
  };
  if (parsed.failOn !== undefined) config.failOn = validateFailOn(parsed.failOn, `failOn in ${file}`);
  if (parsed.focus !== undefined) config.focus = validateFocus(parsed.focus, `focus in ${file}`);
  return config;
}

export function validateFocus(value, label = "--focus") {
  if (!FOCUS_VALUES.includes(value)) {
    throw new UsageError(`Invalid ${label} "${value}". Expected one of: ${FOCUS_VALUES.join(", ")}`);
  }
  return value;
}

export function validateFailOn(value, label = "--fail-on") {
  if (value !== "none" && !SEVERITIES.includes(value)) {
    throw new UsageError(`Invalid ${label} "${value}". Expected one of: ${[...SEVERITIES, "none"].join(", ")}`);
  }
  return value;
}

function stringList(value, key, file) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new UsageError(`${key} in ${file} must be an array of strings`);
  }
  return value;
}

// Minimal gitignore-flavored glob matching: `**` spans directories, `*` and
// `?` stay within one path segment, and a pattern with no slash matches a
// file or directory name at any depth (`*.min.js`, `fixtures`). A trailing
// slash or a bare directory name also matches everything beneath it.
export function compileGlobs(patterns) {
  const matchers = patterns.map(globToRegExp);
  return (relativePath) => {
    const normalized = relativePath.replaceAll("\\", "/");
    return matchers.some((regex) => regex.test(normalized));
  };
}

function globToRegExp(pattern) {
  let glob = pattern.trim().replaceAll("\\", "/").replace(/^\.\//, "");
  const anchored = glob.startsWith("/") || glob.replace(/\/$/, "").includes("/");
  glob = glob.replace(/^\//, "").replace(/\/$/, "");

  let source = "";
  for (let i = 0; i < glob.length; i += 1) {
    const char = glob[i];
    if (char === "*" && glob[i + 1] === "*") {
      if (glob[i + 2] === "/") {
        source += "(?:.*/)?";
        i += 2;
      } else {
        source += ".*";
        i += 1;
      }
    } else if (char === "*") {
      source += "[^/]*";
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += char.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }

  return new RegExp(`${anchored ? "^" : "(?:^|/)"}${source}(?:/.*)?$`);
}
