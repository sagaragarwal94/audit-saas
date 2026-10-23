const SECRET_PATTERNS = [
  // Credentials embedded in connection strings: postgres://user:pass@host
  /(?<=[a-z][a-z0-9+.-]*:\/\/[^\s:/@]*:)[^\s@/]+(?=@)/gi,
  // Credentials in query strings: ?access_key=..., &sig=...
  /(?<=[?&](?:access[_-]?key|api[_-]?key|apikey|key|token|access[_-]?token|sig|signature|secret|password|auth)=)[^&\s"'`#]+/gi,
  /(?:api[_-]?key|secret|token|password|private[_-]?key)\s*[:=]\s*["']?[^"'\s,}]+/gi,
  /\b(sk|pk|rk|ghp|gho|ghu|ghs|glpat)_[A-Za-z0-9_-]{12,}\b/g,
  /\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\b[A-Za-z0-9+/]{32,}={0,2}\b/g,
];

export function redactSecrets(value) {
  let output = String(value || "");
  for (const pattern of SECRET_PATTERNS) output = output.replace(pattern, "[REDACTED]");
  return output;
}
