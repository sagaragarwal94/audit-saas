import { UsageError } from "./config.js";

const REQUIRED_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy"
];
const DEFAULT_TIMEOUT_MS = 15_000;

export function parseRuntimeUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new UsageError(`Invalid --url "${value}". Expected an absolute URL such as https://app.example.com`);
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new UsageError(`Invalid --url "${value}". Only http:// and https:// URLs are supported`);
  }
  return parsed.toString();
}

// Follows redirects so headers are checked on the page a browser actually
// lands on; an http:// URL that redirects to https:// is reported as
// enforcing HTTPS rather than as plain HTTP.
export async function scanRuntimeUrl(url, { fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const requestedUrl = parseRuntimeUrl(url);
  const result = {
    url: requestedUrl,
    finalUrl: requestedUrl,
    https: requestedUrl.startsWith("https://"),
    redirectedToHttps: false,
    reachable: false,
    status: null,
    headers: {},
    missingHeaders: [...REQUIRED_HEADERS],
    error: null
  };

  try {
    const response = await fetchImpl(requestedUrl, {
      method: "GET",
      redirect: "follow",
      headers: { "user-agent": "AuditSaas header check (+https://auditsaas.org)" },
      signal: AbortSignal.timeout(timeoutMs)
    });
    result.reachable = true;
    result.status = response.status;
    result.finalUrl = response.url || requestedUrl;
    result.https = result.finalUrl.startsWith("https://");
    result.redirectedToHttps = !requestedUrl.startsWith("https://") && result.https;
    for (const [key, value] of response.headers.entries()) {
      result.headers[key.toLowerCase()] = value;
    }
    result.missingHeaders = REQUIRED_HEADERS.filter((header) => !result.headers[header]);
    // HSTS is ignored by browsers over plain HTTP, so it can't count there.
    if (!result.https && !result.missingHeaders.includes("strict-transport-security")) {
      result.missingHeaders.push("strict-transport-security");
    }
    await response.body?.cancel?.().catch(() => {});
  } catch (error) {
    result.error = error?.name === "TimeoutError"
      ? `timed out after ${timeoutMs}ms`
      : error instanceof Error ? (error.cause?.message || error.message) : String(error);
  }

  return result;
}
