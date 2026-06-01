const REQUIRED_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy"
];

export async function scanRuntimeUrl(url) {
  const result = {
    url,
    https: url.startsWith("https://"),
    reachable: false,
    status: null,
    headers: {},
    missingHeaders: [...REQUIRED_HEADERS],
    error: null
  };

  try {
    const response = await fetch(url, { method: "GET", redirect: "manual" });
    result.reachable = true;
    result.status = response.status;
    for (const [key, value] of response.headers.entries()) {
      result.headers[key.toLowerCase()] = value;
    }
    result.missingHeaders = REQUIRED_HEADERS.filter((header) => !result.headers[header]);
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error);
  }

  return result;
}
