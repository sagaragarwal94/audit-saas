# Headers And Transport Rules

## HEADERS_HTTPS_RUNTIME
**Title:** Runtime security headers or HTTPS enforcement need hardening
**Category:** headers
**Severity:** medium
**Risk:** Missing browser security headers increase exposure to XSS, clickjacking, MIME sniffing, and data leakage.
**Recommendation:** Enforce HTTPS and configure HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## CONFIG_HTTP_URLS
**Title:** Insecure HTTP URL found in production-relevant code or config
**Category:** headers
**Severity:** medium
**Risk:** Plain HTTP URLs can leak traffic and break secure cookie/OAuth/webhook expectations.
**Recommendation:** Use HTTPS for production URLs, OAuth callbacks, payment webhooks, and API integrations.
**Standards:** OWASP Top 10: A02 Cryptographic Failures
