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

## CSP_UNSAFE_INLINE
**Title:** Content-Security-Policy allows unsafe-inline or unsafe-eval
**Category:** headers
**Severity:** medium
**Risk:** `unsafe-inline`/`unsafe-eval` in a CSP largely defeats its purpose as an XSS mitigation, since it allows the exact inline script execution CSP is meant to block.
**Recommendation:** Use nonces or hashes for required inline scripts instead of `unsafe-inline`, and avoid `unsafe-eval` entirely.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## SOURCE_MAP_ENABLED_PRODUCTION
**Title:** Production build may ship source maps
**Category:** headers
**Severity:** medium
**Risk:** Public source maps let anyone reconstruct your original source code, including comments, variable names, and any logic you intended to keep private.
**Recommendation:** Disable source maps for production builds, or upload them privately to your error-tracking provider instead of serving them publicly.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## MISSING_SRI_EXTERNAL_SCRIPT
**Title:** External script loaded without Subresource Integrity
**Category:** headers
**Severity:** medium
**Risk:** A `<script>` tag pointing at a third-party CDN without an `integrity` attribute will execute whatever that CDN serves, including a compromised or tampered file, with no verification.
**Recommendation:** Add an `integrity` attribute (SRI hash) and `crossorigin="anonymous"` to third-party script tags, or self-host the dependency.
**Standards:** OWASP Top 10: A08 Software and Data Integrity Failures
