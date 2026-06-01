# XSS Rules

## XSS_UNSAFE_HTML
**Title:** Potential XSS through unsafe HTML rendering
**Category:** xss
**Severity:** high
**Risk:** Rendering user-controlled HTML without sanitization can execute attacker-controlled scripts.
**Recommendation:** Avoid raw HTML rendering. If required, sanitize with a proven HTML sanitizer and use a strict CSP.
**Standards:** OWASP Top 10: A03 Injection
