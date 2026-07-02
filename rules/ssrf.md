# SSRF Rules

## SSRF_UNVALIDATED_URL_FETCH
**Title:** Server-side request built from user-controlled input
**Category:** ssrf
**Severity:** high
**Risk:** Fetching a URL taken directly from request input lets an attacker make the server call internal services, cloud metadata endpoints, or arbitrary hosts.
**Recommendation:** Validate outbound URLs against an allowlist of hosts/protocols, block private/link-local IP ranges, and avoid following redirects blindly.
**Standards:** OWASP Top 10: A10 Server-Side Request Forgery
