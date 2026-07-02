# CORS Rules

## CORS_WILDCARD_WITH_CREDENTIALS
**Title:** CORS allows any origin together with credentials
**Category:** cors
**Severity:** critical
**Risk:** A wildcard `Access-Control-Allow-Origin` combined with `Access-Control-Allow-Credentials: true` lets any site read authenticated responses on behalf of a logged-in user.
**Recommendation:** Use an explicit allowlist of trusted origins instead of `*` whenever credentials are allowed.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## CORS_ORIGIN_REFLECTED
**Title:** CORS origin appears to be reflected without an allowlist
**Category:** cors
**Severity:** medium
**Risk:** Reflecting the request `Origin` header back verbatim effectively disables CORS protection for every origin.
**Recommendation:** Validate the incoming origin against an explicit allowlist before echoing it back in `Access-Control-Allow-Origin`.
**Standards:** OWASP Top 10: A05 Security Misconfiguration
