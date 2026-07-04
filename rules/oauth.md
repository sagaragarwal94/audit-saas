# OAuth Rules

## OAUTH_STATE_PARAM_MISSING
**Title:** OAuth authorization request may be missing a state parameter
**Category:** oauth
**Severity:** medium
**Risk:** Without a `state` parameter, an OAuth authorization flow is vulnerable to CSRF, allowing an attacker to bind their own account to a victim's session.
**Recommendation:** Generate a random `state` value per request, store it server-side or in a signed cookie, and verify it on callback before exchanging the authorization code.
**Standards:** OWASP Top 10: A01 Broken Access Control
