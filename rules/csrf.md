# CSRF Rules

## CSRF_PROTECTION_MISSING
**Title:** Cookie-based session app may be missing CSRF protection
**Category:** csrf
**Severity:** medium
**Risk:** State-changing requests authenticated only by cookies can be triggered from another origin without a CSRF token or same-site defense.
**Recommendation:** Use SameSite=Lax/Strict cookies together with a CSRF token (double-submit cookie or synchronizer token) for state-changing routes, or rely on a framework's built-in CSRF middleware.
**Standards:** OWASP Top 10: A01 Broken Access Control; OWASP ASVS V4 Access Control
