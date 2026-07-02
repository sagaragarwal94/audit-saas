# Admin And Debug Surface Rules

## ADMIN_ROUTE_NO_ROLE_CHECK
**Title:** Admin route may be missing a role or permission check
**Category:** admin
**Severity:** critical
**Risk:** An admin-labeled route that only checks for a valid session (not an admin role) can be reached by any authenticated user.
**Recommendation:** Require an explicit role, permission, or claim check (e.g. `role === "admin"`) in every admin route, in addition to authentication.
**Standards:** OWASP Top 10: A01 Broken Access Control

## DEBUG_ENDPOINT_EXPOSED
**Title:** Debug, internal, or test endpoint may be reachable in production
**Category:** admin
**Severity:** high
**Risk:** Debug/internal endpoints often skip auth and can expose environment details, internal state, or admin actions if left reachable after launch.
**Recommendation:** Remove debug/test routes before shipping, or gate them behind authentication and a non-production environment check.
**Standards:** OWASP Top 10: A05 Security Misconfiguration
