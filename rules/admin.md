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

## SWAGGER_UI_EXPOSED_PRODUCTION
**Title:** API documentation UI may be exposed without an environment guard
**Category:** admin
**Severity:** medium
**Risk:** Swagger/OpenAPI UIs left reachable in production hand attackers a full map of your API surface, including internal or undocumented-elsewhere endpoints.
**Recommendation:** Mount API docs routes only when `NODE_ENV !== "production"`, or put them behind authentication.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## INTERNAL_ENDPOINT_INFO_LEAK
**Title:** Health/status endpoint may leak internal environment details
**Category:** admin
**Severity:** medium
**Risk:** A `/health` or `/status` route that echoes back environment variables, config, or dependency versions gives attackers reconnaissance information for free.
**Recommendation:** Return a minimal `{ status: "ok" }` from health checks; keep detailed diagnostics behind authentication.
**Standards:** OWASP Top 10: A05 Security Misconfiguration
