# API And Authorization Rules

## AUTHZ_IDOR_POSSIBLE
**Title:** Possible IDOR: record fetched by ID without ownership scope
**Category:** authorization
**Severity:** critical
**Risk:** Users may access another user's or tenant's records by changing an ID in the URL or request body.
**Recommendation:** Scope every sensitive query by authenticated user, organization, or tenant in the database query itself.
**Code Example:** await db.project.findFirst({ where: { id: projectId, userId: session.user.id } });
**Standards:** OWASP Top 10: A01 Broken Access Control; OWASP API Security: Broken Object Level Authorization

## API_AUTH_MISSING
**Title:** API route may be missing authentication
**Category:** api
**Severity:** high
**Risk:** Public API routes can expose data or trigger sensitive actions without a valid user session.
**Recommendation:** Require server-side authentication and authorization in every sensitive API route.
**Standards:** OWASP Top 10: A01 Broken Access Control

## API_VALIDATION_MISSING
**Title:** Request body validation may be missing
**Category:** api
**Severity:** medium
**Risk:** Unvalidated input can lead to malformed data, injection risks, and unexpected application behavior.
**Recommendation:** Validate request bodies with Zod, Valibot, Joi, Yup, or equivalent schema validation before use.
**Standards:** OWASP Top 10: A03 Injection; OWASP ASVS V5 Validation
