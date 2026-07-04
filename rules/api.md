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

## OPEN_REDIRECT_UNVALIDATED
**Title:** Redirect target may be built from unvalidated user input
**Category:** api
**Severity:** medium
**Risk:** Redirecting to a URL taken directly from a query parameter can be used for phishing or to bypass OAuth redirect_uri allowlists.
**Recommendation:** Validate redirect targets against an allowlist of internal paths or trusted domains before redirecting.
**Standards:** OWASP Top 10: A01 Broken Access Control

## MASS_ASSIGNMENT_RISK
**Title:** Request body may be written directly into a database call
**Category:** api
**Severity:** high
**Risk:** Spreading the raw request body into a create/update call lets attackers set fields they should not control, such as `role`, `isAdmin`, or `plan`.
**Recommendation:** Explicitly allowlist the fields copied from request input into database writes instead of spreading the full body.
**Code Example:** const { name, email } = body; await db.user.update({ where: { id }, data: { name, email } });
**Standards:** OWASP Top 10: A04 Insecure Design; OWASP API Security: Mass Assignment

## API_RATE_LIMIT_MISSING_PUBLIC
**Title:** Public API route may be missing rate limiting
**Category:** api
**Severity:** medium
**Risk:** Endpoints without any rate limiting are vulnerable to scraping, credential stuffing, and cost-driving abuse at scale.
**Recommendation:** Add per-IP and per-account rate limiting (e.g. Upstash, express-rate-limit, a WAF rule) to public-facing API routes.
**Standards:** OWASP API Security: Unrestricted Resource Consumption

## GRAPHQL_INTROSPECTION_ENABLED
**Title:** GraphQL introspection may be enabled in production
**Category:** api
**Severity:** medium
**Risk:** Introspection lets attackers enumerate your entire schema, including fields and mutations not exposed in your app's UI.
**Recommendation:** Disable introspection (and the GraphiQL/Playground UI) outside of development environments.
**Standards:** OWASP API Security: Security Misconfiguration

## GRAPHQL_NO_DEPTH_LIMIT
**Title:** GraphQL server may be missing query depth/cost limiting
**Category:** api
**Severity:** medium
**Risk:** Without a depth or cost limit, a single deeply nested or highly repetitive GraphQL query can exhaust server resources — a denial-of-service vector unique to GraphQL's flexible query shape.
**Recommendation:** Add a depth-limiting or cost-analysis library (e.g. `graphql-depth-limit`, `graphql-cost-analysis`) to the server's validation rules.
**Standards:** OWASP API Security: Unrestricted Resource Consumption

## NEXTJS_SERVER_ACTION_NO_AUTH
**Title:** Next.js Server Action may be missing an authentication check
**Category:** api
**Severity:** critical
**Risk:** A `"use server"` action is a public network endpoint even though it's called like a function — without an explicit auth check, anyone who discovers its action ID can invoke it directly, bypassing any UI-level gating.
**Recommendation:** Verify the session/user at the top of every Server Action that reads or writes sensitive data, exactly as you would in an API route.
**Standards:** OWASP Top 10: A01 Broken Access Control
