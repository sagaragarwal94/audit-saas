# Database Rules

## SQL_INJECTION_RAW_QUERY
**Title:** Possible SQL injection through raw or interpolated query
**Category:** database
**Severity:** critical
**Risk:** String-built SQL can allow attackers to read, modify, or delete database data.
**Recommendation:** Use parameterized queries or ORM query builders. Never concatenate user-controlled data into SQL.
**Standards:** OWASP Top 10: A03 Injection

## SUPABASE_RLS_NOT_CONFIRMED
**Title:** Supabase is used but Row Level Security policies were not found
**Category:** database
**Severity:** medium
**Risk:** Without RLS policies, any authenticated (or anonymous, with the anon key) client can read or write every row in a Supabase table directly from the browser.
**Recommendation:** Enable Row Level Security on every table and add explicit policies scoping access to the authenticated user or tenant.
**Standards:** OWASP Top 10: A01 Broken Access Control

## RESPONSE_MISSING_PAGINATION_LIMIT
**Title:** Query may return an unbounded number of records
**Category:** database
**Severity:** medium
**Risk:** A `findMany`/list query with no `take`/`limit` can return an entire table to a single request, enabling resource-exhaustion and over-fetching more data than the caller should see.
**Recommendation:** Always cap list queries with a `take`/`limit` and offer pagination for anything that can grow unbounded.
**Standards:** OWASP API Security: Unrestricted Resource Consumption
