# Database Rules

## SQL_INJECTION_RAW_QUERY
**Title:** Possible SQL injection through raw or interpolated query
**Category:** database
**Severity:** critical
**Risk:** String-built SQL can allow attackers to read, modify, or delete database data.
**Recommendation:** Use parameterized queries or ORM query builders. Never concatenate user-controlled data into SQL.
**Standards:** OWASP Top 10: A03 Injection
