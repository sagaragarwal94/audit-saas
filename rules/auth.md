# Auth Rules

## AUTH_PASSWORD_HASHING_WEAK
**Title:** Weak or missing password hashing evidence
**Category:** auth
**Severity:** critical
**Risk:** Weak password storage can lead to account takeover if the database is exposed.
**Recommendation:** Use Argon2id or bcrypt with a suitable cost factor, never plaintext or raw SHA/MD5 hashes.
**Standards:** OWASP ASVS V2 Authentication; OWASP Top 10: A07 Identification and Authentication Failures

## AUTH_LOGIN_RATE_LIMIT_MISSING
**Title:** Login endpoint may be missing brute-force protection
**Category:** auth
**Severity:** high
**Risk:** Unthrottled login attempts allow credential stuffing and brute-force attacks.
**Recommendation:** Apply rate limits per IP and per account, track failed attempts, and add lockout/backoff controls.
**Standards:** OWASP ASVS V2 Authentication

## AUTH_SESSION_EXPIRY_MISSING
**Title:** Session expiry is not clearly configured
**Category:** auth
**Severity:** medium
**Risk:** Long-lived or unbounded sessions increase impact after token theft.
**Recommendation:** Configure bounded session expiry, refresh-token rotation where relevant, and server-side logout invalidation.
**Standards:** OWASP ASVS V3 Session Management

## AUTH_COOKIE_FLAGS_MISSING
**Title:** Auth cookies may be missing secure flags
**Category:** auth
**Severity:** medium
**Risk:** Cookies without HttpOnly, Secure, and SameSite controls are easier to steal or abuse.
**Recommendation:** Set HttpOnly, Secure, and SameSite=Lax or Strict for session cookies in production.
**Standards:** OWASP ASVS V3 Session Management

## PASSWORD_RESET_RATE_LIMIT_MISSING
**Title:** Password reset endpoint may be missing rate limiting
**Category:** auth
**Severity:** high
**Risk:** An unthrottled password-reset or forgot-password endpoint allows attackers to enumerate valid accounts or flood users with reset emails.
**Recommendation:** Apply per-IP and per-account rate limits to password reset requests, same as login.
**Standards:** OWASP ASVS V2 Authentication
