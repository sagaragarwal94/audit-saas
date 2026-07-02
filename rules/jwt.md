# JWT Rules

## JWT_ALGORITHM_NOT_ENFORCED
**Title:** JWT verification does not pin an algorithm
**Category:** jwt
**Severity:** critical
**Risk:** Verifying tokens without pinning the expected algorithm allows algorithm-confusion attacks (for example forging an HS256 token signed with a known public RS256 key, or an `alg: none` token).
**Recommendation:** Always pass an explicit `algorithms` allowlist to `jwt.verify` and reject tokens with `alg: none`.
**Code Example:** jwt.verify(token, secret, { algorithms: ["HS256"] });
**Standards:** OWASP ASVS V3 Session Management; OWASP Top 10: A02 Cryptographic Failures

## JWT_SECRET_WEAK_OR_HARDCODED
**Title:** JWT signing secret may be hardcoded or weak
**Category:** jwt
**Severity:** critical
**Risk:** A hardcoded or short JWT secret can be brute-forced or leaked through source control, letting attackers forge valid tokens.
**Recommendation:** Load the signing secret from environment variables, use at least 32 bytes of entropy, and rotate it if it was ever hardcoded.
**Standards:** OWASP ASVS V3 Session Management
