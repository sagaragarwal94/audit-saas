# Cryptography Rules

## WEAK_RANDOM_TOKEN_GENERATION
**Title:** Security token generated with a non-cryptographic random source
**Category:** crypto
**Severity:** high
**Risk:** `Math.random()` is not cryptographically secure and its output can be predicted, letting attackers guess session tokens, password-reset tokens, or API keys generated from it.
**Recommendation:** Generate tokens with `crypto.randomUUID()` or `crypto.randomBytes()` instead of `Math.random()`.
**Code Example:** const token = crypto.randomBytes(32).toString("hex");
**Standards:** OWASP Top 10: A02 Cryptographic Failures
