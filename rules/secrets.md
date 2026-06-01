# Secrets Rules

## SECRETS_ENV_COMMITTED
**Title:** Environment file with possible secrets is present in the project
**Category:** secrets
**Severity:** critical
**Risk:** Committed environment files can leak production credentials and third-party API keys.
**Recommendation:** Remove real `.env` files from version control, rotate exposed secrets, and keep only `.env.example` committed.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## SECRETS_HARDCODED
**Title:** Hardcoded secret-like value detected
**Category:** secrets
**Severity:** critical
**Risk:** Hardcoded keys can be extracted from source code, logs, client bundles, or repository history.
**Recommendation:** Move secrets to server-side environment variables, rotate exposed keys, and add secret scanning to CI.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## SECRETS_FRONTEND_PUBLIC_KEY
**Title:** Secret key may be exposed to frontend code
**Category:** secrets
**Severity:** critical
**Risk:** Secrets in `NEXT_PUBLIC_*` variables or client components can be exposed to every browser user.
**Recommendation:** Never expose OpenAI, Stripe secret, Supabase service role, or private API keys to frontend code. Move calls server-side or behind an authenticated proxy.
**Standards:** OWASP Top 10: A02 Cryptographic Failures
