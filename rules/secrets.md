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

## CI_SECRETS_HARDCODED_IN_WORKFLOW
**Title:** CI/CD workflow file may contain a hardcoded secret
**Category:** secrets
**Severity:** critical
**Risk:** Secrets committed inside a GitHub Actions or other CI workflow file are visible to anyone with repository read access and remain in git history even after removal.
**Recommendation:** Reference secrets only through the CI provider's encrypted secret store (e.g. `${{ secrets.NAME }}`) and rotate any value that was ever hardcoded.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## HARDCODED_CLOUD_CREDENTIAL
**Title:** Cloud provider credential pattern found in source
**Category:** secrets
**Severity:** critical
**Risk:** An AWS access key (or similar cloud credential) committed to source code grants direct access to cloud infrastructure and is routinely scraped by automated bots within minutes of a public push.
**Recommendation:** Remove the credential, rotate it immediately in the cloud provider console, and use environment variables or a secrets manager instead.
**Standards:** OWASP Top 10: A05 Security Misconfiguration

## EXPOSED_BACKUP_FILE
**Title:** Backup or dump file present in the project
**Category:** secrets
**Severity:** high
**Risk:** `.bak`, `.old`, `.backup`, or ad-hoc `.sql` dump files often contain full database contents or old credentials, and are easy to overlook when reviewing what's committed.
**Recommendation:** Remove backup/dump files from version control and store backups outside the repository with proper access controls.
**Standards:** OWASP Top 10: A05 Security Misconfiguration
