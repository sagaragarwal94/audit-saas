# AuditSaas

Open-source local CLI that audits SaaS applications for security, privacy, AI, payments, production readiness, and launch-risk gaps.

AuditSaas runs on your machine, scans your project files locally, and writes reports into your repo. No dashboard, account, license key, Auth0, RevenueCat, or hosted backend is required.

## Quick Start

```bash
npm install
npm test
node ./bin/saas-audit.js scan /path/to/app --out-dir ./audit-output
```

Or run against the included vulnerable fixture:

```bash
npm run fixture:scan
```

## CLI

```bash
saas-audit --version
saas-audit scan .
saas-audit scan . --name "My App"
saas-audit scan . --out-dir ./audit-output
saas-audit scan . --focus security
saas-audit scan . --focus privacy
saas-audit scan . --focus payments
saas-audit scan . --focus ai
saas-audit scan . --url https://app.example.com
```

## Deliverables

Each scan writes:

- `audit-report.md`
- `findings.json`
- `findings.sarif.json` (SARIF 2.1.0, for GitHub code scanning and other CI tooling)
- `priority-action-plan.md`
- `privacy-policy-draft.md`
- `data-inventory.md`
- `production-readiness-checklist.md`
- `auditsaas-run-history.md` in the scanned project
- `ai-review.md` when local AI reviewer config is enabled

## Optional AI Review

The deterministic scanner does not need external services. If you want a second-pass AI review of the findings, point it at any OpenAI-compatible endpoint — a hosted provider with your own API key, or a fully local model server such as Ollama or LM Studio.

Hosted provider with your own key:

```bash
export AUDITSAAS_LLM_API_KEY=your-provider-key
export AUDITSAAS_LLM_MODEL=gpt-4.1-mini
export AUDITSAAS_LLM_BASE_URL=https://api.openai.com/v1
saas-audit scan . --out-dir ./audit-output
```

Local LLM (no API key required):

```bash
export AUDITSAAS_LLM_BASE_URL=http://localhost:11434/v1
export AUDITSAAS_LLM_MODEL=llama3.1
saas-audit scan . --out-dir ./audit-output
```

Use `--no-ai-review` or `AUDITSAAS_AI_REVIEW=false` to skip it. Full source code and keys stay on your machine; the AI reviewer sends only compact, redacted finding context to the configured provider.

## Rule Contributions

Rules live in Markdown under `rules/` and are grouped by category. Add or edit rule files there, then run:

```bash
npm test
npm run fixture:scan
```

Good rule contributions include:

- A clear risk statement.
- Practical evidence patterns.
- A concrete recommendation.
- A mapping to an existing category such as auth, API, payments, privacy, AI, headers, logging, secrets, database, or XSS.

## Current Coverage

46 rules across 20 categories:

- Framework/provider detection for common SaaS stacks.
- Auth security checks: password hashing, login rate limits, session expiry, cookie flags.
- Authorization and IDOR checks.
- API security checks: missing auth, missing validation, open redirects, mass assignment, missing rate limiting, GraphQL introspection.
- SQL injection and XSS pattern checks.
- CORS misconfiguration: wildcard-with-credentials and reflected-origin checks.
- SSRF checks on server-side fetches built from user input.
- JWT checks: unpinned algorithms and weak/hardcoded signing secrets.
- CSRF protection checks for cookie-session apps.
- Dependency checks: missing lockfile, wildcard versions, known deprecated/risky packages.
- File upload checks: unrestricted file type/size, path traversal on write.
- Admin/debug surface checks: admin routes without role checks, exposed debug/internal endpoints.
- Infra checks: Dockerfiles running as root, database ports exposed in compose files.
- Supabase Row Level Security confirmation.
- CI/CD workflow secret exposure checks.
- Dynamic code execution (eval/exec) near user input.
- Secrets and `.env` exposure checks.
- Frontend API key exposure checks.
- Stripe webhook signature and idempotency checks.
- OpenAI/AI cost and abuse checks, prompt-injection review.
- Privacy/data collection inventory, deletion-path, and tracking-consent checks.
- Privacy policy draft generation.
- Security headers and HTTPS scan for deployed URLs.
- Logging, redaction, and anomaly detection recommendations.
- OWASP mapping and prioritized action plan.

## Development

```bash
npm install
npm test
npm run scan
```

Package contents are limited with the `files` allowlist in `package.json`.

## License

Apache-2.0. See `LICENSE`.

The AuditSaas name, logos, and related branding are not licensed for confusing
commercial use. See `NOTICE`.
