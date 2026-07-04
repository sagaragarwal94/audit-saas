# AuditSaas

**Private beta.** This repository is not public. Access is by invitation only — see [Beta Access](#beta-access) below.

Local CLI that audits SaaS applications for security, privacy, AI, payments, production readiness, and launch-risk gaps.

AuditSaas runs on your machine, scans your project files locally, and writes reports into your repo. No dashboard, account, license key, Auth0, RevenueCat, or hosted backend is required.

## Beta Access

AuditSaas is currently invite-only. Request access at [auditsaas.org](https://auditsaas.org) (or directly via the [beta form](https://tally.so/r/KYgbOk)).

Once approved, you'll get one of two things by email, depending on how you're testing:

- **Most testers:** an `auditsaas-<version>.tgz` install package. See Quick Start below — no repo access needed.
- **Contributors adding rules:** a collaborator invite to this private repo instead. Clone it and follow [Development](#development).

Send feedback, bugs, and false positives/negatives to the contact in your invite email.

## Quick Start

After you receive your install package by email:

```bash
npm install -g ./auditsaas-<version>.tgz
saas-audit scan /path/to/app --out-dir ./audit-output
```

That's it — `saas-audit` is now available anywhere on your machine. No git clone, no build step.

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

66 rules across 23 categories:

- Framework/provider detection for common SaaS stacks.
- Auth security checks: password hashing, login/password-reset rate limits, session expiry, cookie flags.
- Authorization and IDOR checks, plus Next.js Server Action auth checks.
- API security checks: missing auth, missing validation, open redirects, mass assignment, missing rate limiting, unbounded list queries, GraphQL introspection and depth-limiting.
- SQL injection and XSS pattern checks.
- CORS misconfiguration: wildcard-with-credentials and reflected-origin checks.
- SSRF checks on server-side fetches built from user input.
- JWT checks: unpinned algorithms, missing expiration, and weak/hardcoded signing secrets.
- CSRF protection checks for cookie-session apps, and OAuth state-parameter checks.
- WebSocket connection auth checks.
- Cryptography checks: non-cryptographic random sources used for tokens/secrets.
- Dependency and supply-chain checks: missing lockfile, wildcard versions, known deprecated/risky packages, install-time scripts.
- File upload checks: unrestricted file type/size, path traversal on write.
- Admin/debug surface checks: admin routes without role checks, exposed debug/internal endpoints, exposed Swagger/API docs UIs, info-leaking health endpoints.
- Infra checks: Dockerfiles running as root, database ports exposed in compose files, public Terraform S3 buckets, open Terraform security groups.
- Supabase Row Level Security confirmation.
- CI/CD workflow secret exposure checks, hardcoded cloud credentials, and exposed backup/dump files.
- Dynamic code execution (eval/exec) near user input.
- Secrets and `.env` exposure checks.
- Frontend API key exposure checks.
- Stripe webhook signature/idempotency checks, and client-trusted checkout amount checks.
- OpenAI/AI cost and abuse checks, prompt-injection review.
- Privacy/data collection inventory, deletion-path, and tracking-consent checks.
- Privacy policy draft generation.
- Security headers, CSP unsafe-inline/eval, missing SRI on external scripts, exposed production source maps, and HTTPS scan for deployed URLs.
- Logging, redaction, verbose-error/stack-trace exposure, and anomaly detection recommendations.
- OWASP mapping and prioritized action plan.

## Language & Platform Coverage

**Today:** full-depth JavaScript/TypeScript — Node.js, Next.js, Remix, Express, Fastify, React, Vue — plus Docker, Docker Compose, and Terraform for infra.

**Roadmap** (prioritized by beta feedback, not shipped speculatively): Python, Java, Kotlin, Swift, Rust, Go, native Android/iOS checks, and IaC providers beyond Terraform (Pulumi, CDK, CloudFormation). See `plan.md` for how this is sequenced.

## Development

For collaborators with repo access (not needed if you just want to run scans — see Quick Start):

```bash
npm install
npm test
npm run scan

# or against the included vulnerable fixture
npm run fixture:scan
```

Package contents are limited with the `files` allowlist in `package.json`. Run `npm run beta:pack` to build the `.tgz` sent to new testers — it writes to `./dist-beta/` and only ever includes `bin/`, `src/`, `rules/`, `README.md`, `LICENSE`, and `NOTICE`.

## License

Private beta license. Not open source. See `LICENSE` and `NOTICE`.
