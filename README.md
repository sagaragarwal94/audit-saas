# AuditSaas

[![CI](https://github.com/sagaragarwal94/audit-saas/actions/workflows/ci.yml/badge.svg)](https://github.com/sagaragarwal94/audit-saas/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/auditsaas.svg)](https://www.npmjs.com/package/auditsaas)
[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)](./LICENSE)

Local CLI that audits SaaS applications for security, privacy, AI, payments, production readiness, and launch-risk gaps.

AuditSaas runs on your machine, scans your project files locally, and writes reports into your repo. No dashboard, account, license key, Auth0, RevenueCat, or hosted backend is required.

Source-available under the [Functional Source License 1.1](./LICENSE) (Apache-2.0 future grant) — free to use, modify, self-host, and contribute to; the one restriction is you can't repackage it into a competing commercial product or service. It auto-converts to the fully permissive Apache License 2.0 on 2028-08-10.

## Quick Start

```bash
npx auditsaas scan .
```

No install step — the project has zero runtime dependencies. Not yet on npm for you? Run it straight from GitHub instead: `npx github:sagaragarwal94/audit-saas scan .`. Or clone it if you want to contribute:

```bash
git clone https://github.com/sagaragarwal94/audit-saas
cd audit-saas
npm install
npm test
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

## Contributing

Issues, new rules, and PRs are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) and the [issue templates](.github/ISSUE_TEMPLATE/). Rules live in Markdown under `rules/` and are grouped by category; every rule needs both a `rules/*.md` entry and a matching detector in `src/rules.js` — `npm test` enforces this via a parity check. After editing `rules/*.md`, run:

```bash
npm test
npm run fixture:scan
npm run build:rules-page   # regenerates the public catalog at site/rules.html
```

Good rule contributions include:

- A clear risk statement.
- Practical evidence patterns.
- A concrete recommendation.
- A mapping to an existing category such as auth, API, payments, privacy, AI, headers, logging, secrets, database, or XSS.

### Try the rule catalog without installing

`.claude/skills/audit-saas-review/SKILL.md` is a [Claude Code Skill](https://github.com/sagaragarwal94/audit-saas/blob/main/.claude/skills/audit-saas-review/SKILL.md) that ships in this repo. Inside a Claude Code session in this repo (or any project with `rules/` copied in), run `/audit-saas-review` to have Claude manually review your code against the same rule catalog, using judgment rather than the CLI's regex detectors.

## Current Coverage

65 rules across 23 categories:

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

**Roadmap** (prioritized by community feedback, not shipped speculatively): Python, Java, Kotlin, Swift, Rust, Go, native Android/iOS checks, and IaC providers beyond Terraform (Pulumi, CDK, CloudFormation). See `plan.md` for how this is sequenced.

## Development

```bash
git clone https://github.com/sagaragarwal94/audit-saas
cd audit-saas
npm install
npm test
npm run scan

# or against the included vulnerable fixture
npm run fixture:scan
```

CI (`.github/workflows/ci.yml`) runs `npm test` on Node 20.x/22.x on every push/PR, plus a check that `site/rules.html` matches `rules/*.md`. Package contents are limited with the `files` allowlist in `package.json`; run `npm run pack` to build a local tarball (writes to `./dist/`).

### Releasing

Publishing to npm (`.github/workflows/publish.yml`) uses [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers) (OIDC) — no `NPM_TOKEN` secret, no long-lived credentials. This requires a one-time bootstrap since a package's Trusted Publisher can only be configured *after* it's been published at least once:

1. **First release only** — publish manually from your own machine, where `npm login`'s normal 2FA prompt handles auth (this is what a CI token can't do without also enabling 2FA-bypass, which trusted publishing avoids entirely):
   ```bash
   npm login
   npm publish --access public
   ```
2. On the package's [npmjs.com settings page](https://www.npmjs.com/package/auditsaas/access), add a Trusted Publisher: provider GitHub Actions, org/user `sagaragarwal94`, repo `audit-saas`, workflow filename `publish.yml`, allowed action `npm publish`.
3. **Every release after that**: bump `version` in `package.json`, commit, then `git tag v<version> && git push --tags` — the workflow re-runs the tests, checks the tag matches `package.json`'s version, and publishes via OIDC automatically.

## License

[Functional Source License 1.1, ALv2 Future License](./LICENSE) (FSL-1.1-ALv2). Source-available: use, modify, self-host, and redistribute for any purpose other than a competing commercial product or service. Automatically converts to the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) on 2028-08-10. See `LICENSE` and `NOTICE`.
