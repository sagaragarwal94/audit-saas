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
saas-audit scan [path] [options]      # also available as `auditsaas`
saas-audit rules [--json]             # list the rule catalog
saas-audit --version
```

| Option | What it does |
|---|---|
| `--name "My App"` | Project name used in reports |
| `--out-dir ./audit-output` | Where reports are written (default `./audit-output`) |
| `--focus security\|privacy\|payments\|ai\|all` | Limit which rule categories run |
| `--url https://app.example.com` | Also check HTTPS and security headers on a live URL (follows redirects, 15s timeout) |
| `--fail-on critical\|high\|medium\|low\|info\|none` | Exit `1` if any finding is at or above that severity |
| `--baseline old/findings.json` | Only report findings that aren't in a previous scan |
| `--config path/.auditsaas.json` | Use a specific config file (default: `<path>/.auditsaas.json` if present) |
| `--json` | Print the full result as JSON on stdout; progress goes to stderr |
| `--no-history` | Don't append to `auditsaas-run-history.md` in the scanned project |
| `--ai-model <model>` / `--no-ai-review` | Override or skip the optional AI review |

Unknown flags and invalid values are rejected instead of silently ignored. Exit codes: `0` success, `1` findings at/above `--fail-on` (or an internal error), `2` invalid usage or config.

## Use It in CI

```yaml
# .github/workflows/auditsaas.yml
name: AuditSaas
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: 24
      - run: npx auditsaas@latest scan . --no-history --no-ai-review --fail-on high
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: audit-output/findings.sarif.json
          category: auditsaas
```

The SARIF output includes stable fingerprints, `security-severity` scores, and links to each rule on [auditsaas.org/rules](https://auditsaas.org/rules), so findings show up in GitHub's Security tab with the right severity and don't duplicate across runs.

Adopting on an existing codebase? Commit a baseline once, then fail only on new findings:

```bash
npx auditsaas scan . --out-dir .auditsaas-baseline --no-history
npx auditsaas scan . --baseline .auditsaas-baseline/findings.json --fail-on high
```

Fingerprints are keyed on rule, file, and the matched code, not on line numbers, so unrelated edits above a finding don't make it "new". A baselined run's `findings.json` and SARIF still contain every current finding, each tagged with `baselineState` (`new` or `unchanged`), so you can promote the latest output to be the next baseline. Only `new` findings count toward the summary and `--fail-on`.

## Configuration and Suppressions

Optional `.auditsaas.json` in the project root:

```json
{
  "ignorePaths": ["test/fixtures/**", "scripts/seed.ts", "*.min.js"],
  "ignoreRules": ["MONITORING_ANOMALY_GAPS"],
  "failOn": "high",
  "focus": "all"
}
```

`ignorePaths` uses gitignore-style globs and those files aren't scanned at all. CLI flags override config values. Unknown keys and malformed JSON are errors, so a typo can't quietly disable your suppressions.

Suppress a single finding in code, ideally with a reason:

```ts
const html = renderMarkdown(post.body); // sanitized by rehype-sanitize
// auditsaas-ignore XSS_UNSAFE_HTML -- output of rehype-sanitize
return <div dangerouslySetInnerHTML={{ __html: html }} />;
```

`auditsaas-ignore` applies to its own line and the next line; `auditsaas-ignore-file RULE_ID` applies to the whole file; omitting the rule ID suppresses every rule. Suppressed findings stay visible in a "Suppressed Findings" table at the end of `audit-report.md`, so they don't disappear from review entirely.

## Deliverables

Each scan writes:

- `audit-report.md`: findings with the matched code line, file:line, confidence, and fix guidance
- `findings.json`: machine-readable findings, each with a stable `fingerprint`
- `findings.sarif.json`: SARIF 2.1.0, for GitHub code scanning and other CI tooling
- `priority-action-plan.md`: a checklist ordered by severity
- `privacy-policy-draft.md`
- `data-inventory.md`
- `production-readiness-checklist.md`
- `auditsaas-run-history.md` in the scanned project (skip with `--no-history`)
- `ai-review.md` when local AI reviewer config is enabled

Evidence is the actual line of your code that matched, secret-redacted. Values from `.env` files and credentials in connection strings are never echoed into reports.

## Optional AI Review

The deterministic scanner does not need external services. If you want a second-pass AI review of the findings, point it at any OpenAI-compatible endpoint — a hosted provider with your own API key, or a fully local model server such as Ollama or LM Studio.

Hosted provider with your own key:

```bash
export AUDITSAAS_LLM_API_KEY=your-provider-key
export AUDITSAAS_LLM_MODEL=your-model-id
export AUDITSAAS_LLM_BASE_URL=https://api.openai.com/v1
saas-audit scan . --out-dir ./audit-output
```

Local LLM (no API key required):

```bash
export AUDITSAAS_LLM_BASE_URL=http://localhost:11434/v1
export AUDITSAAS_LLM_MODEL=llama3.1
saas-audit scan . --out-dir ./audit-output
```

Use `--no-ai-review` or `AUDITSAAS_AI_REVIEW=false` to skip it. Requests time out after 120s (`AUDITSAAS_LLM_TIMEOUT_MS` to change), and models that reject a custom `temperature` are retried without it. If the review fails, the deterministic reports are still written. Full source code and keys stay on your machine; the AI reviewer sends only compact, redacted finding context to the configured provider.

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

`.claude/skills/audit-saas-review/SKILL.md` is a [Claude Code Skill](https://github.com/sagaragarwal94/audit-saas/blob/main/.claude/skills/audit-saas-review/SKILL.md) that ships in this repo. Inside a Claude Code session in this repo, in a project with `auditsaas` installed, or in any project with `rules/` copied in, run `/audit-saas-review [security|privacy|payments|ai|all]`. Claude manually reviews your code against the same rule catalog, traces auth and data paths across files, runs a verification pass to drop false positives, and honors your `.auditsaas.json` and `auditsaas-ignore` suppressions. It's read-only and pairs well with the CLI: let the CLI give the repeatable baseline, and let the skill triage what it found.

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

**Today:** full-depth JavaScript/TypeScript — Node.js, Next.js, Remix, Express, Fastify, Hono, React, Vue, Svelte/SvelteKit, Astro (including `.vue`/`.svelte`/`.astro` single-file components) — plus Docker, Docker Compose, and Terraform for infra.

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

CI (`.github/workflows/ci.yml`) runs `npm test` on Node 20.x/22.x/24.x on every push/PR, checks that `site/rules.html` matches `rules/*.md`, and dogfoods the scanner on this repo (`npm run self-scan`, configured by `.auditsaas.json`), failing on any high or critical finding and uploading SARIF to code scanning. Package contents are limited with the `files` allowlist in `package.json`; run `npm run pack` to build a local tarball (writes to `./dist/`).

### Releasing

Publishing to npm (`.github/workflows/publish.yml`) uses [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers) (OIDC) — no `NPM_TOKEN` secret, no long-lived credentials. This requires a one-time bootstrap since a package's Trusted Publisher can only be configured *after* it's been published at least once:

1. **First release only** — publish manually from your own machine, where `npm login`'s normal 2FA prompt handles auth (this is what a CI token can't do without also enabling 2FA-bypass, which trusted publishing avoids entirely):
   ```bash
   npm login
   npm publish --access public
   ```
2. On the package's [npmjs.com settings page](https://www.npmjs.com/package/auditsaas/access), add a Trusted Publisher: provider GitHub Actions, org/user `sagaragarwal94`, repo `audit-saas`, workflow filename `publish.yml`, allowed action `npm publish`.
3. **Every release after that**: bump `version` in `package.json` and add a changelog entry to `site/changelog.html`, merge to `main`, then tag that commit with `git tag -a v<version> -m "v<version>" && git push origin v<version>`. The workflow re-runs the tests, checks that the tag matches `package.json`'s version, verifies the package contents, publishes via OIDC, and creates the matching [GitHub Release](https://github.com/sagaragarwal94/audit-saas/releases) with generated notes. Re-running it for a version that's already on npm skips the publish, so a failed release can be retried safely.

Tags are `v<major>.<minor>.<patch>`, one per npm version, always on a commit in `main`. Don't move a tag once its version is on npm. Ship a new patch version instead.

## License

[Functional Source License 1.1, ALv2 Future License](./LICENSE) (FSL-1.1-ALv2). Source-available: use, modify, self-host, and redistribute for any purpose other than a competing commercial product or service. Automatically converts to the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) on 2028-08-10. See `LICENSE` and `NOTICE`.
