# AI SaaS Audit Agent

Local-first CLI that audits AI-powered SaaS applications for security, privacy, architecture, scalability, payments, AI cost risks, production readiness, and post-deploy monitoring gaps.

## Quick Start

```bash
npm install
npm test
npm run fixture:scan
node ./bin/saas-audit.js scan /path/to/app --out-dir ./audit-output
```

No external service is required for the MVP. The scanner runs locally and writes deliverables to disk.

## Gravel Homepage

```bash
npm run dev:web
```

The local homepage and customer dashboard run at `http://127.0.0.1:4000`.

Copy `.env.example` to `.env` and provide the values:

- `APP_BASE_URL`
- `SESSION_SECRET`
- `AUTH0_SECRET`
- `AUTH0_DOMAIN`
- `AUTH0_CLIENT_ID`
- `AUTH0_CLIENT_SECRET`
- `REVENUECAT_API_KEY`
- `REVENUECAT_ENTITLEMENT_ID`
- `REVENUECAT_OFFERING_ID`
- `REVENUECAT_STARTER_PACKAGE_ID`
- `REVENUECAT_PRO_PACKAGE_ID`
- `REVENUECAT_WEBHOOK_SECRET`
- `CLI_DOWNLOAD_URL`

Auth0 handles signup, login, logout, and the protected dashboard. Set the Auth0
application callback URL to `/auth/callback` and the logout URL to `/`.
`AUTH0_CALLBACK_URL` is optional; when omitted, the app derives it from
`APP_BASE_URL`.

If Auth0 redirects back with an error such as `Cannot read properties of
undefined (reading 'scope')`, the failure is happening inside Auth0 before the
app receives a login code. Check Auth0 Dashboard > Monitoring > Logs for the
failed transaction, then inspect Actions > Flows > Login and any legacy Rules.
Temporarily disable custom Actions/Rules to confirm the base application login
works with the requested `openid profile email` scope.

RevenueCat checkout is triggered from the dashboard after login. The app uses
the RevenueCat Web SDK with `REVENUECAT_API_KEY`, passes the signed-in Gravel
user id as the RevenueCat App User ID, and presents your configured RevenueCat
paywall/current offering. Package and offering ids are optional; add them later
only if you want the Starter and Pro buttons to target specific packages.

For checkout to open, RevenueCat must have a web billing engine configured and
the current offering must have a web paywall attached. If `REVENUECAT_OFFERING_ID`
is set, that offering id must exist; otherwise the app uses RevenueCat's current
offering. If `REVENUECAT_PRO_PACKAGE_ID` or `REVENUECAT_STARTER_PACKAGE_ID` is
set, the package id must exist inside the chosen offering.

The one-audit trial is enforced in the web backend. A user can start one trial
scan; once a scan is marked completed, additional scans require an active
RevenueCat entitlement. Configure RevenueCat webhooks to mark the backend
subscription active after purchase:

```text
POST /api/revenuecat/webhook
Authorization: Bearer <REVENUECAT_WEBHOOK_SECRET>
```

The CLI reports run progress with the user's dashboard license token:

```bash
curl -X POST http://127.0.0.1:4000/api/cli/runs/<run_id>/progress \
  -H "authorization: Bearer <license_token>" \
  -H "content-type: application/json" \
  -d '{"status":"running","percentComplete":68,"currentStep":"Checking payments","findingsCount":7}'
```

## CLI Licensing Flow

Download the CLI tarball from the authenticated dashboard, install it into a
user-owned system path, and then run `saas-audit` from any project folder.

```bash
node --version # Node.js 20+
mkdir -p ~/.npm-global
npm config set prefix ~/.npm-global
export PATH="$HOME/.npm-global/bin:$PATH"
npm install -g ~/Downloads/ai-saas-audit-agent-*.tgz
saas-audit login
saas-audit whoami
cd /path/to/project
saas-audit scan . --name "My App" --out-dir ./audit-output
```

The CLI uses `GRAVEL_API_BASE` to find the Gravel web app and stores the approved
license token in `~/.gravel/config.json`. `GRAVEL_LICENSE_TOKEN` overrides the
stored token for CI or scripted runs.

Optional AI reviewer:

```bash
export GRAVEL_LLM_API_KEY=your-provider-key
export GRAVEL_LLM_MODEL=gpt-4.1-mini
export GRAVEL_LLM_BASE_URL=https://api.openai.com/v1
saas-audit scan . --out-dir ./audit-output
```

When these local variables are present, the CLI runs an OpenAI-compatible AI
review after the deterministic scanner. Full source code and LLM keys stay on
the user's machine; Gravel sends only compact finding summaries and redacted
evidence snippets to the configured provider. Use `--no-ai-review` or
`GRAVEL_AI_REVIEW=false` to skip it. Use `--ai-model <model>` to override the
model for one run.

The dashboard shows linked CLI devices after browser login approval, plus
macOS, Windows, and Linux Node.js install commands.

Use `--name`, `--project-name`, or `--app-name` to control the app name shown in
dashboard analytics. If omitted, Gravel uses the scanned folder name.

Free tier rules:

- The first successfully completed project run is free.
- Failed or abandoned runs do not consume the free run.
- After the free completed run, the CLI receives a `402` response with the
  billing URL until RevenueCat marks the user subscription active.

The dashboard Analytics section shows plan status, free-run usage, run counts,
findings severity totals, latest run, and project run history.

For `trygravel.com`, deploy the `web/` app to a Node host because Auth0
callbacks, sessions, scan progress, and RevenueCat webhooks are handled by
`web/server.js`. Then point the domain DNS records at that provider.

## CLI

```bash
saas-audit scan .
saas-audit scan . --out-dir ./audit-output
saas-audit scan . --focus security
saas-audit scan . --focus privacy
saas-audit scan . --focus payments
saas-audit scan . --focus ai
saas-audit scan . --url https://app.example.com
```

## Deliverables

- `audit-report.md`
- `findings.json`
- `priority-action-plan.md`
- `privacy-policy-draft.md`
- `data-inventory.md`
- `production-readiness-checklist.md`
- `ai-review.md` when local LLM reviewer config is present

## Current MVP Coverage

- Framework/provider detection for common SaaS stacks
- Auth security checks: password hashing, login rate limits, session expiry, cookie flags
- Authorization and IDOR checks
- API security checks
- SQL injection and XSS pattern checks
- Secrets and `.env` exposure checks
- Frontend API key exposure checks
- Stripe webhook security checks
- OpenAI/AI cost and abuse checks
- Privacy/data collection inventory
- Privacy policy draft generation
- Security headers and HTTPS scan for deployed URLs
- Logging, redaction, and anomaly detection recommendations
- OWASP mapping and prioritized action plan

## Environment Needed

For the local MVP you only need:

- Node.js 20+
- npm 10+

Optional external tools to add later:

- `gitleaks` or `trufflehog` for deeper secret scanning
- `semgrep` for custom static analysis rules
- `osv-scanner` for dependency vulnerabilities
