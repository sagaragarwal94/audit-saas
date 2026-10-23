---
name: audit-saas-review
description: Judgment-based security, privacy, payments, and AI-abuse review of a SaaS codebase against AuditSaas's rule catalog (rules/*.md) — reads the real code and traces auth, data access, webhooks, and LLM calls instead of running regex detectors. Use this whenever someone asks for a security review, pre-launch or production-readiness check, "is my app safe to ship", a privacy/GDPR data review, or a check for IDOR, leaked API keys, missing auth, unverified Stripe webhooks, or unbounded OpenAI/AI spend in a Next.js/Node/React/Vue SaaS — even if they never mention AuditSaas. Also use it to sanity-check or triage findings from a `saas-audit scan` report. Not for reviewing a single PR diff for general correctness bugs.
argument-hint: "[security|privacy|payments|ai|all] [path]"
allowed-tools: Read, Grep, Glob
---

# AuditSaas Manual Review

You're doing a **judgment-based** review against the AuditSaas rule catalog.
The `saas-audit` CLI already covers the deterministic, regex-shaped pass; your
value is everything regex can't do — following an ID from the route to the
query to see whether it's actually scoped, noticing that auth lives in
middleware, recognizing a sanitizer two calls away. That same judgment can be
wrong in ways regex isn't, so say how sure you are.

## 1. Find the rule catalog

Rule IDs, severities, and recommendations must come from the real catalog,
because people compare your report against CLI output and the public rules
page. Look in this order and use the first that has category files
(`auth.md`, `secrets.md`, ...):

1. `./rules/` in the current project (an AuditSaas checkout, or copied in).
2. `./node_modules/auditsaas/rules/` (installed as a dependency).
3. `../../../rules/` relative to this SKILL.md (the skill ships at
   `.claude/skills/audit-saas-review/` inside the AuditSaas package).

`rules/README.md` is the contribution guide, not a category — skip it. If
none of these exist, say so up front and ask for the path. Don't
reconstruct rules from memory; a plausible-looking invented rule ID is worse
than none.

## 2. Scope

Parse the arguments: a focus (`security`, `privacy`, `payments`, `ai`, `all`;
default `all`) and optionally a subdirectory to review. Focus maps to
categories exactly as the CLI does, so results stay comparable:

- `security`: auth, authorization, api, database, xss, secrets, headers,
  logging, cors, ssrf, jwt, csrf, dependencies, uploads, admin, infra,
  injection, crypto, oauth, websocket
- `privacy`: privacy, secrets, logging, api
- `payments`: payments, auth, authorization, api, logging
- `ai`: ai, api, secrets, privacy, logging
- `all`: every category file

A rule's category is its `**Category:**` field (e.g. `AUTHZ_IDOR_POSSIBLE` is
`authorization` but lives in `api.md`), so filter on that field, not the
filename.

Before reading rules, map the app in a few minutes: `package.json`
dependencies, the framework's routing layout (`app/api/**/route.ts`,
`pages/api`, Express routers, Server Actions with `"use server"`),
middleware, and where the DB, payment, and LLM clients are created. Skip
categories with no surface at all (no payments code → skip payments rules),
and say which ones you skipped so the user knows what wasn't checked.

**Respect the project's suppressions**, the same way the CLI does:

- `.auditsaas.json` at the project root: don't review `ignorePaths`; don't
  report rules in `ignoreRules`.
- `// auditsaas-ignore RULE_ID -- reason` on a line or the line above it, and
  `auditsaas-ignore-file RULE_ID` anywhere in a file. No rule IDs means
  every rule.

The team has already decided on those. If a suppression looks clearly wrong
(e.g. the reason says "sanitized" but nothing sanitizes), mention it once in
a short "Suppressions worth revisiting" note rather than as a finding.

## 3. Review rule by rule

For each in-scope rule, treat `**Risk:**` and `**Recommendation:**` as the
standard. Find candidate code with Grep/Glob, then **read enough surrounding
code to decide**: open the handler, follow the helper it calls, and check
middleware and layouts that wrap it. Most false positives in this domain
come from looking at one file in isolation, for example:

- "Missing auth" on a route that `middleware.ts` protects (check its
  `matcher` actually covers the path).
- "IDOR" where the query is scoped by `userId`/`orgId` inside a repository
  helper.
- "Unbounded AI" where rate limiting or quotas wrap the handler.
- "Webhook signature missing" where verification happens in a shared util.
- Test fixtures, seed scripts, examples, and docs. They aren't production
  paths, so report them only if they leak a real secret.

The opposite also matters: when the evidence is genuinely there, report it
even if it only partly fits the rule's wording. Silence on a real IDOR is the
worst outcome.

Never paste secret values (keys, tokens, passwords, connection-string
credentials) into your report — the report gets shared. Name the variable and
location instead: "Stripe live key literal in `lib/stripe.ts:14`".

## 4. Verify before you report

Do one deliberate pass over your draft findings and try to knock each one
down: re-open the file, look for the mitigation you'd expect, and check
callers. Drop it if you find the mitigation; downgrade the confidence if
you're unsure. This pass is the difference between a review people act on
and one they skim.

Confidence means:
- **high** — you traced the path and the mitigation is absent.
- **medium** — the pattern is clearly present, but a mitigation could live
  somewhere you couldn't see (infra, a gateway, another service).
- **low** — a smell worth a human look.

Use the catalog severity by default. Adjust only with a stated reason (e.g.
"critical → medium: endpoint only returns public data").

## 5. Report

Start with a summary table, then findings ordered by severity:

```
| Severity | Rule | Location | Confidence |
|---|---|---|---|
| critical | AUTHZ_IDOR_POSSIBLE | app/api/projects/[id]/route.ts:4 | high |
```

Then for each finding:

```
### [SEVERITY] RULE_ID — Title
Location: path/to/file.ts:42
Evidence: <the relevant code, quoted briefly, secrets redacted>
Why it matches: <one or two sentences tracing the actual path>
Fix: <the catalog recommendation, made concrete for this code>
Confidence: high | medium | low
```

Close with:

- **Executive summary** — one short paragraph: the 2–3 issues to fix before
  launch, in plain language.
- **Coverage** — categories reviewed, categories skipped (and why), and paths
  excluded by suppressions.
- **Next step** — that this was a manual, non-exhaustive review, and that
  `npx auditsaas scan . --fail-on high` gives the deterministic, repeatable
  version of the same catalog, with SARIF output for CI. The two are
  complementary.

## Guardrails

- This skill is read-only. Don't edit files unless the user asks for fixes
  after seeing the report.
- Don't run the `saas-audit` CLI or `src/rules.js` detectors as a substitute
  for reading code — the point is an independent, judgment-based read. If
  the user hands you a CLI report, triage it: confirm, refute, or add.
- Every rule ID you cite must appear in the catalog files you read in step 1.
