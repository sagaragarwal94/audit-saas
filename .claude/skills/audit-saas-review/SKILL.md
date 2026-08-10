---
name: audit-saas-review
description: Manually reviews the current codebase against AuditSaas's security/privacy/payments/AI rule catalog using human judgment, without running the saas-audit CLI's regex detectors. Use when someone wants a fast, install-free second opinion on their SaaS app's security/privacy/production-readiness, or wants to try AuditSaas's rule taxonomy before installing the CLI.
---

# AuditSaas Manual Review

You are doing a **manual, judgment-based** code review against the AuditSaas
rule catalog. This is deliberately different from the `saas-audit` CLI: the
CLI runs fixed regex detectors and is deterministic; you read real code and
use judgment, so you will catch things regex can't (and can also be wrong in
ways regex isn't — say so when you're not sure).

## Step 0 — Locate the rule catalog

Never invent rule content. Find the real `rules/*.md` files, in this order,
and stop at the first one that has `.md` files matching `auth.md`, `xss.md`,
`secrets.md`, etc.:

1. `./rules/` relative to the current working directory (you're inside a
   clone of the auditsaas repo, or someone copied `rules/` into their project).
2. `./node_modules/auditsaas/rules/` relative to the current working directory
   (auditsaas installed as a project dependency).
3. Walk up from this skill file's own directory: this file lives at
   `.claude/skills/audit-saas-review/SKILL.md`, so `../../../rules/` (three
   levels up) is the auditsaas repo root's `rules/` folder when this skill
   is used from inside a real auditsaas checkout.
4. If none of these resolve, tell the user plainly that the bundled rule
   catalog could not be found, ask them for its path, and if they don't have
   one, say so explicitly in your final report rather than fabricating rule
   IDs or severities from memory.

Skip `rules/README.md` — it's documentation, not a rule file.

## Step 1 — Scope the review

If the user gave you a focus argument (`security`, `privacy`, `payments`,
`ai`, or `all`), use it. Otherwise default to `all`. Map focus to categories
exactly like the CLI does:

- `security`: auth, authorization, api, database, xss, secrets, headers,
  logging, cors, ssrf, jwt, csrf, dependencies, uploads, admin, infra,
  injection, crypto, oauth, websocket
- `privacy`: privacy, secrets, logging, api
- `payments`: payments, auth, authorization, api, logging
- `ai`: ai, api, secrets, privacy, logging
- `all`: every category (every file in `rules/`)

Each category maps 1:1 to a filename (`rules/auth.md` = category `auth`).
Before reading every file, do one quick pass over the project (package.json
dependencies, a few grep passes for `stripe`, `openai`, `jsonwebtoken`,
`prisma`/`supabase`, etc.) so you can skip categories with clearly zero
relevant surface (e.g. don't spend the user's time on `payments.md` if there
is no payments code at all) — but when in doubt, check it anyway.

## Step 2 — Review, one rule at a time

For each in-scope `rules/<category>.md` file: read it, and for each `## RULE_ID`
block, treat its `**Risk:**` and `**Recommendation:**` text as the standard
you're checking against. Then actually look at the relevant source files —
don't guess. Only report a finding if you found real, specific evidence:
quote the file path, line/snippet, and explain in one sentence why it matches
the rule's risk. If a rule doesn't apply (no matching code exists at all),
skip it silently — don't pad the report with "N/A" entries.

Do not paste raw secret values, API keys, or credentials you find into your
report — describe the location and pattern only (e.g. "hardcoded key-shaped
string in `config/stripe.ts:14`"), never the literal value.

## Step 3 — Report

For each finding, use this shape (mirrors the rule catalog fields so it's
easy to compare against a real `saas-audit scan` run):

```
### [SEVERITY] RULE_ID — Title
File: path/to/file.ts:42
Evidence: <short quote or paraphrase of the actual code>
Risk: <from the rule catalog>
Recommendation: <from the rule catalog, adapted to what you saw>
Confidence: <your honest confidence — this is judgment, not regex>
```

End with:
- A one-paragraph executive summary (worst 2-3 issues, plain language).
- A note that this was a manual, non-exhaustive review complementary to the
  `saas-audit` CLI, and that running `npx github:sagaragarwal94/audit-saas
  scan .` gives a deterministic, repeatable, CI-friendly version of the same
  rule catalog — this review is a preview, not a replacement.

## Guardrails

- Never invoke or shell out to the `saas-audit` CLI, `src/rules.js`, or any
  regex detector — this skill's entire value is the judgment-based pass.
- Never invent a rule ID that isn't literally present in the files you read
  in Step 0.
- This is a read-only review: don't edit the user's files unless they
  explicitly ask you to fix something after seeing the report.
