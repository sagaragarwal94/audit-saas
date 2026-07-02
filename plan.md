# AuditSaas Pricing Plan

## Context

- Product: a local CLI that audits SaaS codebases for security, privacy, AI-abuse, payments, and production-readiness gaps (46 rules / 20 categories today).
- Runs 100% on the user's machine. No hosted backend, no database, no per-scan infra cost. The only external cost is the *user's own* AI-review API key/local LLM, which they pay for directly — not us.
- Current state: private beta, invite-only, distributed as an npm tarball (`npm run beta:pack`) or repo access. No pricing or license enforcement exists yet.
- Audience: solo founders and small teams shipping fast, often with AI coding assistants (Cursor, Claude Code, v0, Lovable, Bolt, etc.) — the "vibe-coding" crowd from the HN/PH/Twitter/Reddit launch copy.

## Recommendation: freemium + one-time audit + team tier

Because the CLI has near-zero marginal cost per scan, the pricing question isn't "can we afford to give more away" — it's "what unlocks willingness to pay without adding infra we don't need yet." Three tiers, no infra required beyond a payment link and manual key issuance at this stage:

### 1. Free — the on-ramp
- Full scanner, but only the **secrets + auth** rule categories active (the two categories with the highest "oh no" moment — committed `.env` files, hardcoded keys, missing rate limits — and the easiest to demo in a screenshot).
- No AI review.
- Goal: every HN/PH/Reddit visitor can `npx auditsaas scan .` and get real value in under a minute, with an obvious reason to upgrade (report shows "12 more checks available in Indie — auth, payments, AI, SSRF, CORS, ...").

### 2. Indie — $19/mo or $149/yr (~35% off annual)
- All 46 rules across all 20 categories.
- SARIF export for GitHub code scanning / CI.
- AI review (bring your own key, or local LLM — unlimited either way since it's not our API cost).
- Priority access to new rules as categories are added.
- Positioning: priced like the tools this audience already pays for (Vercel Pro, Supabase Pro tier neighbors), not like enterprise security tooling.

### 3. Launch Audit — $79–99 one-time
- One full scan + the generated priority-action-plan + a short (15 min) async or live review of the findings.
- For the founder who wants a single pre-launch gut-check, not a subscription.
- High margin, easy to fulfill (it's the same CLI output plus your time), and converts people who'd never sign up for a monthly tool.

### 4. Team — $49–99/mo, up to 5 seats/projects
- Everything in Indie, across multiple projects/repos under one license.
- Slack/webhook notification on scan completion (future work), custom/internal rules, priority support.
- Add this tier only once beta feedback shows agencies/studios auditing multiple client projects — don't build it speculatively.

## Why this shape (not usage-based, not pure open-core)

- **Not usage-based** (pay-per-scan): scans are cheap and fast; metering discourages the exact behavior you want (scan often, scan on every change). Flat subscription aligns incentives better.
- **Not pure open-core** (give away the CLI, charge for a dashboard): there's no dashboard, and building one just to gate pricing would be scope creep this product doesn't need. Gating by *rule category count* is simpler and matches how the product already works (`--focus security|privacy|payments|ai`).
- **One-time tier matters for this audience**: a lot of solo builders will never subscribe to a security tool but will pay once, right before they post their Show HN. Losing that segment to "subscription only" leaves money on the table.

## Licensing/enforcement approach

The CLI is plain Node.js source — it can't be meaningfully DRM'd, and trying to would hurt trust with exactly the audience we want (people already skeptical of "vibe-coded SaaS" doing sketchy things with license checks). Treat this like Sentry/PostHog self-host licensing: an honesty-based fence, not a lock.

- **V1 (now, during beta):** no enforcement. Everything is free for invited testers. Don't build licensing infra yet — there's no signal it's needed until beta feedback validates the product.
- **V1.5 (at public launch):** CLI reads `AUDITSAAS_LICENSE_KEY` (env var, same pattern as the existing `AUDITSAAS_LLM_*` vars). If unset, only the free rule categories run. A lightweight serverless endpoint (Vercel function + KV or a simple Stripe-linked Postgres table) validates the key format/status — no need for a full billing dashboard on day one.
- **Payments:** Stripe Checkout + Payment Links for Indie/Team (recurring) and Launch Audit (one-time). Skip building a custom checkout page; Stripe-hosted pages are enough at this scale.
- **Key delivery:** Stripe webhook → generate a key → email it. Fully scriptable without a dashboard; a dashboard becomes worth building only once manual key issuance becomes a bottleneck.

## Rollout tied to the current beta

1. **Now:** beta stays fully free/unlocked for all invited testers — the goal right now is feedback and false-positive reduction, not revenue.
2. **At public launch (HN/PH/Twitter/Reddit):** ship Free + Indie tiers alongside the launch posts. Grandfather every beta tester into a free Indie tier for 3–6 months as a thank-you — they're your first testimonials.
3. **Later, only if demand shows up:** add the Team tier once multiple beta testers mention auditing client/agency projects.

## Open questions to decide before public launch

- Confirm the free-tier category split (recommended: secrets + auth) actually produces a compelling "aha" without giving away so much that Indie feels unnecessary.
- Decide Indie annual discount depth (35% suggested above, matches common dev-tool anchoring).
- Decide whether Launch Audit includes a human review call or is fully automated — the call adds trust/conversion but doesn't scale past a handful of customers per week.
