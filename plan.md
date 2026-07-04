# AuditSaas Pricing Plan

## Context

- Product: a local CLI that audits SaaS codebases for security, privacy, AI-abuse, payments, and production-readiness gaps — **66 rules across 23 categories** as of this revision (up from 46/20; see "Rule coverage" below).
- Runs 100% on the user's machine. No hosted backend, no database, no per-scan infra cost. The only external cost is the *user's own* AI-review API key/local LLM, which they pay for directly — not us.
- Current state: private beta, invite-only, distributed as an npm tarball (`npm run beta:pack`) or repo access. No pricing or license enforcement exists yet.
- Audience: solo founders and small teams shipping fast, often with AI coding assistants (Cursor, Claude Code, v0, Lovable, Bolt, etc.) — the "vibe-coding" crowd from the HN/PH/Twitter/Reddit launch copy.

## Rule coverage: is 66 rules enough?

46 was a reasonable v1, but "enough" isn't really the right frame for a security scanner — coverage compounds, and gaps in coverage are invisible until someone gets bitten by exactly the thing you didn't check for. This revision adds 20 more rules (auth/JWT hardening, cryptographic randomness, OAuth CSRF, WebSocket auth, cloud/Terraform misconfiguration, supply-chain install scripts, hardcoded cloud credentials, exposed backups, CSP/SRI/source-map hygiene, Stripe amount tampering, unbounded queries, GraphQL depth limits, and — given how common the pattern is right now — unauthenticated Next.js Server Actions), bringing the total to 66 across 23 categories.

Where to keep expanding, roughly in priority order:
1. **Framework-specific depth**: Next.js middleware bypass patterns, Remix loader/action auth, tRPC procedure-level auth — the audience skews heavily Next.js, so going deeper there beats going wider into frameworks few beta testers use.
2. **Dependency CVE lookup**: today's dependency rules are pattern-based (lockfile presence, known-risky package names). A real `npm audit`/OSV database lookup would catch actual CVEs, not just known-bad packages — this is the single highest-leverage gap left, but it's a bigger build (needs a vulnerability database, either shelling out to `npm audit --json` or bundling an offline OSV snapshot).
3. **IaC beyond Terraform**: Pulumi, AWS CDK, and raw CloudFormation are common enough among this audience to be worth a second pass once Terraform rules prove valuable in beta feedback.
4. **Rules driven by real false negatives**: the most valuable next 20 rules are the ones beta testers report as "this should have caught X" — prioritize those over more speculative additions.

This is inherently open-ended (a rule catalog for a security scanner never reaches "done"), which is actually a good thing for pricing: it means there's a durable reason to keep the product up to date, not a one-time build.

## Pricing model: flat tiers gated by rule coverage only — no scan quotas, no seats

Earlier drafts of this plan modeled pricing on Firecrawl's scan-credit ladder. Decision: drop that. No scan-based metering and no per-seat pricing — gating on usage volume or headcount adds billing complexity and support friction (users hitting caps mid-audit, seat management for what are mostly solo/small teams) without matching how this audience actually evaluates a security tool: by what it catches, not how many times they ran it. Every tier below gets **unlimited scans and unlimited team members**; the only thing that changes between tiers is rule coverage and support level.

The tier bands below were validated directly with the private-beta waitlist survey ("If this were paid, what would feel fair?" — options were Free only / $9–19/mo / $20–49/mo / a one-time fee / not sure yet). The paid tiers map onto the two price bands that got real signal; "not sure yet" isn't a plan, it's a market-research bucket that just tells us to keep the Free tier generous enough to convert people once they've seen real value.

### Free — $0/mo
- Only the **secrets + auth** categories active (2 of 23) — enough to produce a real "oh no" moment (a committed `.env`, a missing login rate limit) in under a minute, with an obvious reason to upgrade.
- Unlimited scans, unlimited projects, unlimited team members
- Community support
- No AI review

### Pro — $15/mo, or $12/mo billed yearly (save $36/yr) *(the $9–19/mo band)*
- All 66 rules, all 23 categories
- Unlimited scans, unlimited projects, unlimited team members
- SARIF export for CI
- AI review enabled (bring your own key, or local LLM)
- Email support

### Business — $35/mo, or $29/mo billed yearly (save $72/yr) *(the $20–49/mo band)* — *Recommended*
- Everything in Pro
- Priority access to new rules as they ship
- Custom/internal rule support
- Priority support with faster response times
- Early input into the language/platform roadmap (Python, Java, Kotlin, Swift, Rust, Go, Android/iOS)

### Enterprise — custom
- Self-host / on-prem option
- SSO
- Dedicated custom rule development
- Dedicated support & SLA, bulk discounts

### Launch Audit — $79 one-time *(the one-time-fee band, sits outside the tier ladder)*
- One full scan + the generated priority-action-plan + a short async review of the findings.
- For the founder who wants a single pre-launch gut-check, not a subscription — a meaningful chunk of this audience will pay once and never subscribe. Keep this as a separate one-time SKU, not a tier, since it serves a different buyer intent than Pro/Business.

## Why this shape

- **No scan quotas**: a security scanner that throttles how often you can check your own code sends the wrong message, and metering adds real engineering (usage tracking, overage handling, "you're out of scans" UX) for a product that costs us nothing per scan to run. Unlimited-scans-on-every-tier is both simpler to build and more honest positioning.
- **No seat-based pricing**: this audience is mostly solo builders and small teams where "per seat" reads as nickel-and-diming, not enterprise-appropriate segmentation. Gating on rule coverage and support level instead avoids that friction entirely.
- **Two paid bands, not five**: the waitlist survey gave two real price signals ($9–19 and $20–49). Building more tiers than the data supports is guessing; Pro and Business map directly onto what people said they'd actually pay.
- **One-time tier survives alongside the ladder**: a lot of solo builders will never subscribe to a security tool but will pay once, right before they post their Show HN. Losing that segment to "subscription only" leaves money on the table, and it costs nothing to keep it as a side offer.

## Licensing/enforcement approach

The CLI is plain Node.js source — it can't be meaningfully DRM'd, and trying to would hurt trust with exactly the audience we want (people already skeptical of "vibe-coded SaaS" doing sketchy things with license checks). Treat this like Sentry/PostHog self-host licensing: an honesty-based fence, not a lock.

- **V1 (now, during beta):** no enforcement. Everything is free and fully unlocked for invited testers. Don't build licensing infra yet — there's no signal it's needed until beta feedback validates the product.
- **V1.5 (at public launch):** CLI reads `AUDITSAAS_LICENSE_KEY` (env var, same pattern as the existing `AUDITSAAS_LLM_*` vars). A lightweight endpoint validates the key and returns which rule categories that plan unlocks — no scan counting needed since there's no volume gate, just a category allowlist to check `runRules()` against.
- **Payments:** Stripe Checkout + Payment Links for Pro/Business (recurring) and Launch Audit (one-time). Skip building a custom checkout page; Stripe-hosted pages are enough at this scale.
- **Key delivery:** Stripe webhook → generate a key → email it. Fully scriptable without a dashboard; a dashboard becomes worth building only once manual key issuance becomes a bottleneck.

## Rollout tied to the current beta

1. **Now:** beta stays fully free/unlocked for all invited testers — the goal right now is feedback, false-positive reduction, and validating which rule categories people actually care about (this directly informs the Free-tier category split above).
2. **At public launch (HN/PH/Twitter/Reddit):** ship Free + Pro + Business alongside the launch posts. Grandfather every beta tester into Business free for 3–6 months as a thank-you — they're your first testimonials.
3. **Later, only if demand shows up:** add an Enterprise motion (SSO, self-host, dedicated custom rules) once multiple beta testers mention agency/enterprise procurement requirements.

## Open questions to decide before public launch

- Confirm the Free-tier category split (secrets + auth) actually produces a compelling "aha" without giving away so much that Pro feels unnecessary — this is exactly what beta feedback should tell us.
- Watch actual usage patterns post-launch for signs the no-quota model gets abused (e.g. one account running thousands of scans/day) — unlikely given the audience, but worth a lightweight abuse-rate-limit at the infra level even without a billed quota.
- Decide whether Launch Audit includes a human review call or is fully automated — the call adds trust/conversion but doesn't scale past a handful of customers per week.
- Decide the real dependency-CVE-lookup build (see "Rule coverage" above) before or after public launch — it's the biggest remaining credibility gap for the security-literate HN audience specifically.
