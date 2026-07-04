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

## Pricing model: tiered plans gated by scan volume + rule coverage

Modeled on how developer-tool APIs like Firecrawl price (a free tier, a small starter tier, a "recommended" middle tier, and a scale tier, all billed monthly or discounted yearly) — but adapted to this product's actual unit of value. Firecrawl meters *pages scraped*; the equivalent unit here is **scans run per month**, since that's the action a user actually repeats. Rule coverage becomes the qualitative gate on top, the same way Firecrawl gates concurrency and support tier rather than what a scrape can *do*.

### Free — $0/mo
- **10 scans/month**
- Only the **secrets + auth** categories active (2 of 23) — enough to produce a real "oh no" moment (a committed `.env`, a missing login rate limit) in under a minute, with an obvious reason to upgrade.
- 1 project
- Community support (GitHub issues / Discord, once either exists)
- No AI review

### Hobby — $15/mo, or $12/mo billed yearly (save $36/yr)
- **150 scans/month**
- All 66 rules, all 23 categories
- 1 project
- SARIF export for CI
- Email support

### Standard — $49/mo, or $39/mo billed yearly (save $120/yr) — *Recommended*
- **750 scans/month**
- Everything in Hobby
- Up to 5 projects
- AI review enabled (bring your own key, or local LLM — this costs us nothing either way, so it's a feature gate, not a cost-driven one)
- Priority access to new rules as they ship
- Standard support

### Growth — $125/mo, or $99/mo billed yearly (save $312/yr)
- **3,000 scans/month**
- Everything in Standard
- Unlimited projects
- 5 team seats
- Priority support

### Scale — $249/mo billed yearly
- **Unlimited scans**
- Unlimited seats/projects
- Custom/internal rule support
- Dedicated support & SLA

### Enterprise — custom
- Self-host / on-prem option
- SSO
- Custom rule development
- Bulk discounts, dedicated support & SLA

**Scan credits don't roll over** month to month, matching the convention this model is based on — it keeps the pricing math simple and avoids stockpiling incentives.

### Launch Audit — $79 one-time (sits outside the ladder)
- One full scan + the generated priority-action-plan + a short async review of the findings.
- For the founder who wants a single pre-launch gut-check, not a subscription — a meaningful chunk of this audience will pay once and never subscribe. Keep this as a separate one-time SKU, not a tier, since it serves a different buyer intent than the monthly ladder above.

## Why this shape

- **Scans-as-credits, not pay-per-finding or pay-per-line-of-code**: scans are the unit of value the user actually understands and repeats (run before every deploy, in CI, etc.), same logic as Firecrawl metering pages rather than API calls or bytes.
- **Rule-category gating on top of volume, not instead of it**: a pure volume gate (e.g. "10 scans free, unlimited if you pay") wouldn't showcase the product's actual differentiator, which is breadth of coverage. A pure feature gate (all scans free, pay for more rules) doesn't scale revenue with usage. Doing both mirrors how Firecrawl gates on pages *and* concurrency/support simultaneously.
- **One-time tier survives alongside the ladder**: a lot of solo builders will never subscribe to a security tool but will pay once, right before they post their Show HN. Losing that segment to "subscription only" leaves money on the table, and it costs nothing to keep it as a side offer.

## Licensing/enforcement approach

The CLI is plain Node.js source — it can't be meaningfully DRM'd, and trying to would hurt trust with exactly the audience we want (people already skeptical of "vibe-coded SaaS" doing sketchy things with license checks). Treat this like Sentry/PostHog self-host licensing: an honesty-based fence, not a lock.

- **V1 (now, during beta):** no enforcement. Everything is free and fully unlocked for invited testers. Don't build licensing infra yet — there's no signal it's needed until beta feedback validates the product.
- **V1.5 (at public launch):** CLI reads `AUDITSAAS_LICENSE_KEY` (env var, same pattern as the existing `AUDITSAAS_LLM_*` vars). Server-side, a lightweight endpoint tracks scan-credit usage per key and which rule categories that plan unlocks — no need for a full billing dashboard on day one, just enough state to gate `runRules()` by category and count scans against the monthly credit.
- **Payments:** Stripe Checkout + Payment Links for the subscription tiers and the one-time Launch Audit. Skip building a custom checkout page; Stripe-hosted pages are enough at this scale.
- **Key delivery:** Stripe webhook → generate a key → email it. Fully scriptable without a dashboard; a dashboard becomes worth building only once manual key issuance or usage tracking becomes a bottleneck.

## Rollout tied to the current beta

1. **Now:** beta stays fully free/unlocked for all invited testers — the goal right now is feedback, false-positive reduction, and validating which rule categories people actually care about (this directly informs the Free-tier category split above).
2. **At public launch (HN/PH/Twitter/Reddit):** ship Free + Hobby + Standard alongside the launch posts. Grandfather every beta tester into Standard free for 3–6 months as a thank-you — they're your first testimonials.
3. **Later, only if demand shows up:** add Growth/Scale once multiple beta testers mention auditing client/agency projects or running AuditSaas across many repos in CI.

## Open questions to decide before public launch

- Confirm the Free-tier category split (secrets + auth) actually produces a compelling "aha" without giving away so much that Hobby feels unnecessary — this is exactly what beta feedback should tell us.
- Validate the scan-credit numbers above (10 / 150 / 750 / 3,000) against actual beta usage patterns once we have telemetry — these are informed guesses, not measured.
- Decide whether Launch Audit includes a human review call or is fully automated — the call adds trust/conversion but doesn't scale past a handful of customers per week.
- Decide the real dependency-CVE-lookup build (see "Rule coverage" above) before or after public launch — it's the biggest remaining credibility gap for the security-literate HN audience specifically.
