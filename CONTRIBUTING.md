# Contributing

Thanks for helping improve AuditSaas. Contributions are welcome — issues, rule additions, bug fixes, and PRs alike. AuditSaas is source-available under the [Functional Source License](./LICENSE); contributing doesn't require signing anything beyond that.

## Good First Contributions

- Add scanner rules in `rules/`.
- Improve report wording.
- Add vulnerable fixture examples.
- Add tests for new rule categories.

## Local Setup

```bash
npm install
npm test
npm run fixture:scan
```

## Rule Guidelines

Every rule has two halves that must ship together — `npm test` enforces this
via `test/rule-parity.test.js`, which fails if either half is missing:

1. A Markdown block in `rules/<category>.md` (see `rules/README.md` for the
   exact shape) explaining the risk, recommendation, and category.
2. A matching detector object with the same `id` in `src/rules.js`.

Rules should be practical and explain:

- What risk is being detected.
- What evidence or pattern points to the risk.
- How a SaaS team should fix it.
- Which category the rule belongs to.

Keep recommendations specific, calm, and actionable. Add or update a fixture
test proving the detector fires before opening a PR.
