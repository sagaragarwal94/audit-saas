# Contributing

Thanks for helping improve AuditSaas.

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

Rules should be practical and explain:

- What risk is being detected.
- What evidence or pattern points to the risk.
- How a SaaS team should fix it.
- Which category the rule belongs to.

Keep recommendations specific, calm, and actionable.
