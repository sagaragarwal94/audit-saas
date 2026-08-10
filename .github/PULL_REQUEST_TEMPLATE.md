## What does this change

## Checklist

- [ ] `npm test` passes locally (includes the rule-catalog/detector parity check)
- [ ] If this adds a rule: both a `rules/<category>.md` entry **and** a matching
      detector in `src/rules.js` are included (see `CONTRIBUTING.md`)
- [ ] If this adds a rule: a fixture test proves the detector actually fires
- [ ] If this touches `rules/*.md`: ran `npm run build:rules-page` and
      committed the resulting `site/rules.html` diff (if any)
