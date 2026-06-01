# Gravel Rule Catalog

Rules are organized by category in Markdown files. Each rule block uses this shape:

```md
## RULE_ID
**Title:** Human readable title
**Category:** auth
**Severity:** critical
**Risk:** What can go wrong.
**Recommendation:** What the user should do.
**Code Example:** Optional short fix example.
**Standards:** Standard one; Standard two
```

The scanner loads this Markdown metadata at runtime. The executable detector for each rule currently lives in `src/rules.js`, keyed by the same `RULE_ID`.

To add a new detector-backed rule:

1. Add a rule block to the matching category file, or create a new category Markdown file.
2. Add a detector object with the same `id` in `src/rules.js`.
3. Add or update a fixture test that proves the rule fires.

The Markdown catalog is the editable public rule layer; JavaScript remains the detection layer for rules that need code analysis.
