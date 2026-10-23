# AuditSaas Rule Catalog

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
3. Add a test that proves the rule fires on vulnerable code **and** stays quiet on the safe look-alike (see `test/precision.test.js` and the `scanFiles` helper in `test/helpers.js`).

Detector conventions in `src/rules.js`:

- Use `findingForFile(...)` so the finding points at the matched line and the report shows the real (secret-redacted) code as evidence.
- Pick the narrowest file set: `appCodeFiles` (app source, no tests), `sourceFiles`, `nonDocFiles` (anything but Markdown), or `filesWith(project, "api_route")`. Rules that fire on a README describing the risk are noise.
- Never put secret values in `evidence`. Pass an explicit redacted evidence string for secret rules.
- A detector that throws is reported in the scan's `errors` and skipped. It won't take the scan down, but it will show up as a warning.

Users can suppress any rule with `// auditsaas-ignore RULE_ID -- reason`, `auditsaas-ignore-file RULE_ID`, or `ignoreRules` in `.auditsaas.json`. Choose precision over recall when a pattern is ambiguous, because a noisy rule teaches people to suppress it.

The Markdown catalog is the editable public rule layer; JavaScript remains the detection layer for rules that need code analysis.
