# Dependency Rules

## DEPENDENCY_NO_LOCKFILE
**Title:** No dependency lockfile found
**Category:** dependencies
**Severity:** medium
**Risk:** Without a lockfile, dependency versions can drift between installs, pulling in unreviewed or vulnerable transitive updates.
**Recommendation:** Commit `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` and install with `--frozen-lockfile` in CI.
**Standards:** OWASP Top 10: A06 Vulnerable and Outdated Components

## DEPENDENCY_WILDCARD_VERSION
**Title:** Dependency pinned to a wildcard or `latest` version
**Category:** dependencies
**Severity:** medium
**Risk:** `*` or `latest` version ranges can silently pull in breaking or malicious updates, including supply-chain attacks published under a trusted package name.
**Recommendation:** Pin dependencies to specific or caret-ranged versions and review updates deliberately.
**Standards:** OWASP Top 10: A06 Vulnerable and Outdated Components

## DEPENDENCY_KNOWN_RISKY_PACKAGE
**Title:** Deprecated or historically compromised package detected
**Category:** dependencies
**Severity:** high
**Risk:** Some packages are deprecated, unmaintained, or have a documented history of supply-chain compromise; continuing to depend on them carries elevated risk.
**Recommendation:** Replace deprecated/unmaintained packages with actively maintained alternatives and run `npm audit` regularly.
**Standards:** OWASP Top 10: A06 Vulnerable and Outdated Components

## POSTINSTALL_SCRIPT_RISK
**Title:** package.json runs a script automatically on install
**Category:** dependencies
**Severity:** medium
**Risk:** `postinstall`/`preinstall` scripts execute arbitrary code the moment `npm install` runs, and are a common vector for supply-chain attacks in compromised packages. Having one in your own project also means every contributor and CI runner executes it blindly.
**Recommendation:** Avoid install-time scripts where possible; if one is required, keep it minimal, reviewed, and version-controlled.
**Standards:** OWASP Top 10: A06 Vulnerable and Outdated Components
