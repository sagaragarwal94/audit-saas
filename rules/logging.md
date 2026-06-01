# Logging And Monitoring Rules

## LOGGING_SECRETS_RISK
**Title:** Logs may include secrets or sensitive request data
**Category:** logging
**Severity:** high
**Risk:** Logging tokens, passwords, full request bodies, or provider payloads can create a secondary data breach path.
**Recommendation:** Redact secrets from logs and avoid logging full request bodies, authorization headers, cookies, payment payloads, and AI prompts unless explicitly scrubbed.
**Standards:** OWASP Top 10: A09 Security Logging and Monitoring Failures

## MONITORING_ANOMALY_GAPS
**Title:** Post-deploy anomaly detection plan is missing or incomplete
**Category:** logging
**Severity:** medium
**Risk:** Without security and cost anomaly alerts, abuse can continue unnoticed after launch.
**Recommendation:** Add alerts for failed login spikes, repeated 401/403s, sequential ID access, AI spend spikes, webhook failures, admin access, and error-rate increases.
**Standards:** OWASP Top 10: A09 Security Logging and Monitoring Failures
