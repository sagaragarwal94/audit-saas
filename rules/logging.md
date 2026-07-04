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

## VERBOSE_ERROR_STACK_TRACE_TO_CLIENT
**Title:** API response may return a raw error message or stack trace
**Category:** logging
**Severity:** medium
**Risk:** Returning `err.stack` or a raw error message to the client can leak file paths, library versions, query fragments, or other internals useful for an attacker's reconnaissance.
**Recommendation:** Log the full error server-side, and return a generic error message to the client.
**Standards:** OWASP Top 10: A09 Security Logging and Monitoring Failures
