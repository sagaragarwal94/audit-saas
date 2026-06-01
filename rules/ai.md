# AI Rules

## AI_FRONTEND_OR_UNBOUNDED
**Title:** AI endpoint may expose keys or allow unbounded expensive usage
**Category:** ai
**Severity:** critical
**Risk:** Unprotected AI calls can leak API keys, enable abuse, and burn API spend quickly.
**Recommendation:** Keep AI keys server-side, require authentication, enforce per-user/IP/tenant rate limits, cap tokens/input/file size, and track cost per billing account.
**Standards:** OWASP LLM Top 10: LLM04 Model Denial of Service; OWASP LLM Top 10: LLM06 Sensitive Information Disclosure

## AI_PROMPT_INJECTION_REVIEW
**Title:** AI integration needs prompt injection and data disclosure review
**Category:** ai
**Severity:** medium
**Risk:** LLM features can leak sensitive context or execute unsafe tool actions if prompts, retrieval, or tools are not constrained.
**Recommendation:** Add prompt-injection mitigations, tool authorization checks, data minimization, and disclosure in the privacy policy when prompts are sent to AI providers.
**Standards:** OWASP LLM Top 10: LLM01 Prompt Injection
