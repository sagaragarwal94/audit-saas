# Code Execution And Deserialization Rules

## CODE_EXECUTION_EVAL_USER_INPUT
**Title:** Dynamic code execution near user-controlled input
**Category:** injection
**Severity:** critical
**Risk:** `eval`, `new Function`, or `child_process.exec` used near request input can allow full remote code execution if any user-controlled value reaches it.
**Recommendation:** Remove dynamic code execution entirely, or if unavoidable, use a strict sandbox and never pass unsanitized user input into it.
**Standards:** OWASP Top 10: A03 Injection
