# File Upload Rules

## UPLOAD_UNRESTRICTED_FILE_TYPE
**Title:** File upload endpoint may not restrict file type or size
**Category:** uploads
**Severity:** high
**Risk:** Accepting any file type or size lets attackers upload executable scripts, oversized payloads, or files that trigger downstream parser vulnerabilities.
**Recommendation:** Validate MIME type and extension against an allowlist, enforce a maximum file size, and store uploads outside the web root or in object storage with restricted execution.
**Standards:** OWASP Top 10: A04 Insecure Design; OWASP ASVS V12 File and Resources

## UPLOAD_PATH_TRAVERSAL
**Title:** Uploaded file may be written using a user-controlled path
**Category:** uploads
**Severity:** critical
**Risk:** Writing a file using an attacker-supplied filename or path can overwrite arbitrary files via `../` traversal.
**Recommendation:** Generate a server-side random filename, strip path separators, and write only inside a fixed, dedicated upload directory.
**Standards:** OWASP Top 10: A01 Broken Access Control; OWASP ASVS V12 File and Resources
