import path from "node:path";
import { loadRuleCatalog } from "./rule-catalog.js";

const FOCUS_MAP = {
  security: ["auth", "authorization", "api", "database", "xss", "secrets", "headers", "logging"],
  privacy: ["privacy", "secrets", "logging", "api"],
  payments: ["payments", "auth", "authorization", "api", "logging"],
  ai: ["ai", "api", "secrets", "privacy", "logging"],
  all: null
};

const RULE_CATALOG = loadRuleCatalog();

export function runRules(project, context) {
  const categories = FOCUS_MAP[context.focus] || null;
  return rules
    .filter((rule) => !categories || categories.includes(rule.category))
    .flatMap((rule) => rule.detect(project, context).map((finding) => normalizeFinding(rule, finding)));
}

function normalizeFinding(rule, finding) {
  const metadata = { ...rule, ...(RULE_CATALOG.get(rule.id) || {}) };
  return {
    id: metadata.id,
    title: finding.title || metadata.title,
    severity: finding.severity || metadata.severity,
    category: metadata.category,
    file: finding.file,
    line: finding.line,
    evidence: finding.evidence,
    risk: finding.risk || metadata.risk,
    recommendation: finding.recommendation || metadata.recommendation,
    codeExample: finding.codeExample || metadata.codeExample,
    confidence: finding.confidence || "medium",
    standards: finding.standards || metadata.standards || []
  };
}

function sourceFiles(project) {
  return project.files.filter((file) => !file.classification.includes("environment") && /\.(t|j)sx?$|\.mjs$|\.cjs$/.test(file.relativePath));
}

function filesWith(project, label) {
  return project.files.filter((file) => file.classification.includes(label));
}

function lineOf(content, pattern) {
  const idx = typeof pattern === "string" ? content.indexOf(pattern) : content.search(pattern);
  if (idx < 0) return undefined;
  return content.slice(0, idx).split("\n").length;
}

function hasAny(content, patterns) {
  return patterns.some((pattern) => pattern.test(content));
}

function findingForFile(ruleData, file, pattern, extra = {}) {
  return {
    ...ruleData,
    file: file.relativePath,
    line: lineOf(file.content, pattern),
    evidence: String(pattern)
      .replaceAll("/", "")
      .slice(0, 140),
    ...extra
  };
}

const rules = [
  {
    id: "AUTH_PASSWORD_HASHING_WEAK",
    title: "Weak or missing password hashing evidence",
    category: "auth",
    severity: "critical",
    risk: "Weak password storage can lead to account takeover if the database is exposed.",
    recommendation: "Use Argon2id or bcrypt with a suitable cost factor, never plaintext or raw SHA/MD5 hashes.",
    standards: ["OWASP ASVS V2 Authentication", "OWASP Top 10: A07 Identification and Authentication Failures"],
    detect(project) {
      const authFiles = filesWith(project, "auth");
      const findings = [];
      for (const file of authFiles) {
        if (/password/i.test(file.content) && /\b(md5|sha1|sha256|createHash)\b/i.test(file.content) && !/bcrypt|argon2/i.test(file.content)) {
          findings.push(findingForFile({}, file, /\b(md5|sha1|sha256|createHash)\b/i, { confidence: "high" }));
        }
      }
      const customPasswordSeen = authFiles.some((file) => /password/i.test(file.content));
      const strongHashSeen = authFiles.some((file) => /bcrypt|argon2/i.test(file.content));
      if (customPasswordSeen && !strongHashSeen) {
        findings.push({
          title: "Custom password handling found without strong hashing evidence",
          severity: "high",
          risk: "Password flows need explicit strong hashing verification before launch.",
          recommendation: "Verify every password write path uses Argon2id or bcrypt and never stores plaintext passwords.",
          confidence: "medium",
          standards: ["OWASP ASVS V2 Authentication"]
        });
      }
      return findings;
    }
  },
  {
    id: "AUTH_LOGIN_RATE_LIMIT_MISSING",
    title: "Login endpoint may be missing brute-force protection",
    category: "auth",
    severity: "high",
    risk: "Unthrottled login attempts allow credential stuffing and brute-force attacks.",
    recommendation: "Apply rate limits per IP and per account, track failed attempts, and add lockout/backoff controls.",
    standards: ["OWASP ASVS V2 Authentication"],
    detect(project) {
      return filesWith(project, "auth")
        .filter((file) => /login|signin|signIn|credentials/i.test(file.relativePath + file.content))
        .filter((file) => !/rateLimit|limiter|upstash|slowDown|failedLogin|attempt/i.test(file.content))
        .map((file) => findingForFile({}, file, /login|signin|signIn|credentials/i));
    }
  },
  {
    id: "AUTH_SESSION_EXPIRY_MISSING",
    title: "Session expiry is not clearly configured",
    category: "auth",
    severity: "medium",
    risk: "Long-lived or unbounded sessions increase impact after token theft.",
    recommendation: "Configure bounded session expiry, refresh-token rotation where relevant, and server-side logout invalidation.",
    standards: ["OWASP ASVS V3 Session Management"],
    detect(project) {
      const authFiles = filesWith(project, "auth");
      if (authFiles.length === 0) return [];
      const hasExpiry = authFiles.some((file) => /maxAge|expires|expiresIn|session.*strategy|jwt.*maxAge/i.test(file.content));
      return hasExpiry ? [] : [{ confidence: "low" }];
    }
  },
  {
    id: "AUTH_COOKIE_FLAGS_MISSING",
    title: "Auth cookies may be missing secure flags",
    category: "auth",
    severity: "medium",
    risk: "Cookies without HttpOnly, Secure, and SameSite controls are easier to steal or abuse.",
    recommendation: "Set HttpOnly, Secure, and SameSite=Lax or Strict for session cookies in production.",
    standards: ["OWASP ASVS V3 Session Management"],
    detect(project) {
      return sourceFiles(project)
        .filter((file) => /cookies?\(|setCookie|Set-Cookie/i.test(file.content))
        .filter((file) => !/httpOnly/i.test(file.content) || !/secure/i.test(file.content) || !/sameSite/i.test(file.content))
        .map((file) => findingForFile({}, file, /cookies?\(|setCookie|Set-Cookie/i));
    }
  },
  {
    id: "AUTHZ_IDOR_POSSIBLE",
    title: "Possible IDOR: record fetched by ID without ownership scope",
    category: "authorization",
    severity: "critical",
    risk: "Users may access another user's or tenant's records by changing an ID in the URL or request body.",
    recommendation: "Scope every sensitive query by authenticated user, organization, or tenant in the database query itself.",
    codeExample: "await db.project.findFirst({ where: { id: projectId, userId: session.user.id } });",
    standards: ["OWASP Top 10: A01 Broken Access Control", "OWASP API Security: Broken Object Level Authorization"],
    detect(project) {
      return filesWith(project, "api_route")
        .filter((file) => /params\.|searchParams|get\(['\"]id|where:\s*{\s*id|findUnique|findById/i.test(file.content))
        .filter((file) => !/userId|ownerId|tenantId|orgId|organizationId|accountId|auth\.userId|session\.user/i.test(file.content))
        .map((file) => findingForFile({}, file, /findUnique|findById|where:\s*{\s*id/i, { confidence: "medium" }));
    }
  },
  {
    id: "API_AUTH_MISSING",
    title: "API route may be missing authentication",
    category: "api",
    severity: "high",
    risk: "Public API routes can expose data or trigger sensitive actions without a valid user session.",
    recommendation: "Require server-side authentication and authorization in every sensitive API route.",
    standards: ["OWASP Top 10: A01 Broken Access Control"],
    detect(project) {
      return filesWith(project, "api_route")
        .filter((file) => !file.classification.includes("payment"))
        .filter((file) => /export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)|router\.(get|post|put|patch|delete)/i.test(file.content))
        .filter((file) => !/auth\(|getServerSession|currentUser|getAuth|requireAuth|session|jwtVerify|supabase\.auth/i.test(file.content))
        .map((file) => findingForFile({}, file, /export\s+async\s+function|router\./i, { confidence: "medium" }));
    }
  },
  {
    id: "API_VALIDATION_MISSING",
    title: "Request body validation may be missing",
    category: "api",
    severity: "medium",
    risk: "Unvalidated input can lead to malformed data, injection risks, and unexpected application behavior.",
    recommendation: "Validate request bodies with Zod, Valibot, Joi, Yup, or equivalent schema validation before use.",
    standards: ["OWASP Top 10: A03 Injection", "OWASP ASVS V5 Validation"],
    detect(project) {
      return filesWith(project, "api_route")
        .filter((file) => /request\.json\(|req\.body|formData\(/i.test(file.content))
        .filter((file) => !/zod|z\.object|safeParse|parseAsync|joi|yup|valibot|superstruct/i.test(file.content))
        .map((file) => findingForFile({}, file, /request\.json\(|req\.body|formData\(/i));
    }
  },
  {
    id: "SQL_INJECTION_RAW_QUERY",
    title: "Possible SQL injection through raw or interpolated query",
    category: "database",
    severity: "critical",
    risk: "String-built SQL can allow attackers to read, modify, or delete database data.",
    recommendation: "Use parameterized queries or ORM query builders. Never concatenate user-controlled data into SQL.",
    standards: ["OWASP Top 10: A03 Injection"],
    detect(project) {
      return sourceFiles(project)
        .filter((file) => /\$queryRawUnsafe|executeRawUnsafe|\.query\(\s*`|SELECT .* \$\{|WHERE .* \+/is.test(file.content))
        .map((file) => findingForFile({}, file, /\$queryRawUnsafe|executeRawUnsafe|\.query\(\s*`|SELECT .* \$\{|WHERE .* \+/is, { confidence: "high" }));
    }
  },
  {
    id: "XSS_UNSAFE_HTML",
    title: "Potential XSS through unsafe HTML rendering",
    category: "xss",
    severity: "high",
    risk: "Rendering user-controlled HTML without sanitization can execute attacker-controlled scripts.",
    recommendation: "Avoid raw HTML rendering. If required, sanitize with a proven HTML sanitizer and use a strict CSP.",
    standards: ["OWASP Top 10: A03 Injection"],
    detect(project) {
      return sourceFiles(project)
        .filter((file) => /dangerouslySetInnerHTML|innerHTML\s*=|document\.write/i.test(file.content))
        .filter((file) => !/dompurify|sanitizeHtml|sanitize\(/i.test(file.content))
        .map((file) => findingForFile({}, file, /dangerouslySetInnerHTML|innerHTML\s*=|document\.write/i, { confidence: "high" }));
    }
  },
  {
    id: "SECRETS_ENV_COMMITTED",
    title: "Environment file with possible secrets is present in the project",
    category: "secrets",
    severity: "critical",
    risk: "Committed environment files can leak production credentials and third-party API keys.",
    recommendation: "Remove real `.env` files from version control, rotate exposed secrets, and keep only `.env.example` committed.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return filesWith(project, "environment")
        .filter((file) => !/\.env\.example$/.test(file.relativePath))
        .filter((file) => /(SECRET|PRIVATE|TOKEN|PASSWORD|OPENAI|STRIPE|SUPABASE|DATABASE_URL)\s*=/i.test(file.content))
        .map((file) => findingForFile({}, file, /(SECRET|PRIVATE|TOKEN|PASSWORD|OPENAI|STRIPE|SUPABASE|DATABASE_URL)\s*=/i, { confidence: "high" }));
    }
  },
  {
    id: "SECRETS_HARDCODED",
    title: "Hardcoded secret-like value detected",
    category: "secrets",
    severity: "critical",
    risk: "Hardcoded keys can be extracted from source code, logs, client bundles, or repository history.",
    recommendation: "Move secrets to server-side environment variables, rotate exposed keys, and add secret scanning to CI.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      const secretPatterns = [
        /sk_live_[A-Za-z0-9]{12,}/,
        /sk_test_[A-Za-z0-9]{12,}/,
        /sk-proj-[A-Za-z0-9_-]{20,}/,
        /OPENAI_API_KEY\s*=\s*['"][^'"]+['"]/,
        /STRIPE_SECRET_KEY\s*=\s*['"][^'"]+['"]/
      ];
      return sourceFiles(project).flatMap((file) =>
        secretPatterns
          .filter((pattern) => pattern.test(file.content))
          .map((pattern) => findingForFile({}, file, pattern, { evidence: "Secret-like value redacted", confidence: "high" }))
      );
    }
  },
  {
    id: "SECRETS_FRONTEND_PUBLIC_KEY",
    title: "Secret key may be exposed to frontend code",
    category: "secrets",
    severity: "critical",
    risk: "Secrets in `NEXT_PUBLIC_*` variables or client components can be exposed to every browser user.",
    recommendation: "Never expose OpenAI, Stripe secret, Supabase service role, or private API keys to frontend code. Move calls server-side or behind an authenticated proxy.",
    standards: ["OWASP Top 10: A02 Cryptographic Failures"],
    detect(project) {
      return project.files
        .filter((file) => /NEXT_PUBLIC_.*(SECRET|PRIVATE|TOKEN|OPENAI|STRIPE_SECRET|SERVICE_ROLE|API_KEY)/i.test(file.content))
        .map((file) => findingForFile({}, file, /NEXT_PUBLIC_.*(SECRET|PRIVATE|TOKEN|OPENAI|STRIPE_SECRET|SERVICE_ROLE|API_KEY)/i, { confidence: "high" }));
    }
  },
  {
    id: "PAYMENT_STRIPE_WEBHOOK_SIGNATURE_MISSING",
    title: "Stripe webhook may not verify event signatures",
    category: "payments",
    severity: "critical",
    risk: "Attackers may forge payment events and unlock paid features or alter subscription state.",
    recommendation: "Use `stripe.webhooks.constructEvent` with the raw request body and webhook signing secret before processing events.",
    codeExample: "const event = stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET);",
    standards: ["OWASP API Security: Unrestricted Access to Sensitive Business Flows"],
    detect(project) {
      return filesWith(project, "payment")
        .filter((file) => /webhook/i.test(file.relativePath + file.content) && /stripe/i.test(file.content))
        .filter((file) => !/webhooks\.constructEvent|constructEventAsync/i.test(file.content))
        .map((file) => findingForFile({}, file, /webhook/i, { confidence: "high" }));
    }
  },
  {
    id: "PAYMENT_IDEMPOTENCY_MISSING",
    title: "Payment webhook may be missing idempotency handling",
    category: "payments",
    severity: "high",
    risk: "Repeated webhook delivery can duplicate side effects, corrupt subscription state, or issue duplicate credits.",
    recommendation: "Store processed event IDs and make subscription updates idempotent.",
    detect(project) {
      return filesWith(project, "payment")
        .filter((file) => /webhook/i.test(file.relativePath + file.content))
        .filter((file) => !/event\.id|idempot|processed/i.test(file.content))
        .map((file) => findingForFile({}, file, /webhook/i));
    }
  },
  {
    id: "AI_FRONTEND_OR_UNBOUNDED",
    title: "AI endpoint may expose keys or allow unbounded expensive usage",
    category: "ai",
    severity: "critical",
    risk: "Unprotected AI calls can leak API keys, enable abuse, and burn API spend quickly.",
    recommendation: "Keep AI keys server-side, require authentication, enforce per-user/IP/tenant rate limits, cap tokens/input/file size, and track cost per billing account.",
    standards: ["OWASP LLM Top 10: LLM04 Model Denial of Service", "OWASP LLM Top 10: LLM06 Sensitive Information Disclosure"],
    detect(project) {
      return sourceFiles(project)
        .filter((file) => file.classification.includes("ai"))
        .filter((file) => /openai|generateText|streamText|chat\.completions|responses\.create/i.test(file.content))
        .filter((file) => !/rateLimit|quota|maxTokens|max_tokens|usage|billing|plan|auth\(|session|getAuth/i.test(file.content))
        .map((file) => findingForFile({}, file, /openai|generateText|streamText|chat\.completions|responses\.create/i, { confidence: "medium" }));
    }
  },
  {
    id: "AI_PROMPT_INJECTION_REVIEW",
    title: "AI integration needs prompt injection and data disclosure review",
    category: "ai",
    severity: "medium",
    risk: "LLM features can leak sensitive context or execute unsafe tool actions if prompts, retrieval, or tools are not constrained.",
    recommendation: "Add prompt-injection mitigations, tool authorization checks, data minimization, and disclosure in the privacy policy when prompts are sent to AI providers.",
    standards: ["OWASP LLM Top 10: LLM01 Prompt Injection"],
    detect(project) {
      return sourceFiles(project)
        .filter((file) => file.classification.includes("ai"))
        .filter((file) => /system|tools|function_call|retriev|vector|prompt/i.test(file.content))
        .map((file) => findingForFile({}, file, /system|tools|function_call|retriev|vector|prompt/i, { confidence: "low" }));
    }
  },
  {
    id: "PRIVACY_DATA_COLLECTION_FOUND",
    title: "User data collection requires privacy disclosure",
    category: "privacy",
    severity: "medium",
    risk: "Collected personal data, AI prompts, analytics, and payment metadata need clear privacy policy disclosure and retention controls.",
    recommendation: "Review the generated data inventory and publish a lawyer-reviewed privacy policy before public launch.",
    standards: ["Privacy by Design", "OWASP ASVS V14 Configuration"],
    detect(_project, context) {
      return context.dataInventory.length > 0 ? [{ evidence: `${context.dataInventory.length} data collection categories detected`, confidence: "high" }] : [];
    }
  },
  {
    id: "LOGGING_SECRETS_RISK",
    title: "Logs may include secrets or sensitive request data",
    category: "logging",
    severity: "high",
    risk: "Logging tokens, passwords, full request bodies, or provider payloads can create a secondary data breach path.",
    recommendation: "Redact secrets from logs and avoid logging full request bodies, authorization headers, cookies, payment payloads, and AI prompts unless explicitly scrubbed.",
    standards: ["OWASP Top 10: A09 Security Logging and Monitoring Failures"],
    detect(project) {
      return sourceFiles(project)
        .filter((file) => /console\.(log|error|warn)|logger\.(info|error|warn|debug)/i.test(file.content))
        .filter((file) => /password|token|secret|authorization|cookie|request|req\.body|payload|prompt/i.test(file.content))
        .map((file) => findingForFile({}, file, /console\.(log|error|warn)|logger\.(info|error|warn|debug)/i, { confidence: "medium" }));
    }
  },
  {
    id: "MONITORING_ANOMALY_GAPS",
    title: "Post-deploy anomaly detection plan is missing or incomplete",
    category: "logging",
    severity: "medium",
    risk: "Without security and cost anomaly alerts, abuse can continue unnoticed after launch.",
    recommendation: "Add alerts for failed login spikes, repeated 401/403s, sequential ID access, AI spend spikes, webhook failures, admin access, and error-rate increases.",
    standards: ["OWASP Top 10: A09 Security Logging and Monitoring Failures"],
    detect(project) {
      const hasMonitoring = project.providers.observability.length > 0 || project.files.some((file) => /Sentry|Datadog|Axiom|OpenTelemetry|Better Stack|Logtail|PostHog/i.test(file.content));
      return hasMonitoring ? [] : [{ confidence: "medium" }];
    }
  },
  {
    id: "HEADERS_HTTPS_RUNTIME",
    title: "Runtime security headers or HTTPS enforcement need hardening",
    category: "headers",
    severity: "medium",
    risk: "Missing browser security headers increase exposure to XSS, clickjacking, MIME sniffing, and data leakage.",
    recommendation: "Enforce HTTPS and configure HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(_project, context) {
      if (!context.runtime) return [];
      const missing = context.runtime.missingHeaders || [];
      const findings = [];
      if (!context.runtime.https) {
        findings.push({ title: "Production URL is not using HTTPS", severity: "critical", evidence: context.runtime.url, confidence: "high" });
      }
      if (missing.length > 0) {
        findings.push({ evidence: `Missing headers: ${missing.join(", ")}`, confidence: "high" });
      }
      return findings;
    }
  },
  {
    id: "CONFIG_HTTP_URLS",
    title: "Insecure HTTP URL found in production-relevant code or config",
    category: "headers",
    severity: "medium",
    risk: "Plain HTTP URLs can leak traffic and break secure cookie/OAuth/webhook expectations.",
    recommendation: "Use HTTPS for production URLs, OAuth callbacks, payment webhooks, and API integrations.",
    standards: ["OWASP Top 10: A02 Cryptographic Failures"],
    detect(project) {
      return project.files
        .filter((file) => /http:\/\/(?!localhost|127\.0\.0\.1)/i.test(file.content))
        .map((file) => findingForFile({}, file, /http:\/\/(?!localhost|127\.0\.0\.1)/i));
    }
  }
];
