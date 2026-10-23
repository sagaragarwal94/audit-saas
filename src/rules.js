// auditsaas-ignore-file -- detector patterns, not application code
import path from "node:path";
import { loadRuleCatalog } from "./rule-catalog.js";
import { redactSecrets } from "./redact.js";
import { isLockfile } from "./scanner.js";

export const FOCUS_MAP = {
  security: [
    "auth", "authorization", "api", "database", "xss", "secrets", "headers", "logging",
    "cors", "ssrf", "jwt", "csrf", "dependencies", "uploads", "admin", "infra", "injection",
    "crypto", "oauth", "websocket"
  ],
  privacy: ["privacy", "secrets", "logging", "api"],
  payments: ["payments", "auth", "authorization", "api", "logging"],
  ai: ["ai", "api", "secrets", "privacy", "logging"],
  all: null
};

const RULE_CATALOG = loadRuleCatalog();

// A detector that throws (e.g. a catastrophic regex on an odd file) is
// reported in `errors` instead of aborting the whole scan.
export function runRules(project, context) {
  const categories = FOCUS_MAP[context.focus] || null;
  const errors = [];
  const findings = rules
    .filter((rule) => !categories || categories.includes(rule.category))
    .flatMap((rule) => {
      try {
        return rule.detect(project, context).map((finding) => normalizeFinding(rule, finding));
      } catch (error) {
        errors.push({ ruleId: rule.id, message: error instanceof Error ? error.message : String(error) });
        return [];
      }
    });
  return { findings, errors };
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

const SOURCE_FILE_PATTERN = /\.(t|j)sx?$|\.[mc][jt]s$|\.(vue|svelte|astro)$/;

// Minified bundles are build output, not reviewable source, and their huge
// single lines are where regex backtracking costs explode.
function sourceFiles(project) {
  return project.files.filter((file) => !file.classification.includes("environment") && !file.minified && SOURCE_FILE_PATTERN.test(file.relativePath));
}

function isTestFile(relativePath) {
  return /\.(test|spec)\.[jt]sx?$/i.test(relativePath) || /(^|[\\/])(__tests__|__mocks__)([\\/]|$)/i.test(relativePath);
}

function isDocFile(file) {
  return /\.(md|mdx)$/i.test(file.relativePath);
}

// Everything except prose docs: rules that scan config, HTML, or env files
// as well as code shouldn't fire on a README that merely describes a risk.
function nonDocFiles(project) {
  return project.files.filter((file) => !isDocFile(file));
}

// Source files that represent real application behavior: excludes docs/config
// (already excluded by sourceFiles) and test/spec files, so rules that assume
// a live login/payment/AI endpoint don't fire on assertions or fixtures.
function appCodeFiles(project) {
  return sourceFiles(project).filter((file) => !isTestFile(file.relativePath));
}

function filesWith(project, label) {
  return project.files.filter((file) => file.classification.includes(label));
}

function appFilesWith(project, label) {
  return appCodeFiles(project).filter((file) => file.classification.includes(label));
}

function matchIndex(content, pattern) {
  if (typeof pattern === "string") return content.indexOf(pattern);
  // search() ignores lastIndex, so global regexes are safe here too.
  return content.search(pattern);
}

function lineOf(content, pattern) {
  const idx = matchIndex(content, pattern);
  if (idx < 0) return undefined;
  return content.slice(0, idx).split("\n").length;
}

// The actual source line that matched, trimmed and secret-redacted, so
// reports show the user's code rather than the detector's regex. Lines from
// .env files name the variable but never echo its value, whichever rule hit.
function evidenceLine(file, line) {
  if (!line) return undefined;
  const text = file.content.split(/\r?\n/)[line - 1]?.trim() || "";
  if (!text) return undefined;
  if (file.classification.includes("environment")) {
    const key = text.split("=")[0].replace(/^export\s+/, "").trim();
    return key && key !== text ? `${key}=[REDACTED]` : "[REDACTED]";
  }
  const clipped = text.length > 160 ? `${text.slice(0, 157)}...` : text;
  return redactSecrets(clipped);
}

function findingForFile(ruleData, file, pattern, extra = {}) {
  const line = lineOf(file.content, pattern);
  return {
    ...ruleData,
    file: file.relativePath,
    line,
    evidence: evidenceLine(file, line) || `Matched by file path: ${file.relativePath}`,
    ...extra
  };
}

// getUser()/getSession() count only as bare calls or on an auth client;
// db.getUser(params.id) is a data lookup, not an auth check.
const AUTH_CALL = /\bauth\(|getServerSession|currentUser|getAuth|requireAuth|withAuth|(?<![\w.])(getSession|getUser)\(|auth\.api\.getSession|\.auth\.getUser\(|validateRequest|verifyToken|jwtVerify|supabase\.auth|getKindeServerSession|session\.user/i;
const LLM_CALL = /chat\.completions\.create|responses\.create|messages\.create|generateText|streamText|generateObject|streamObject|\.invoke\(|generateContent\(/;
const MANAGED_AUTH_PROVIDERS = ["clerk", "supabase", "firebase", "authjs", "nextauth", "better_auth"];
// Endpoints that are unauthenticated by design, recognized only as the first
// segment under api/ (or app/ for route handlers), so api/orders/[id]/status
// or api/admin/register still get checked.
const AUTH_ENDPOINT_PATH = /(^|\/)(api|app)\/(auth|login|log-in|signin|sign-in|signup|sign-up|register|logout|forgot-password|reset-password|webhooks?|health|status)(\/|\.|$)|\[\.\.\.nextauth\]/i;

// Server-side code: route handlers, Server Actions, and non-component
// modules. Keeps "password"/"login" in a React form from reading as a
// custom credential store.
function isServerSide(file) {
  return file.classification.includes("api_route") ||
    /^\s*["']use server["']/m.test(file.content) ||
    !/\.(tsx|jsx|vue|svelte|astro)$/.test(file.relativePath);
}

const CREDENTIAL_HANDLER = /export\s+(async\s+)?function\s+POST|export\s+const\s+POST\b|\b(router|app)\.post\(|\bauthorize\s*\(|^\s*["']use server["']|login|signin|signIn|credentials|forgot.?password|reset.?password/im;

function handlesCredentials(file) {
  return file.classification.includes("api_route") ||
    /^\s*["']use server["']/m.test(file.content) ||
    /\bauthorize\s*\(|CredentialsProvider|Credentials\(|router\.post\(|app\.post\(/.test(file.content);
}

function isPlaceholderSecret(value) {
  return /(.)\1{7,}/.test(value) || /your|example|placeholder|dummy|fake|redacted|changeme/i.test(value);
}

export const rules = [
  {
    id: "AUTH_PASSWORD_HASHING_WEAK",
    title: "Weak or missing password hashing evidence",
    category: "auth",
    severity: "critical",
    risk: "Weak password storage can lead to account takeover if the database is exposed.",
    recommendation: "Use Argon2id or bcrypt with a suitable cost factor, never plaintext or raw SHA/MD5 hashes.",
    standards: ["OWASP ASVS V2 Authentication", "OWASP Top 10: A07 Identification and Authentication Failures"],
    detect(project) {
      const authFiles = appFilesWith(project, "auth").filter(isServerSide);
      const findings = [];
      for (const file of authFiles) {
        if (/password/i.test(file.content) && /\b(md5|sha1|sha256|createHash)\b/i.test(file.content) && !/bcrypt|argon2/i.test(file.content)) {
          findings.push(findingForFile({}, file, /\b(md5|sha1|sha256|createHash)\b/i, { confidence: "high" }));
        }
      }
      const customPasswordSeen = authFiles.some((file) => /password/i.test(file.content));
      const strongHashSeen = authFiles.some((file) => /bcrypt|argon2/i.test(file.content));
      const managedAuth = project.providers.auth.some((provider) => MANAGED_AUTH_PROVIDERS.includes(provider));
      if (customPasswordSeen && !strongHashSeen && !managedAuth && findings.length === 0) {
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
      return appFilesWith(project, "auth")
        .filter(handlesCredentials)
        .filter((file) => /login|signin|signIn|credentials/i.test(file.relativePath + file.content))
        .filter((file) => !/rateLimit|limiter|upstash|slowDown|failedLogin|attempt/i.test(file.content))
        .map((file) => findingForFile({}, file, CREDENTIAL_HANDLER));
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
      const authFiles = appFilesWith(project, "auth");
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
      const cookieWrite = /cookies\(\)\)?\.set\(|\.cookies\.set\(|\bres\.cookie\(|setCookie\(|['"]Set-Cookie['"]|cookie\.serialize\(/i;
      return appCodeFiles(project)
        .filter((file) => cookieWrite.test(file.content))
        .filter((file) => !/httpOnly/i.test(file.content) || !/secure/i.test(file.content) || !/sameSite/i.test(file.content))
        .map((file) => findingForFile({}, file, cookieWrite));
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
      // Many Next.js apps enforce auth once in middleware; keep reporting
      // the route (middleware matchers are easy to get wrong) at low confidence.
      const middlewareAuth = filesWith(project, "middleware").some((file) => AUTH_CALL.test(file.content) || /clerkMiddleware|authMiddleware|withAuth/.test(file.content));
      return appFilesWith(project, "api_route")
        .filter((file) => !file.classification.includes("payment"))
        .filter((file) => !AUTH_ENDPOINT_PATH.test(file.relativePath))
        .filter((file) => /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\b|router\.(get|post|put|patch|delete)/i.test(file.content))
        .filter((file) => !AUTH_CALL.test(file.content) && !/\bsession\b/i.test(file.content))
        .map((file) => findingForFile({}, file, /export\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\b|router\./i, { confidence: middlewareAuth ? "low" : "medium" }));
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
      // Interpolation inside a template passed as a call *argument*, or string
      // concatenation onto SQL. Tagged templates (sql`...${id}`, $queryRaw`...`)
      // are parameterized by the driver and deliberately not matched.
      // Quantifiers are bounded so a long minified line can't trigger
      // catastrophic backtracking.
      const pattern = /\$(queryRawUnsafe|executeRawUnsafe)\(|\.(query|execute|raw|unsafe)\(\s*`[^`]{0,500}?\$\{|"[^"\n]{0,200}?\b(SELECT\s[^"\n]{1,200}?\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^"\n]{0,200}"\s*\+\s*[\w(]|'[^'\n]{0,200}?\b(SELECT\s[^'\n]{1,200}?\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^'\n]{0,200}'\s*\+\s*[\w(]/i;
      return appCodeFiles(project)
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "high" }));
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
      return appCodeFiles(project)
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
        .filter((file) => !file.gitIgnored)
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
        /sk-ant-[A-Za-z0-9_-]{20,}/,
        /gh[pousr]_[A-Za-z0-9]{36}/,
        /xox[baprs]-[A-Za-z0-9-]{10,}/,
        /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
        /OPENAI_API_KEY\s*=\s*['"][^'"]+['"]/,
        /STRIPE_SECRET_KEY\s*=\s*['"][^'"]+['"]/
      ];
      return nonDocFiles(project)
        .filter((file) => !file.classification.includes("environment"))
        .filter((file) => !isLockfile(file.relativePath))
        .flatMap((file) =>
          secretPatterns.flatMap((pattern) => {
            const real = [...file.content.matchAll(new RegExp(pattern.source, `${pattern.flags}g`))]
              .map((match) => match[0])
              .find((value) => !isPlaceholderSecret(value));
            return real ? [findingForFile({}, file, real, { evidence: "Secret-like value redacted", confidence: "high" })] : [];
          })
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
      // Browser-exposed env prefixes across Next.js, Vite, Expo, CRA, Nuxt,
      // and SvelteKit/Astro. Keys designed to be public (Stripe publishable,
      // Supabase anon, Firebase web config, analytics/DSNs) are skipped.
      const exposed = /\b(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|OPENAI|ANTHROPIC|STRIPE_SECRET|API_KEY|TOKEN)[A-Z0-9_]*\b/g;
      const intendedPublic = /PUBLISHABLE|ANON|FIREBASE|MAPS|POSTHOG|SENTRY|MAPBOX|ALGOLIA_SEARCH|TURNSTILE|RECAPTCHA|SITE_KEY|MEASUREMENT/;
      // ...unless the name itself says it's a secret (RECAPTCHA_SECRET_KEY,
      // SENTRY_AUTH_TOKEN, FIREBASE_ADMIN_PRIVATE_KEY, POSTHOG_PERSONAL_API_KEY).
      const secretShaped = /SECRET|PRIVATE|SERVICE_ROLE|AUTH_TOKEN|PERSONAL|ADMIN/;
      const isExposedSecret = (name) => secretShaped.test(name) || !intendedPublic.test(name);
      return nonDocFiles(project).filter((file) => !isTestFile(file.relativePath)).flatMap((file) => {
        const name = [...file.content.matchAll(exposed)].map((match) => match[0]).find(isExposedSecret);
        return name ? [findingForFile({}, file, name, { confidence: "high" })] : [];
      });
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
      return appFilesWith(project, "payment")
        .filter((file) => file.classification.includes("api_route"))
        .filter((file) => /webhook/i.test(file.relativePath + file.content) && /stripe/i.test(file.content))
        .filter((file) => !/webhooks\.constructEvent|constructEventAsync/i.test(file.content))
        .map((file) => findingForFile({}, file, /request\.json\(|req\.body|export\s+async\s+function\s+POST|webhook/i, { confidence: "high" }));
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
      return appFilesWith(project, "payment")
        .filter((file) => file.classification.includes("api_route"))
        .filter((file) => /webhook/i.test(file.relativePath + file.content))
        .filter((file) => !/event\.id|idempot|processed/i.test(file.content))
        .map((file) => findingForFile({}, file, /event\.type|request\.json\(|req\.body|export\s+async\s+function\s+POST|webhook/i));
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
      return appCodeFiles(project)
        .filter((file) => file.classification.includes("ai"))
        .filter((file) => LLM_CALL.test(file.content))
        .filter((file) => !/rateLimit|quota|maxTokens|max_tokens|maxOutputTokens|max_output_tokens|usage|billing|plan|auth\(|session|getAuth/i.test(file.content))
        .map((file) => findingForFile({}, file, LLM_CALL, { confidence: "medium" }));
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
      return appCodeFiles(project)
        .filter((file) => file.classification.includes("ai"))
        .filter((file) => LLM_CALL.test(file.content))
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
    id: "PRIVACY_NO_DELETION_ENDPOINT",
    title: "User data is collected but no account/data deletion path was found",
    category: "privacy",
    severity: "medium",
    risk: "GDPR, CCPA, and similar regulations require a way for users to request deletion of their personal data; without one, the app cannot honor erasure requests.",
    recommendation: "Add an account deletion flow (self-service or support-triggered) that removes or anonymizes personal data across all data stores.",
    standards: ["GDPR Article 17 Right to Erasure", "CCPA Right to Delete"],
    detect(project, context) {
      if (!context.dataInventory || context.dataInventory.length === 0) return [];
      const hasDeletion = nonDocFiles(project).some((file) => /delete.?account|deleteUser|account.?deletion|gdpr.?delet|right.?to.?eras/i.test(file.relativePath + file.content));
      return hasDeletion ? [] : [{ confidence: "low" }];
    }
  },
  {
    id: "PRIVACY_THIRD_PARTY_TRACKING_NO_CONSENT",
    title: "Analytics or tracking script found without a visible consent mechanism",
    category: "privacy",
    severity: "medium",
    risk: "Loading analytics, ads, or session-replay scripts before obtaining consent can violate GDPR/ePrivacy and similar cookie-consent requirements.",
    recommendation: "Gate non-essential tracking scripts behind a cookie consent banner and only load them after opt-in where required.",
    standards: ["GDPR", "ePrivacy Directive"],
    detect(project) {
      const hasTracking = nonDocFiles(project).some((file) => /google-analytics|gtag\(|posthog\.init|mixpanel\.init|segment\.io|hotjar|fullstory|clarity\.ms/i.test(file.content));
      if (!hasTracking) return [];
      const hasConsent = nonDocFiles(project).some((file) => /cookie.?consent|consent.?banner|cookieyes|onetrust|cookiebot/i.test(file.relativePath + file.content));
      return hasConsent ? [] : [{ confidence: "low" }];
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
      // The sensitive value has to appear in the log call itself, not just
      // somewhere in the same file.
      const pattern = /(console\.(log|error|warn|info|debug)|logger\.(info|error|warn|debug))\([^\n]*\b(password|passwd|token|secret|authorization|cookie|req\.body|body|payload|prompt|event)\b/i;
      return appCodeFiles(project)
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
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
      const hasMonitoring = project.providers.observability.length > 0 || nonDocFiles(project).some((file) => /Sentry|Datadog|Axiom|OpenTelemetry|Better Stack|Logtail|PostHog/i.test(file.content));
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
      // An unreachable URL says nothing about its headers; the report shows
      // the connection error instead of a misleading "everything missing".
      if (!context.runtime?.reachable) return [];
      const missing = context.runtime.missingHeaders || [];
      const findings = [];
      if (!context.runtime.https) {
        findings.push({ title: "Production URL is not using HTTPS", severity: "critical", evidence: context.runtime.finalUrl || context.runtime.url, confidence: "high" });
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
      // XML namespace URIs (SVG xmlns, schemas) are identifiers, not network
      // calls; local/dev hosts and documentation domains are also skipped.
      const pattern = /http:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|(?:www\.)?w3\.org|schemas\.|json-schema\.org|purl\.org|ns\.adobe\.com|(?:www\.)?example\.(?:com|org|net))\b)[^\s"'`<>)\\]+/i;
      return nonDocFiles(project)
        .filter((file) => !isTestFile(file.relativePath))
        .filter((file) => !isLockfile(file.relativePath))
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern));
    }
  },
  {
    id: "CORS_WILDCARD_WITH_CREDENTIALS",
    title: "CORS allows any origin together with credentials",
    category: "cors",
    severity: "critical",
    risk: "A wildcard Access-Control-Allow-Origin combined with credentials lets any site read authenticated responses on behalf of a logged-in user.",
    recommendation: "Use an explicit allowlist of trusted origins instead of `*` whenever credentials are allowed.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*/i.test(file.content))
        .filter((file) => /Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?true/i.test(file.content) || /credentials\s*:\s*true/i.test(file.content))
        .map((file) => findingForFile({}, file, /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*/i, { confidence: "high" }));
    }
  },
  {
    id: "CORS_ORIGIN_REFLECTED",
    title: "CORS origin appears to be reflected without an allowlist",
    category: "cors",
    severity: "medium",
    risk: "Reflecting the request Origin header back verbatim effectively disables CORS protection for every origin.",
    recommendation: "Validate the incoming origin against an explicit allowlist before echoing it back in Access-Control-Allow-Origin.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /Access-Control-Allow-Origin['"]?\s*[:,]\s*(req(uest)?\.headers\.(get\()?['"]?origin|origin\))/i.test(file.content))
        .filter((file) => !/allowlist|allowedOrigins|whitelist/i.test(file.content))
        .map((file) => findingForFile({}, file, /Access-Control-Allow-Origin['"]?\s*[:,]\s*(req(uest)?\.headers\.(get\()?['"]?origin|origin\))/i, { confidence: "medium" }));
    }
  },
  {
    id: "SSRF_UNVALIDATED_URL_FETCH",
    title: "Server-side request built from user-controlled input",
    category: "ssrf",
    severity: "high",
    risk: "Fetching a URL taken directly from request input lets an attacker make the server call internal services, cloud metadata endpoints, or arbitrary hosts.",
    recommendation: "Validate outbound URLs against an allowlist of hosts/protocols, block private/link-local IP ranges, and avoid following redirects blindly.",
    standards: ["OWASP Top 10: A10 Server-Side Request Forgery"],
    detect(project) {
      return filesWith(project, "api_route")
        .filter((file) => /(fetch|axios\.(get|post)|got\(|request\()\(\s*[^)'"`]*\b(req|request|params|body|searchParams|query)\b/i.test(file.content))
        .filter((file) => !/allowlist|allowedHosts|new URL\(.*\)\.hostname\s*===|isPrivateIp|blockPrivate/i.test(file.content))
        .map((file) => findingForFile({}, file, /(fetch|axios\.(get|post)|got\(|request\()\(/i, { confidence: "medium" }));
    }
  },
  {
    id: "JWT_ALGORITHM_NOT_ENFORCED",
    title: "JWT verification does not pin an algorithm",
    category: "jwt",
    severity: "critical",
    risk: "Verifying tokens without pinning the expected algorithm allows algorithm-confusion attacks, including forged alg:none tokens.",
    recommendation: "Always pass an explicit algorithms allowlist to jwt.verify and reject tokens with alg: none.",
    codeExample: "jwt.verify(token, secret, { algorithms: [\"HS256\"] });",
    standards: ["OWASP ASVS V3 Session Management", "OWASP Top 10: A02 Cryptographic Failures"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /jwt\.verify\(/i.test(file.content))
        .filter((file) => !/algorithms\s*:/i.test(file.content))
        .map((file) => findingForFile({}, file, /jwt\.verify\(/i, { confidence: "high" }));
    }
  },
  {
    id: "JWT_SECRET_WEAK_OR_HARDCODED",
    title: "JWT signing secret may be hardcoded or weak",
    category: "jwt",
    severity: "critical",
    risk: "A hardcoded or short JWT secret can be brute-forced or leaked through source control, letting attackers forge valid tokens.",
    recommendation: "Load the signing secret from environment variables, use at least 32 bytes of entropy, and rotate it if it was ever hardcoded.",
    standards: ["OWASP ASVS V3 Session Management"],
    detect(project) {
      const pattern = /jwt\.(sign|verify)\([^)]*,\s*['"][^'"]{1,64}['"]/i;
      return appCodeFiles(project)
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { evidence: "Secret-like literal redacted", confidence: "medium" }));
    }
  },
  {
    id: "CSRF_PROTECTION_MISSING",
    title: "Cookie-based session app may be missing CSRF protection",
    category: "csrf",
    severity: "medium",
    risk: "State-changing requests authenticated only by cookies can be triggered from another origin without a CSRF token or same-site defense.",
    recommendation: "Use SameSite=Lax/Strict cookies together with a CSRF token, or a framework's built-in CSRF middleware, for state-changing routes.",
    standards: ["OWASP Top 10: A01 Broken Access Control", "OWASP ASVS V4 Access Control"],
    detect(project) {
      const usesCookieSession = appCodeFiles(project).some((file) => /express-session|cookie-session|session\(\s*{/i.test(file.content));
      if (!usesCookieSession) return [];
      const hasCsrf = nonDocFiles(project).some((file) => /csurf|csrf|sameSite\s*:\s*['"]strict['"]/i.test(file.content));
      return hasCsrf ? [] : [{ confidence: "low" }];
    }
  },
  {
    id: "DEPENDENCY_NO_LOCKFILE",
    title: "No dependency lockfile found",
    category: "dependencies",
    severity: "medium",
    risk: "Without a lockfile, dependency versions can drift between installs, pulling in unreviewed or vulnerable transitive updates.",
    recommendation: "Commit package-lock.json, pnpm-lock.yaml, or yarn.lock and install with a frozen-lockfile flag in CI.",
    standards: ["OWASP Top 10: A06 Vulnerable and Outdated Components"],
    detect(project) {
      if (!project.packageJson) return [];
      const hasLockfile = project.allPaths.some((file) => !file.includes("/") && isLockfile(file));
      return hasLockfile ? [] : [{ confidence: "medium" }];
    }
  },
  {
    id: "DEPENDENCY_WILDCARD_VERSION",
    title: "Dependency pinned to a wildcard or latest version",
    category: "dependencies",
    severity: "medium",
    risk: "Wildcard or latest version ranges can silently pull in breaking or malicious updates, including supply-chain attacks published under a trusted package name.",
    recommendation: "Pin dependencies to specific or caret-ranged versions and review updates deliberately.",
    standards: ["OWASP Top 10: A06 Vulnerable and Outdated Components"],
    detect(project) {
      const deps = { ...(project.packageJson?.dependencies || {}), ...(project.packageJson?.devDependencies || {}) };
      const wildcardDeps = Object.entries(deps).filter(([, version]) => version === "*" || version === "latest");
      return wildcardDeps.length > 0
        ? [{ evidence: wildcardDeps.map(([name]) => name).join(", "), confidence: "high" }]
        : [];
    }
  },
  {
    id: "DEPENDENCY_KNOWN_RISKY_PACKAGE",
    title: "Deprecated or historically compromised package detected",
    category: "dependencies",
    severity: "high",
    risk: "Some packages are deprecated, unmaintained, or have a documented history of supply-chain compromise; continuing to depend on them carries elevated risk.",
    recommendation: "Replace deprecated/unmaintained packages with actively maintained alternatives and run npm audit regularly.",
    standards: ["OWASP Top 10: A06 Vulnerable and Outdated Components"],
    detect(project) {
      const riskyPackages = ["request", "node-sass", "left-pad", "event-stream", "colors", "faker", "node-uuid"];
      const deps = { ...(project.packageJson?.dependencies || {}), ...(project.packageJson?.devDependencies || {}) };
      const found = riskyPackages.filter((name) => deps[name]);
      return found.length > 0 ? [{ evidence: found.join(", "), confidence: "high" }] : [];
    }
  },
  {
    id: "UPLOAD_UNRESTRICTED_FILE_TYPE",
    title: "File upload endpoint may not restrict file type or size",
    category: "uploads",
    severity: "high",
    risk: "Accepting any file type or size lets attackers upload executable scripts, oversized payloads, or files that trigger downstream parser vulnerabilities.",
    recommendation: "Validate MIME type and extension against an allowlist, enforce a maximum file size, and store uploads outside the web root or in object storage with restricted execution.",
    standards: ["OWASP Top 10: A04 Insecure Design", "OWASP ASVS V12 File and Resources"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /multer\(|formidable\(|busboy|new\s+Formidable/i.test(file.content))
        .filter((file) => !/fileFilter|mimetype|allowedTypes|maxFileSize|limits\s*:/i.test(file.content))
        .map((file) => findingForFile({}, file, /multer\(|formidable\(|busboy|new\s+Formidable/i, { confidence: "medium" }));
    }
  },
  {
    id: "UPLOAD_PATH_TRAVERSAL",
    title: "Uploaded file may be written using a user-controlled path",
    category: "uploads",
    severity: "critical",
    risk: "Writing a file using an attacker-supplied filename or path can overwrite arbitrary files via path traversal.",
    recommendation: "Generate a server-side random filename, strip path separators, and write only inside a fixed, dedicated upload directory.",
    standards: ["OWASP Top 10: A01 Broken Access Control", "OWASP ASVS V12 File and Resources"],
    detect(project) {
      const pattern = /(writeFile|createWriteStream)\([^)]*\.(originalname|originalFilename|filename)\b/i;
      return appCodeFiles(project)
        .filter((file) => pattern.test(file.content))
        .filter((file) => !/path\.basename|sanitize-filename|randomUUID|crypto\.random/i.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  },
  {
    id: "ADMIN_ROUTE_NO_ROLE_CHECK",
    title: "Admin route may be missing a role or permission check",
    category: "admin",
    severity: "critical",
    risk: "An admin-labeled route that only checks for a valid session (not an admin role) can be reached by any authenticated user.",
    recommendation: "Require an explicit role, permission, or claim check in every admin route, in addition to authentication.",
    standards: ["OWASP Top 10: A01 Broken Access Control"],
    detect(project) {
      return filesWith(project, "api_route")
        .filter((file) => /\/admin\//i.test(file.relativePath))
        .filter((file) => !/role\s*===|isAdmin|permission|hasRole|requireRole|claims\.role/i.test(file.content))
        .map((file) => findingForFile({}, file, /\/admin\//i, { confidence: "medium" }));
    }
  },
  {
    id: "DEBUG_ENDPOINT_EXPOSED",
    title: "Debug, internal, or test endpoint may be reachable in production",
    category: "admin",
    severity: "high",
    risk: "Debug/internal endpoints often skip auth and can expose environment details, internal state, or admin actions if left reachable after launch.",
    recommendation: "Remove debug/test routes before shipping, or gate them behind authentication and a non-production environment check.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return filesWith(project, "api_route")
        .filter((file) => /\/(debug|internal|__test|test-only)\//i.test(file.relativePath))
        .filter((file) => !AUTH_CALL.test(file.content) && !/process\.env\.NODE_ENV\s*!==\s*['"]production['"]/i.test(file.content))
        .map((file) => findingForFile({}, file, /\/(debug|internal|__test|test-only)\//i, { confidence: "medium" }));
    }
  },
  {
    id: "INFRA_DOCKER_ROOT_USER",
    title: "Docker image may run as root",
    category: "infra",
    severity: "medium",
    risk: "Containers running as root increase the blast radius of a container escape or dependency compromise.",
    recommendation: "Add a non-root USER directive to the Dockerfile and drop unnecessary capabilities.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return project.files
        .filter((file) => /Dockerfile/i.test(path.basename(file.relativePath)))
        .filter((file) => !/^\s*USER\s+\S+/im.test(file.content))
        .map((file) => findingForFile({}, file, /FROM/i, { confidence: "medium" }));
    }
  },
  {
    id: "INFRA_DB_PORT_EXPOSED",
    title: "Database or cache port may be exposed to the host network",
    category: "infra",
    severity: "high",
    risk: "Publishing database/cache ports beyond the internal Docker network can expose data stores directly to the internet on misconfigured hosts.",
    recommendation: "Remove public port mappings for data stores in production compose files and restrict access to the internal network or a VPN/bastion.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      const pattern = /["']?(0\.0\.0\.0:)?\d{1,5}:(5432|3306|27017|6379|9200|5984)["']?/;
      return project.files
        .filter((file) => /docker-compose|(^|\/)compose\.ya?ml$/i.test(file.relativePath))
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  },
  {
    id: "SUPABASE_RLS_NOT_CONFIRMED",
    title: "Supabase is used but Row Level Security policies were not found",
    category: "database",
    severity: "medium",
    risk: "Without RLS policies, any authenticated (or anonymous, with the anon key) client can read or write every row in a Supabase table directly from the browser.",
    recommendation: "Enable Row Level Security on every table and add explicit policies scoping access to the authenticated user or tenant.",
    standards: ["OWASP Top 10: A01 Broken Access Control"],
    detect(project) {
      if (!project.providers.database.includes("supabase")) return [];
      const hasRls = nonDocFiles(project).some((file) => /row level security|enable row level security|create policy/i.test(file.content));
      return hasRls ? [] : [{ confidence: "low" }];
    }
  },
  {
    id: "CI_SECRETS_HARDCODED_IN_WORKFLOW",
    title: "CI/CD workflow file may contain a hardcoded secret",
    category: "secrets",
    severity: "critical",
    risk: "Secrets committed inside a CI workflow file are visible to anyone with repository read access and remain in git history even after removal.",
    recommendation: "Reference secrets only through the CI provider's encrypted secret store and rotate any value that was ever hardcoded.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      const pattern = /(sk_live_|sk-proj-|ghp_|xox[baprs]-)[A-Za-z0-9_-]{10,}/;
      return project.files
        .filter((file) => /\.github[\\/]workflows[\\/]/.test(file.relativePath))
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { evidence: "Secret-like value redacted", confidence: "high" }));
    }
  },
  {
    id: "CODE_EXECUTION_EVAL_USER_INPUT",
    title: "Dynamic code execution near user-controlled input",
    category: "injection",
    severity: "critical",
    risk: "eval, new Function, or child_process.exec used near request input can allow full remote code execution if any user-controlled value reaches it.",
    recommendation: "Remove dynamic code execution entirely, or if unavoidable, use a strict sandbox and never pass unsanitized user input into it.",
    standards: ["OWASP Top 10: A03 Injection"],
    detect(project) {
      return filesWith(project, "api_route")
        .filter((file) => /\beval\(|new Function\(|child_process\.exec\(|exec\(\s*`/i.test(file.content))
        .filter((file) => /req\.|request\.|params\.|body\b/i.test(file.content))
        .map((file) => findingForFile({}, file, /\beval\(|new Function\(|child_process\.exec\(/i, { confidence: "medium" }));
    }
  },
  {
    id: "PASSWORD_RESET_RATE_LIMIT_MISSING",
    title: "Password reset endpoint may be missing rate limiting",
    category: "auth",
    severity: "high",
    risk: "An unthrottled password-reset or forgot-password endpoint allows attackers to enumerate valid accounts or flood users with reset emails.",
    recommendation: "Apply per-IP and per-account rate limits to password reset requests, same as login.",
    standards: ["OWASP ASVS V2 Authentication"],
    detect(project) {
      return appFilesWith(project, "auth")
        .filter(handlesCredentials)
        .filter((file) => /forgot.?password|reset.?password|password.?reset/i.test(file.relativePath + file.content))
        .filter((file) => !/rateLimit|limiter|upstash|slowDown|attempt/i.test(file.content))
        .map((file) => findingForFile({}, file, CREDENTIAL_HANDLER, { confidence: "medium" }));
    }
  },
  {
    id: "JWT_NO_EXPIRATION",
    title: "JWT is signed without an expiration",
    category: "jwt",
    severity: "high",
    risk: "Tokens signed without expiresIn remain valid forever, so a leaked token gives permanent access instead of a bounded window.",
    recommendation: "Always set expiresIn when signing a JWT, and pair it with refresh-token rotation if long-lived sessions are needed.",
    codeExample: "jwt.sign(payload, secret, { expiresIn: \"15m\" });",
    standards: ["OWASP ASVS V3 Session Management"],
    detect(project) {
      const pattern = /jwt\.sign\([^)]*\)/s;
      return appCodeFiles(project)
        .filter((file) => /jwt\.sign\(/i.test(file.content))
        .filter((file) => !/expiresIn/i.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  },
  {
    id: "WEAK_RANDOM_TOKEN_GENERATION",
    title: "Security token generated with a non-cryptographic random source",
    category: "crypto",
    severity: "high",
    risk: "Math.random() is not cryptographically secure and its output can be predicted, letting attackers guess session tokens, password-reset tokens, or API keys generated from it.",
    recommendation: "Generate tokens with crypto.randomUUID() or crypto.randomBytes() instead of Math.random().",
    codeExample: "const token = crypto.randomBytes(32).toString(\"hex\");",
    standards: ["OWASP Top 10: A02 Cryptographic Failures"],
    detect(project) {
      const pattern = /(token|secret|apiKey|sessionId|resetCode|otp)\s*[:=][^;]*Math\.random\(\)/i;
      return appCodeFiles(project)
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  },
  {
    id: "OAUTH_STATE_PARAM_MISSING",
    title: "OAuth authorization request may be missing a state parameter",
    category: "oauth",
    severity: "medium",
    risk: "Without a state parameter, an OAuth authorization flow is vulnerable to CSRF, allowing an attacker to bind their own account to a victim's session.",
    recommendation: "Generate a random state value per request, store it server-side or in a signed cookie, and verify it on callback before exchanging the authorization code.",
    standards: ["OWASP Top 10: A01 Broken Access Control"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /\/authorize\?|oauth2?\/authorize|response_type=code/i.test(file.content))
        .filter((file) => /client_id/i.test(file.content))
        .filter((file) => !/[?&]state=|state:\s*[a-zA-Z]/i.test(file.content))
        .map((file) => findingForFile({}, file, /\/authorize\?|oauth2?\/authorize|response_type=code/i, { confidence: "low" }));
    }
  },
  {
    id: "WEBSOCKET_NO_AUTH",
    title: "WebSocket connection handler may be missing authentication",
    category: "websocket",
    severity: "high",
    risk: "An unauthenticated WebSocket connection can let any client subscribe to real-time data or trigger actions meant for authenticated users only.",
    recommendation: "Verify a session or token on connection (and on reconnection) before accepting subscriptions or forwarding messages.",
    standards: ["OWASP Top 10: A01 Broken Access Control"],
    detect(project) {
      const pattern = /io\.on\(\s*['"]connection['"]|new WebSocket\.Server|wss\.on\(\s*['"]connection['"]/i;
      return appCodeFiles(project)
        .filter((file) => pattern.test(file.content))
        .filter((file) => !/auth|token|verify|jwt|session/i.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  },
  {
    id: "MISSING_SRI_EXTERNAL_SCRIPT",
    title: "External script loaded without Subresource Integrity",
    category: "headers",
    severity: "medium",
    risk: "A script tag pointing at a third-party CDN without an integrity attribute will execute whatever that CDN serves, including a compromised or tampered file, with no verification.",
    recommendation: "Add an integrity attribute (SRI hash) and crossorigin=\"anonymous\" to third-party script tags, or self-host the dependency.",
    standards: ["OWASP Top 10: A08 Software and Data Integrity Failures"],
    detect(project) {
      const pattern = /<script[^>]+src=["']https?:\/\/[^"']+["'][^>]*>/gi;
      // These vendors serve evergreen scripts and document that SRI will
      // break them; flagging them would only teach users to ignore the rule.
      const evergreen = /js\.stripe\.com|googletagmanager\.com|google-analytics\.com|google\.com\/recaptcha|challenges\.cloudflare\.com|js\.hcaptcha\.com|maps\.googleapis\.com|accounts\.google\.com\/gsi|apis\.google\.com/i;
      return project.files
        .filter((file) => file.ext === ".html" || file.ext === ".htm")
        .flatMap((file) => {
          const tag = (file.content.match(pattern) || []).find((match) => !/integrity=/i.test(match) && !evergreen.test(match));
          return tag ? [findingForFile({}, file, tag, { confidence: "medium" })] : [];
        });
    }
  },
  {
    id: "SWAGGER_UI_EXPOSED_PRODUCTION",
    title: "API documentation UI may be exposed without an environment guard",
    category: "admin",
    severity: "medium",
    risk: "Swagger/OpenAPI UIs left reachable in production hand attackers a full map of your API surface, including internal or undocumented-elsewhere endpoints.",
    recommendation: "Mount API docs routes only when NODE_ENV !== \"production\", or put them behind authentication.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /swagger-ui-express|swaggerUi\.serve/i.test(file.content))
        .filter((file) => !/NODE_ENV\s*!==?\s*['"]production['"]|isProduction/i.test(file.content))
        .map((file) => findingForFile({}, file, /swagger-ui-express|swaggerUi\.serve/i, { confidence: "medium" }));
    }
  },
  {
    id: "INTERNAL_ENDPOINT_INFO_LEAK",
    title: "Health/status endpoint may leak internal environment details",
    category: "admin",
    severity: "medium",
    risk: "A /health or /status route that echoes back environment variables, config, or dependency versions gives attackers reconnaissance information for free.",
    recommendation: "Return a minimal { status: \"ok\" } from health checks; keep detailed diagnostics behind authentication.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return filesWith(project, "api_route")
        .filter((file) => /\/(health|status)\b/i.test(file.relativePath))
        .filter((file) => /process\.env|package\.json|versions?\b/i.test(file.content))
        .map((file) => findingForFile({}, file, /\/(health|status)\b/i, { confidence: "low" }));
    }
  },
  {
    id: "POSTINSTALL_SCRIPT_RISK",
    title: "package.json runs a script automatically on install",
    category: "dependencies",
    severity: "medium",
    risk: "postinstall/preinstall scripts execute arbitrary code the moment npm install runs, and are a common vector for supply-chain attacks in compromised packages.",
    recommendation: "Avoid install-time scripts where possible; if one is required, keep it minimal, reviewed, and version-controlled.",
    standards: ["OWASP Top 10: A06 Vulnerable and Outdated Components"],
    detect(project) {
      const scripts = project.packageJson?.scripts || {};
      const found = ["postinstall", "preinstall"].filter((name) => scripts[name]);
      return found.length > 0 ? [{ evidence: found.map((name) => `${name}: ${scripts[name]}`).join("; "), confidence: "high" }] : [];
    }
  },
  {
    id: "HARDCODED_CLOUD_CREDENTIAL",
    title: "Cloud provider credential pattern found in source",
    category: "secrets",
    severity: "critical",
    risk: "An AWS access key (or similar cloud credential) committed to source code grants direct access to cloud infrastructure and is routinely scraped by automated bots within minutes of a public push.",
    recommendation: "Remove the credential, rotate it immediately in the cloud provider console, and use environment variables or a secrets manager instead.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      const pattern = /\b(?:AKIA|ASIA)(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16}\b/;
      return project.files
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { evidence: "Cloud credential redacted", confidence: "high" }));
    }
  },
  {
    id: "EXPOSED_BACKUP_FILE",
    title: "Backup or dump file present in the project",
    category: "secrets",
    severity: "high",
    risk: "Backup or ad-hoc dump files often contain full database contents or old credentials, and are easy to overlook when reviewing what's committed.",
    recommendation: "Remove backup/dump files from version control and store backups outside the repository with proper access controls.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return project.allPaths
        .filter((file) => /\.(bak|backup|old|dump)$/i.test(file) || /(^|\/)[^/]*(dump|backup)[^/]*\.sql(\.gz)?$/i.test(file) || /\.sql\.gz$/i.test(file))
        .filter((file) => !/migrations?\//i.test(file))
        .filter((file) => !project.isGitIgnored?.(file))
        .map((file) => ({ file, evidence: `Backup/dump file: ${file}`, confidence: "medium" }));
    }
  },
  {
    id: "TERRAFORM_PUBLIC_S3_BUCKET",
    title: "Terraform config may create a publicly readable storage bucket",
    category: "infra",
    severity: "critical",
    risk: "An S3 bucket with a public-read ACL or disabled public-access-block settings can expose every object in it to the internet, including user uploads or backups.",
    recommendation: "Keep buckets private by default and use signed URLs or a CDN with access controls for anything that needs to be public.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      const pattern = /acl\s*=\s*["'](public-read|public-read-write)["']|block_public_acls\s*=\s*false/i;
      return project.files
        .filter((file) => file.ext === ".tf")
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "high" }));
    }
  },
  {
    id: "TERRAFORM_OPEN_SECURITY_GROUP",
    title: "Terraform config may open a sensitive port to the entire internet",
    category: "infra",
    severity: "high",
    risk: "A security group ingress rule with 0.0.0.0/0 on an administrative port (SSH 22, RDP 3389) or a database port exposes that service to internet-wide scanning and brute force.",
    recommendation: "Restrict ingress CIDR blocks to known IP ranges or a VPN/bastion, never 0.0.0.0/0 for administrative or database ports.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      return project.files
        .filter((file) => file.ext === ".tf")
        .filter((file) => /0\.0\.0\.0\/0/.test(file.content))
        .filter((file) => /\b(22|3389|5432|3306|27017|6379)\b/.test(file.content))
        .map((file) => findingForFile({}, file, /0\.0\.0\.0\/0/, { confidence: "medium" }));
    }
  },
  {
    id: "CSP_UNSAFE_INLINE",
    title: "Content-Security-Policy allows unsafe-inline or unsafe-eval",
    category: "headers",
    severity: "medium",
    risk: "unsafe-inline/unsafe-eval in a CSP largely defeats its purpose as an XSS mitigation, since it allows the exact inline script execution CSP is meant to block.",
    recommendation: "Use nonces or hashes for required inline scripts instead of unsafe-inline, and avoid unsafe-eval entirely.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      const pattern = /Content-Security-Policy[^;'"]*['"]?[^;]*unsafe-(inline|eval)/i;
      return nonDocFiles(project)
        .filter((file) => !isTestFile(file.relativePath))
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "high" }));
    }
  },
  {
    id: "SOURCE_MAP_ENABLED_PRODUCTION",
    title: "Production build may ship source maps",
    category: "headers",
    severity: "medium",
    risk: "Public source maps let anyone reconstruct your original source code, including comments, variable names, and any logic you intended to keep private.",
    recommendation: "Disable source maps for production builds, or upload them privately to your error-tracking provider instead of serving them publicly.",
    standards: ["OWASP Top 10: A05 Security Misconfiguration"],
    detect(project) {
      const pattern = /productionBrowserSourceMaps\s*:\s*true|devtool\s*:\s*['"]source-map['"]/;
      return project.files
        .filter((file) => /next\.config|webpack\.config/i.test(file.relativePath))
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "high" }));
    }
  },
  {
    id: "STRIPE_CLIENT_TRUSTED_AMOUNT",
    title: "Checkout may trust a price or amount value sent from the client",
    category: "payments",
    severity: "critical",
    risk: "If a checkout or payment-intent handler reads the amount or price directly from the request body, a user can tamper with it client-side and pay any amount they choose.",
    recommendation: "Always look up the price/amount server-side from a fixed price ID or your own product catalog — never trust a client-submitted amount.",
    standards: ["OWASP API Security: Unrestricted Access to Sensitive Business Flows"],
    detect(project) {
      const pattern = /(amount|unit_amount|price)\s*:\s*(req(uest)?\.body|body)\.(amount|price|total)/i;
      return filesWith(project, "payment")
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  },
  {
    id: "RESPONSE_MISSING_PAGINATION_LIMIT",
    title: "Query may return an unbounded number of records",
    category: "database",
    severity: "medium",
    risk: "A findMany/list query with no take/limit can return an entire table to a single request, enabling resource-exhaustion and over-fetching more data than the caller should see.",
    recommendation: "Always cap list queries with a take/limit and offer pagination for anything that can grow unbounded.",
    standards: ["OWASP API Security: Unrestricted Resource Consumption"],
    detect(project) {
      const pattern = /\.findMany\(\s*\)|\.findMany\(\s*\{\s*\}\s*\)|\.findMany\(\{\s*where\s*:[^}]*\}\s*\)/s;
      return filesWith(project, "api_route")
        .filter((file) => /\.findMany\(/i.test(file.content))
        .filter((file) => !/take\s*:|limit\s*:|skip\s*:/i.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "low" }));
    }
  },
  {
    id: "GRAPHQL_NO_DEPTH_LIMIT",
    title: "GraphQL server may be missing query depth/cost limiting",
    category: "api",
    severity: "medium",
    risk: "Without a depth or cost limit, a single deeply nested or highly repetitive GraphQL query can exhaust server resources — a denial-of-service vector unique to GraphQL's flexible query shape.",
    recommendation: "Add a depth-limiting or cost-analysis library (e.g. graphql-depth-limit, graphql-cost-analysis) to the server's validation rules.",
    standards: ["OWASP API Security: Unrestricted Resource Consumption"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /ApolloServer|graphqlHTTP|createYoga/i.test(file.content))
        .filter((file) => !/depthLimit|graphql-depth-limit|costAnalysis|graphql-cost-analysis/i.test(file.content))
        .map((file) => findingForFile({}, file, /ApolloServer|graphqlHTTP|createYoga/i, { confidence: "low" }));
    }
  },
  {
    id: "NEXTJS_SERVER_ACTION_NO_AUTH",
    title: "Next.js Server Action may be missing an authentication check",
    category: "api",
    severity: "critical",
    risk: "A \"use server\" action is a public network endpoint even though it's called like a function — without an explicit auth check, anyone who discovers its action ID can invoke it directly, bypassing any UI-level gating.",
    recommendation: "Verify the session/user at the top of every Server Action that reads or writes sensitive data, exactly as you would in an API route.",
    standards: ["OWASP Top 10: A01 Broken Access Control"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /^\s*["']use server["'];?\s*$/m.test(file.content))
        .filter((file) => /\bexport\s+(async\s+)?function\b/.test(file.content))
        .filter((file) => !AUTH_CALL.test(file.content))
        .map((file) => findingForFile({}, file, /["']use server["']/, { confidence: "medium" }));
    }
  },
  {
    id: "OPEN_REDIRECT_UNVALIDATED",
    title: "Redirect target may be built from unvalidated user input",
    category: "api",
    severity: "medium",
    risk: "Redirecting to a URL taken directly from a query parameter can be used for phishing or to bypass OAuth redirect_uri allowlists.",
    recommendation: "Validate redirect targets against an allowlist of internal paths or trusted domains before redirecting.",
    standards: ["OWASP Top 10: A01 Broken Access Control"],
    detect(project) {
      const pattern = /redirect\(\s*(req(uest)?\.(query|nextUrl\.searchParams\.get)|searchParams\.get|params\.)/i;
      return filesWith(project, "api_route")
        .filter((file) => pattern.test(file.content))
        .filter((file) => !/allowlist|allowedRedirects|startsWith\(['"]\//i.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  },
  {
    id: "MASS_ASSIGNMENT_RISK",
    title: "Request body may be written directly into a database call",
    category: "api",
    severity: "high",
    risk: "Spreading the raw request body into a create/update call lets attackers set fields they should not control, such as role, isAdmin, or plan.",
    recommendation: "Explicitly allowlist the fields copied from request input into database writes instead of spreading the full body.",
    codeExample: "const { name, email } = body; await db.user.update({ where: { id }, data: { name, email } });",
    standards: ["OWASP Top 10: A04 Insecure Design", "OWASP API Security: Mass Assignment"],
    detect(project) {
      const pattern = /\.(create|update)\(\s*\{[^}]*data:\s*\{?\s*\.\.\.(body|req\.body)/is;
      return filesWith(project, "api_route")
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  },
  {
    id: "API_RATE_LIMIT_MISSING_PUBLIC",
    title: "Public API route may be missing rate limiting",
    category: "api",
    severity: "medium",
    risk: "Endpoints without any rate limiting are vulnerable to scraping, credential stuffing, and cost-driving abuse at scale.",
    recommendation: "Add per-IP and per-account rate limiting (e.g. Upstash, express-rate-limit, a WAF rule) to public-facing API routes.",
    standards: ["OWASP API Security: Unrestricted Resource Consumption"],
    detect(project) {
      const apiRoutes = filesWith(project, "api_route");
      if (apiRoutes.length === 0) return [];
      const hasAnyRateLimit = apiRoutes.some((file) => /rateLimit|limiter|upstash|slowDown/i.test(file.content));
      return hasAnyRateLimit ? [] : [{ confidence: "low", evidence: `${apiRoutes.length} API route(s) found with no rate-limiting library detected anywhere in the project` }];
    }
  },
  {
    id: "GRAPHQL_INTROSPECTION_ENABLED",
    title: "GraphQL introspection may be enabled in production",
    category: "api",
    severity: "medium",
    risk: "Introspection lets attackers enumerate your entire schema, including fields and mutations not exposed in your app's UI.",
    recommendation: "Disable introspection (and the GraphiQL/Playground UI) outside of development environments.",
    standards: ["OWASP API Security: Security Misconfiguration"],
    detect(project) {
      return appCodeFiles(project)
        .filter((file) => /ApolloServer|graphqlHTTP|createYoga/i.test(file.content))
        .filter((file) => !/introspection:\s*(false|process\.env)|NODE_ENV\s*!==?\s*['"]production['"]/i.test(file.content))
        .map((file) => findingForFile({}, file, /ApolloServer|graphqlHTTP|createYoga/i, { confidence: "low" }));
    }
  },
  {
    id: "VERBOSE_ERROR_STACK_TRACE_TO_CLIENT",
    title: "API response may return a raw error message or stack trace",
    category: "logging",
    severity: "medium",
    risk: "Returning err.stack or a raw error message to the client can leak file paths, library versions, query fragments, or other internals useful for an attacker's reconnaissance.",
    recommendation: "Log the full error server-side, and return a generic error message to the client.",
    standards: ["OWASP Top 10: A09 Security Logging and Monitoring Failures"],
    detect(project) {
      const pattern = /(json|send)\(\s*\{[^}]*(error|message)\s*:\s*(err(or)?)\.(stack|message)/is;
      return filesWith(project, "api_route")
        .filter((file) => pattern.test(file.content))
        .map((file) => findingForFile({}, file, pattern, { confidence: "medium" }));
    }
  }
];
