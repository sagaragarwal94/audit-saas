import assert from "node:assert/strict";
import test from "node:test";
import { loadRuleCatalog } from "../src/rule-catalog.js";

const EXPECTED_RULES = [
  "AUTH_PASSWORD_HASHING_WEAK",
  "AUTH_LOGIN_RATE_LIMIT_MISSING",
  "AUTH_SESSION_EXPIRY_MISSING",
  "AUTH_COOKIE_FLAGS_MISSING",
  "AUTHZ_IDOR_POSSIBLE",
  "API_AUTH_MISSING",
  "API_VALIDATION_MISSING",
  "SQL_INJECTION_RAW_QUERY",
  "XSS_UNSAFE_HTML",
  "SECRETS_ENV_COMMITTED",
  "SECRETS_HARDCODED",
  "SECRETS_FRONTEND_PUBLIC_KEY",
  "PAYMENT_STRIPE_WEBHOOK_SIGNATURE_MISSING",
  "PAYMENT_IDEMPOTENCY_MISSING",
  "AI_FRONTEND_OR_UNBOUNDED",
  "AI_PROMPT_INJECTION_REVIEW",
  "PRIVACY_DATA_COLLECTION_FOUND",
  "LOGGING_SECRETS_RISK",
  "MONITORING_ANOMALY_GAPS",
  "HEADERS_HTTPS_RUNTIME",
  "CONFIG_HTTP_URLS",
  "CORS_WILDCARD_WITH_CREDENTIALS",
  "CORS_ORIGIN_REFLECTED",
  "SSRF_UNVALIDATED_URL_FETCH",
  "JWT_ALGORITHM_NOT_ENFORCED",
  "JWT_SECRET_WEAK_OR_HARDCODED",
  "CSRF_PROTECTION_MISSING",
  "DEPENDENCY_NO_LOCKFILE",
  "DEPENDENCY_WILDCARD_VERSION",
  "DEPENDENCY_KNOWN_RISKY_PACKAGE",
  "UPLOAD_UNRESTRICTED_FILE_TYPE",
  "UPLOAD_PATH_TRAVERSAL",
  "ADMIN_ROUTE_NO_ROLE_CHECK",
  "DEBUG_ENDPOINT_EXPOSED",
  "INFRA_DOCKER_ROOT_USER",
  "INFRA_DB_PORT_EXPOSED",
  "OPEN_REDIRECT_UNVALIDATED",
  "MASS_ASSIGNMENT_RISK",
  "API_RATE_LIMIT_MISSING_PUBLIC",
  "GRAPHQL_INTROSPECTION_ENABLED",
  "SUPABASE_RLS_NOT_CONFIRMED",
  "CI_SECRETS_HARDCODED_IN_WORKFLOW",
  "PRIVACY_NO_DELETION_ENDPOINT",
  "PRIVACY_THIRD_PARTY_TRACKING_NO_CONSENT",
  "CODE_EXECUTION_EVAL_USER_INPUT",
];

test("loads categorized markdown rule metadata", () => {
  const catalog = loadRuleCatalog();

  for (const id of EXPECTED_RULES) {
    const rule = catalog.get(id);
    assert.ok(rule, `${id} should exist in markdown catalog`);
    assert.ok(rule.title, `${id} should have a title`);
    assert.ok(rule.category, `${id} should have a category`);
    assert.ok(rule.severity, `${id} should have a severity`);
    assert.ok(rule.risk, `${id} should have risk text`);
    assert.ok(rule.recommendation, `${id} should have recommendation text`);
  }
});
