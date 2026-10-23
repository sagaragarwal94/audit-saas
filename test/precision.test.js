// auditsaas-ignore-file SECRETS_HARDCODED -- deliberately fake key samples used as scanner input
import assert from "node:assert/strict";
import test from "node:test";
import { ids, scanFiles } from "./helpers.js";

test("evidence is the matched source line, not the detector regex", async () => {
  const result = await scanFiles({
    "app/api/items/route.ts": `export async function GET() {\n  const html = "<b>x</b>";\n  return Response.json({ html });\n}\n`,
    "components/Post.tsx": `export function Post({ body }) {\n  return <div dangerouslySetInnerHTML={{ __html: body }} />;\n}\n`,
  });
  const xss = result.findings.find((finding) => finding.id === "XSS_UNSAFE_HTML");
  assert.ok(xss);
  assert.equal(xss.line, 2);
  assert.match(xss.evidence, /dangerouslySetInnerHTML=\{\{ __html: body \}\}/);
});

test("env-file evidence names the variable without echoing the value", async () => {
  const result = await scanFiles({
    ".env": "DATABASE_URL=postgres://admin:hunter2@db.internal/app\n",
  });
  const finding = result.findings.find((item) => item.id === "SECRETS_ENV_COMMITTED");
  assert.equal(finding.evidence, "DATABASE_URL=[REDACTED]");
  assert.doesNotMatch(JSON.stringify(result.findings), /hunter2/);
});

test("SQL injection: flags interpolated/concatenated SQL but not parameterized tagged templates", async () => {
  const unsafe = await scanFiles({
    "lib/a.ts": "export const q = (id) => db.query(`SELECT * FROM users WHERE id = ${id}`);\n",
    "lib/b.ts": "export const q = (id) => db.query(\"SELECT * FROM users WHERE id = '\" + id);\n",
    "lib/c.ts": "export const q = (id) => prisma.$queryRawUnsafe(`SELECT 1`);\n",
  });
  assert.equal(ids(unsafe).filter((id) => id === "SQL_INJECTION_RAW_QUERY").length, 3);

  const safe = await scanFiles({
    "lib/a.ts": "export const q = (id) => sql`SELECT * FROM users WHERE id = ${id}`;\n",
    "lib/b.ts": "export const q = (id) => prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;\n",
    "lib/c.ts": "const title = `Selected ${count} items`;\nconst where = 'WHERE';\nconst plus = a + b;\n",
  });
  assert.ok(!ids(safe).includes("SQL_INJECTION_RAW_QUERY"));
});

test("XML namespace URIs and docs are not reported as insecure HTTP URLs", async () => {
  const result = await scanFiles({
    "public/index.html": `<svg xmlns="http://www.w3.org/2000/svg"></svg>\n`,
    "README.md": "Call http://api.partner.com for details\n",
    "lib/client.ts": `export const base = "http://localhost:3000";\n`,
  });
  assert.ok(!ids(result).includes("CONFIG_HTTP_URLS"));

  const insecure = await scanFiles({ "lib/client.ts": `export const base = "http://api.partner.com/v1";\n` });
  assert.ok(ids(insecure).includes("CONFIG_HTTP_URLS"));
});

test("markdown docs describing a risk don't trigger code rules", async () => {
  const result = await scanFiles({
    "docs/security.md": [
      "Never set NEXT_PUBLIC_OPENAI_API_KEY.",
      "Content-Security-Policy: script-src 'unsafe-inline' is bad.",
      "We use Sentry for monitoring and google-analytics with gtag(.",
    ].join("\n"),
  });
  assert.deepEqual(
    ids(result).filter((id) => ["SECRETS_FRONTEND_PUBLIC_KEY", "CSP_UNSAFE_INLINE", "PRIVACY_THIRD_PARTY_TRACKING_NO_CONSENT"].includes(id)),
    []
  );
  assert.ok(ids(result).includes("MONITORING_ANOMALY_GAPS"), "a README mentioning Sentry is not monitoring");
});

test("frontend secret exposure covers other frameworks and skips keys meant to be public", async () => {
  const exposed = await scanFiles({ "src/ai.ts": "const key = import.meta.env.VITE_OPENAI_API_KEY;\n" });
  assert.ok(ids(exposed).includes("SECRETS_FRONTEND_PUBLIC_KEY"));

  const intended = await scanFiles({
    "src/config.ts": [
      "const a = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;",
      "const b = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;",
      "const c = process.env.NEXT_PUBLIC_FIREBASE_API_KEY;",
    ].join("\n"),
  });
  assert.ok(!ids(intended).includes("SECRETS_FRONTEND_PUBLIC_KEY"));
});

test("hardcoded secrets: placeholders and AWS's documented example key are ignored", async () => {
  const result = await scanFiles({
    "lib/stripe.ts": `const key = "sk_test_xxxxxxxxxxxxxxxx";\nconst aws = "AKIAIOSFODNN7EXAMPLE";\n`,
  });
  assert.ok(!ids(result).includes("SECRETS_HARDCODED"));
  assert.ok(!ids(result).includes("HARDCODED_CLOUD_CREDENTIAL"));

  const real = await scanFiles({ "lib/key.ts": `const pem = "-----BEGIN PRIVATE KEY-----";\n` });
  assert.ok(ids(real).includes("SECRETS_HARDCODED"));
});

test("cookie reads are not cookie writes", async () => {
  const read = await scanFiles({
    "app/page.tsx": `import { cookies } from "next/headers";\nexport default async function Page() { const theme = (await cookies()).get("theme"); return theme; }\n`,
  });
  assert.ok(!ids(read).includes("AUTH_COOKIE_FLAGS_MISSING"));

  const write = await scanFiles({
    "app/api/login/route.ts": `import { cookies } from "next/headers";\nexport async function POST() { (await cookies()).set("session", "abc"); }\n`,
  });
  assert.ok(ids(write).includes("AUTH_COOKIE_FLAGS_MISSING"));
});

test("API auth: login/webhook endpoints are exempt and middleware auth lowers confidence", async () => {
  const route = `export async function GET() { return Response.json(await db.item.findMany({ take: 10 })); }\n`;
  const plain = await scanFiles({ "app/api/items/route.ts": route, "app/api/login/route.ts": route });
  const plainFindings = plain.findings.filter((finding) => finding.id === "API_AUTH_MISSING");
  assert.deepEqual(plainFindings.map((finding) => finding.file), ["app/api/items/route.ts"]);
  assert.equal(plainFindings[0].confidence, "medium");

  const withMiddleware = await scanFiles({
    "app/api/items/route.ts": route,
    "middleware.ts": `import { clerkMiddleware } from "@clerk/nextjs/server";\nexport default clerkMiddleware();\n`,
  });
  assert.equal(withMiddleware.findings.find((finding) => finding.id === "API_AUTH_MISSING").confidence, "low");
});

test("a React login form isn't treated as a custom password store", async () => {
  const result = await scanFiles({
    "app/login/page.tsx": `export default function Login() { return <form><input type="password" name="password" /></form>; }\n`,
  });
  assert.ok(!ids(result).includes("AUTH_PASSWORD_HASHING_WEAK"));
  assert.ok(!ids(result).includes("AUTH_LOGIN_RATE_LIMIT_MISSING"));
});

test("logging rule requires the sensitive value in the log call itself", async () => {
  const quiet = await scanFiles({
    "app/api/x/route.ts": `export async function POST(request) {\n  console.log("handling");\n  const token = await getToken(request);\n}\n`,
  });
  assert.ok(!ids(quiet).includes("LOGGING_SECRETS_RISK"));

  const loud = await scanFiles({ "app/api/x/route.ts": `export async function POST(request) {\n  console.log("auth", token);\n}\n` });
  const finding = loud.findings.find((item) => item.id === "LOGGING_SECRETS_RISK");
  assert.equal(finding.line, 2);
});

test("SRI rule skips evergreen vendor scripts that can't use integrity hashes", async () => {
  const vendor = await scanFiles({ "public/index.html": `<script src="https://js.stripe.com/v3/"></script>\n` });
  assert.ok(!ids(vendor).includes("MISSING_SRI_EXTERNAL_SCRIPT"));

  const cdn = await scanFiles({ "public/index.html": `<script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/x.js"></script>\n` });
  assert.ok(ids(cdn).includes("MISSING_SRI_EXTERNAL_SCRIPT"));
});

test("lockfile detection recognizes bun and modern compose file names", async () => {
  const bun = await scanFiles({ "package.json": "{}", "bun.lock": "{}" });
  assert.ok(!ids(bun).includes("DEPENDENCY_NO_LOCKFILE"));

  const compose = await scanFiles({ "compose.yaml": "services:\n  db:\n    ports:\n      - \"5432:5432\"\n" });
  assert.ok(ids(compose).includes("INFRA_DB_PORT_EXPOSED"));
});

test("Vue and Svelte single-file components are scanned", async () => {
  const result = await scanFiles({
    "src/components/Bio.vue": `<template><div v-html="bio"></div></template>\n<script setup>\nconst el = document.getElementById("x");\nel.innerHTML = props.bio;\n</script>\n`,
  });
  assert.ok(ids(result).includes("XSS_UNSAFE_HTML"));
});

test("long single-line files can't trigger catastrophic regex backtracking", async () => {
  const line = `const x = "${"select a from b ".repeat(280)}`; // ~4.5KB, below the minified threshold
  const started = Date.now();
  await scanFiles({ "lib/long.ts": `${line}\n`, "public/app.min.js": `${'"' + "select a from b ".repeat(20_000)}\n` });
  assert.ok(Date.now() - started < 2000, `scan took ${Date.now() - started}ms`);
});

test("public-key allowlist never overrides a secret-shaped variable name", async () => {
  const result = await scanFiles({
    "src/a.ts": "const a = process.env.NEXT_PUBLIC_RECAPTCHA_SECRET_KEY;\n",
    "src/b.ts": "const b = process.env.NEXT_PUBLIC_SENTRY_AUTH_TOKEN;\n",
    "src/c.ts": "const c = process.env.NEXT_PUBLIC_MAPBOX_TOKEN;\n",
  });
  const files = result.findings.filter((finding) => finding.id === "SECRETS_FRONTEND_PUBLIC_KEY").map((finding) => finding.file);
  assert.deepEqual(files.sort(), ["src/a.ts", "src/b.ts"]);
});

test("a placeholder earlier in a file doesn't hide a real secret later", async () => {
  const result = await scanFiles({
    // Assembled at runtime so this repo never contains a live-key-shaped literal.
    "lib/stripe.ts": `// e.g. sk_live_XXXXXXXXXXXXXXXX\n\n\nexport const key = "${"sk_" + "live_"}51HabcDEFghiJKLmnoPQR";\n`,
  });
  const finding = result.findings.find((item) => item.id === "SECRETS_HARDCODED");
  assert.ok(finding);
  assert.equal(finding.line, 4);
});

test("no rule echoes .env values, and query-string credentials are redacted", async () => {
  const result = await scanFiles({
    ".env": "PARTNER_URL=http://api.partner.io/v1?access_key=a1b2c3d4e5\n",
    "lib/client.ts": `export const u = "http://api.partner.io/v1?token=zzz999&page=2";\n`,
  });
  const serialized = JSON.stringify(result.findings);
  assert.doesNotMatch(serialized, /a1b2c3d4e5|zzz999/);
  assert.ok(result.findings.some((finding) => finding.evidence === "PARTNER_URL=[REDACTED]"));
});

test("only top-level auth/health routes are exempt from the missing-auth check", async () => {
  const handler = "export async function PATCH(request) { return Response.json(await request.json()); }\n";
  const result = await scanFiles({
    "app/api/orders/[id]/status/route.ts": handler,
    "app/api/admin/register/route.ts": handler,
    "app/api/health/route.ts": handler,
  });
  const files = result.findings.filter((finding) => finding.id === "API_AUTH_MISSING").map((finding) => finding.file);
  assert.deepEqual(files.sort(), ["app/api/admin/register/route.ts", "app/api/orders/[id]/status/route.ts"]);
});

test("a data lookup named getUser isn't mistaken for an auth check", async () => {
  const result = await scanFiles({
    "app/api/users/[id]/route.ts": "export async function GET(_r, { params }) { return Response.json(await db.getUser(params.id)); }\n",
    "app/api/me/route.ts": "export async function GET() { const user = await getUser(); return Response.json(user); }\n",
  });
  const files = result.findings.filter((finding) => finding.id === "API_AUTH_MISSING").map((finding) => finding.file);
  assert.deepEqual(files, ["app/api/users/[id]/route.ts"]);
});
