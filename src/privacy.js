const DATA_PATTERNS = [
  ["Email address", /email/i, "Signup/profile/contact forms, auth, or payment flows"],
  ["Name", /\b(firstName|lastName|fullName|name)\b/i, "Profile, billing, or onboarding forms"],
  ["Phone number", /phone|tel/i, "Contact, billing, or onboarding forms"],
  ["Billing/payment metadata", /stripe|checkout|subscription|invoice|payment/i, "Payment provider integration"],
  ["AI prompts and outputs", /prompt|message|chat|openai|anthropic|generateText|streamText/i, "AI feature inputs and generated outputs"],
  ["Uploaded files", /upload|file|multipart|formData/i, "File upload or document processing"],
  ["Analytics and usage events", /posthog|analytics|gtag|mixpanel|amplitude|track\(/i, "Analytics SDK or event tracking"],
  ["IP/device/browser data", /ip|userAgent|headers\(|request\.headers|geo/i, "Request logs, analytics, security controls"],
  ["Cookies and browser storage", /localStorage|sessionStorage|cookie/i, "Browser-side persistence"],
  ["Error and diagnostic data", /sentry|logger|console\.error|datadog|axiom/i, "Logging or error monitoring"]
];

const THIRD_PARTIES = [
  ["Stripe", /stripe/i],
  ["OpenAI", /openai/i],
  ["Anthropic", /anthropic/i],
  ["Supabase", /supabase/i],
  ["Clerk", /clerk/i],
  ["Firebase", /firebase/i],
  ["Resend", /resend/i],
  ["SendGrid", /sendgrid/i],
  ["PostHog", /posthog/i],
  ["Sentry", /sentry/i],
  ["Datadog", /datadog/i]
];

export function buildDataInventory(project) {
  const inventory = [];
  for (const [dataType, pattern, defaultSource] of DATA_PATTERNS) {
    const matches = project.files.filter((file) => pattern.test(file.relativePath) || pattern.test(file.content));
    if (matches.length === 0) continue;
    inventory.push({
      dataType,
      source: inferSource(matches, defaultSource),
      storedIn: inferStorage(project, matches),
      sharedWith: inferThirdParties(project, matches),
      risk: inferRisk(dataType),
      evidenceFiles: matches.slice(0, 5).map((file) => file.relativePath)
    });
  }
  return inventory;
}

export function buildPrivacyPolicy(project, dataInventory) {
  const processors = [...new Set(dataInventory.flatMap((item) => item.sharedWith).filter(Boolean))];
  const company = "Your Company";
  const app = project.packageJson?.name || "the application";

  return `# Privacy Policy Draft

This privacy policy draft was generated from a technical scan of ${app}. It should be reviewed by a qualified legal professional before publication.

## Information We Collect

Based on the scanned codebase, the application may collect:

${dataInventory.length ? dataInventory.map((item) => `- ${item.dataType}: collected through ${item.source}.`).join("\n") : "- No clear personal-data collection points were detected by the scanner."}

## How We Use Information

${company} may use collected information to provide the service, authenticate users, process payments, operate AI-powered features, respond to support requests, monitor abuse, improve reliability, and meet legal or security obligations.

## Where Data Is Stored

Detected storage locations include:

${dataInventory.length ? dataInventory.map((item) => `- ${item.dataType}: ${item.storedIn}.`).join("\n") : "- No storage locations were detected."}

## Third-Party Processors

Detected third-party services include:

${processors.length ? processors.map((processor) => `- ${processor}`).join("\n") : "- No third-party processors were detected."}

## AI Provider Usage

If the application sends prompts, uploaded content, or generated outputs to AI providers, users should be told what data is sent, why it is processed, and whether it is stored by the provider. Avoid sending sensitive personal data to AI providers unless necessary and disclosed.

## Payments

Payment information should be processed by a payment provider such as Stripe. The application should store only the minimum payment metadata required to manage subscriptions, invoices, account status, and fraud prevention.

## Cookies and Analytics

The application may use cookies, browser storage, analytics tools, and logs to maintain sessions, measure usage, detect abuse, and improve the product. Users should be given legally appropriate cookie notices and choices where required.

## Data Retention

Retain personal information only for as long as needed to provide the service, meet legal obligations, resolve disputes, prevent abuse, and enforce agreements. Define retention windows for account data, logs, AI prompts, uploaded files, and billing records.

## Security

Use reasonable technical and organizational safeguards, including HTTPS, access controls, secret management, logging redaction, rate limits, and monitoring for suspicious activity.

## User Rights

Depending on user location, users may have rights to access, correct, delete, export, or restrict processing of their personal information. Provide a contact path for privacy requests.

## Contact

For privacy questions, contact: privacy@example.com.

## Updates

This policy may be updated as the product, data practices, or legal requirements change.
`;
}

function inferSource(matches, fallback) {
  if (matches.some((file) => /form|input|textarea/i.test(file.content))) return "forms or user input fields";
  if (matches.some((file) => /api\//i.test(file.relativePath))) return "API requests";
  return fallback;
}

function inferStorage(project, matches) {
  const haystack = `${matches.map((file) => file.content).join("\n")}\n${project.files.map((file) => file.relativePath).join("\n")}`;
  const stores = [];
  if (/prisma|drizzle|insert|create\(|update\(|CREATE TABLE|supabase\.from/i.test(haystack)) stores.push("database");
  if (/s3|bucket|blob|storage/i.test(haystack)) stores.push("object storage");
  if (/localStorage/i.test(haystack)) stores.push("browser localStorage");
  if (/sessionStorage/i.test(haystack)) stores.push("browser sessionStorage");
  if (/cookie/i.test(haystack)) stores.push("cookies");
  if (/console\.|logger|sentry|datadog|axiom/i.test(haystack)) stores.push("logs/observability tools");
  return stores.length ? stores.join(", ") : "unknown or external provider";
}

function inferThirdParties(project, matches) {
  const haystack = `${matches.map((file) => file.content).join("\n")}\n${JSON.stringify(project.packageJson || {})}`;
  return THIRD_PARTIES.filter(([, pattern]) => pattern.test(haystack)).map(([name]) => name);
}

function inferRisk(dataType) {
  if (/AI|Uploaded|Billing|payment/i.test(dataType)) return "High";
  if (/Email|Phone|IP|device/i.test(dataType)) return "Medium";
  return "Low";
}
