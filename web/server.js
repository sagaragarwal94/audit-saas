import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  createReadStream,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(root, "..");
const dataDir = join(root, "data");
const dbPath = join(dataDir, "app-db.json");
const revenueCatSdkPath = join(
  projectRoot,
  "node_modules",
  "@revenuecat",
  "purchases-js",
  "dist",
  "Purchases.es.js",
);

loadEnv(join(projectRoot, ".env"));

const config = {
  appBaseUrl: process.env.APP_BASE_URL || "http://127.0.0.1:4000",
  host: process.env.HOST || "127.0.0.1",
  port: Number.parseInt(process.env.PORT || "4000", 10),
  sessionSecret: process.env.AUTH0_SECRET || process.env.SESSION_SECRET || "dev-only-session-secret",
  auth0Domain: process.env.AUTH0_DOMAIN || "",
  auth0ClientId: process.env.AUTH0_CLIENT_ID || "",
  auth0ClientSecret: process.env.AUTH0_CLIENT_SECRET || "",
  auth0CallbackUrl: process.env.AUTH0_CALLBACK_URL || "",
  auth0Audience: process.env.AUTH0_AUDIENCE || "",
  revenueCatApiKey: process.env.REVENUECAT_API_KEY || "",
  revenueCatEntitlementId: process.env.REVENUECAT_ENTITLEMENT_ID || "pro",
  revenueCatOfferingId: process.env.REVENUECAT_OFFERING_ID || "",
  revenueCatStarterPackageId: process.env.REVENUECAT_STARTER_PACKAGE_ID || "",
  revenueCatProPackageId: process.env.REVENUECAT_PRO_PACKAGE_ID || "",
  revenueCatStarterUrl: process.env.REVENUECAT_STARTER_PURCHASE_URL || "",
  revenueCatProUrl: process.env.REVENUECAT_PRO_PURCHASE_URL || "",
  revenueCatWebhookSecret: process.env.REVENUECAT_WEBHOOK_SECRET || "",
  cliDownloadUrl: process.env.CLI_DOWNLOAD_URL || "",
};

const types = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
};

ensureDb();

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", `http://${request.headers.host}`);

    if (request.method === "GET" && url.pathname === "/") {
      return handleHome(request, response);
    }

    if (request.method === "GET" && url.pathname === "/auth/login") {
      return handleLogin(request, response);
    }

    if (request.method === "GET" && url.pathname === "/auth/callback") {
      return handleCallback(request, response, url);
    }

    if (request.method === "GET" && url.pathname === "/auth/logout") {
      return handleLogout(request, response);
    }

    if (request.method === "GET" && url.pathname === "/dashboard") {
      return handleDashboard(request, response);
    }

    if (request.method === "GET" && url.pathname === "/release-notes") {
      return handleReleaseNotes(request, response);
    }

    if (request.method === "GET" && url.pathname === "/download") {
      return handleDownload(request, response);
    }

    if (request.method === "GET" && url.pathname === "/billing") {
      return handleBilling(request, response, url);
    }

    if (request.method === "GET" && url.pathname === "/api/billing/config") {
      return handleBillingConfig(request, response);
    }

    if (request.method === "GET" && url.pathname === "/api/me") {
      return handleMe(request, response);
    }

    if (request.method === "GET" && url.pathname === "/api/analytics") {
      return handleAnalytics(request, response);
    }

    if (request.method === "GET" && url.pathname === "/analytics/findings.json") {
      return handleAnalyticsExport(request, response, "json");
    }

    if (request.method === "GET" && url.pathname === "/analytics/report.md") {
      return handleAnalyticsExport(request, response, "markdown");
    }

    if (request.method === "GET" && url.pathname === "/analytics") {
      return handleAnalyticsPage(request, response);
    }

    if (request.method === "POST" && url.pathname === "/api/cli/device") {
      return handleCreateDevice(request, response);
    }

    if (request.method === "GET" && url.pathname === "/cli/verify") {
      return handleDeviceVerify(request, response, url);
    }

    if (request.method === "POST" && url.pathname === "/api/cli/device/approve") {
      return handleApproveDevice(request, response);
    }

    if (request.method === "POST" && url.pathname === "/api/devices/disconnect") {
      return handleDisconnectDevice(request, response);
    }

    if (request.method === "POST" && url.pathname === "/api/cli/token") {
      return handleCliToken(request, response);
    }

    if (request.method === "POST" && url.pathname === "/api/cli/runs/start") {
      return handleCliRunStart(request, response);
    }

    if (request.method === "POST" && /^\/api\/cli\/runs\/[^/]+\/progress$/.test(url.pathname)) {
      return handleCliRunProgress(request, response, url.pathname.split("/")[4]);
    }

    if (request.method === "POST" && /^\/api\/cli\/runs\/[^/]+\/complete$/.test(url.pathname)) {
      return handleCliRunComplete(request, response, url.pathname.split("/")[4]);
    }

    if (request.method === "POST" && url.pathname === "/api/revenuecat/webhook") {
      return handleRevenueCatWebhook(request, response);
    }

    if (request.method === "GET" && url.pathname === "/assets/vendor/purchases-js.esm.js") {
      return serveFile(revenueCatSdkPath, "text/javascript; charset=utf-8", response);
    }

    return serveStatic(url, response);
  } catch (error) {
    console.error(error);
    sendText(response, 500, "Internal server error");
  }
});

server.listen(config.port, config.host, () => {
  console.log(`Gravel app running at http://${config.host}:${config.port}`);
});

function loadEnv(filePath) {
  if (!existsSync(filePath)) return;

  const lines = readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const index = trimmed.indexOf("=");
    if (index === -1) continue;

    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = value;
  }
}

function ensureDb() {
  mkdirSync(dataDir, { recursive: true });
  if (!existsSync(dbPath)) {
    writeDb({ users: [], scans: [], subscriptions: [], devices: [] });
  }
}

function readDb() {
  return JSON.parse(readFileSync(dbPath, "utf8"));
}

function writeDb(db) {
  writeFileSync(dbPath, `${JSON.stringify(db, null, 2)}\n`);
}

function handleLogin(request, response) {
  if (!auth0Configured()) {
    return sendHtml(response, 500, renderMessage("Auth0 is not configured", [
      "Add AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, and AUTH0_CALLBACK_URL to .env.",
    ]));
  }

  const callbackUrl = getAuth0CallbackUrl(request);
  const signedState = signOAuthState();

  const authorizeUrl = new URL(`https://${config.auth0Domain}/authorize`);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("response_mode", "query");
  authorizeUrl.searchParams.set("client_id", config.auth0ClientId);
  authorizeUrl.searchParams.set("redirect_uri", callbackUrl);
  authorizeUrl.searchParams.set("scope", "openid profile email");
  authorizeUrl.searchParams.set("state", signedState);
  if (config.auth0Audience) {
    authorizeUrl.searchParams.set("audience", config.auth0Audience);
  }

  response.writeHead(302, {
    location: authorizeUrl.toString(),
  });
  response.end();
}

async function handleCallback(request, response, url) {
  const auth0Error = url.searchParams.get("error_description") || url.searchParams.get("error");
  if (auth0Error) {
    return sendHtml(response, 400, renderMessage("Auth0 authorization failed", [
      `Auth0 returned: ${auth0Error}.`,
      "This error was generated inside Auth0 before the app received a login code. Check Auth0 tenant logs and any Login Flow Actions or Rules attached to this application.",
    ]));
  }

  const state = url.searchParams.get("state") || "";
  const code = url.searchParams.get("code") || "";
  const stateResult = verifyOAuthState(state);

  if (!code || !stateResult.ok) {
    return sendHtml(response, 400, renderMessage("Login could not be verified", [
      "The Auth0 state value was missing, expired, or altered. Please start login again from the homepage.",
      "Also make sure the exact callback URL shown in the Auth0 redirect is allowed in Auth0.",
    ]));
  }

  const callbackUrl = getAuth0CallbackUrl(request);
  const tokenResponse = await fetch(`https://${config.auth0Domain}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      client_id: config.auth0ClientId,
      client_secret: config.auth0ClientSecret,
      code,
      redirect_uri: callbackUrl,
    }),
  });

  if (!tokenResponse.ok) {
    return sendHtml(response, 502, renderMessage("Auth0 token exchange failed", [
      "Check your Auth0 app settings and callback URL.",
    ]));
  }

  const tokens = await tokenResponse.json();
  const profileResponse = await fetch(`https://${config.auth0Domain}/userinfo`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });

  if (!profileResponse.ok) {
    return sendHtml(response, 502, renderMessage("Could not load Auth0 profile", [
      "The login succeeded, but the profile request failed.",
    ]));
  }

  const profile = await profileResponse.json();
  const user = upsertUser(profile);
  const session = signSession({ userId: user.id, createdAt: Date.now() });

  response.writeHead(302, {
    location: "/dashboard",
    "set-cookie": [
      cookie("gravel_session", session, {
        maxAge: 60 * 60 * 24 * 14,
        httpOnly: true,
        secure: isSecureRequest(request),
      }),
      cookie("gravel_oauth_state", "", {
        maxAge: 0,
        httpOnly: true,
        secure: isSecureRequest(request),
      }),
    ],
  });
  response.end();
}

function handleLogout(request, response) {
  const returnTo = `${config.appBaseUrl}/`;
  const logoutUrl = config.auth0Domain
    ? `https://${config.auth0Domain}/v2/logout?${new URLSearchParams({
        client_id: config.auth0ClientId,
        returnTo,
      })}`
    : "/";

  response.writeHead(302, {
    location: logoutUrl,
    "set-cookie": cookie("gravel_session", "", {
      maxAge: 0,
      httpOnly: true,
      secure: isSecureRequest(request),
    }),
  });
  response.end();
}

function getAuth0CallbackUrl(request) {
  if (config.auth0CallbackUrl) return config.auth0CallbackUrl;

  return `${getRequestBaseUrl(request)}/auth/callback`;
}

function getRequestBaseUrl(request) {
  const host = request.headers["x-forwarded-host"] || request.headers.host;
  const proto =
    request.headers["x-forwarded-proto"] ||
    (config.appBaseUrl.startsWith("https://") ? "https" : "http");

  return `${proto}://${host}`;
}

function isSecureRequest(request) {
  const proto = request.headers["x-forwarded-proto"];
  return proto === "https" || getRequestBaseUrl(request).startsWith("https://");
}

function handleDashboard(request, response) {
  const user = requireUser(request, response);
  if (!user) return;

  const db = readDb();
  const scans = db.scans
    .filter((scan) => scan.userId === user.id)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const activeSubscription = db.subscriptions.find(
    (subscription) => subscription.userId === user.id && subscription.status === "active",
  );
  const paid = Boolean(activeSubscription);
  const trialUsed = Boolean(user.trialCompletedAt);
  const canStartScan = paid || !trialUsed;

  sendHtml(response, 200, renderDashboard({ user, scans, paid, trialUsed, canStartScan }));
}

function handleDownload(request, response) {
  const user = requireUser(request, response);
  if (!user) return;

  if (config.cliDownloadUrl) {
    response.writeHead(302, { location: config.cliDownloadUrl });
    response.end();
    return;
  }

  const packed = packCliTarball();
  if (!packed.ok) {
    return sendHtml(response, 500, renderMessage("CLI download failed", [
      packed.error || "The CLI archive could not be generated.",
    ]));
  }

  response.writeHead(200, {
    "content-type": "application/gzip",
    "content-disposition": `attachment; filename="${packed.filename}"`,
    "cache-control": "no-store",
  });
  createReadStream(packed.path).pipe(response);
}

function handleBilling(request, response, url) {
  const user = requireUser(request, response);
  if (!user) return;

  const plan = url.searchParams.get("plan") || "pro";
  sendHtml(response, 200, renderBilling({ user, plan }));
}

function handleBillingConfig(request, response) {
  const user = requireUser(request, response, true);
  if (!user) return;

  sendJson(response, 200, {
    apiKey: config.revenueCatApiKey,
    appUserId: user.id,
    customerEmail: user.email,
    entitlementId: config.revenueCatEntitlementId,
    offeringId: config.revenueCatOfferingId,
    packages: {
      starter: config.revenueCatStarterPackageId,
      pro: config.revenueCatProPackageId,
    },
  });
}

function handleMe(request, response) {
  const cliAuth = getBearerToken(request) ? requireCliUser(request, response) : null;
  const user = cliAuth?.user || requireUser(request, response, true);
  if (!user) return;

  const db = cliAuth?.db || readDb();
  const scans = db.scans.filter((scan) => scan.userId === user.id);
  const activeSubscription = db.subscriptions.find(
    (subscription) => subscription.userId === user.id && subscription.status === "active",
  );

  sendJson(response, 200, {
    user: publicUser(user),
    trial: {
      completed: Boolean(user.trialCompletedAt),
      canRunScan: Boolean(activeSubscription) || !user.trialCompletedAt,
    },
    subscription: activeSubscription || null,
    scans,
  });
}

function handleAnalytics(request, response) {
  const user = requireUser(request, response, true);
  if (!user) return;

  const db = readDb();
  sendJson(response, 200, buildAnalytics(db, user));
}

function handleAnalyticsPage(request, response) {
  const user = requireUser(request, response);
  if (!user) return;

  const db = readDb();
  sendHtml(response, 200, renderAnalyticsPage({ user, analytics: buildAnalytics(db, user) }));
}

function handleHome(request, response) {
  const user = getSessionUser(request);
  const html = readFileSync(join(root, "index.html"), "utf8");
  sendHtml(response, 200, user ? renderSignedInHome(html, user) : html);
}

function handleReleaseNotes(request, response) {
  const user = getSessionUser(request);
  sendHtml(response, 200, renderReleaseNotes({ user }));
}

function handleAnalyticsExport(request, response, format) {
  const user = requireUser(request, response, true);
  if (!user) return;

  const db = readDb();
  const analytics = buildAnalytics(db, user);
  const filename = format === "json" ? "gravel-findings.json" : "gravel-report.md";
  const content = format === "json"
    ? `${JSON.stringify({ user: publicUser(user), analytics }, null, 2)}\n`
    : renderAnalyticsMarkdown(user, analytics);

  response.writeHead(200, {
    "content-type": format === "json" ? "application/json; charset=utf-8" : "text/markdown; charset=utf-8",
    "content-disposition": `attachment; filename="${filename}"`,
    "cache-control": "no-store",
  });
  response.end(content);
}

async function handleCreateDevice(request, response) {
  const body = await readJson(request);
  const now = new Date();
  const db = readDb();
  db.devices = db.devices || [];
  const deviceId = body.deviceId || randomId();
  const existingDevice = db.devices.find((candidate) => candidate.deviceId === deviceId);
  if (existingDevice && ["approved", "claimed"].includes(existingDevice.status) && existingDevice.userId) {
    const user = db.users.find((candidate) => candidate.id === existingDevice.userId);
    if (user) {
      existingDevice.deviceToken = existingDevice.deviceToken || createDeviceToken();
      existingDevice.status = "claimed";
      existingDevice.lastSeenAt = now.toISOString();
      writeDb(db);
      return sendJson(response, 200, {
        deviceCode: existingDevice.deviceCode,
        userCode: existingDevice.userCode,
        verificationUrl: `${getRequestBaseUrl(request)}/cli/verify?user_code=${encodeURIComponent(existingDevice.userCode)}`,
        expiresAt: existingDevice.expiresAt,
        alreadyLinked: true,
        licenseToken: existingDevice.deviceToken,
        plan: getUserPlan(db, user).plan,
        userId: user.id,
        email: user.email,
      });
    }
  }

  const device = {
    deviceCode: randomId(),
    userCode: formatUserCode(),
    deviceId,
    status: "pending",
    cliName: body.cliName || "Gravel CLI",
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 10 * 60 * 1000).toISOString(),
    approvedAt: "",
    userId: "",
  };

  db.devices.push(device);
  writeDb(db);

  sendJson(response, 201, {
    deviceCode: device.deviceCode,
    userCode: device.userCode,
    verificationUrl: `${getRequestBaseUrl(request)}/cli/verify?user_code=${encodeURIComponent(device.userCode)}`,
    expiresAt: device.expiresAt,
  });
}

function handleDeviceVerify(request, response, url) {
  const user = requireUser(request, response);
  if (!user) return;

  const userCode = normalizeUserCode(url.searchParams.get("user_code") || "");
  const db = readDb();
  const device = findPendingDevice(db, userCode);
  if (!device) {
    return sendHtml(response, 404, renderMessage("Device code not found", [
      "Start `saas-audit login` again and use the fresh verification link.",
    ]));
  }

  sendHtml(response, 200, renderDeviceVerify({ user, device }));
}

async function handleApproveDevice(request, response) {
  const user = requireUser(request, response, true);
  if (!user) return;

  const body = await readJson(request);
  const db = readDb();
  const device = findPendingDevice(db, body.userCode || "");
  if (!device) return sendJson(response, 404, { error: "device_not_found" });

  device.status = "approved";
  device.userId = user.id;
  device.approvedAt = new Date().toISOString();
  writeDb(db);
  sendJson(response, 200, { ok: true });
}

async function handleCliToken(request, response) {
  const body = await readJson(request);
  const db = readDb();
  const device = (db.devices || []).find((candidate) => candidate.deviceCode === body.deviceCode);
  if (!device) return sendJson(response, 404, { error: "device_not_found" });
  if (new Date(device.expiresAt).getTime() < Date.now()) {
    device.status = "expired";
    writeDb(db);
    return sendJson(response, 400, { error: "expired" });
  }
  if (device.status !== "approved") return sendJson(response, 202, { status: device.status });

  const user = db.users.find((candidate) => candidate.id === device.userId);
  if (!user) return sendJson(response, 404, { error: "user_not_found" });

  device.status = "claimed";
  device.deviceToken = device.deviceToken || createDeviceToken();
  device.claimedAt = device.claimedAt || new Date().toISOString();
  device.lastSeenAt = new Date().toISOString();
  writeDb(db);
  sendJson(response, 200, {
    licenseToken: device.deviceToken,
    plan: getUserPlan(db, user).plan,
    userId: user.id,
    email: user.email,
    deviceId: device.deviceId,
  });
}

async function handleDisconnectDevice(request, response) {
  const contentType = request.headers["content-type"] || "";
  const isJson = contentType.includes("application/json");
  const user = requireUser(request, response, isJson);
  if (!user) return;

  const body = isJson ? await readJson(request) : await readForm(request);
  const db = readDb();
  const device = (db.devices || []).find((candidate) => candidate.deviceId === body.deviceId && candidate.userId === user.id);
  if (!device) {
    if (isJson) return sendJson(response, 404, { error: "device_not_found" });
    response.writeHead(302, { location: "/dashboard#devices" });
    response.end();
    return;
  }

  device.status = "disconnected";
  device.disconnectedAt = new Date().toISOString();
  device.deviceToken = "";
  writeDb(db);
  if (isJson) return sendJson(response, 200, { ok: true });
  response.writeHead(302, { location: "/dashboard#devices" });
  response.end();
}

async function handleCliRunStart(request, response) {
  const auth = requireCliUser(request, response);
  if (!auth) return;

  const { db, user } = auth;
  const entitlement = getUserPlan(db, user);
  if (hasCompletedFreeRun(db, user.id) && !entitlement.paid) {
    return sendJson(response, 402, {
      error: "license_required",
      message: "Your free completed project run has been used. Purchase a license to continue.",
      checkoutUrl: getCheckoutUrl("pro", user),
    });
  }

  const body = await readJson(request);
  const scan = createRunRecord(user.id, body);
  db.scans.push(scan);
  writeDb(db);
  sendJson(response, 201, { run: scan, plan: entitlement.plan });
}

async function handleCliRunProgress(request, response, runId) {
  const auth = requireCliUser(request, response);
  if (!auth) return;

  const { db, user } = auth;
  const scan = db.scans.find((candidate) => candidate.id === runId && candidate.userId === user.id);
  if (!scan) return sendJson(response, 404, { error: "run_not_found" });

  const body = await readJson(request);
  updateRun(scan, body);
  writeDb(db);
  sendJson(response, 200, { run: scan });
}

async function handleCliRunComplete(request, response, runId) {
  const auth = requireCliUser(request, response);
  if (!auth) return;

  const { db, user } = auth;
  const scan = db.scans.find((candidate) => candidate.id === runId && candidate.userId === user.id);
  if (!scan) return sendJson(response, 404, { error: "run_not_found" });

  const body = await readJson(request);
  updateRun(scan, {
    ...body,
    status: "completed",
    percentComplete: 100,
    currentStep: "Audit completed",
  });
  scan.completedAt = scan.completedAt || new Date().toISOString();
  if (!hasCompletedFreeRun(db, user.id, scan.id) && !getUserPlan(db, user).paid) {
    scan.consumedFreeRun = true;
    user.trialCompletedAt = user.trialCompletedAt || scan.completedAt;
  }

  writeDb(db);
  sendJson(response, 200, { run: scan, analytics: buildAnalytics(db, user) });
}

async function handleRevenueCatWebhook(request, response) {
  if (config.revenueCatWebhookSecret) {
    const bearer = getBearerToken(request);
    if (bearer !== config.revenueCatWebhookSecret) {
      return sendJson(response, 401, { error: "invalid_webhook_secret" });
    }
  }

  const body = await readJson(request);
  const event = body.event || body;
  const appUserId = event.app_user_id || event.appUserId || body.app_user_id;
  const productId = event.product_id || event.productId || "";
  const entitlement = event.entitlement_id || event.entitlementId || "pro";
  const type = String(event.type || event.event_type || "").toLowerCase();
  const active = !["cancellation", "expiration", "billing_issue"].some((name) =>
    type.includes(name),
  );

  if (!appUserId) {
    return sendJson(response, 400, { error: "missing_app_user_id" });
  }

  const db = readDb();
  const user = db.users.find(
    (candidate) => candidate.id === appUserId || candidate.auth0UserId === appUserId,
  );
  if (!user) {
    return sendJson(response, 202, { status: "ignored", reason: "user_not_found" });
  }

  const existing = db.subscriptions.find((subscription) => subscription.userId === user.id);
  const subscription = existing || { id: randomId(), userId: user.id, createdAt: new Date().toISOString() };
  subscription.status = active ? "active" : "inactive";
  subscription.productId = productId;
  subscription.entitlement = entitlement;
  subscription.revenueCatAppUserId = appUserId;
  subscription.updatedAt = new Date().toISOString();

  if (!existing) db.subscriptions.push(subscription);
  writeDb(db);
  sendJson(response, 200, { ok: true });
}

function renderSignedInHome(html, user) {
  const signedInHeader = `<header class="site-header">
      ${renderBrand("/dashboard")}
      <nav class="nav" aria-label="Primary navigation">
        <a href="/dashboard">Dashboard</a>
        <a href="/analytics">Analytics</a>
        <a href="/release-notes">Release notes</a>
        <a href="/billing">Upgrade</a>
        <a href="/auth/logout">Log out</a>
      </nav>
      <a class="header-cta" href="/dashboard">Open dashboard</a>
    </header>`;

  return html
    .replace(/<header class="site-header">[\s\S]*?<\/header>/, signedInHeader)
    .replaceAll('href="/auth/login"', 'href="/dashboard"')
    .replaceAll(">Start free run<", ">Open dashboard<")
    .replaceAll(">Start free<", ">Open dashboard<")
    .replaceAll(">Choose Pro<", user.trialCompletedAt ? ">Upgrade<" : ">Open dashboard<");
}

function serveStatic(url, response) {
  const cleanPath = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, "");
  const pathname = cleanPath === "/" ? "/index.html" : cleanPath;
  const filePath = join(root, pathname);

  if (!filePath.startsWith(root) || !existsSync(filePath) || statSync(filePath).isDirectory()) {
    sendText(response, 404, "Not found");
    return;
  }

  serveFile(filePath, types[extname(filePath)] || "application/octet-stream", response);
}

function serveFile(filePath, contentType, response) {
  if (!existsSync(filePath) || statSync(filePath).isDirectory()) {
    sendText(response, 404, "Not found");
    return;
  }

  response.writeHead(200, {
    "content-type": contentType,
    "cache-control": "no-store",
  });
  createReadStream(filePath).pipe(response);
}

function upsertUser(profile) {
  const db = readDb();
  let user = db.users.find((candidate) => candidate.auth0UserId === profile.sub);

  if (!user) {
    user = {
      id: randomId(),
      auth0UserId: profile.sub,
      email: profile.email || "",
      name: profile.name || profile.nickname || profile.email || "Gravel user",
      picture: profile.picture || "",
      licenseToken: `grv_${randomId()}${randomId()}`,
      trialStartedAt: new Date().toISOString(),
      trialCompletedAt: "",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    db.users.push(user);
  } else {
    user.email = profile.email || user.email;
    user.name = profile.name || profile.nickname || user.name;
    user.picture = profile.picture || user.picture;
    user.updatedAt = new Date().toISOString();
  }

  writeDb(db);
  return user;
}

function requireCliUser(request, response) {
  const token = getBearerToken(request);
  const deviceId = request.headers["x-gravel-device-id"] || "";
  const db = readDb();
  const device = (db.devices || []).find((candidate) => candidate.deviceToken === token || (deviceId && candidate.deviceId === deviceId));
  if (device && device.deviceToken === token) {
    if (device.status === "disconnected") {
      sendJson(response, 401, { error: "device_disconnected", message: "This CLI device was disconnected. Run `saas-audit logout` and `saas-audit login` to reconnect." });
      return null;
    }
    const user = db.users.find((candidate) => candidate.id === device.userId);
    if (!user) {
      sendJson(response, 401, { error: "invalid_license_token" });
      return null;
    }
    device.lastSeenAt = new Date().toISOString();
    writeDb(db);
    return { db, user, device };
  }

  if (deviceId && device?.status === "disconnected") {
    sendJson(response, 401, { error: "device_disconnected", message: "This CLI device was disconnected. Run `saas-audit logout` and `saas-audit login` to reconnect." });
    return null;
  }

  const user = db.users.find((candidate) => candidate.licenseToken === token);
  if (!user) {
    sendJson(response, 401, { error: "invalid_license_token" });
    return null;
  }

  return { db, user };
}

function createRunRecord(userId, body = {}) {
  return {
    id: randomId(),
    userId,
    projectName: body.projectName || "Untitled SaaS audit",
    projectPathHash: body.projectPathHash || "",
    source: body.source || "cli",
    status: "running",
    percentComplete: 5,
    currentStep: "Audit started",
    findingsCount: 0,
    findingsSummary: emptyFindingsSummary(),
    findings: [],
    aiReviewStatus: "not_started",
    aiReviewSummary: "",
    aiReviewModel: "",
    aiReviewGeneratedAt: "",
    reportUrl: "",
    reportPath: "",
    consumedFreeRun: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    completedAt: "",
  };
}

function updateRun(scan, body = {}) {
  scan.status = body.status || scan.status;
  scan.percentComplete = clampNumber(body.percentComplete, scan.percentComplete, 0, 100);
  scan.currentStep = body.currentStep || scan.currentStep;
  scan.findingsCount = clampNumber(body.findingsCount, scan.findingsCount, 0, 100000);
  scan.findingsSummary = normalizeFindingsSummary(body.findingsSummary || scan.findingsSummary);
  if (Array.isArray(body.findings)) {
    scan.findings = body.findings.slice(0, 500).map(normalizeFinding);
  }
  scan.aiReviewStatus = body.aiReviewStatus || scan.aiReviewStatus;
  scan.aiReviewSummary = body.aiReviewSummary ? String(body.aiReviewSummary).slice(0, 1200) : scan.aiReviewSummary;
  scan.aiReviewModel = body.aiReviewModel ? String(body.aiReviewModel).slice(0, 120) : scan.aiReviewModel;
  scan.aiReviewGeneratedAt = body.aiReviewGeneratedAt || scan.aiReviewGeneratedAt;
  scan.reportUrl = body.reportUrl || scan.reportUrl;
  scan.reportPath = body.reportPath || scan.reportPath;
  scan.updatedAt = new Date().toISOString();
}

function normalizeFinding(finding = {}) {
  return {
    title: String(finding.title || "Untitled finding").slice(0, 220),
    severity: String(finding.severity || "info").slice(0, 30),
    category: String(finding.category || "general").slice(0, 80),
    file: String(finding.file || "").slice(0, 400),
    line: clampNumber(finding.line, 0, 0, 1000000),
    confidence: String(finding.confidence || "").slice(0, 80),
    evidence: String(finding.evidence || "").slice(0, 1000),
    risk: String(finding.risk || "").slice(0, 1600),
    recommendation: String(finding.recommendation || "").slice(0, 1600),
    standards: Array.isArray(finding.standards) ? finding.standards.slice(0, 10).map((value) => String(value).slice(0, 120)) : [],
  };
}

function emptyFindingsSummary() {
  return { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function normalizeFindingsSummary(summary = {}) {
  return {
    total: clampNumber(summary.total, 0, 0, 100000),
    critical: clampNumber(summary.critical, 0, 0, 100000),
    high: clampNumber(summary.high, 0, 0, 100000),
    medium: clampNumber(summary.medium, 0, 0, 100000),
    low: clampNumber(summary.low, 0, 0, 100000),
    info: clampNumber(summary.info, 0, 0, 100000),
  };
}

function getUserPlan(db, user) {
  const subscription = db.subscriptions.find(
    (candidate) => candidate.userId === user.id && candidate.status === "active",
  );
  return subscription
    ? { paid: true, plan: subscription.entitlement || "pro", subscription }
    : { paid: false, plan: "free", subscription: null };
}

function hasCompletedFreeRun(db, userId, excludeRunId = "") {
  return db.scans.some(
    (scan) =>
      scan.userId === userId &&
      scan.id !== excludeRunId &&
      scan.status === "completed" &&
      Boolean(scan.consumedFreeRun || scan.completedAt),
  );
}

function buildAnalytics(db, user) {
  const scans = db.scans
    .filter((scan) => scan.userId === user.id)
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const completed = scans.filter((scan) => scan.status === "completed");
  const latest = scans[0] || null;
  const severity = scans.reduce((acc, scan) => {
    const summary = normalizeFindingsSummary(scan.findingsSummary);
    for (const key of Object.keys(acc)) acc[key] += summary[key] || 0;
    return acc;
  }, emptyFindingsSummary());
  const plan = getUserPlan(db, user);

  return {
    plan: plan.plan,
    paid: plan.paid,
    freeRunUsed: hasCompletedFreeRun(db, user.id),
    totals: {
      runs: scans.length,
      completed: completed.length,
      running: scans.filter((scan) => scan.status === "running").length,
      findings: severity.total,
    },
    severity,
    latest,
    runs: scans,
  };
}

function renderAnalyticsMarkdown(user, analytics) {
  const lines = [
    "# Gravel Audit Report",
    "",
    `Account: ${user.email || user.name || user.id}`,
    `Plan: ${analytics.plan}`,
    `Free run: ${analytics.freeRunUsed ? "used" : "available"}`,
    `Runs: ${analytics.totals.runs}`,
    `Completed: ${analytics.totals.completed}`,
    `Findings: ${analytics.totals.findings}`,
    "",
    "## Severity Breakdown",
    "",
    `- Critical: ${analytics.severity.critical}`,
    `- High: ${analytics.severity.high}`,
    `- Medium: ${analytics.severity.medium}`,
    `- Low: ${analytics.severity.low}`,
    `- Info: ${analytics.severity.info}`,
    "",
    "## Runs",
    "",
  ];

  for (const run of analytics.runs) {
    const summary = normalizeFindingsSummary(run.findingsSummary);
    lines.push(
      `### ${run.projectName}`,
      "",
      `- Run ID: ${run.id}`,
      `- Status: ${run.status}`,
      `- Completed: ${run.completedAt || "not completed"}`,
      `- Findings: ${summary.total} total, ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.info} info`,
      `- AI review: ${run.aiReviewStatus || "not_started"}${run.aiReviewModel ? ` (${run.aiReviewModel})` : ""}`,
      `- Report path: ${run.reportPath || run.reportUrl || "not reported"}`,
      "",
    );

    if (run.aiReviewSummary) {
      lines.push("#### AI Review Summary", "", run.aiReviewSummary, "");
    }

    if (Array.isArray(run.findings) && run.findings.length) {
      lines.push("#### Findings", "");
      for (const finding of run.findings) {
        lines.push(
          `- [${finding.severity}] ${finding.title}`,
          `  - Category: ${finding.category || "general"}`,
          `  - File: ${finding.file || "project-wide"}${finding.line ? `:${finding.line}` : ""}`,
          `  - Recommendation: ${finding.recommendation || "Review in local report."}`,
        );
      }
      lines.push("");
    }
  }

  return `${lines.join("\n")}\n`;
}

function findPendingDevice(db, userCode) {
  const normalized = normalizeUserCode(userCode);
  return (db.devices || []).find(
    (device) =>
      normalizeUserCode(device.userCode) === normalized &&
      device.status === "pending" &&
      new Date(device.expiresAt).getTime() > Date.now(),
  );
}

function formatUserCode() {
  return randomBytes(4).toString("hex").toUpperCase().replace(/^(.{4})(.{4})$/, "$1-$2");
}

function createDeviceToken() {
  return `grvdev_${randomBytes(24).toString("base64url")}`;
}

function normalizeUserCode(value) {
  return String(value || "").replace(/[^a-z0-9]/gi, "").toUpperCase();
}

function packCliTarball() {
  const outDir = join(dataDir, "downloads");
  mkdirSync(outDir, { recursive: true });
  const result = spawnSync("npm", ["pack", "--pack-destination", outDir, "--silent"], {
    cwd: projectRoot,
    env: { ...process.env, npm_config_cache: join(dataDir, "npm-cache") },
    encoding: "utf8",
  });

  if (result.status !== 0) {
    return { ok: false, error: result.stderr || result.stdout || "npm pack failed" };
  }

  const filename = String(result.stdout || "").trim().split(/\r?\n/).pop();
  if (!filename) return { ok: false, error: "npm pack did not return an archive name" };
  return { ok: true, filename, path: join(outDir, filename) };
}

function requireUser(request, response, json = false) {
  const session = parseCookies(request.headers.cookie || "").gravel_session;
  const payload = verifySession(session || "");
  if (!payload) {
    if (json) {
      sendJson(response, 401, { error: "login_required" });
    } else {
      response.writeHead(302, { location: "/auth/login" });
      response.end();
    }
    return null;
  }

  const user = readDb().users.find((candidate) => candidate.id === payload.userId);
  if (!user) {
    if (json) sendJson(response, 401, { error: "user_not_found" });
    else {
      response.writeHead(302, { location: "/auth/login" });
      response.end();
    }
    return null;
  }

  return user;
}

function getSessionUser(request) {
  const session = parseCookies(request.headers.cookie || "").gravel_session;
  const payload = verifySession(session || "");
  if (!payload) return null;
  return readDb().users.find((candidate) => candidate.id === payload.userId) || null;
}

function signOAuthState() {
  const nonce = randomId();
  const timestamp = Date.now().toString(36);
  const payload = `${nonce}.${timestamp}`;
  const signature = createHmac("sha256", config.sessionSecret).update(payload).digest("hex");
  return `${payload}.${signature}`;
}

function verifyOAuthState(value) {
  const [nonce, timestamp, signature] = String(value || "").split(".");
  if (!nonce || !timestamp || !signature) return { ok: false, reason: "malformed" };

  const payload = `${nonce}.${timestamp}`;
  const expected = createHmac("sha256", config.sessionSecret).update(payload).digest("hex");
  if (!safeEqual(signature, expected)) return { ok: false, reason: "signature" };

  const createdAt = Number.parseInt(timestamp, 36);
  if (!Number.isFinite(createdAt) || Date.now() - createdAt > 10 * 60 * 1000) {
    return { ok: false, reason: "expired" };
  }

  return { ok: true };
}

function signSession(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", config.sessionSecret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verifySession(value) {
  const [encoded, signature] = value.split(".");
  if (!encoded || !signature) return null;

  const expected = createHmac("sha256", config.sessionSecret).update(encoded).digest("base64url");
  if (!safeEqual(signature, expected)) return null;

  try {
    return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function safeEqual(a, b) {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  return aBuffer.length === bBuffer.length && timingSafeEqual(aBuffer, bBuffer);
}

function auth0Configured() {
  return Boolean(config.auth0Domain && config.auth0ClientId && config.auth0ClientSecret);
}

function publicUser(user) {
  return {
    id: user.id,
    auth0UserId: user.auth0UserId,
    email: user.email,
    name: user.name,
    trialStartedAt: user.trialStartedAt,
    trialCompletedAt: user.trialCompletedAt,
  };
}

function renderDashboard({ user, scans, paid, trialUsed }) {
  const latestScan = scans[0];
  const statusText = paid ? "Active plan" : trialUsed ? "Trial used" : "Trial available";
  const checkoutUrl = getCheckoutUrl("pro", user);
  const db = readDb();
  const analytics = buildAnalytics(db, user);
  const devices = getLinkedDevices(db, user);

  return layout(
    "Dashboard",
    `
      <header class="app-header">
        ${renderBrand("/dashboard")}
        <nav class="nav app-nav" aria-label="Dashboard navigation">
          <a href="#overview">Overview</a>
          <a href="/release-notes">Release notes</a>
          <a href="/analytics">Analytics</a>
          <a href="${escapeHtml(checkoutUrl)}">Upgrade</a>
          <a href="/auth/logout">Log out</a>
        </nav>
      </header>
      <main class="dashboard-shell" id="overview">
        <section class="dashboard-hero">
          <div>
            <p class="eyebrow">${escapeHtml(statusText)}</p>
            <h1>Welcome, ${escapeHtml(user.name)}.</h1>
            <p class="hero-lede">Download the CLI, connect it through browser login, and run audits locally. Gravel validates your license before each run and sends completed results back here.</p>
          </div>
          <div class="status-card">
            <span>License token</span>
            <code>${escapeHtml(user.licenseToken)}</code>
          </div>
        </section>

        <section class="dashboard-grid">
          <article class="panel">
            <div class="panel-heading">
              <h2>${icon("terminal")} CLI access</h2>
              <span class="pill ${paid ? "good" : trialUsed ? "warn" : "good"}">${escapeHtml(statusText)}</span>
            </div>
            <p>${trialUsed && !paid ? "Your free completed run has been used. The CLI will ask you to purchase a license before the next run." : "Download the CLI and run your first completed project audit for free."}</p>
            <div class="panel-actions">
              ${
                trialUsed && !paid
                  ? `<a class="button button-primary" href="${escapeHtml(checkoutUrl)}">${icon("key")} Purchase license</a>`
                  : `<a class="button button-primary" href="/download">${icon("download")} Download CLI</a>`
              }
              <a class="button button-secondary" href="#download-cli">Setup commands</a>
            </div>
          </article>

          <article class="panel">
            <div class="panel-heading">
              <h2>Latest progress</h2>
              <span class="pill">${latestScan ? escapeHtml(latestScan.status) : "No scans"}</span>
            </div>
            <div class="progress-bar" aria-label="Latest scan progress">
              <span style="width: ${latestScan ? Number(latestScan.percentComplete) : 0}%"></span>
            </div>
            <p id="latest-progress-copy">${latestScan ? `${escapeHtml(latestScan.currentStep)} · ${latestScan.findingsCount} findings` : "Run the CLI locally to see progress and reports here."}</p>
          </article>
        </section>

        <section class="panel devices-panel" id="devices">
          <div class="panel-heading">
            <h2>${icon("terminal")} Linked devices</h2>
            <span class="pill">${devices.length} connected</span>
          </div>
          ${renderLinkedDevices(devices)}
        </section>

        <section class="panel download-panel" id="download-cli">
          <div class="panel-heading">
            <h2>${icon("download")} Download CLI</h2>
            <span class="pill">Tarball</span>
          </div>
          <p>Install Node.js 20 or newer, download the CLI archive, then install it into a user-owned system path. After that, <code>saas-audit</code> works from any project folder.</p>
          <div class="install-grid">
            ${renderInstallCard("macOS", "brew install node@20", "mkdir -p ~/.npm-global && npm config set prefix ~/.npm-global && echo 'export PATH=\"$HOME/.npm-global/bin:$PATH\"' >> ~/.zshrc && export PATH=\"$HOME/.npm-global/bin:$PATH\" && npm install -g ~/Downloads/ai-saas-audit-agent-*.tgz")}
            ${renderInstallCard("Windows", "winget install OpenJS.NodeJS.LTS", "npm config set prefix \"%USERPROFILE%\\.npm-global\" && setx PATH \"%USERPROFILE%\\.npm-global;%PATH%\" && npm install -g \"%USERPROFILE%\\Downloads\\ai-saas-audit-agent-*.tgz\"")}
            ${renderInstallCard("Linux", "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs", "mkdir -p ~/.npm-global && npm config set prefix ~/.npm-global && echo 'export PATH=\"$HOME/.npm-global/bin:$PATH\"' >> ~/.bashrc && export PATH=\"$HOME/.npm-global/bin:$PATH\" && npm install -g ~/Downloads/ai-saas-audit-agent-*.tgz")}
          </div>
          <pre><code>saas-audit login
cd /path/to/your/project
saas-audit scan . --out-dir ./audit-output</code></pre>
          <div class="panel-actions">
            <a class="button button-primary" href="/download">${icon("download")} Download tarball</a>
          </div>
        </section>

        <section class="analytics-section" id="analytics">
          <div class="panel-heading">
            <div>
              <p class="eyebrow">Analytics</p>
              <h2>${icon("activity")} Audit summary</h2>
            </div>
            <a class="button button-secondary" href="/analytics">Open detailed report</a>
          </div>
          <div class="analytics-grid">
            ${renderMetricCard("Runs", analytics.totals.runs, "Total CLI project runs")}
            ${renderMetricCard("Completed", analytics.totals.completed, "Successful completed audits")}
            ${renderMetricCard("Findings", analytics.totals.findings, "Findings reported by CLI")}
            ${renderMetricCard("Plan", analytics.plan, analytics.freeRunUsed ? "Free run used" : "Free run available")}
          </div>
        </section>

        <section class="panel scan-panel">
          <div class="panel-heading">
            <h2>${icon("activity")} Project runs</h2>
            <span>${scans.length} total</span>
          </div>
          ${renderScanTable(scans)}
        </section>
      </main>
      ${renderDeviceDisconnectScript()}
    `,
  );
}

function renderBilling({ user, plan }) {
  const selectedPlan = plan === "starter" ? "starter" : "pro";
  const packageId =
    selectedPlan === "starter"
      ? config.revenueCatStarterPackageId || "current monthly package"
      : config.revenueCatProPackageId || "RevenueCat paywall default";

  return layout(
    "Upgrade",
    `
      <header class="app-header">
        ${renderBrand("/dashboard")}
        <nav class="nav app-nav" aria-label="Billing navigation">
          <a href="/dashboard">Dashboard</a>
          <a href="/release-notes">Release notes</a>
          <a href="/analytics">Analytics</a>
          <a href="/auth/logout">Log out</a>
        </nav>
      </header>
      <main class="dashboard-shell billing-shell" data-plan="${escapeHtml(selectedPlan)}">
        <section class="dashboard-hero">
          <div>
            <p class="eyebrow">RevenueCat checkout</p>
            <h1>Unlock Gravel ${escapeHtml(selectedPlan)}.</h1>
            <p class="hero-lede">Gravel will use your signed-in account as the RevenueCat App User ID, so the subscription maps back to your dashboard automatically.</p>
          </div>
          <div class="status-card">
            <span>App User ID</span>
            <code>${escapeHtml(user.id)}</code>
          </div>
        </section>

        <section class="panel billing-panel">
          <div class="panel-heading">
            <h2>Checkout</h2>
            <span class="pill">${escapeHtml(packageId)}</span>
          </div>
          ${
            config.revenueCatApiKey
              ? `<div id="billing-status" class="empty-state">Loading RevenueCat checkout...</div>
                 <div id="billing-actions" class="panel-actions"></div>
                 <div id="revenuecat-paywall"></div>`
              : `<p class="empty-state">Add REVENUECAT_API_KEY to .env to enable the RevenueCat Web SDK checkout.</p>`
          }
        </section>
      </main>
      <script type="module" src="/billing.js"></script>
    `,
  );
}

function renderAnalyticsPage({ user, analytics }) {
  const checkoutUrl = getCheckoutUrl("pro", user);
  return layout(
    "Analytics",
    `
      <header class="app-header">
        ${renderBrand("/dashboard")}
        <nav class="nav app-nav" aria-label="Analytics navigation">
          <a href="/dashboard">Dashboard</a>
          <a href="/release-notes">Release notes</a>
          <a href="${escapeHtml(checkoutUrl)}">Upgrade</a>
          <a href="/auth/logout">Log out</a>
        </nav>
      </header>
      <main class="dashboard-shell">
        <section class="dashboard-hero">
          <div>
            <p class="eyebrow">Analytics</p>
            <h1>Detailed audit report.</h1>
            <p class="hero-lede">Review CLI runs, project names, severity totals, report paths, and license usage for ${escapeHtml(user.email || user.name)}.</p>
          </div>
          <div class="status-card">
            <span>Plan</span>
            <code>${escapeHtml(analytics.plan)} · ${analytics.freeRunUsed ? "free run used" : "free run available"}</code>
          </div>
        </section>
        <section class="analytics-grid">
          ${renderMetricCard("Runs", analytics.totals.runs, "Total CLI project runs")}
          ${renderMetricCard("Completed", analytics.totals.completed, "Successful completed audits")}
          ${renderMetricCard("Running", analytics.totals.running, "Audits currently reporting progress")}
          ${renderMetricCard("Findings", analytics.totals.findings, "Total reported findings")}
        </section>
        <section class="analytics-detail-grid">
          <article class="panel">
            <div class="panel-heading">
              <h2>${icon("activity")} Severity breakdown</h2>
              <span class="pill">${analytics.severity.total} findings</span>
            </div>
            ${renderSeverityReport(analytics.severity)}
          </article>
          <article class="panel">
            <div class="panel-heading">
            <h2>${icon("download")} Latest report</h2>
              <span class="pill">${analytics.latest ? escapeHtml(analytics.latest.status) : "No data"}</span>
            </div>
            ${renderLatestReport(analytics.latest)}
          </article>
        </section>
        <section class="panel scan-panel">
          <div class="panel-heading">
            <h2>${icon("terminal")} Run history</h2>
            <div class="panel-actions compact-actions">
              <a class="button button-secondary" href="/analytics/report.md">${icon("download")} Markdown</a>
              <a class="button button-secondary" href="/analytics/findings.json">${icon("download")} JSON</a>
              <span>${analytics.runs.length} total</span>
            </div>
          </div>
          ${renderScanTable(analytics.runs)}
        </section>
      </main>
    `,
  );
}

function renderScanTable(scans) {
  if (!scans.length) {
    return `<p class="empty-state">No CLI project runs yet. Download the CLI, run browser login, then scan a repository to populate this table.</p>`;
  }

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Project</th>
            <th>Status</th>
            <th>Progress</th>
            <th>Findings</th>
            <th>AI review</th>
            <th>Free run</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
          ${scans
            .map(
              (scan) => `
                <tr>
                  <td>${escapeHtml(scan.projectName)}</td>
                  <td>${escapeHtml(scan.status)}</td>
                  <td>${scan.percentComplete}%</td>
                  <td>${scan.findingsSummary?.total ?? scan.findingsCount}</td>
                  <td>${escapeHtml(scan.aiReviewStatus || "not_started")}</td>
                  <td>${scan.consumedFreeRun ? "yes" : "no"}</td>
                  <td>${new Date(scan.updatedAt).toLocaleString()}</td>
                </tr>
              `,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderMetricCard(label, value, caption) {
  return `<article class="metric-card">
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(value)}</strong>
    <p>${escapeHtml(caption)}</p>
  </article>`;
}

function renderReleaseNotes({ user }) {
  const nav = user
    ? `<a href="/dashboard">Dashboard</a><a href="/analytics">Analytics</a><a href="/billing">Upgrade</a><a href="/auth/logout">Log out</a>`
    : `<a href="/">Home</a><a href="/#product">Product</a><a href="/#pricing">Pricing</a><a href="/auth/login">Sign in</a>`;

  return layout(
    "Release Notes",
    `
      <header class="app-header">
        ${renderBrand(user ? "/dashboard" : "/")}
        <nav class="nav app-nav" aria-label="Release notes navigation">
          ${nav}
        </nav>
      </header>
      <main class="dashboard-shell">
        <section class="dashboard-hero">
          <div>
            <p class="eyebrow">Release notes</p>
            <h1>What changed in Gravel beta.</h1>
            <p class="hero-lede">A short product log for CLI install flow, device linking, licensing, analytics, and report export improvements.</p>
          </div>
          <div class="status-card">
            <span>Channel</span>
            <code>Beta</code>
          </div>
        </section>
        <section class="panel">
          <div class="panel-heading">
            <h2>${icon("activity")} Latest updates</h2>
            <span class="pill">May 2026</span>
          </div>
          <div class="release-list">
            ${renderReleaseNote("Device management", "Linked devices now appear on the dashboard and can be disconnected. New CLI logins use device-scoped tokens so access can be revoked per machine.")}
            ${renderReleaseNote("Detailed exports", "Analytics now offers Markdown and JSON downloads with run history, severity totals, report paths, and detailed findings sent by the CLI.")}
            ${renderReleaseNote("Project run history", "Every completed CLI scan appends a `gravel-run-history.md` summary inside the audited project so repeat runs build a local audit log.")}
            ${renderReleaseNote("System CLI install", "Install instructions now use a user-owned npm global prefix so `saas-audit` works from any project folder without path-based commands.")}
            ${renderReleaseNote("RevenueCat licensing", "The CLI checks backend subscription state before each run. One completed project run is free; repeat scans require an active entitlement.")}
          </div>
        </section>
      </main>
    `,
  );
}

function renderReleaseNote(title, body) {
  return `<article class="release-note">
    <strong>${escapeHtml(title)}</strong>
    <p>${escapeHtml(body)}</p>
  </article>`;
}

function renderBrand(href = "/") {
  return `<a class="brand" href="${escapeHtml(href)}" aria-label="Gravel home">
    <span class="brand-mark" aria-hidden="true">G</span>
    <span>Gravel</span>
    <span class="beta-tag">Beta</span>
  </a>`;
}

function getLinkedDevices(db, user) {
  return (db.devices || [])
    .filter((device) => device.userId === user.id && ["approved", "claimed"].includes(device.status))
    .sort((a, b) => String(b.approvedAt || b.createdAt).localeCompare(String(a.approvedAt || a.createdAt)));
}

function renderLinkedDevices(devices) {
  if (!devices.length) {
    return `<p class="empty-state">No CLI devices are linked yet. Download the tarball, install it with the setup commands, then run <code>saas-audit login</code> to connect this account.</p>`;
  }

  return `<div class="device-list">
    ${devices.map((device) => `<article class="device-row">
      <div>
        <strong>${escapeHtml(device.cliName || "Gravel CLI")}</strong>
        <span>${escapeHtml(device.userCode)} · ${escapeHtml(device.status)}${device.lastSeenAt ? ` · last seen ${new Date(device.lastSeenAt).toLocaleString()}` : ""}</span>
      </div>
      <div class="device-actions">
        <time>${new Date(device.approvedAt || device.createdAt).toLocaleString()}</time>
        <form method="post" action="/api/devices/disconnect" data-disconnect-device>
          <input type="hidden" name="deviceId" value="${escapeHtml(device.deviceId || "")}" />
          <button class="button button-ghost danger" type="submit">${icon("unlink")} Disconnect</button>
        </form>
      </div>
    </article>`).join("")}
  </div>`;
}

function renderDeviceDisconnectScript() {
  return `<script>
    document.querySelectorAll("[data-disconnect-device]").forEach((form) => {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const response = await fetch("/api/devices/disconnect", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ deviceId: form.querySelector("[name='deviceId']")?.value || "" })
        });
        if (response.ok) window.location.reload();
      });
    });
  </script>`;
}

function renderInstallCard(os, nodeCommand, unpackCommand) {
  return `<article class="install-card">
    <h3>${escapeHtml(os)}</h3>
    <span>Install Node.js</span>
    <code>${escapeHtml(nodeCommand)}</code>
    <span>Unpack CLI</span>
    <code>${escapeHtml(unpackCommand)}</code>
  </article>`;
}

function renderSeverityReport(severity) {
  if (!severity.total) {
    return `<p class="empty-state">No findings have been reported yet. Run the CLI and complete a project audit to populate this report.</p>`;
  }

  return `<div class="severity-list">
    ${["critical", "high", "medium", "low", "info"].map((level) => {
      const count = severity[level] || 0;
      const width = severity.total ? Math.round((count / severity.total) * 100) : 0;
      return `<div class="severity-row">
        <div>
          <strong>${escapeHtml(level)}</strong>
          <span>${count}</span>
        </div>
        <div class="severity-track"><span class="severity-fill ${escapeHtml(level)}" style="width: ${width}%"></span></div>
      </div>`;
    }).join("")}
  </div>`;
}

function renderLatestReport(latest) {
  if (!latest) {
    return `<p class="empty-state">No completed report yet. Your latest CLI run will appear here after it reports progress.</p>`;
  }

  const summary = normalizeFindingsSummary(latest.findingsSummary);
  return `<dl class="report-list">
    <div><dt>Project</dt><dd>${escapeHtml(latest.projectName)}</dd></div>
    <div><dt>Status</dt><dd>${escapeHtml(latest.status)}</dd></div>
    <div><dt>Progress</dt><dd>${latest.percentComplete}%</dd></div>
    <div><dt>Findings</dt><dd>${summary.total} total, ${summary.critical} critical, ${summary.high} high</dd></div>
    <div><dt>AI review</dt><dd>${escapeHtml(latest.aiReviewStatus || "not_started")}${latest.aiReviewModel ? ` · ${escapeHtml(latest.aiReviewModel)}` : ""}</dd></div>
    ${latest.aiReviewSummary ? `<div><dt>AI summary</dt><dd>${escapeHtml(latest.aiReviewSummary)}</dd></div>` : ""}
    <div><dt>Report path</dt><dd>${escapeHtml(latest.reportPath || latest.reportUrl || "Not reported")}</dd></div>
    <div><dt>Updated</dt><dd>${new Date(latest.updatedAt).toLocaleString()}</dd></div>
  </dl>`;
}

function icon(name) {
  const icons = {
    activity: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M22 12h-4l-3 8-6-16-3 8H2"/></svg>',
    download: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></svg>',
    key: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m15.5 7.5 1 1"/><path d="m13 10 1 1"/><path d="M5 19l6.5-6.5"/><circle cx="15" cy="9" r="5"/></svg>',
    terminal: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m4 17 6-6-6-6"/><path d="M12 19h8"/></svg>',
    unlink: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m18.84 12.25 1.41-1.41a4 4 0 0 0-5.66-5.66l-2.12 2.12"/><path d="m5.17 11.75-1.41 1.41a4 4 0 0 0 5.66 5.66l2.12-2.12"/><path d="m8 8 8 8"/></svg>',
  };
  return `<span class="svg-icon">${icons[name] || icons.activity}</span>`;
}

function renderMessage(title, messages) {
  return layout(
    title,
    `
      <main class="message-shell">
        ${renderBrand("/")}
        <section class="panel">
          <h1>${escapeHtml(title)}</h1>
          ${messages.map((message) => `<p>${escapeHtml(message)}</p>`).join("")}
          <a class="button button-primary" href="/">Back home</a>
        </section>
      </main>
    `,
  );
}

function renderDeviceVerify({ user, device }) {
  return layout(
    "Connect CLI",
    `
      <main class="message-shell">
        ${renderBrand("/")}
        <section class="panel">
          <p class="eyebrow">CLI login</p>
          <h1>Connect ${escapeHtml(device.cliName)}?</h1>
          <p>This will let the CLI run audits for ${escapeHtml(user.email || user.name)} and report project analytics to your dashboard.</p>
          <code>${escapeHtml(device.userCode)}</code>
          <form method="post" action="/api/cli/device/approve" data-device-form>
            <input type="hidden" name="userCode" value="${escapeHtml(device.userCode)}" />
            <button class="button button-primary" type="submit">${icon("key")} Approve CLI</button>
            <a class="button button-secondary" href="/dashboard">Cancel</a>
          </form>
        </section>
      </main>
      <script>
        document.querySelector("[data-device-form]")?.addEventListener("submit", async (event) => {
          event.preventDefault();
          const form = event.currentTarget;
          const response = await fetch(form.action, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ userCode: form.userCode.value })
          });
          window.location.href = response.ok ? "/dashboard" : "/cli/verify?user_code=" + encodeURIComponent(form.userCode.value);
        });
      </script>
    `,
  );
}

function getCheckoutUrl(plan, user) {
  const url = plan === "starter" ? config.revenueCatStarterUrl : config.revenueCatProUrl;
  if (!url || url.includes("replace-with")) {
    return `${config.appBaseUrl}/billing?plan=${encodeURIComponent(plan)}`;
  }

  const checkoutUrl = new URL(url);
  checkoutUrl.searchParams.set("app_user_id", user.id);
  checkoutUrl.searchParams.set("email", user.email);
  return checkoutUrl.toString();
}

function layout(title, body) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)} | Gravel</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body>${body}</body>
</html>`;
}

function cookie(name, value, options = {}) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "SameSite=Lax",
  ];

  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (typeof options.maxAge === "number") parts.push(`Max-Age=${options.maxAge}`);

  return parts.join("; ");
}

function parseCookies(header) {
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        return [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
      }),
  );
}

function getBearerToken(request) {
  const auth = request.headers.authorization || "";
  return auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
}

function randomId() {
  return randomBytes(16).toString("hex");
}

function clampNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, number));
}

async function readJson(request) {
  const raw = await readBody(request);
  if (!raw) return {};
  return JSON.parse(raw);
}

async function readForm(request) {
  const raw = await readBody(request);
  return Object.fromEntries(new URLSearchParams(raw));
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function sendJson(response, status, data) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(data));
}

function sendText(response, status, text) {
  response.writeHead(status, { "content-type": "text/plain; charset=utf-8" });
  response.end(text);
}

function sendHtml(response, status, html) {
  response.writeHead(status, { "content-type": "text/html; charset=utf-8" });
  response.end(html);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
