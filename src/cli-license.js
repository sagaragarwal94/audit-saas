import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";

const CONFIG_DIR = path.join(os.homedir(), ".gravel");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");

export function apiBase() {
  return process.env.GRAVEL_API_BASE || process.env.GRAVEL_API_URL || "http://127.0.0.1:4000";
}

export async function readCredentials() {
  if (process.env.GRAVEL_LICENSE_TOKEN) {
    return { licenseToken: process.env.GRAVEL_LICENSE_TOKEN, source: "env" };
  }

  try {
    return { ...JSON.parse(await fs.readFile(CONFIG_PATH, "utf8")), source: "file" };
  } catch {
    return null;
  }
}

export async function getDeviceId() {
  const credentials = await readCredentials();
  if (credentials?.deviceId) return credentials.deviceId;
  return `cli_${createHash("sha256").update(`${os.hostname()}:${CONFIG_PATH}`).digest("hex").slice(0, 24)}`;
}

export async function writeCredentials(credentials) {
  await fs.mkdir(CONFIG_DIR, { recursive: true });
  await fs.writeFile(CONFIG_PATH, `${JSON.stringify(credentials, null, 2)}\n`, { mode: 0o600 });
}

export async function clearCredentials() {
  await fs.rm(CONFIG_PATH, { force: true });
}

export async function createDevice(deviceId) {
  return request("/api/cli/device", {
    method: "POST",
    body: { cliName: "Gravel CLI", deviceId },
  });
}

export async function pollDeviceToken(deviceCode) {
  return request("/api/cli/token", {
    method: "POST",
    body: { deviceCode },
    allowAccepted: true,
  });
}

export async function startRun(credentials, payload) {
  return request("/api/cli/runs/start", {
    method: "POST",
    token: credentials.licenseToken,
    deviceId: credentials.deviceId,
    body: payload,
  });
}

export async function updateRun(credentials, runId, payload) {
  return request(`/api/cli/runs/${runId}/progress`, {
    method: "POST",
    token: credentials.licenseToken,
    deviceId: credentials.deviceId,
    body: payload,
  });
}

export async function completeRun(credentials, runId, payload) {
  return request(`/api/cli/runs/${runId}/complete`, {
    method: "POST",
    token: credentials.licenseToken,
    deviceId: credentials.deviceId,
    body: payload,
  });
}

export async function whoami(credentials) {
  return request("/api/me", {
    method: "GET",
    token: credentials.licenseToken,
    deviceId: credentials.deviceId,
  });
}

export function hashProjectPath(target) {
  return createHash("sha256").update(path.resolve(target)).digest("hex").slice(0, 24);
}

async function request(route, { method, token, deviceId, body, allowAccepted = false }) {
  const response = await fetch(`${apiBase()}${route}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(deviceId ? { "x-gravel-device-id": deviceId } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json().catch(() => ({}));
  if (allowAccepted && response.status === 202) return data;
  if (!response.ok) {
    const error = new Error(data.message || data.error || `Request failed with ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}
