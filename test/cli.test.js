import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { makeProject } from "./helpers.js";

const BIN = path.resolve("bin/saas-audit.js");
const FIXTURE = path.resolve("test/fixtures/vulnerable-app");

function run(args, options = {}) {
  const result = spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", AUDITSAAS_AI_REVIEW: "false" },
    ...options,
  });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
}

async function tmpOut() {
  return fs.mkdtemp(path.join(os.tmpdir(), "auditsaas-cli-"));
}

test("usage errors exit 2 with a clear message", async () => {
  const unknownFlag = run(["scan", FIXTURE, "--fokus", "ai"]);
  assert.equal(unknownFlag.code, 2);
  assert.match(unknownFlag.stderr, /Unknown option '--fokus'/);

  const badFocus = run(["scan", FIXTURE, "--focus", "everything"]);
  assert.equal(badFocus.code, 2);
  assert.match(badFocus.stderr, /Invalid --focus "everything"/);

  const badFailOn = run(["scan", FIXTURE, "--fail-on", "severe"]);
  assert.equal(badFailOn.code, 2);

  const badUrl = run(["scan", FIXTURE, "--url", "app.example.com"]);
  assert.equal(badUrl.code, 2);
  assert.match(badUrl.stderr, /Invalid --url/);

  const missing = run(["scan", path.join(os.tmpdir(), "definitely-not-a-real-dir-auditsaas")]);
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /does not exist/);

  const fileTarget = run(["scan", path.join(FIXTURE, "package.json")]);
  assert.equal(fileTarget.code, 2);
  assert.match(fileTarget.stderr, /not a directory/);

  const unknownCommand = run(["scna"]);
  assert.equal(unknownCommand.code, 2);
});

test("--fail-on sets exit code 1 only when findings meet the threshold", async () => {
  const failing = run(["scan", FIXTURE, "--out-dir", await tmpOut(), "--no-history", "--fail-on", "critical"]);
  assert.equal(failing.code, 1, failing.stderr);
  assert.match(failing.stdout + failing.stderr, /at or above "critical"/);

  const clean = await makeProject({ "src/index.ts": "export const ok = true;\n" });
  const passing = run(["scan", clean, "--out-dir", await tmpOut(), "--no-history", "--fail-on", "high"]);
  assert.equal(passing.code, 0, passing.stderr);
});

test("options work before the path and --json keeps stdout machine-readable", async () => {
  const outDir = await tmpOut();
  const result = run(["scan", "--json", "--no-history", "--out-dir", outDir, "--focus", "payments", FIXTURE]);
  assert.equal(result.code, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.focus, "payments");
  assert.ok(parsed.findings.some((finding) => finding.id === "PAYMENT_STRIPE_WEBHOOK_SIGNATURE_MISSING"));
  assert.ok(parsed.findings.every((finding) => finding.fingerprint));
  assert.match(result.stderr, /Scanning/);
});

test("--no-history leaves the scanned project untouched", async () => {
  const project = await makeProject({ "src/index.ts": "export const ok = true;\n" });
  run(["scan", project, "--out-dir", await tmpOut(), "--no-history"]);
  await assert.rejects(fs.access(path.join(project, "auditsaas-run-history.md")));

  run(["scan", project, "--out-dir", await tmpOut()]);
  await fs.access(path.join(project, "auditsaas-run-history.md"));
});

test("rules command lists the catalog", () => {
  const text = run(["rules"]);
  assert.equal(text.code, 0);
  assert.match(text.stdout, /AUTHZ_IDOR_POSSIBLE/);

  const json = JSON.parse(run(["rules", "--json"]).stdout);
  assert.ok(json.length >= 65);
  assert.ok(json.every((rule) => rule.id && rule.severity && rule.category));
});

test("version and help", () => {
  const version = run(["--version"]);
  assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+$/);
  const help = run(["scan", "--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /--fail-on/);
});
