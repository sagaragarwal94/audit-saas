#!/usr/bin/env node
// Release gate for packaging problems unit tests can't see:
//  1. `npm publish --dry-run` must not auto-correct package.json. npm applies
//     those corrections only at publish time (not in `npm pack`), so the
//     published manifest would silently differ from the committed one --
//     npm 12 drops "./"-prefixed bin entries this way, which would ship a
//     package with no runnable command.
//  2. The packed tarball must install into an empty project, and both bins
//     must run and scan the vulnerable fixture.
// Run via `npm run smoke:package`.

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "auditsaas-smoke-"));
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

try {
  const corrections = publishCorrections();
  if (corrections.length) {
    throw new Error(`npm would rewrite package.json at publish time (run "npm pkg fix" and commit):\n${corrections.join("\n")}`);
  }

  const packed = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", work], root));
  // npm <=11 prints [ {...} ]; npm 12 prints { "<name>": {...} }.
  const entry = Array.isArray(packed) ? packed[0] : (packed.filename ? packed : Object.values(packed)[0]);
  const tarball = path.join(work, entry.filename);

  const app = path.join(work, "app");
  fs.mkdirSync(app);
  fs.writeFileSync(path.join(app, "package.json"), JSON.stringify({ name: "smoke", version: "1.0.0", private: true }));
  run("npm", ["install", "--no-audit", "--no-fund", tarball], app);

  const expected = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const installed = JSON.parse(fs.readFileSync(path.join(app, "node_modules", expected.name, "package.json"), "utf8"));
  const missingBins = Object.keys(expected.bin).filter((name) => !installed.bin?.[name]);
  if (missingBins.length) throw new Error(`bins dropped from the published manifest: ${missingBins.join(", ")}`);

  for (const bin of Object.keys(expected.bin)) {
    const binPath = path.join(app, "node_modules", ".bin", bin);
    const version = run(binPath, ["--version"], app).trim();
    if (version !== expected.version) throw new Error(`${bin} --version printed "${version}", expected ${expected.version}`);
  }

  const outDir = path.join(work, "out");
  const fixture = path.join(root, "test", "fixtures", "vulnerable-app");
  run(path.join(app, "node_modules", ".bin", "auditsaas"), ["scan", fixture, "--out-dir", outDir, "--no-history", "--no-ai-review"], app);
  const findings = JSON.parse(fs.readFileSync(path.join(outDir, "findings.json"), "utf8"));
  if (!findings.some((finding) => finding.id === "PAYMENT_STRIPE_WEBHOOK_SIGNATURE_MISSING")) {
    throw new Error("installed package scanned the fixture but missed a known finding");
  }

  console.log(`Package smoke test passed: ${entry.filename}, bins ${Object.keys(expected.bin).join(" + ")}, ${findings.length} fixture findings`);
} catch (error) {
  console.error(`Package smoke test failed: ${error.stderr || error.message}`);
  process.exitCode = 1;
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}

// npm prints these as warnings and still exits 0, so read stderr directly.
function publishCorrections() {
  const result = spawnSync("npm", ["publish", "--dry-run"], { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`npm publish --dry-run failed:\n${result.stderr}`);
  return result.stderr.split("\n").filter((line) => /auto-corrected|was invalid and removed/i.test(line));
}
