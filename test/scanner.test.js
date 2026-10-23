import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { collectProject } from "../src/scanner.js";
import { runRules } from "../src/rules.js";
import { makeProject } from "./helpers.js";

test("scanner skips binary files, symlinks, and ignored build dirs without crashing", async () => {
  const root = await makeProject({
    "src/index.ts": "export const a = 1;\n",
    "src/blob.json": "abc\u0000def",
    ".svelte-kit/output/server.js": "eval(req.body)\n",
  });
  await fs.symlink(path.join(root, "src"), path.join(root, "linked-src"));

  const project = await collectProject(root);
  const paths = project.files.map((file) => file.relativePath);
  assert.deepEqual(paths, ["src/index.ts"]);
  assert.equal(project.skipped.binary, 1);
});

test("an unreadable directory is skipped, not fatal", { skip: process.getuid?.() === 0 }, async () => {
  const root = await makeProject({ "src/index.ts": "export const a = 1;\n", "locked/secret.ts": "x" });
  await fs.chmod(path.join(root, "locked"), 0o000);
  try {
    const project = await collectProject(root);
    assert.deepEqual(project.files.map((file) => file.relativePath), ["src/index.ts"]);
    assert.equal(project.skipped.unreadable, 1);
  } finally {
    await fs.chmod(path.join(root, "locked"), 0o755);
  }
});

test("a detector that throws is reported in errors and doesn't abort the scan", () => {
  const project = { files: [], allPaths: [], packageJson: null, providers: { auth: [], payments: [], ai: [], database: [], observability: [] } };
  const context = { focus: "all", runtime: null, get dataInventory() { throw new Error("boom"); } };
  const { findings, errors } = runRules(project, context);
  assert.ok(errors.some((error) => error.ruleId === "PRIVACY_DATA_COLLECTION_FOUND" && /boom/.test(error.message)));
  assert.ok(findings.some((finding) => finding.id === "MONITORING_ANOMALY_GAPS"));
});

test("files inside gitignored directories count as gitignored", async () => {
  const root = await makeProject({ ".gitignore": "local-secrets/\n", "local-secrets/.env": "STRIPE_SECRET_KEY=sk_live_abc\n" });
  const { execFileSync } = await import("node:child_process");
  execFileSync("git", ["init", "-q", root]);
  const project = await collectProject(root);
  assert.equal(project.files.find((file) => file.relativePath === "local-secrets/.env").gitIgnored, true);
  const { findings } = runRules(project, { focus: "secrets", runtime: null, dataInventory: [] });
  assert.ok(!findings.some((finding) => finding.id === "SECRETS_ENV_COMMITTED"));
});
