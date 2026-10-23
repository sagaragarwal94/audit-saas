import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { compileGlobs, loadConfig } from "../src/config.js";
import { ids, makeProject, scanFiles } from "./helpers.js";

const XSS_LINE = "export const Post = ({ body }) => <div dangerouslySetInnerHTML={{ __html: body }} />;\n";

test("inline auditsaas-ignore suppresses on the same line or the line above", async () => {
  const result = await scanFiles({
    "a.tsx": `${XSS_LINE.trim()} // auditsaas-ignore XSS_UNSAFE_HTML -- sanitized upstream\n`,
    "b.tsx": `// auditsaas-ignore\n${XSS_LINE}`,
    "c.tsx": `// auditsaas-ignore SQL_INJECTION_RAW_QUERY\n${XSS_LINE}`,
  });
  const xss = result.findings.filter((finding) => finding.id === "XSS_UNSAFE_HTML");
  assert.deepEqual(xss.map((finding) => finding.file), ["c.tsx"], "a directive for a different rule must not suppress");
  assert.equal(result.suppressed.filter((finding) => finding.suppressedBy === "inline-directive").length, 2);
  assert.equal(result.summary.suppressed, result.suppressed.length);
});

test("auditsaas-ignore-file and config ignoreRules suppress, ignorePaths skips scanning", async () => {
  const target = await makeProject({
    "a.tsx": `/* auditsaas-ignore-file XSS_UNSAFE_HTML */\n${XSS_LINE}`,
    "fixtures/b.tsx": XSS_LINE,
    "lib/c.ts": "export const q = (id) => db.query(`SELECT * FROM t WHERE id = ${id}`);\n",
    ".auditsaas.json": JSON.stringify({ ignorePaths: ["fixtures"], ignoreRules: ["SQL_INJECTION_RAW_QUERY"] }),
  });
  const outDir = await fs.mkdtemp(path.join(os.tmpdir(), "auditsaas-out-"));
  const { auditProject } = await import("../src/index.js");
  const result = await auditProject({ target, outDir });

  assert.ok(!ids(result).includes("XSS_UNSAFE_HTML"));
  assert.ok(!ids(result).includes("SQL_INJECTION_RAW_QUERY"));
  assert.ok(!result.project.files.some((file) => file.relativePath.startsWith("fixtures/")));
  assert.deepEqual(result.suppressed.map((finding) => finding.suppressedBy).sort(), ["config", "file-directive"]);
  assert.match(await fs.readFile(path.join(outDir, "audit-report.md"), "utf8"), /## Suppressed Findings/);
});

test("baseline hides previously seen findings, even after lines shift", async () => {
  const first = await scanFiles({ "a.tsx": XSS_LINE });
  const baselinePath = path.join(first.outDir, "findings.json");

  const target = await makeProject({ "a.tsx": `// a new comment shifts every line\n\n${XSS_LINE}`, "b.tsx": XSS_LINE });
  const outDir = await fs.mkdtemp(path.join(os.tmpdir(), "auditsaas-out-"));
  const { auditProject } = await import("../src/index.js");
  const second = await auditProject({ target, outDir, baseline: baselinePath });

  const xss = second.findings.filter((finding) => finding.id === "XSS_UNSAFE_HTML");
  assert.deepEqual(xss.map((finding) => finding.file), ["b.tsx"]);
  assert.ok(second.summary.baselined >= 1);
});

test("fingerprints are stable and unique per occurrence", async () => {
  const result = await scanFiles({ "a.tsx": `${XSS_LINE}${XSS_LINE}` });
  const prints = result.findings.filter((finding) => finding.id === "XSS_UNSAFE_HTML").map((finding) => finding.fingerprint);
  const again = await scanFiles({ "a.tsx": `${XSS_LINE}${XSS_LINE}` });
  assert.equal(new Set(result.findings.map((finding) => finding.fingerprint)).size, result.findings.length);
  assert.deepEqual(again.findings.filter((finding) => finding.id === "XSS_UNSAFE_HTML").map((finding) => finding.fingerprint), prints);
});

test("compileGlobs follows gitignore-style semantics", () => {
  const match = compileGlobs(["test/fixtures/**", "*.min.js", "generated", "/root-only.ts", "src/**/*.gen.ts"]);
  assert.ok(match("test/fixtures/app/route.ts"));
  assert.ok(match("public/vendor/jquery.min.js"));
  assert.ok(match("packages/a/generated/types.ts"));
  assert.ok(match("root-only.ts"));
  assert.ok(!match("nested/root-only.ts"));
  assert.ok(match("src/a/b/schema.gen.ts"));
  assert.ok(match("src/schema.gen.ts"));
  assert.ok(!match("test/fixture.ts"));
  assert.ok(!match("lib/main.js"));
});

test("loadConfig rejects malformed or unknown config instead of silently ignoring it", async () => {
  const bad = await makeProject({ ".auditsaas.json": "{ not json" });
  await assert.rejects(loadConfig(bad), /not valid JSON/);

  const typo = await makeProject({ ".auditsaas.json": JSON.stringify({ ignorePath: ["x"] }) });
  await assert.rejects(loadConfig(typo), /Unknown key\(s\).*ignorePath/);

  const badFailOn = await makeProject({ ".auditsaas.json": JSON.stringify({ failOn: "severe" }) });
  await assert.rejects(loadConfig(badFailOn), /Invalid failOn/);

  const none = await makeProject({});
  assert.deepEqual(await loadConfig(none), { path: null, ignorePaths: [], ignoreRules: [] });
  await assert.rejects(loadConfig(none, path.join(none, "missing.json")), /Could not read config/);
});

test("a baselined run's findings.json can be reused as the next baseline", async () => {
  const { auditProject } = await import("../src/index.js");
  const target = await makeProject({ "a.tsx": XSS_LINE });
  const out1 = await fs.mkdtemp(path.join(os.tmpdir(), "auditsaas-out-"));
  await auditProject({ target, outDir: out1 });

  await fs.writeFile(path.join(target, "b.tsx"), XSS_LINE);
  const out2 = await fs.mkdtemp(path.join(os.tmpdir(), "auditsaas-out-"));
  const second = await auditProject({ target, outDir: out2, baseline: path.join(out1, "findings.json") });
  const exported = JSON.parse(await fs.readFile(path.join(out2, "findings.json"), "utf8"));
  assert.ok(exported.some((finding) => finding.baselineState === "unchanged"));
  assert.ok(exported.some((finding) => finding.baselineState === "new" && finding.file === "b.tsx"));
  assert.ok(second.findings.every((finding) => finding.baselineState === "new"));

  const out3 = await fs.mkdtemp(path.join(os.tmpdir(), "auditsaas-out-"));
  const third = await auditProject({ target, outDir: out3, baseline: path.join(out2, "findings.json") });
  assert.equal(third.summary.total, 0, "everything from run 2's output is already known");
});
