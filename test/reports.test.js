import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { renderSarif } from "../src/reports.js";
import { scanFiles } from "./helpers.js";

test("SARIF output is GitHub code-scanning ready", async () => {
  const result = await scanFiles({
    "package.json": JSON.stringify({ name: "demo" }),
    "app/api/items/[id]/route.ts": "export async function GET(_r, { params }) { return Response.json(await db.item.findUnique({ where: { id: params.id } })); }\n",
  }, { toolVersion: "9.9.9" });
  const sarif = JSON.parse(await fs.readFile(path.join(result.outDir, "findings.sarif.json"), "utf8"));
  const run = sarif.runs[0];

  assert.equal(sarif.version, "2.1.0");
  assert.equal(run.tool.driver.version, "9.9.9");
  assert.equal(run.results.length, result.findings.length);

  for (const sarifResult of run.results) {
    assert.ok(sarifResult.locations.length === 1, `${sarifResult.ruleId} must have a location`);
    assert.ok(sarifResult.partialFingerprints["auditsaasFingerprint/v1"]);
    assert.equal(run.tool.driver.rules[sarifResult.ruleIndex].id, sarifResult.ruleId);
  }

  const idor = run.tool.driver.rules.find((rule) => rule.id === "AUTHZ_IDOR_POSSIBLE");
  assert.equal(idor.properties["security-severity"], "9.5");
  assert.equal(idor.helpUri, "https://auditsaas.org/rules#AUTHZ_IDOR_POSSIBLE");

  const projectWide = run.results.find((item) => !result.findings[run.results.indexOf(item)].file);
  assert.equal(projectWide.locations[0].physicalLocation.artifactLocation.uri, "package.json");
});

test("SARIF omits locations rather than inventing one when there is no manifest", () => {
  const sarif = renderSarif({
    project: { packageJson: null },
    findings: [{ id: "X", title: "t", severity: "low", category: "c", fingerprint: "f" }],
  });
  assert.deepEqual(sarif.runs[0].results[0].locations, []);
});
