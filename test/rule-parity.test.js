import assert from "node:assert/strict";
import test from "node:test";
import { loadRuleCatalog } from "../src/rule-catalog.js";
import { rules } from "../src/rules.js";

test("markdown rule catalog and src/rules.js detectors stay in sync", () => {
  const catalogIds = new Set(loadRuleCatalog().keys());
  const detectorIds = new Set(rules.map((rule) => rule.id));

  const docsWithoutDetector = [...catalogIds].filter((id) => !detectorIds.has(id)).sort();
  const detectorsWithoutDocs = [...detectorIds].filter((id) => !catalogIds.has(id)).sort();

  assert.deepEqual(detectorsWithoutDocs, [], `every detector needs a matching rules/*.md entry: ${detectorsWithoutDocs.join(", ")}`);
  assert.deepEqual(docsWithoutDetector, [], `every documented rule needs a detector: ${docsWithoutDetector.join(", ")}`);
});
