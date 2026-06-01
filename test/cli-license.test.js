import assert from "node:assert/strict";
import test from "node:test";
import { hashProjectPath } from "../src/cli-license.js";

test("hashProjectPath returns stable short hashes", () => {
  const first = hashProjectPath("test/fixtures/vulnerable-app");
  const second = hashProjectPath("test/fixtures/vulnerable-app");

  assert.equal(first, second);
  assert.equal(first.length, 24);
  assert.match(first, /^[a-f0-9]+$/);
});
