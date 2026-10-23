import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { auditProject } from "../src/index.js";

export async function makeProject(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "auditsaas-project-"));
  for (const [relativePath, content] of Object.entries(files)) {
    const fullPath = path.join(root, relativePath);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, content);
  }
  return root;
}

export async function scanFiles(files, options = {}) {
  const target = await makeProject(files);
  const outDir = await fs.mkdtemp(path.join(os.tmpdir(), "auditsaas-out-"));
  const result = await auditProject({ target, outDir, ...options });
  return { ...result, target };
}

// A fetch stand-in that never answers and rejects when aborted. The ref'd
// timer mimics an open socket: AbortSignal.timeout's own timer is unref'd,
// so without it Node 20 would let the event loop drain before the abort.
export function hangingFetch(_url, { signal }) {
  return new Promise((_resolve, reject) => {
    const keepAlive = setTimeout(() => {}, 60_000);
    signal.addEventListener("abort", () => {
      clearTimeout(keepAlive);
      reject(signal.reason);
    });
  });
}

export function ids(result) {
  return result.findings.map((finding) => finding.id);
}
