import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { loadRuleCatalog } from "../src/rule-catalog.js";

const SITE = path.resolve("site");
const pages = fs.readdirSync(SITE).filter((name) => name.endsWith(".html"));
const read = (name) => fs.readFileSync(path.join(SITE, name), "utf8");
const { version } = JSON.parse(fs.readFileSync("package.json", "utf8"));

test("site advertises the current package version and has a changelog entry for it", () => {
  const index = read("index.html");
  const jsonLd = JSON.parse(index.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)[1]);
  assert.equal(jsonLd.softwareVersion, version, "bump softwareVersion in site/index.html");
  assert.match(index, new RegExp(`New in v${version.replaceAll(".", "\\.")}`), "update the release pill in site/index.html");
  assert.match(read("changelog.html"), new RegExp(`<h2>[^<]*v${version.replaceAll(".", "\\.")}</h2>`), "add a changelog entry for this version");
});

test("rule counts on the site match the catalog", () => {
  const total = loadRuleCatalog().size;
  assert.match(read("index.html"), new RegExp(`<strong>${total}</strong><span>built-in detection rules`));
  assert.match(read("rules.html"), new RegExp(`<p class="eyebrow">${total} rules`));
  assert.equal((read("rules.html").match(/<div class="rule" id="/g) || []).length, total);
});

test("pages stay compatible with the strict CSP in vercel.json", () => {
  const csp = JSON.parse(fs.readFileSync(path.join(SITE, "vercel.json"), "utf8"))
    .headers.flatMap((rule) => rule.headers)
    .find((header) => header.key === "Content-Security-Policy").value;
  assert.match(csp, /script-src 'self';/);
  assert.match(csp, /style-src 'self';/);

  for (const page of pages) {
    const html = read(page);
    const inlineScripts = [...html.matchAll(/<script(?![^>]*\bsrc=)(?![^>]*type="application\/ld\+json")[^>]*>/g)];
    assert.deepEqual(inlineScripts.map((match) => match[0]), [], `${page}: inline <script> is blocked by CSP; put it in site/site.js`);
    assert.doesNotMatch(html, /\sstyle="/, `${page}: inline style attributes are blocked by CSP`);
    assert.doesNotMatch(html, /\son(click|load|change|input)=/i, `${page}: inline event handlers are blocked by CSP`);
    assert.match(html, /<script src="\/site\.js"><\/script>/, `${page}: missing /site.js`);
  }
});

test("internal links and rule anchors resolve", () => {
  const anchors = new Map(pages.map((page) => [page, new Set([...read(page).matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]))]));
  const pageFor = (route) => (route === "/" || route === "" ? "index.html" : `${route.replace(/^\//, "")}.html`);

  for (const page of pages) {
    for (const [, href] of read(page).matchAll(/href="(\/[^"]*|#[^"]+)"/g)) {
      if (/\.(css|js|png|txt|xml)$/.test(href) || href.startsWith("/.well-known/")) {
        assert.ok(fs.existsSync(path.join(SITE, href)), `${page}: ${href} does not exist`);
        continue;
      }
      const [route, hash] = href.startsWith("#") ? [`/${page.replace(/\.html$/, "").replace(/^index$/, "")}`, href.slice(1)] : href.split("#");
      const target = pageFor(route);
      assert.ok(anchors.has(target), `${page}: link ${href} points at missing page ${target}`);
      if (hash) assert.ok(anchors.get(target).has(hash), `${page}: link ${href} points at missing anchor #${hash}`);
    }
  }
});
