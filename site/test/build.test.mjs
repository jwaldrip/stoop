// The built output, read from disk and checked from outside the build. The build runs the
// same checks and fails on them; these tests read the files independently, so a change that
// weakens a check is caught here, and the token wiring is exercised end to end.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ensureBuilt, SITE, SITE_DIR } from "./support/build.mjs";
import { tokenFor } from "./support/token.mjs";
import { REGISTRATION_URL } from "../lib/origin-trial.mjs";

const read = (rel) => readFileSync(join(SITE_DIR, rel), "utf8");
const index = () => JSON.parse(read("docs-index.json"));
const htmlFileFor = (canonical) => (canonical === "https://stoop.build/" ? "index.html" : canonical.replace("https://stoop.build/", ""));
const pagesOnly = () => index().pages.filter((p) => p.path !== "AGENTS.md");

// Runs the build in a child process with extra environment, and returns the result.
function build(env = {}) {
  return spawnSync(process.execPath, [join(SITE, "build.mjs")], { encoding: "utf8", env: { ...process.env, ...env } });
}

before(() => ensureBuilt());
// The token tests rewrite the output, so the plain build is restored for the other tests.
after(() => {
  const result = build({ STOOP_SITE_TOKEN_FILE: join(tmpdir(), "stoop-no-token-file-here") });
  if (result.status !== 0) throw new Error(`restoring the plain build failed:\n${result.stdout}${result.stderr}`);
});

test("every page advertises its markdown twin, and the twin is served at that address", () => {
  for (const page of pagesOnly()) {
    const html = read(htmlFileFor(page.canonical));
    assert.ok(html.includes(`<link rel="alternate" type="text/markdown" href="${page.url}">`), `${page.canonical} advertises ${page.url}`);
    assert.ok(existsSync(join(SITE_DIR, page.path)), `${page.path} is built`);
  }
});

test("every page loads the WebMCP script, and no origin-trial tag appears unless a token is configured", () => {
  const configured = existsSync(join(SITE, "webmcp-origin-trial.txt"));
  for (const page of pagesOnly()) {
    const html = read(htmlFileFor(page.canonical));
    assert.match(html, /<script src="(\.\.\/)*webmcp\.js" defer><\/script>/, `${page.canonical} loads webmcp.js`);
    assert.equal(html.includes('http-equiv="origin-trial"'), configured, `${page.canonical} origin-trial tag matches the configuration`);
  }
});

test("llms.txt has the llmstxt.org shape: an H1, a summary, the sections in order, and every docs page", () => {
  const text = read("llms.txt");
  assert.equal(text.split("\n")[0], "# stoop");
  assert.ok(text.split("\n").some((line) => line.startsWith("> ")), "a blockquote summary");
  const headings = text.split("\n").filter((line) => line.startsWith("## ")).map((line) => line.slice(3));
  assert.deepEqual(headings, ["Docs", "Guide", "Install", "Source", "Optional"]);
  const docsSection = text.split("## Docs\n")[1].split("\n## ")[0];
  for (const page of pagesOnly().filter((p) => p.canonical.includes("/docs/"))) {
    assert.ok(docsSection.includes(`](${page.url}): `), `${page.url} is in the Docs section`);
  }
  assert.ok(text.includes("curl -fsSL https://stoop.build/install.sh | sh"), "the install line");
  assert.ok(text.includes("](https://github.com/jwaldrip/stoop)") && text.includes("](https://github.com/jwaldrip/stoop/releases)"), "the source links");
});

test("every same-site link in llms.txt resolves to a built file", () => {
  for (const [, url] of read("llms.txt").matchAll(/\]\((https:\/\/[^)]+)\)/g)) {
    if (!url.startsWith("https://stoop.build/")) continue;
    const path = url.slice("https://stoop.build/".length).split("#")[0] || "index.html";
    assert.ok(existsSync(join(SITE_DIR, path)), `${url} resolves to ${path}`);
  }
});

test("llms-full.txt holds the guide and every docs page, each under its source URL", () => {
  const full = read("llms-full.txt");
  for (const page of index().pages.filter((p) => p.path !== "index.md")) assert.ok(full.includes(`Source: ${page.url}\n`), `${page.url} has a section`);
  assert.ok(full.includes(read("AGENTS.md").split("\n")[0]), "the guide's first line is present");
});

test("the sitemap lists every page, and robots.txt points at it without blocking any crawler", () => {
  const listed = [...read("sitemap.xml").matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]).sort();
  assert.deepEqual(listed, pagesOnly().map((p) => p.canonical).sort());
  const robots = read("robots.txt");
  assert.match(robots, /^User-agent: \*$/m);
  assert.match(robots, /^Allow: \/$/m);
  assert.match(robots, /^Sitemap: https:\/\/stoop\.build\/sitemap\.xml$/m);
  assert.doesNotMatch(robots, /Disallow/);
});

test("the canonical link of each page is its sitemap URL, and each twin begins with that same canonical URL", () => {
  for (const page of pagesOnly()) {
    const canonical = /<link rel="canonical" href="([^"]+)">/.exec(read(htmlFileFor(page.canonical)))[1];
    assert.equal(canonical, page.canonical);
    assert.equal(read(page.path).split("\n")[0], `Canonical: ${page.canonical}`);
  }
});

test("the discovery text has no en or em dash, and the index carries the install command and four recipes", () => {
  for (const file of ["llms.txt", "llms-full.txt", "docs-index.json", "webmcp.js", ...pagesOnly().map((p) => p.path)]) {
    assert.doesNotMatch(read(file), /[\u2013\u2014]/, `${file} has no dash`);
  }
  const data = index();
  assert.equal(data.install.command, "curl -fsSL https://stoop.build/install.sh | sh");
  assert.deepEqual(Object.keys(data.recipes).sort(), ["buildkite", "circleci", "github", "gitlab"]);
});

test("the agent guide is copied verbatim, and its twin is the guide itself", () => {
  assert.equal(read("AGENTS.md"), readFileSync(join(SITE, "static", "AGENTS.md"), "utf8"));
});

test("a token configured in the file is written into the head of every page, once", () => {
  const dir = mkdtempSync(join(tmpdir(), "stoop-token-"));
  const file = join(dir, "token.txt");
  writeFileSync(file, `${tokenFor(Date.now(), 200)}\n`);
  const result = build({ STOOP_SITE_TOKEN_FILE: file });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  for (const page of pagesOnly()) {
    const head = read(htmlFileFor(page.canonical)).split("</head>")[0];
    assert.equal(head.split('http-equiv="origin-trial"').length - 1, 1, `${page.canonical} has one origin-trial tag`);
  }
});

test("a token that expires within 21 days fails the build, and the failure names the registration URL", () => {
  const dir = mkdtempSync(join(tmpdir(), "stoop-token-"));
  const file = join(dir, "token.txt");
  writeFileSync(file, `${tokenFor(Date.now(), 10)}\n`);
  const result = build({ STOOP_SITE_TOKEN_FILE: file });
  const output = result.stdout + result.stderr;
  assert.notEqual(result.status, 0);
  assert.match(output, /within 21 days/);
  assert.ok(output.includes(REGISTRATION_URL), "the registration URL is named");
});

test("a token for another site fails the build", () => {
  const dir = mkdtempSync(join(tmpdir(), "stoop-token-"));
  const file = join(dir, "token.txt");
  writeFileSync(file, `${tokenFor(Date.now(), 200, { origin: "https://example.com:443" })}\n`);
  const result = build({ STOOP_SITE_TOKEN_FILE: file });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not cover https:\/\/stoop\.build/);
});

test("llms.txt links the agent guide and the MCP twin, and both are built", () => {
  // The token tests above leave a failed build in _site, so rebuild the plain site first.
  const restore = build({ STOOP_SITE_TOKEN_FILE: join(tmpdir(), "stoop-no-token-file-here") });
  assert.equal(restore.status, 0, restore.stdout + restore.stderr);
  const text = read("llms.txt");
  assert.ok(text.includes("](https://stoop.build/AGENTS.md)"), "llms.txt links the agent guide at /AGENTS.md");
  assert.ok(text.includes("](https://stoop.build/docs/mcp.md)"), "llms.txt links the MCP twin at /docs/mcp.md");
  assert.ok(existsSync(join(SITE_DIR, "AGENTS.md")), "AGENTS.md is built at the site root");
  assert.ok(existsSync(join(SITE_DIR, "docs", "mcp.md")), "the MCP twin is built");
  assert.ok(existsSync(join(SITE_DIR, "docs", "mcp.html")), "the MCP page is built");
});
