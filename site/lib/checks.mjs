// Build assertions. Each check returns a list of problems; build.mjs prints them all
// and fails if any exist. They read the files that were written to disk, so they test
// what is served, not the in-memory model that produced it.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, dirname } from "node:path";
import { markdownTokens, firstDifference } from "./text.mjs";
import { SITE } from "./discovery.mjs";

const DASH = /[\u2013\u2014]/;
const SITE_LINK = /https:\/\/stoop\.build\/[^\s)"'<>\]]*/g;

// The built file a same-site URL serves, relative to the output root, or null.
export function fileForUrl(url) {
  const u = new URL(url);
  if (u.origin !== new URL(SITE).origin) return null;
  let path = u.pathname.replace(/^\/+/, "");
  if (path === "" || path.endsWith("/")) path += "index.html";
  return { path: decodeURIComponent(path), fragment: decodeURIComponent(u.hash.slice(1)) };
}

const walk = (dir) => readdirSync(dir).flatMap((name) => {
  const p = join(dir, name);
  return statSync(p).isDirectory() ? walk(p) : [p];
});

// Every relative reference in built HTML and CSS must resolve, and every same-site
// fragment in built HTML must name an id that exists in its target page.
export function checkBuiltLinks(out) {
  const problems = [];
  const files = walk(out).filter((f) => f.endsWith(".html") || f.endsWith(".css"));
  const idsCache = new Map();
  const idsOf = (file) => {
    if (!idsCache.has(file)) idsCache.set(file, new Set([...readFileSync(file, "utf8").matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
    return idsCache.get(file);
  };
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    const where = relative(out, file);
    for (const m of text.matchAll(/(?:href|src|srcset)="([^"]+)"|url\(([^)]+)\)/g)) {
      for (let ref of (m[1] ?? m[2]).split(",").map((s) => s.trim().split(/\s+/)[0])) {
        if (!ref || /^(https?:|mailto:|#|data:)/.test(ref)) continue;
        ref = ref.split("#")[0];
        if (!ref) continue;
        const target = join(dirname(file), ref);
        if (!existsSync(target)) problems.push(`broken local reference: ${where} -> ${ref}`);
      }
    }
    if (!file.endsWith(".html")) continue;
    for (const m of text.matchAll(/href="([^"#]*)#([^"]+)"/g)) {
      const [, path, fragment] = m;
      if (/^(https?:|mailto:)/.test(path)) continue;
      const target = path === "" ? file : join(dirname(file), path);
      if (!existsSync(target) || !target.endsWith(".html")) continue;
      if (!idsOf(target).has(fragment)) problems.push(`missing anchor: ${where} -> ${path}#${fragment}`);
    }
  }
  return problems;
}

// Every twin matches its page: the file on disk is the body under a canonical line, the
// words match the visible words of the scope, and the page advertises the twin.
export function checkPages(out, pages) {
  const problems = [];
  const sitemapped = new Set();
  const sitemap = existsSync(join(out, "sitemap.xml")) ? readFileSync(join(out, "sitemap.xml"), "utf8") : "";
  for (const m of sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)) sitemapped.add(m[1]);
  const pageUrls = new Set(pages.filter((p) => p.key).map((p) => p.canonicalUrl));
  for (const url of sitemapped) if (!pageUrls.has(url)) problems.push(`sitemap lists ${url}, which is not a page`);
  for (const url of pageUrls) if (!sitemapped.has(url)) problems.push(`sitemap does not list ${url}`);

  for (const page of pages) {
    if (!page.key) continue;
    const html = readFileSync(join(out, page.key), "utf8");
    const canonical = /<link rel="canonical" href="([^"]+)">/.exec(html)?.[1];
    if (canonical !== page.canonicalUrl) problems.push(`${page.key}: canonical is ${canonical}, expected ${page.canonicalUrl}`);
    const alternate = /<link rel="alternate" type="text\/markdown" href="([^"]+)">/.exec(html)?.[1];
    if (alternate !== page.url) problems.push(`${page.key}: markdown alternate is ${alternate}, expected ${page.url}`);
    if (!existsSync(join(out, page.path))) {
      problems.push(`${page.key}: twin ${page.path} is missing`);
      continue;
    }
    const twin = readFileSync(join(out, page.path), "utf8");
    if (twin !== page.twin) problems.push(`${page.path}: file on disk differs from the generated twin`);
    if (twin.split("\n")[0] !== `Canonical: ${page.canonicalUrl}`) problems.push(`${page.path}: first line must be the canonical URL`);
    const body = twin.slice(twin.indexOf("\n\n") + 2);
    const diff = firstDifference(page.htmlTokens, markdownTokens(body));
    if (diff) problems.push(`${page.path}: words differ from ${page.key} at word ${diff.index} (page: "${diff.html}" twin: "${diff.twin}")`);
  }
  return problems;
}

// Every same-site link in a generated text file resolves to a built file, and a fragment
// on a twin names an anchor the twin actually has.
export function checkGeneratedLinks(out, files) {
  const problems = [];
  for (const rel of files) {
    const text = readFileSync(join(out, rel), "utf8");
    for (const m of new Set((text.match(SITE_LINK) ?? []).map((url) => url.replace(/[.,;:!?]+$/, "")))) {
      const target = fileForUrl(m);
      if (!target || !target.path || !existsSync(join(out, target.path)) || statSync(join(out, target.path)).isDirectory()) {
        problems.push(`${rel}: ${m} does not resolve to a built file`);
        continue;
      }
      if (target.fragment && target.path.endsWith(".md")) {
        const body = readFileSync(join(out, target.path), "utf8");
        if (!body.includes(`<a id="${target.fragment}"></a>`)) problems.push(`${rel}: ${m} names an anchor the twin lacks`);
      }
    }
  }
  return problems;
}

export function checkDashes(out, files) {
  return files.filter((rel) => DASH.test(readFileSync(join(out, rel), "utf8")))
    .map((rel) => `${rel} contains an en or em dash`);
}

export function checkLlms(out, { docs, guide, home }) {
  const problems = [];
  const text = readFileSync(join(out, "llms.txt"), "utf8");
  const lines = text.split("\n");
  if (lines[0] !== "# stoop") problems.push("llms.txt must open with an H1 title");
  if (!lines.some((line) => line.startsWith("> "))) problems.push("llms.txt needs a blockquote summary");
  const sections = lines.filter((line) => line.startsWith("## ")).map((line) => line.slice(3));
  for (const name of ["Docs", "Guide", "Install", "Source", "Optional"]) {
    if (!sections.includes(name)) problems.push(`llms.txt has no "${name}" section`);
  }
  const docsBlock = text.split("## Docs\n")[1]?.split("\n## ")[0] ?? "";
  const docsLinks = [...docsBlock.matchAll(/^- \[[^\]]+\]\((https:\/\/stoop\.build\/[^)]+)\): /gm)].map((m) => m[1]);
  const expected = docs.map((p) => p.url);
  if (JSON.stringify(docsLinks) !== JSON.stringify(expected)) problems.push(`llms.txt Docs section lists ${docsLinks.length} pages, expected ${expected.length}: ${expected.join(", ")}`);
  if (!text.includes(`](${guide.url})`)) problems.push("llms.txt does not link the agent guide");
  if (!text.includes(`](${home.url})`)) problems.push("llms.txt does not link the home page");
  const full = readFileSync(join(out, "llms-full.txt"), "utf8");
  for (const page of [guide, ...docs]) {
    if (!full.includes(`Source: ${page.url}\n`)) problems.push(`llms-full.txt has no section for ${page.url}`);
  }
  return problems;
}

export function checkIndex(out, index, pages) {
  const problems = [];
  if (index.pages.length !== pages.length) problems.push(`docs-index.json lists ${index.pages.length} pages, expected ${pages.length}`);
  for (const page of pages) {
    const entry = index.pages.find((p) => p.path === page.path);
    if (!entry) {
      problems.push(`docs-index.json has no entry for ${page.path}`);
      continue;
    }
    if (entry.body_length !== page.body.length) problems.push(`docs-index.json body_length for ${page.path} is stale`);
    for (const s of entry.sections) {
      if (!(0 <= s.start && s.start <= s.end && s.end <= s.tree_end && s.tree_end <= entry.body_length)) {
        problems.push(`docs-index.json section ${s.id ?? s.title} in ${page.path} has offsets outside the body`);
      }
    }
  }
  for (const provider of ["github", "gitlab", "circleci", "buildkite"]) {
    if (!index.recipes[provider]?.code) problems.push(`docs-index.json has no ${provider} recipe`);
  }
  return problems;
}

export function checkRobots(out) {
  const text = readFileSync(join(out, "robots.txt"), "utf8");
  const problems = [];
  if (/^Disallow:/m.test(text)) problems.push("robots.txt disallows crawling");
  if (!text.includes(`Sitemap: ${SITE}/sitemap.xml`)) problems.push("robots.txt does not point to the sitemap");
  return problems;
}

export function checkRequiredFiles(out, required) {
  return required.filter((rel) => !existsSync(join(out, rel))).map((rel) => `missing generated file ${rel}`);
}
