// Builds the stoop site into site/_site. Node 18+, no dependencies.
//   node site/build.mjs
// Pages in pages/ start with <!--meta {json}-->. Docs pages are fragments wrapped in
// the docs layout; the home page is a whole document. {{root}} becomes the relative
// path back to the site root, so links also work when hosted under a prefix.
//
// Discovery: every page also gets a Markdown twin generated from its built HTML
// (lib/markdown.mjs), and the build writes llms.txt, llms-full.txt, docs-index.json
// (read by the WebMCP tools in static/webmcp.js), robots.txt and sitemap.xml. Then it
// checks all of it (lib/checks.mjs). Any failure fails the build.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, cpSync, rmSync, statSync, existsSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parseHtml, descendants, findFirst, hasClass, textOf } from "./lib/html.mjs";
import { toMarkdown, targetKey, isChrome, languageOf } from "./lib/markdown.mjs";
import { htmlTokens, sectionsOf } from "./lib/text.mjs";
import { checkToken, REGISTRATION_URL } from "./lib/origin-trial.mjs";
import { SITE, INSTALL_COMMAND, ROBOTS, llmsTxt, llmsFull, sitemapXml, docsIndex } from "./lib/discovery.mjs";
import { checkBuiltLinks, checkPages, checkGeneratedLinks, checkDashes, checkLlms, checkIndex, checkRobots, checkRequiredFiles } from "./lib/checks.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const out = join(here, "_site");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(join(here, "static"), out, { recursive: true });
cpSync(join(repo, "assets"), join(out, "assets"), { recursive: true });
cpSync(join(here, "install.sh"), join(out, "install.sh"));
writeFileSync(join(out, "CNAME"), "stoop.build\n");

// The origin-trial token for WebMCP, if one is registered. Chrome stable needs it, and
// without one the tools simply stay off for visitors. The file holds one base64 token.
const tokenFile = process.env.STOOP_SITE_TOKEN_FILE || join(here, "webmcp-origin-trial.txt");
const token = existsSync(tokenFile) ? readFileSync(tokenFile, "utf8").trim() : "";
const trial = checkToken(token || null);
console.log(`origin trial: ${trial.message}`);
if (trial.state === "fail") {
  console.error(`site build failed:\n  ${trial.message}\n  registration: ${REGISTRATION_URL}`);
  process.exit(1);
}
const ORIGIN_TRIAL = token ? `<meta http-equiv="origin-trial" content="${token}">\n` : "";

// The lockup and mark, inlined so their ink follows the page theme.
const inline = (file) =>
  readFileSync(join(repo, "assets", file), "utf8")
    .replace(/<\?xml[^>]*>/, "")
    .replace(/<title>[^<]*<\/title>/, "")
    .replace(/ width="\d+" height="\d+"/, "")
    .replace(/role="img" aria-label="stoop"/, 'aria-hidden="true" focusable="false"')
    .replaceAll('<path fill="#15181c"', '<path class="ink"')
    .trim();
const LOGO = inline("stoop-logo-on-light.svg");

const DOCS = [
  ["getting-started", "Getting started"],
  ["how-it-works", "How it works"],
  ["ci", "CI recipes"],
  ["cli", "CLI reference"],
  ["stoopignore", ".stoopignore"],
  ["blind-spots", "Blind spots"],
  ["faq", "FAQ"],
  ["roadmap", "Roadmap"],
];

// One line per page for the discovery files and the WebMCP index. These sentences are
// metadata: they do not appear on the pages, whose own descriptions stay in <meta> tags.
const SUMMARY = {
  home: "stoop wraps a command, traces the files it reads, and skips it when none changed.",
  "getting-started": "Install stoop, wrap a first command, and read the decision it prints.",
  "how-it-works": "The tracer, the proof, the comparison, and every reason stoop runs instead of recording.",
  ci: "Recipes for GitHub Actions, GitLab CI, CircleCI and Buildkite, and how proofs are shared.",
  cli: "Every command, option, environment variable and exit code.",
  stoopignore: "Paths whose reads do not count, and outputs that need not stay in place.",
  "blind-spots": "What a file trace cannot see, and the settings that cover each gap.",
  faq: "Short answers on safety, speed, caches, monorepos, Node, macOS and prior art.",
  roadmap: "Where stoop is going. Nothing on it is built yet.",
};

// The agent guide is written and owned separately (site/static/AGENTS.md). It is copied
// verbatim, and it is read here for llms-full.txt, the twin list and the WebMCP index.
const GUIDE = {
  path: "AGENTS.md",
  title: "Agent guide",
  summary: "How an AI agent uses stoop: commands, exit codes, reading a decision, CI, and MCP.",
};

// docs/index.html only redirects to the first docs page. It is not a page, so it has no twin.
const REDIRECTS = ["docs/index.html"];

function readPage(file) {
  const src = readFileSync(file, "utf8");
  const m = src.match(/^<!--meta\s+(\{[\s\S]*?\})\s*-->\n?/);
  if (!m) throw new Error(`${file}: missing <!--meta {...}--> header`);
  return { meta: JSON.parse(m[1]), body: src.slice(m[0].length) };
}

const TOGGLE = `<button class="theme-toggle" type="button" data-theme-toggle hidden></button>`;
const head = ({ title, description, root, canonical, markdown }) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${ORIGIN_TRIAL}<title>${title}</title>
<meta name="description" content="${description}">
<meta name="theme-color" content="#eef2f5" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0d1216" media="(prefers-color-scheme: dark)">
<script>try{var t=localStorage.getItem("stoop-theme");if(t==="light"||t==="dark"){document.documentElement.dataset.theme=t;document.querySelectorAll('meta[name="theme-color"]').forEach(function(m){m.dataset.orig=m.content;m.content=t==="dark"?"#0d1216":"#eef2f5"})}}catch(e){}</script>
<link rel="canonical" href="https://stoop.build/${canonical}">
<link rel="alternate" type="text/markdown" href="${markdown}">
<link rel="icon" href="${root}assets/stoop-app.svg" type="image/svg+xml">
<link rel="icon" href="${root}assets/favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="${root}assets/apple-touch-icon.png">
<meta property="og:type" content="website">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:image" content="https://stoop.build/assets/social-preview.png">
<meta property="og:image:width" content="1280">
<meta property="og:image:height" content="640">
<meta name="twitter:card" content="summary_large_image">
<link rel="preload" href="${root}fonts/BodoniModa-normal-400_900.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="${root}fonts/IBMPlexSans-normal-400.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="${root}styles.css">
<script src="${root}chrome.js" defer></script>
<script src="${root}copy.js" defer></script>
<script src="${root}webmcp.js" defer></script>
</head>`;

const ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"];
const strip = (html) => html.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();

// Tables keep their column names on every cell, so a table stacked on a narrow
// screen can still say which column a value came from.
function labelTables(html) {
  return html.replace(/<table([^>]*)>([\s\S]*?)<\/table>/g, (whole, attrs, inner) => {
    const head = inner.match(/<thead>([\s\S]*?)<\/thead>/);
    if (!head) return whole;
    const names = [...head[1].matchAll(/<th[^>]*>([\s\S]*?)<\/th>/g)].map((m) => strip(m[1]).replaceAll('"', "&quot;"));
    const body = inner.replace(/<tbody>([\s\S]*?)<\/tbody>/, (b) =>
      b.replace(/<tr([^>]*)>([\s\S]*?)<\/tr>/g, (_, trAttrs, cells) => {
        let i = 0;
        return `<tr${trAttrs}>${cells.replace(/<(td|th)(\s[^>]*)?>/g, (_, tag, a = "") => `<${tag}${a} data-label="${names[i++] ?? ""}">`)}</tr>`;
      }));
    return `<table${attrs}>${body}</table>`;
  });
}

// Inline code breaks only between its words: a short flag or bracketed option
// such as [--store DIR] never splits across lines. The text is unchanged.
function keepCodeWords(html) {
  return html.replace(/(?<!<pre>)<code>([^<]*)<\/code>/g, (whole, text) => {
    const words = [];
    let word = "", depth = 0;
    for (let i = 0; i < text.length; i++) {
      const rest = text.slice(i);
      if (rest.startsWith("&lt;")) { depth++; word += "&lt;"; i += 3; continue; }
      if (rest.startsWith("&gt;")) { depth = Math.max(0, depth - 1); word += "&gt;"; i += 3; continue; }
      const c = text[i];
      if (c === "[") depth++;
      if (c === "]") depth = Math.max(0, depth - 1);
      if (c === " " && depth === 0) { words.push(word); word = ""; continue; }
      word += c;
    }
    words.push(word);
    if (words.length === 1 && !/[-/]/.test(text)) return whole;
    const wrap = (w) => (strip(w.replace(/&\w+;/g, "x")).length <= 28 && /[-/[\]]/.test(w) ? `<span class="nobr">${w}</span>` : w);
    return `<code>${words.map(wrap).join(" ")}</code>`;
  });
}

const finish = (html) => keepCodeWords(labelTables(html));

function docsPage(slug, meta, body) {
  const root = "../";
  const i = DOCS.findIndex(([s]) => s === slug);
  const prev = DOCS[i - 1];
  const next = DOCS[i + 1];
  const rail = DOCS.map(([s, t]) =>
    `<li><a href="${s}.html"${s === slug ? ' aria-current="page"' : ""}>${t}</a></li>`).join("\n        ");
  const img = meta.image
    ? `<figure><img src="${root}images/${meta.image}.webp" srcset="${root}images/${meta.image}-800.webp 800w, ${root}images/${meta.image}.webp 1536w" sizes="(max-width: 900px) 100vw, 40vw" alt="${meta.alt}" width="1536" height="1024" data-chrome-lightbox></figure>`
    : "";
  const sections = [...body.matchAll(/<h2 id="([^"]+)">([\s\S]*?)<\/h2>/g)];
  const toc = sections.length > 1
    ? `<div class="toc">
      <a class="toc-top" href="#main">${meta.title}</a>
      <nav aria-label="On this page" data-chrome-toc>
        <ol>
          ${sections.map(([, id, t]) => `<li><a href="#${id}">${t}</a></li>`).join("\n          ")}
        </ol>
      </nav>
    </div>`
    : "";
  return `${head({ title: `${meta.title} · stoop`, description: meta.description, root, canonical: `docs/${slug}.html`, markdown: `${SITE}/docs/${slug}.md` })}
<body>
<a class="skip" href="#main">Skip to the page</a>
<div data-chrome-progress role="progressbar" aria-label="Reading progress" aria-valuemin="0" aria-valuemax="100"></div>
<div class="docs">
  <nav class="rail" aria-label="Field guide">
    <a class="lockup" href="${root}index.html" aria-label="stoop home">${LOGO}</a>
    <details class="chapters" open>
      <summary><span class="n">${ROMAN[i] ?? i + 1}</span> ${DOCS[i][1]}</summary>
      <div class="chapter-list">
        <ol>
          ${rail}
        </ol>
        <div class="out">
          ${TOGGLE}
          <a href="https://github.com/jwaldrip/stoop">Source on GitHub</a>
          <a href="https://github.com/jwaldrip/stoop/issues">Report a problem</a>
        </div>
      </div>
    </details>
    <script>{const d=document.currentScript.previousElementSibling,m=matchMedia("(max-width: 900px)"),f=()=>{d.open=!m.matches};f();m.addEventListener("change",f)}</script>
  </nav>
  <main class="page" id="main">
    <header class="plate">
      <div class="plate-text">
        <h1>${meta.title}</h1>
        <p class="lede">${meta.lede}</p>
      </div>
      ${img}
    </header>
    <div class="leaf">
      <article class="prose">
${body.trim()}
        <nav class="next" aria-label="Pages">
          ${prev ? `<a class="prev-page" rel="prev" href="${prev[0]}.html"><span aria-hidden="true">←</span> ${prev[1]}</a>` : `<a class="prev-page" href="${root}index.html"><span aria-hidden="true">←</span> stoop</a>`}
          ${next ? `<a class="next-page" rel="next" href="${next[0]}.html">${next[1]} <span aria-hidden="true">→</span></a>` : ""}
        </nav>
      </article>
      ${toc}
    </div>
    <footer class="made"><a class="maker" href="https://withbushido.ai" aria-label="The Bushido Collective" title="The Bushido Collective"><span class="seal" aria-hidden="true"></span></a></footer>
  </main>
</div>
</body>
</html>
`;
}

const walk = (d) => readdirSync(d).flatMap((f) => {
  const p = join(d, f);
  return statSync(p).isDirectory() ? walk(p) : [p];
});
const collapse = (s) => s.replace(/\s+/g, " ").trim();

// ---- Pages: the built HTML, parsed once so every later step reads what a browser shows.
const home = (() => {
  const { meta, body } = readPage(join(here, "pages", "index.html"));
  const html = finish(head({ title: meta.title, description: meta.description, root: "", canonical: "", markdown: `${SITE}/index.md` }) +
    "\n" + body.replaceAll("{{logo}}", LOGO).replaceAll("{{toggle}}", TOGGLE).replaceAll("{{root}}", ""));
  return { kind: "home", key: "index.html", path: "index.md", canonicalUrl: `${SITE}/`, meta, html };
})();
const docsPages = DOCS.map(([slug]) => {
  const { meta, body } = readPage(join(here, "pages", "docs", `${slug}.html`));
  return { kind: "docs", slug, key: `docs/${slug}.html`, path: `docs/${slug}.md`, canonicalUrl: `${SITE}/docs/${slug}.html`, meta, html: finish(docsPage(slug, meta, body.replaceAll("{{root}}", "../"))) };
});
const pages = [home, ...docsPages];
for (const page of pages) {
  page.url = `${SITE}/${page.path}`;
  page.title = page.meta.title;
  page.summary = page.kind === "home" ? SUMMARY.home : SUMMARY[page.slug];
  if (!page.summary) throw new Error(`${page.key}: no one-line summary in SUMMARY`);
  page.tree = parseHtml(page.html, page.key);
}

const agentsFile = join(here, "static", "AGENTS.md");
if (!existsSync(agentsFile)) throw new Error("site/static/AGENTS.md is missing: it is the agent guide, and every build needs it");
const agentsText = readFileSync(agentsFile, "utf8");
const guide = { kind: "guide", key: null, path: GUIDE.path, url: `${SITE}/AGENTS.md`, canonicalUrl: `${SITE}/AGENTS.md`, title: GUIDE.title, summary: GUIDE.summary, body: agentsText, twin: agentsText, sections: sectionsOf(agentsText, GUIDE.title) };

// ---- Links: a link to a fragment needs that anchor in the target page.
// Anchors are emitted into a twin only when some visible link names them, so the
// twins stay free of noise. Chrome links do not count: they are removed from twins.
const refs = new Map(pages.map((p) => [p.key, new Set()]));
const idsOf = new Map(pages.map((p) => [p.key, new Set(descendants(p.tree).filter((n) => n.type === "element" && n.attrs.id).map((n) => n.attrs.id))]));
function* visible(node) {
  for (const child of node.children ?? []) {
    if (child.type !== "element" || isChrome(child)) continue;
    yield child;
    yield* visible(child);
  }
}
for (const page of pages) {
  for (const el of visible(page.tree)) {
    if (el.tag !== "a" || el.attrs.href === undefined) continue;
    const target = targetKey(el.attrs.href, page.canonicalUrl);
    if (!target || !target.fragment) continue;
    if (!refs.has(target.key)) throw new Error(`${page.key} links to ${el.attrs.href}, which is not a built page`);
    refs.get(target.key).add(target.fragment);
  }
}
// ---- Install command and CI recipes, read from the pages so they cannot drift.
const installBox = findFirst(home.tree, (n) => n.tag === "div" && hasClass(n, "install"));
const installPre = findFirst(installBox, (n) => n.tag === "pre");
const installNote = findFirst(installBox, (n) => n.tag === "p");
const command = textOf(installPre).replace(/^\$\s*/, "").trim();
if (command !== INSTALL_COMMAND) throw new Error(`the home page install command is "${command}", expected "${INSTALL_COMMAND}"`);
const install = { command, platform: collapse(textOf(installNote)), docs: `${SITE}/docs/getting-started.md#install` };
refs.get("docs/getting-started.html").add("install");

const RECIPE_SECTIONS = { github: "github-actions", gitlab: "gitlab", circleci: "circleci", buildkite: "buildkite" };
const ci = pages.find((p) => p.key === "docs/ci.html");
const recipes = {};
{
  const article = findFirst(ci.tree, (n) => n.tag === "article" && hasClass(n, "prose"));
  const found = new Map();
  let current = null;
  for (const node of descendants(article)) {
    if (node.type !== "element") continue;
    if (node.tag === "h2") current = { id: node.attrs.id, title: collapse(textOf(node)) };
    else if (node.tag === "pre" && current && !found.has(current.id)) {
      found.set(current.id, { title: current.title, language: languageOf(node), code: textOf(node).replace(/\n$/, "") });
    }
  }
  for (const [provider, id] of Object.entries(RECIPE_SECTIONS)) {
    const recipe = found.get(id);
    if (!recipe) throw new Error(`docs/ci.html has no code block under #${id}`);
    recipes[provider] = { title: recipe.title, language: recipe.language, docs: `${SITE}/docs/ci.md#${id}`, code: recipe.code };
    refs.get("docs/ci.html").add(id);
  }
}

for (const [key, ids] of refs) {
  for (const id of ids) if (!idsOf.get(key).has(id)) throw new Error(`a link names #${id} in ${key}, which has no element with that id`);
}

// ---- Twins: Markdown generated from each page's scope, with the words checked later.
function scopeOf(page) {
  if (page.kind === "home") {
    const header = findFirst(page.tree, (n) => n.tag === "header" && hasClass(n, "dive"));
    const main = findFirst(page.tree, (n) => n.tag === "main" && n.attrs.id === "main");
    const footer = findFirst(page.tree, (n) => n.tag === "footer" && hasClass(n, "dusk"));
    if (!header || !main || !footer) throw new Error(`${page.key}: the home page needs its header, main and footer`);
    return [...header.children, ...main.children, ...footer.children];
  }
  const plate = findFirst(page.tree, (n) => n.tag === "header" && hasClass(n, "plate"));
  const article = findFirst(page.tree, (n) => n.tag === "article" && hasClass(n, "prose"));
  if (!plate || !article) throw new Error(`${page.key}: a docs page needs its plate header and its prose article`);
  return [...plate.children, ...article.children];
}
for (const page of pages) {
  const scope = scopeOf(page);
  page.body = toMarkdown(scope, { file: page.key, pageUrl: page.canonicalUrl, refs: refs.get(page.key) });
  page.twin = `Canonical: ${page.canonicalUrl}\n\n${page.body}`;
  page.htmlTokens = htmlTokens(scope);
  page.sections = sectionsOf(page.body, page.title);
}

// ---- Write everything.
mkdirSync(join(out, "docs"), { recursive: true });
for (const page of pages) writeFileSync(join(out, page.key), page.html);
writeFileSync(join(out, "docs", "index.html"),
  `<!doctype html><meta charset="utf-8"><title>stoop docs</title><meta http-equiv="refresh" content="0; url=getting-started.html"><link rel="canonical" href="getting-started.html"><a href="getting-started.html">Getting started</a>\n`);
for (const page of pages) writeFileSync(join(out, page.path), page.twin);
writeFileSync(join(out, "llms.txt"), llmsTxt({ home, guide, docs: docsPages, install }));
writeFileSync(join(out, "llms-full.txt"), llmsFull({ guide, docs: docsPages }));
const indexPages = [home, guide, ...docsPages];
writeFileSync(join(out, "docs-index.json"), `${JSON.stringify(docsIndex({ pages: indexPages, install, recipes }))}\n`);
writeFileSync(join(out, "robots.txt"), ROBOTS);
writeFileSync(join(out, "sitemap.xml"), sitemapXml([...pages.map((p) => p.canonicalUrl)]));
writeFileSync(join(out, ".nojekyll"), "");

// ---- Checks on the files as written.
const slugs = readdirSync(join(here, "pages", "docs")).filter((f) => f.endsWith(".html")).map((f) => f.slice(0, -5));
const unlisted = slugs.filter((s) => !DOCS.some(([slug]) => slug === s));
const built = walk(out).map((f) => relative(out, f));
const pageKeys = new Set(pages.map((p) => p.key));
const stray = built.filter((f) => f.endsWith(".html") && !pageKeys.has(f) && !REDIRECTS.includes(f));
const generatedText = ["llms.txt", "llms-full.txt", "docs-index.json", "robots.txt", "sitemap.xml", ...indexPages.map((p) => p.path)];
const problems = [
  ...unlisted.map((s) => `pages/docs/${s}.html is not in DOCS, so it would never be built`),
  ...stray.map((f) => `${f} is a built page that the build does not know about`),
  ...checkRequiredFiles(out, ["CNAME", ".nojekyll", "install.sh", "webmcp.js", "AGENTS.md", "docs/index.html", "llms.txt", "llms-full.txt", "robots.txt", "sitemap.xml", "docs-index.json", ...pages.flatMap((p) => [p.key, p.path])]),
  ...checkPages(out, pages),
  ...checkGeneratedLinks(out, generatedText),
  ...checkDashes(out, [...indexPages.map((p) => p.path), "llms.txt", "llms-full.txt", "docs-index.json", "webmcp.js", "AGENTS.md"]),
  ...checkLlms(out, { docs: docsPages, guide, home }),
  ...checkIndex(out, JSON.parse(readFileSync(join(out, "docs-index.json"), "utf8")), indexPages),
  ...checkRobots(out),
  ...indexPages.filter((p) => p.summary.length > 110).map((p) => `${p.path}: the one-line summary is ${p.summary.length} characters, over 110`),
  ...checkBuiltLinks(out),
];
if (problems.length) {
  console.error(`site build failed:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log(`built ${walk(out).length} files into ${relative(process.cwd(), out) || "."}`);
