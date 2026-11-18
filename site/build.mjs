// Builds the stoop site into site/_site. Node 18+, no dependencies.
//   node site/build.mjs
// Pages in pages/ start with <!--meta {json}-->. Docs pages are fragments wrapped in
// the docs layout; the home page is a whole document. {{root}} becomes the relative
// path back to the site root, so links also work when hosted under a prefix.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, cpSync, rmSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const out = join(here, "_site");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(join(here, "static"), out, { recursive: true });
cpSync(join(repo, "assets"), join(out, "assets"), { recursive: true });
cpSync(join(here, "install.sh"), join(out, "install.sh"));
writeFileSync(join(out, "CNAME"), "stoop.build\n");

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

function readPage(file) {
  const src = readFileSync(file, "utf8");
  const m = src.match(/^<!--meta\s+(\{[\s\S]*?\})\s*-->\n?/);
  if (!m) throw new Error(`${file}: missing <!--meta {...}--> header`);
  return { meta: JSON.parse(m[1]), body: src.slice(m[0].length) };
}

const TOGGLE = `<button class="theme-toggle" type="button" data-theme-toggle hidden></button>`;
const head = ({ title, description, root, canonical }) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<meta name="description" content="${description}">
<meta name="theme-color" content="#eef2f5" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0d1216" media="(prefers-color-scheme: dark)">
<script>try{var t=localStorage.getItem("stoop-theme");if(t==="light"||t==="dark"){document.documentElement.dataset.theme=t;document.querySelectorAll('meta[name="theme-color"]').forEach(function(m){m.dataset.orig=m.content;m.content=t==="dark"?"#0d1216":"#eef2f5"})}}catch(e){}</script>
<link rel="canonical" href="https://stoop.build/${canonical}">
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
  return `${head({ title: `${meta.title} · stoop`, description: meta.description, root, canonical: `docs/${slug}.html` })}
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
  </main>
</div>
</body>
</html>
`;
}

// Home
{
  const { meta, body } = readPage(join(here, "pages", "index.html"));
  const html = head({ title: meta.title, description: meta.description, root: "", canonical: "" }) +
    "\n" + body.replaceAll("{{logo}}", LOGO).replaceAll("{{toggle}}", TOGGLE).replaceAll("{{root}}", "");
  writeFileSync(join(out, "index.html"), finish(html));
}
// Docs
mkdirSync(join(out, "docs"), { recursive: true });
for (const [slug] of DOCS) {
  const { meta, body } = readPage(join(here, "pages", "docs", `${slug}.html`));
  writeFileSync(join(out, "docs", `${slug}.html`), finish(docsPage(slug, meta, body.replaceAll("{{root}}", "../"))));
}
writeFileSync(join(out, "docs", "index.html"),
  `<!doctype html><meta charset="utf-8"><title>stoop docs</title><meta http-equiv="refresh" content="0; url=getting-started.html"><link rel="canonical" href="getting-started.html"><a href="getting-started.html">Getting started</a>\n`);
writeFileSync(join(out, ".nojekyll"), "");
writeFileSync(join(out, "robots.txt"), "User-agent: *\nAllow: /\nSitemap: https://stoop.build/sitemap.xml\n");
writeFileSync(join(out, "sitemap.xml"), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${["", ...DOCS.map(([slug]) => `docs/${slug}.html`)].map((path) => `<url><loc>https://stoop.build/${path}</loc></url>`).join("")}</urlset>\n`);

// Every local link and asset reference must resolve.
const missing = [];
const walk = (d) => readdirSync(d).flatMap((f) => {
  const p = join(d, f);
  return statSync(p).isDirectory() ? walk(p) : [p];
});
for (const file of walk(out).filter((f) => f.endsWith(".html") || f.endsWith(".css"))) {
  const text = readFileSync(file, "utf8");
  for (const m of text.matchAll(/(?:href|src|srcset)="([^"]+)"|url\(([^)]+)\)/g)) {
    for (let ref of (m[1] ?? m[2]).split(",").map((s) => s.trim().split(/\s+/)[0])) {
      if (!ref || /^(https?:|mailto:|#|data:)/.test(ref)) continue;
      ref = ref.split("#")[0];
      if (!ref) continue;
      const target = join(dirname(file), ref);
      try { statSync(target); } catch { missing.push(`${relative(out, file)} -> ${ref}`); }
    }
  }
}
if (missing.length) {
  console.error(`broken local references:\n  ${missing.join("\n  ")}`);
  process.exit(1);
}
console.log(`built ${walk(out).length} files into ${relative(process.cwd(), out) || "."}`);
