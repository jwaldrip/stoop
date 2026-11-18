// Builds the stoop site into site/_site. Node 18+, no dependencies.
//   node site/build.mjs
// Pages in pages/ start with <!--meta {json}-->. Docs pages are fragments wrapped in
// the docs layout; the home page is a whole document. {{root}} becomes the relative
// path back to the site root, so the site works under any base path (GitHub Pages
// serves it at /stoop/).
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
<link rel="canonical" href="https://jwaldrip.github.io/stoop/${canonical}">
<link rel="icon" href="${root}assets/stoop-app.svg" type="image/svg+xml">
<link rel="icon" href="${root}assets/favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="${root}assets/apple-touch-icon.png">
<meta property="og:type" content="website">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:image" content="https://jwaldrip.github.io/stoop/assets/social-preview.png">
<meta property="og:image:width" content="1280">
<meta property="og:image:height" content="640">
<meta name="twitter:card" content="summary_large_image">
<link rel="preload" href="${root}fonts/BodoniModa-normal-400_900.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="${root}fonts/IBMPlexSans-normal-400.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="${root}styles.css">
<script src="${root}chrome.js" defer></script>
</head>`;

function docsPage(slug, meta, body) {
  const root = "../";
  const i = DOCS.findIndex(([s]) => s === slug);
  const prev = DOCS[i - 1];
  const next = DOCS[i + 1];
  const rail = DOCS.map(([s, t]) =>
    `<li><a href="${s}.html"${s === slug ? ' aria-current="page"' : ""}>${t}</a></li>`).join("\n      ");
  const img = meta.image
    ? `<figure><img src="${root}images/${meta.image}.webp" srcset="${root}images/${meta.image}-800.webp 800w, ${root}images/${meta.image}.webp 1536w" sizes="(max-width: 900px) 100vw, 40vw" alt="${meta.alt}" width="1536" height="1024" data-chrome-lightbox></figure>`
    : "";
  return `${head({ title: `${meta.title} · stoop`, description: meta.description, root, canonical: `docs/${slug}.html` })}
<body>
<a class="skip" href="#main">Skip to the page</a>
<div data-chrome-progress role="progressbar" aria-label="Reading progress" aria-valuemin="0" aria-valuemax="100"></div>
<div class="docs">
  <nav class="rail" aria-label="Field guide">
    <a class="lockup" href="${root}index.html" aria-label="stoop home">${LOGO}</a>
    <ol>
      ${rail}
    </ol>
    <div class="out">
      ${TOGGLE}
      <a href="https://github.com/jwaldrip/stoop">Source on GitHub</a>
      <a href="https://github.com/jwaldrip/stoop/issues">Report a problem</a>
    </div>
  </nav>
  <main class="page" id="main">
    <header class="plate">
      <div class="plate-text">
        <h1>${meta.title}</h1>
        <p class="lede">${meta.lede}</p>
      </div>
      ${img}
    </header>
    <article class="prose">
${body.trim()}
      <nav class="next" aria-label="Pages">
        <span>${prev ? `<a href="${prev[0]}.html">${prev[1]}</a>` : `<a href="${root}index.html">stoop</a>`}</span>
        <span>${next ? `<a href="${next[0]}.html">${next[1]}</a>` : ""}</span>
      </nav>
    </article>
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
  writeFileSync(join(out, "index.html"), html);
}
// Docs
mkdirSync(join(out, "docs"), { recursive: true });
for (const [slug] of DOCS) {
  const { meta, body } = readPage(join(here, "pages", "docs", `${slug}.html`));
  writeFileSync(join(out, "docs", `${slug}.html`), docsPage(slug, meta, body.replaceAll("{{root}}", "../")));
}
writeFileSync(join(out, "docs", "index.html"),
  `<!doctype html><meta charset="utf-8"><title>stoop docs</title><meta http-equiv="refresh" content="0; url=getting-started.html"><link rel="canonical" href="getting-started.html"><a href="getting-started.html">Getting started</a>\n`);
writeFileSync(join(out, ".nojekyll"), "");

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
