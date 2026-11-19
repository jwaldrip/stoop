// Text comparison and section extraction shared by the build checks and the index.
// Both sides of the twin check reduce to the same thing: the words a reader sees.
import { isChrome } from "./markdown.mjs";

const WORD = /[\p{L}\p{N}]+/gu;
const FENCE = /^(?:>\s?)*\s*```/;

// Visible words of a parsed HTML scope, in document order. Images contribute their alt
// text and role="img" elements their aria-label, because those are what a reader hears.
export function htmlTokens(nodes) {
  const parts = [];
  const walk = (node) => {
    if (node.type === "text") {
      parts.push(node.text);
      return;
    }
    if (isChrome(node)) return;
    if (node.tag === "img") parts.push(node.attrs.alt ?? "");
    if (node.attrs.role === "img" && node.attrs["aria-label"]) parts.push(node.attrs["aria-label"]);
    for (const child of node.children) walk(child);
  };
  for (const node of nodes) walk(node);
  return parts.join(" ").match(WORD) ?? [];
}

// Visible words of a twin body. Fence lines carry only a language and list markers and
// link targets are markup, so none of them count; the code inside a fence always does.
export function markdownTokens(markdown) {
  const out = [];
  let fenced = false;
  for (let line of markdown.split("\n")) {
    if (FENCE.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (!fenced) {
      line = line
        .replace(/<a id="[^"]*"><\/a>/g, "")
        .replace(/^((?:>\s?)*\s*)(?:[-*+]|\d+[.)])\s+/, "$1")
        .replace(/\]\([^)]*\)/g, "]");
    }
    out.push(...(line.match(WORD) ?? []));
  }
  return out;
}

export function firstDifference(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return { index: i, html: a.slice(Math.max(0, i - 4), i + 6).join(" "), twin: b.slice(Math.max(0, i - 4), i + 6).join(" ") };
  }
  return null;
}

// Headings from level 2 down, outside fenced code. The level-1 title and any text
// before the first section form an "intro" section. Each section runs to the next
// heading of any level (`end`) and to the next heading of its own level or higher
// (`tree_end`), so a reader can ask for a section with everything under it.
export function sectionsOf(body, title) {
  const heads = [];
  let fenced = false;
  let offset = 0;
  for (const line of body.split("\n")) {
    if (FENCE.test(line)) fenced = !fenced;
    else if (!fenced) {
      const m = /^(#{1,6}) (.+)$/.exec(line);
      if (m) heads.push({ level: m[1].length, raw: m[2], start: offset });
    }
    offset += line.length + 1;
  }
  const sections = [];
  const first = heads.find((h) => h.level >= 2);
  const introEnd = first ? first.start : body.length;
  sections.push({ id: "intro", title, level: 1, start: 0, end: introEnd, tree_end: introEnd });
  const subs = heads.filter((h) => h.level >= 2);
  subs.forEach((h, i) => {
    const anchor = /<a id="([^"]*)"><\/a>$/.exec(h.raw);
    const plain = plainText(h.raw.replace(/\s*<a id="[^"]*"><\/a>$/, ""));
    const next = subs.slice(i + 1).find((x) => x.level <= h.level);
    const anyNext = heads[heads.indexOf(h) + 1];
    sections.push({
      id: anchor ? anchor[1] : null,
      title: plain,
      level: h.level,
      start: h.start,
      end: anyNext ? anyNext.start : body.length,
      tree_end: next ? next.start : body.length,
    });
  });
  return sections;
}

// Markdown to the words a search snippet shows.
export function plainText(md) {
  return md
    .replace(/<a id="[^"]*"><\/a>/g, " ")
    .replace(/^(?:>\s?)*\s*```.*$/gm, " ")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1 ")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\\([\\`*\[\]<>])/g, "$1")
    .replace(/[*`#>|]/g, " ")
    .replace(/^\s*(?:[-+]|\d+[.)])\s+/gm, " ")
    .replace(/\s+/g, " ")
    .trim();
}
