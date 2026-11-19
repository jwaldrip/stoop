// Converts the site's own HTML into Markdown for the .md twins. It handles exactly
// the vocabulary the pages use and throws on any other element, so no text is
// dropped silently. The only elements removed are the chrome selected by isChrome():
// navigation, skip links, the theme toggle, the logo lockup, the maker mark and the
// progress bar. Their text is interface, not content, and the build's text check
// (text.mjs) compares the twin with the same scope, so a dropped sentence fails it.
import { classesOf, findAll, hasClass, textOf } from "./html.mjs";

export class TwinError extends Error {}

export const SITE_ORIGIN = "https://stoop.build";

const BLOCK = new Set(["h1", "h2", "h3", "h4", "h5", "h6", "p", "div", "section", "header", "main", "article", "footer", "figure", "figcaption", "blockquote", "hr", "ul", "ol", "dl", "table", "pre"]);
const INLINE = new Set(["span", "strong", "b", "em", "i", "code", "a", "img", "br"]);

export function isChrome(el) {
  return el.tag === "nav" || el.tag === "script" || el.tag === "style" || el.tag === "button"
    || hasClass(el, "skip") || hasClass(el, "lockup") || hasClass(el, "maker") || hasClass(el, "topline")
    || "data-chrome-progress" in el.attrs || "data-chrome-toc" in el.attrs;
}

// Maps an href written in a page to the URL its twin serves. Same-site .html pages
// become .md; directories become index.md; fragments stay; other origins are kept.
export function resolveHref(href, pageUrl) {
  const url = new URL(href, pageUrl);
  if (url.origin !== SITE_ORIGIN) return url.href;
  if (url.pathname.endsWith(".html")) url.pathname = `${url.pathname.slice(0, -5)}.md`;
  else if (url.pathname.endsWith("/")) url.pathname = `${url.pathname}index.md`;
  return url.href;
}

// The built HTML file a same-site href points at, as a key such as "docs/cli.html".
export function targetKey(href, pageUrl) {
  const url = new URL(href, pageUrl);
  if (url.origin !== SITE_ORIGIN) return null;
  let path = url.pathname.replace(/^\/+/, "");
  if (path === "" || path.endsWith("/")) path += "index.html";
  return { key: path, fragment: decodeURIComponent(url.hash.slice(1)) };
}

const escapeInline = (s) => s.replace(/[\\`*\[\]<>]/g, "\\$&");
const collapse = (s) => s.replace(/\s+/g, " ");

function anchorOf(el, ctx) {
  const id = el.attrs.id;
  return id && ctx.refs.has(id) ? `<a id="${id}"></a>` : "";
}

function fence(lang, text) {
  const f = text.includes("```") ? "````" : "```";
  return `${f}${lang}\n${text}\n${f}`;
}

function quote(text) {
  return text.split("\n").map((line) => (line ? `> ${line}` : ">")).join("\n");
}

const indent = (text, width) => text.split("\n").map((line, k) => (k === 0 || !line ? line : " ".repeat(width) + line)).join("\n");

// The language of a code block: an explicit language-* class wins, then the shell
// prompt, then YAML keys. Anything else is plain text.
export function languageOf(pre) {
  const code = findAll(pre, (n) => n.tag === "code")[0];
  const explicit = [...classesOf(pre), ...(code ? classesOf(code) : [])].find((c) => c.startsWith("language-"));
  if (explicit) return explicit.slice("language-".length);
  if (/^\$ /m.test(textOf(pre))) return "console";
  if (findAll(pre, (n) => n.tag === "span" && hasClass(n, "k")).length) return "yaml";
  return "text";
}

function inline(nodes, ctx) {
  let out = "";
  for (const node of nodes) {
    if (node.type === "text") {
      out += escapeInline(collapse(node.text));
      continue;
    }
    if (isChrome(node)) continue;
    const anchor = anchorOf(node, ctx);
    switch (node.tag) {
      case "span": out += anchor + inline(node.children, ctx) + (hasClass(node, "n") ? " " : ""); break;
      case "strong": case "b": out += anchor + wrap("**", node, ctx); break;
      case "em": case "i": out += anchor + wrap("*", node, ctx); break;
      case "code": out += anchor + codeSpan(textOf(node)); break;
      case "a": out += anchor + link(node, ctx); break;
      case "img": out += anchor + image(node, ctx); break;
      case "br": out += "  \n"; break;
      default: throw new TwinError(`${ctx.file}:${node.line}: <${node.tag}> is not supported inside text`);
    }
  }
  return out;
}

function wrap(marker, node, ctx) {
  const inner = inline(node.children, ctx);
  const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(inner);
  return m[2] ? `${m[1]}${marker}${m[2]}${marker}${m[3]}` : m[1] + m[3];
}

function codeSpan(raw) {
  const text = raw.replace(/\n/g, " ");
  if (!text) return "";
  const ticks = text.includes("`") ? "``" : "`";
  const pad = ticks.length > 1 ? " " : "";
  return `${ticks}${pad}${text}${pad}${ticks}`;
}

function link(node, ctx) {
  const text = inline(node.children, ctx).trim();
  if (node.attrs.href === undefined) return text;
  const target = resolveHref(node.attrs.href, ctx.pageUrl);
  return `[${text || escapeInline(target)}](${target})`;
}

function image(node, ctx) {
  if (node.attrs.src === undefined) throw new TwinError(`${ctx.file}:${node.line}: <img> has no src`);
  return `![${escapeInline(node.attrs.alt ?? "")}](${resolveHref(node.attrs.src, ctx.pageUrl)})`;
}

// Block-level nodes become blocks; runs of text and inline elements become one paragraph.
export function blocks(nodes, ctx) {
  const out = [];
  let run = [];
  const flush = () => {
    if (run.length) {
      const text = inline(run, ctx).trim();
      if (text) out.push(text);
    }
    run = [];
  };
  for (const node of nodes) {
    if (node.type === "text" || INLINE.has(node.tag)) {
      if (!(node.type === "element" && isChrome(node))) run.push(node);
      continue;
    }
    flush();
    if (isChrome(node)) continue;
    out.push(...block(node, ctx));
  }
  flush();
  return out;
}

function block(el, ctx) {
  if (!BLOCK.has(el.tag)) throw new TwinError(`${ctx.file}:${el.line}: <${el.tag}> is not supported`);
  const anchor = anchorOf(el, ctx);
  const lead = anchor ? [anchor] : [];

  if (/^h[1-6]$/.test(el.tag)) {
    const text = inline(el.children, ctx).trim();
    if (!text) throw new TwinError(`${ctx.file}:${el.line}: empty <${el.tag}>`);
    // Every heading keeps its id as an anchor, so each section has a stable link target.
    const id = el.attrs.id ? ` <a id="${el.attrs.id}"></a>` : "";
    return [`${"#".repeat(Number(el.tag[1]))} ${text}${id}`];
  }

  switch (el.tag) {
    case "p": {
      const text = inline(el.children, ctx).trim();
      if (!text) return lead;
      return [...lead, hasClass(el, "lede") || hasClass(el, "note") ? quote(text) : text];
    }
    case "div":
      if (hasClass(el, "term")) return [...lead, ...terminal(el, ctx)];
      if (el.attrs.role === "img") throw new TwinError(`${ctx.file}:${el.line}: role="img" on <div> has no conversion`);
      if (hasClass(el, "note")) return [...lead, quote(blocks(el.children, ctx).join("\n\n"))];
      return [...lead, ...blocks(el.children, ctx)];
    case "section": case "header": case "main": case "article": case "footer": case "figure": case "figcaption":
      return [...lead, ...blocks(el.children, ctx)];
    case "blockquote":
      return [...lead, quote(blocks(el.children, ctx).join("\n\n"))];
    case "hr":
      return [...lead, "---"];
    case "ul": case "ol":
      return [...lead, list(el, ctx)];
    case "dl":
      return [...lead, ...definitions(el, ctx)];
    case "table":
      return [...lead, table(el, ctx)];
    case "pre":
      return [...lead, fence(languageOf(el), textOf(el).replace(/\n$/, ""))];
    default:
      throw new TwinError(`${ctx.file}:${el.line}: <${el.tag}> is not supported`);
  }
}

// A transcript: its child lines become one text block, preceded by its accessible
// description when the element is an image (role="img", aria-label).
function terminal(el, ctx) {
  const parts = [];
  if (el.attrs["aria-label"]) parts.push(inline([{ type: "text", text: el.attrs["aria-label"] }], ctx).trim());
  const lines = [];
  for (const child of el.children) {
    if (child.type === "text") {
      if (child.text.trim()) throw new TwinError(`${ctx.file}:${child.parent.line}: text inside a transcript must sit in a line`);
      continue;
    }
    if (child.tag !== "div") throw new TwinError(`${ctx.file}:${child.line}: <${child.tag}> inside a transcript`);
    lines.push(textOf(child));
  }
  parts.push(fence("text", lines.join("\n")));
  return parts;
}

function list(el, ctx) {
  const ordered = el.tag === "ol";
  const items = [];
  let n = 0;
  for (const child of el.children) {
    if (child.type === "text") {
      if (child.text.trim()) throw new TwinError(`${ctx.file}:${el.line}: text directly inside <${el.tag}>`);
      continue;
    }
    if (isChrome(child)) continue;
    if (child.tag !== "li") throw new TwinError(`${ctx.file}:${child.line}: <${child.tag}> directly inside <${el.tag}>`);
    n++;
    const marker = ordered ? `${n}. ` : "- ";
    const parts = blocks(child.children, ctx);
    // A nested list sits tight under the line it belongs to; other blocks get a blank line.
    const body = parts.reduce((acc, part, k) => (k === 0 ? part : `${acc}${/^(?:- |\d+\. )/.test(part) ? "\n" : "\n\n"}${part}`), "");
    items.push(parts.length ? marker + indent(body, marker.length) : marker.trimEnd());
  }
  return items.join("\n");
}

function definitions(el, ctx) {
  const out = [];
  for (const child of el.children) {
    if (child.type === "text") {
      if (child.text.trim()) throw new TwinError(`${ctx.file}:${el.line}: text directly inside <dl>`);
      continue;
    }
    if (child.tag === "dt") {
      const term = inline(child.children, ctx).trim();
      if (!term) throw new TwinError(`${ctx.file}:${child.line}: empty <dt>`);
      out.push(`${anchorOf(child, ctx)}**${term}**`);
    } else if (child.tag === "dd") {
      out.push(...blocks(child.children, ctx));
    } else {
      throw new TwinError(`${ctx.file}:${child.line}: <${child.tag}> directly inside <dl>`);
    }
  }
  return out;
}

function table(el, ctx) {
  const elements = (node, names) => node.children.filter((c) => c.type === "element" && names.includes(c.tag));
  for (const child of el.children) {
    if (child.type === "element" && !["thead", "tbody", "tr"].includes(child.tag)) {
      throw new TwinError(`${ctx.file}:${child.line}: <${child.tag}> inside <table>`);
    }
  }
  const headRows = elements(el, ["thead"]).flatMap((s) => elements(s, ["tr"]));
  if (headRows.length > 1) throw new TwinError(`${ctx.file}:${el.line}: more than one header row`);
  const bodyRows = [...elements(el, ["tbody"]).flatMap((s) => elements(s, ["tr"])), ...elements(el, ["tr"])];
  const cellText = (cell) => inline(cell.children, ctx).replace(/\s+/g, " ").trim().replace(/\|/g, "\\|");
  const rowCells = (row) => elements(row, ["td", "th"]).map(cellText);
  const head = headRows.map(rowCells);
  const body = bodyRows.map(rowCells);
  const columns = Math.max(0, ...[...head, ...body].map((r) => r.length));
  if (!columns) throw new TwinError(`${ctx.file}:${el.line}: table has no cells`);
  const pad = (row) => Array.from({ length: columns }, (_, i) => row[i] ?? "");
  const line = (cells) => `| ${cells.join(" | ")} |`;
  const header = head.length ? pad(head[0]) : Array(columns).fill("");
  return [line(header), line(Array(columns).fill("---")), ...body.map((r) => line(pad(r)))].join("\n");
}

// Converts the children of a scope root (already selected by the caller) into the
// body of a twin. `ctx` = { file, pageUrl, refs: Set of ids that some link targets }.
export function toMarkdown(nodes, ctx) {
  return `${blocks(nodes, ctx).join("\n\n")}\n`;
}
