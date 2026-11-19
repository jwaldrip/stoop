// A strict reader for the site's own HTML. It has no dependencies and fails on
// anything it does not understand: unknown entities, malformed tags, and end tags
// that do not close the element on top of the stack. Text and attribute values are
// decoded here, once, so every later step sees the characters a browser shows.

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
const RAW_TEXT = new Set(["script", "style"]);
const NAMED = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00a0",
  thinsp: "\u2009", ensp: "\u2002", emsp: "\u2003", middot: "\u00b7", hellip: "\u2026",
  rarr: "\u2192", larr: "\u2190", times: "\u00d7", copy: "\u00a9",
};

const OPEN = /<([a-zA-Z][a-zA-Z0-9-]*)((?:\s+[^\s"'>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*(\/?)>/y;
const CLOSE = /<\/([a-zA-Z][a-zA-Z0-9-]*)\s*>/y;
const ATTR = /\s+([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

export class HtmlError extends Error {}

export function decodeEntities(text, where = "text") {
  return text.replace(/&(#[xX][0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);/g, (whole, name) => {
    if (name[0] === "#") {
      const hex = name[1] === "x" || name[1] === "X";
      const code = hex ? parseInt(name.slice(2), 16) : parseInt(name.slice(1), 10);
      try {
        return String.fromCodePoint(code);
      } catch {
        throw new HtmlError(`${where}: invalid character reference ${whole}`);
      }
    }
    if (!Object.hasOwn(NAMED, name)) throw new HtmlError(`${where}: unknown entity ${whole}`);
    return NAMED[name];
  });
}

// Returns { type: "element", tag, attrs, children, parent, line } nodes and
// { type: "text", text, parent } nodes under a synthetic "#root" element.
export function parseHtml(source, file = "html") {
  const lineStarts = [0];
  for (let k = 0; k < source.length; k++) if (source.charCodeAt(k) === 10) lineStarts.push(k + 1);
  const lineOf = (index) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const fail = (index, message) => {
    throw new HtmlError(`${file}:${lineOf(index)}: ${message}`);
  };

  const root = { type: "element", tag: "#root", attrs: {}, children: [], parent: null, line: 1 };
  let top = root;

  const addText = (raw, index) => {
    if (!raw) return;
    const text = decodeEntities(raw, `${file}:${lineOf(index)}`);
    const last = top.children[top.children.length - 1];
    if (last && last.type === "text") last.text += text;
    else top.children.push({ type: "text", text, parent: top });
  };

  let i = 0;
  while (i < source.length) {
    const lt = source.indexOf("<", i);
    if (lt === -1) {
      addText(source.slice(i), i);
      break;
    }
    addText(source.slice(i, lt), i);
    i = lt;

    if (source.startsWith("<!--", i)) {
      const end = source.indexOf("-->", i + 4);
      if (end === -1) fail(i, "unterminated comment");
      i = end + 3;
      continue;
    }
    if (source.startsWith("<!", i)) {
      const end = source.indexOf(">", i);
      if (end === -1) fail(i, "unterminated declaration");
      i = end + 1;
      continue;
    }

    CLOSE.lastIndex = i;
    const close = CLOSE.exec(source);
    if (close) {
      const name = close[1].toLowerCase();
      if (top.tag !== name) fail(i, `</${name}> does not close <${top.tag}>`);
      top = top.parent;
      i = CLOSE.lastIndex;
      continue;
    }

    OPEN.lastIndex = i;
    const open = OPEN.exec(source);
    if (!open) fail(i, "malformed tag");
    const tag = open[1].toLowerCase();
    const attrs = {};
    for (const m of open[2].matchAll(ATTR)) {
      attrs[m[1].toLowerCase()] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? "", `${file}:${lineOf(i)}`);
    }
    const el = { type: "element", tag, attrs, children: [], parent: top, line: lineOf(i) };
    top.children.push(el);
    i = OPEN.lastIndex;
    if (open[3] === "/" || VOID.has(tag)) continue;

    if (RAW_TEXT.has(tag)) {
      const endTag = new RegExp(`</${tag}\\s*>`, "gi");
      endTag.lastIndex = i;
      const end = endTag.exec(source);
      if (!end) fail(i, `unterminated <${tag}>`);
      if (end.index > i) el.children.push({ type: "text", text: source.slice(i, end.index), parent: el });
      i = endTag.lastIndex;
      continue;
    }
    top = el;
  }
  if (top !== root) fail(source.length, `<${top.tag}> is never closed`);
  return root;
}

export const classesOf = (el) => (el.attrs.class ?? "").split(/\s+/).filter(Boolean);
export const hasClass = (el, name) => classesOf(el).includes(name);

export function* descendants(node) {
  for (const child of node.children ?? []) {
    yield child;
    if (child.children) yield* descendants(child);
  }
}

export const findAll = (node, predicate) => [...descendants(node)].filter(predicate);
export const findFirst = (node, predicate) => {
  for (const d of descendants(node)) if (predicate(d)) return d;
  return undefined;
};

export function textOf(node) {
  if (node.type === "text") return node.text;
  return (node.children ?? []).map(textOf).join("");
}
