// Unit tests for the HTML reader, the HTML-to-Markdown converter, and the word check that
// ties a twin to its page. Each rule in lib/markdown.mjs has a test that fails if it breaks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseHtml, HtmlError } from "../lib/html.mjs";
import { toMarkdown, TwinError } from "../lib/markdown.mjs";
import { htmlTokens, markdownTokens, sectionsOf, plainText } from "../lib/text.mjs";

const PAGE = "https://stoop.build/docs/cli.html";

function convert(html, { refs = [], pageUrl = PAGE } = {}) {
  const root = parseHtml(`<main>${html}</main>`, "fixture.html");
  const main = root.children[0];
  return toMarkdown(main.children, { file: "fixture.html", pageUrl, refs: new Set(refs) });
}

test("headings keep their text and carry their id as an anchor", () => {
  assert.equal(convert('<h2 id="changed-hook">Changed-unit hook</h2>'), '## Changed-unit hook <a id="changed-hook"></a>\n');
  assert.equal(convert("<h3>Plain heading</h3>"), "### Plain heading\n");
});

test("paragraphs keep strong and emphasis and escape markdown characters in text", () => {
  assert.equal(convert("<p>a <strong>b</strong> <em>c</em> *x* [y] `z`</p>"), "a **b** *c* \\*x\\* \\[y\\] \\`z\\`\n");
});

test("inline code keeps its text, using double backticks when the code holds one", () => {
  assert.equal(convert("<p><code>stoop run -- make</code></p>"), "`stoop run -- make`\n");
  assert.equal(convert("<p><code>a`b</code></p>"), "`` a`b ``\n");
  assert.equal(convert("<p><code>a &lt;b&gt; &amp;&amp; c</code></p>"), "`a <b> && c`\n");
});

test("links point at the markdown twin, keep their fragment, and leave other origins alone", () => {
  assert.equal(convert('<p><a href="blind-spots.html#network">Blind spots</a></p>'), "[Blind spots](https://stoop.build/docs/blind-spots.md#network)\n");
  assert.equal(convert('<p><a href="../index.html#compared">Compare</a></p>'), "[Compare](https://stoop.build/index.md#compared)\n");
  assert.equal(convert('<p><a href="#changed-hook">here</a></p>'), "[here](https://stoop.build/docs/cli.md#changed-hook)\n");
  assert.equal(convert('<p><a class="src" href="https://bazel.build/x">bazel.build</a></p>'), "[bazel.build](https://bazel.build/x)\n");
});

test("images keep their alt text and resolve their source", () => {
  assert.equal(convert('<figure><img src="../images/a.webp" alt="A bird [on] a ledge" width="1" height="1"></figure>'),
    "![A bird \\[on\\] a ledge](https://stoop.build/images/a.webp)\n");
});

test("unordered and ordered lists nest, and continuation paragraphs stay in their item", () => {
  assert.equal(convert("<ul><li>one</li><li>two<ul><li>inner</li></ul></li></ul>"), "- one\n- two\n  - inner\n");
  assert.equal(convert("<ol><li><strong>Watch.</strong> Runs.<p>Next paragraph.</p></li><li>Two</li></ol>"),
    "1. **Watch.** Runs.\n\n   Next paragraph.\n2. Two\n");
});

test("a numeral span is followed by a space, so it does not run into its link", () => {
  assert.equal(convert('<ol><li><span class="n">i</span><a href="getting-started.html">Getting started</a></li></ol>'),
    "1. i [Getting started](https://stoop.build/docs/getting-started.md)\n");
});

test("definition lists give each term in bold, then its definition blocks", () => {
  assert.equal(convert("<dl><dt>--key NAME</dt><dd>Name the proof.</dd><dt>--root DIR</dt><dd><p>Root.</p><pre><code>x</code></pre></dd></dl>"),
    "**--key NAME**\n\nName the proof.\n\n**--root DIR**\n\nRoot.\n\n```text\nx\n```\n");
});

test("a table with a header row keeps its columns and escapes pipes inside cells", () => {
  assert.equal(convert("<table><thead><tr><th>Shell</th><th>Write</th></tr></thead><tbody><tr><td>dash</td><td><code>{a|b}</code></td></tr></tbody></table>"),
    "| Shell | Write |\n| --- | --- |\n| dash | `{a\\|b}` |\n");
});

test("a table without a header keeps its row headers in the first column", () => {
  assert.equal(convert('<table><tbody><tr><th scope="row">Files</th><td>Traced.</td></tr></tbody></table>'),
    "|  |  |\n| --- | --- |\n| Files | Traced. |\n");
});

test("code blocks keep their text and take their language from the prompt, the YAML keys, or a language class", () => {
  assert.equal(convert('<pre><code><span class="p">$</span> curl -fsSL https://stoop.build/install.sh | sh</code></pre>'),
    "```console\n$ curl -fsSL https://stoop.build/install.sh | sh\n```\n");
  assert.equal(convert('<pre><code><span class="k">defaults</span>:\n  <span class="k">run</span>:</code></pre>'),
    "```yaml\ndefaults:\n  run:\n```\n");
  assert.equal(convert('<pre><code class="language-gitignore"># note\nnode_modules</code></pre>'), "```gitignore\n# note\nnode_modules\n```\n");
  assert.equal(convert("<pre>plain &gt; text</pre>"), "```text\nplain > text\n```\n");
});

test("notes and lede paragraphs become quotes", () => {
  assert.equal(convert('<div class="note"><p><strong>Tracing needs Linux.</strong> On macOS it runs.</p></div>'),
    "> **Tracing needs Linux.** On macOS it runs.\n");
  assert.equal(convert('<p class="lede">Every command.</p>'), "> Every command.\n");
});

test("a transcript keeps its description and its lines in one text block", () => {
  const html = '<div class="term" role="img" aria-label="A session."><div class="cmd">stoop run -- cargo build</div><div class="out hit">stoop: skip cargo</div><div class="elide">   … cargo compiles …</div></div>';
  assert.equal(convert(html), "A session.\n\n```text\nstoop run -- cargo build\nstoop: skip cargo\n   … cargo compiles …\n```\n");
});

test("figures keep their image and caption", () => {
  assert.equal(convert('<figure><img src="../images/a.webp" alt="A bird."><figcaption>Captured, <code>c9082e1</code>.</figcaption></figure>'),
    "![A bird.](https://stoop.build/images/a.webp)\n\nCaptured, `c9082e1`.\n");
});

test("chrome is removed, and only chrome", () => {
  const out = convert('<nav aria-label="Site"><a href="x.html">Field guide</a></nav><div class="topline"><a class="lockup" href="index.html"><svg></svg></a></div><p>Kept.</p><button data-theme-toggle hidden></button><a class="skip" href="#main">Skip</a>');
  assert.equal(out, "Kept.\n");
});

test("an element the converter does not know fails the conversion instead of being dropped", () => {
  assert.throws(() => convert("<p>a</p><video src='x.mp4'></video>"), (error) => error instanceof TwinError && /<video> is not supported/.test(error.message));
  assert.throws(() => convert("<p>a <blink>b</blink></p>"), (error) => error instanceof TwinError && /<blink> is not supported inside text/.test(error.message));
  assert.throws(() => convert("<ul><p>x</p></ul>"), TwinError);
  assert.throws(() => convert("<li>loose</li>"), TwinError);
  assert.throws(() => convert("<table><caption>c</caption><tbody><tr><td>x</td></tr></tbody></table>"), TwinError);
  assert.throws(() => convert("<table><thead><tr><th>a</th></tr><tr><th>b</th></tr></thead></table>"), TwinError);
  assert.throws(() => convert("<figure><img alt='no source'></figure>"), TwinError);
});

test("an anchor is emitted for a block only when a link names it", () => {
  assert.equal(convert('<dl><dt id="opt-key">--key NAME</dt><dd>x</dd></dl>'), "**--key NAME**\n\nx\n");
  assert.equal(convert('<dl><dt id="opt-key">--key NAME</dt><dd>x</dd></dl>', { refs: ["opt-key"] }), '<a id="opt-key"></a>**--key NAME**\n\nx\n');
});

test("the HTML reader decodes entities and rejects what it cannot read", () => {
  const root = parseHtml("<p>&lt;a&gt; &amp; &thinsp;&#65;&#x42;</p>", "t.html");
  assert.equal(root.children[0].children[0].text, "<a> & \u2009AB");
  assert.throws(() => parseHtml("<p>&bogus;</p>", "t.html"), (e) => e instanceof HtmlError && /unknown entity &bogus;/.test(e.message));
  assert.throws(() => parseHtml("<div><span></div>", "t.html"), (e) => e instanceof HtmlError && /does not close/.test(e.message));
  assert.throws(() => parseHtml("<div>", "t.html"), (e) => e instanceof HtmlError && /never closed/.test(e.message));
  assert.throws(() => parseHtml("<p>a < b</p>", "t.html"), HtmlError);
});

test("the HTML reader keeps script text raw and reads void and self-closing elements", () => {
  const root = parseHtml('<script>if (a < b && c) { x = "</p>"; }</script><img src="a.png" alt="a"><svg><path d="M0 0"/></svg>', "t.html");
  const [script, img, svg] = root.children;
  assert.equal(script.children[0].text, 'if (a < b && c) { x = "</p>"; }');
  assert.equal(img.attrs.alt, "a");
  assert.equal(svg.children[0].tag, "path");
});

test("the word check fails when the twin drops a visible sentence, and passes when nothing changed", () => {
  const html = "<h2>Title</h2><p>Visible <strong>words</strong> here.</p><ul><li>item one</li></ul>";
  const root = parseHtml(`<main>${html}</main>`, "fixture.html");
  const scope = root.children[0].children;
  const twin = convert(html);
  assert.deepEqual(htmlTokens(scope), markdownTokens(twin));
  const dropped = twin.replace("Visible **words** here.\n\n", "");
  assert.notDeepEqual(htmlTokens(scope), markdownTokens(dropped));
  const renumbered = twin.replace("- item one", "- item one 99");
  assert.notDeepEqual(htmlTokens(scope), markdownTokens(renumbered));
});

test("list markers and anchors are not words, but code inside a fence always is", () => {
  assert.deepEqual(markdownTokens("1. one\n- two <a id=\"x\"></a> [three](https://stoop.build/a.md)\n"), ["one", "two", "three"]);
  assert.deepEqual(markdownTokens("```yaml\n- 2 items\n```\n"), ["2", "items"]);
});

test("sections run from heading to heading, and the tree end includes sub-sections", () => {
  const body = "# Title\n\nIntro words.\n\n## One <a id=\"one\"></a>\n\nA.\n\n### Sub\n\nB.\n\n## Two\n\nC.\n\n```md\n## not a heading\n```\n";
  const sections = sectionsOf(body, "Title");
  assert.deepEqual(sections.map((s) => s.id), ["intro", "one", null, null]);
  const one = sections[1];
  assert.equal(body.slice(one.start, one.end).startsWith("## One"), true);
  assert.equal(body.slice(one.start, one.tree_end).includes("### Sub"), true);
  assert.equal(body.slice(one.start, one.tree_end).includes("## Two"), false);
  assert.equal(sections.some((s) => s.title === "not a heading"), false);
  assert.equal(plainText("**Bold** [link](https://x.y/z) `code`"), "Bold link code");
});

test("a twin escapes angle brackets, so text such as <command> is not read as markup", () => {
  assert.equal(convert("<p>run &lt;command&gt;</p>"), "run \\<command\\>\n");
  assert.equal(convert("<p>a &lt;b&gt; c</p>"), "a \\<b\\> c\n");
});
