// The WebMCP script, tested in a VM with a stub modelContext and a fetch that reads the
// built site. The positive checks prove the shipped script meets the contract. The
// mutation tests prove that each guard fails on a broken copy, so a green run means
// something. The browser test (webmcp.browser.test.mjs) repeats the checks in Chrome.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { ensureBuilt, SITE_DIR } from "./support/build.mjs";
import { loadScript } from "./support/vm-host.mjs";
import { contractProblems, LIMITS } from "./support/contract.mjs";
import {
  readShipped, readIndex, staticProblems, signalProblems, executeAll, budgetProblems, contentProblems, paginationProblems, badInputProblems,
} from "./support/guards.mjs";

before(() => ensureBuilt());

// Replaces the one tool in `tools` whose name matches, leaving the rest unchanged.
const withTool = (tools, name, patch) => tools.map((t) => (t.name === name ? { ...t, ...patch(t) } : t));
const registeredTools = async () => (await executeAll(readShipped(), SITE_DIR)).tools;

// Replaces `from` with `to` in the shipped source and insists the replacement happened.
function mutate(from, to) {
  const source = readShipped();
  assert.ok(source.includes(from), `the mutation target is present: ${from.slice(0, 60)}`);
  return source.replace(from, to);
}

test("the shipped script registers the five read-only tools, and they meet the contract", async () => {
  const { tools, outputs, errors } = await executeAll(readShipped(), SITE_DIR);
  assert.deepEqual(tools.map((t) => t.name), ["list_pages", "read_page", "search_docs", "get_install_command", "get_ci_recipe"]);
  assert.deepEqual(budgetProblems(tools, outputs, errors), []);
  for (const tool of tools) {
    assert.equal(tool.annotations.readOnlyHint, true, `${tool.name} is read-only`);
    assert.equal(tool.annotations.consequentialHint, false, `${tool.name} is not consequential`);
    assert.equal(typeof tool.annotations.untrustedContentHint, "boolean", `${tool.name} states untrustedContentHint`);
  }
});

test("each tool resolves with an object of at most 1500 serialised characters, with the content it promises", async () => {
  const { outputs } = await executeAll(readShipped(), SITE_DIR);
  for (const [name, output] of Object.entries(outputs)) {
    assert.equal(typeof output, "object", `${name} resolves with an object`);
    const size = JSON.stringify(output).length;
    assert.ok(size <= LIMITS.output, `${name} serialises to ${size} characters`);
  }
  assert.deepEqual(contentProblems(outputs, readIndex(SITE_DIR)), []);
});

test("following next_offset rebuilds a long page exactly", async () => {
  assert.deepEqual(await paginationProblems(readShipped(), SITE_DIR, "docs/ci.md"), []);
  assert.deepEqual(await paginationProblems(readShipped(), SITE_DIR, "docs/cli.md"), []);
});

test("a newline cut accounts for a longer next section in the final window", async () => {
  const text = `${"a".repeat(1279)}\n${"b".repeat(3000)}`;
  const longId = "long-section-".repeat(20);
  const index = { pages: [{ path: "docs/window.md", body_length: text.length, sections: [
    { id: longId, start: 1280, tree_end: 2500 },
    { id: "x", start: 2500, tree_end: text.length },
  ] }] };
  const fetch = async (url) => ({
    ok: true,
    text: async () => String(url).endsWith("/docs-index.json") ? JSON.stringify(index) : text,
  });
  const readWindow = async (source) => {
    const { tools } = await loadScript({ source, fetch });
    return tools.find((tool) => tool.name === "read_page").execute(
      { path: "docs/window.md" }, { signal: new AbortController().signal },
    );
  };
  const old = mutate("while (cut > 0 && measure(at(cut)) > LIMIT)", "while (false)");
  const oversized = await readWindow(old);
  assert.ok(JSON.stringify(oversized).length > LIMITS.output, "the old cut exceeds the budget");

  const result = await readWindow(readShipped());
  assert.ok(JSON.stringify(result).length <= LIMITS.output);
  assert.equal(result.next_section, longId);
  assert.ok(result.next_offset > 0);
  assert.equal(result.next_offset, result.markdown.length);
  assert.equal(result.markdown, text.slice(0, result.next_offset));
  assert.deepEqual(await paginationProblems(readShipped(), SITE_DIR, "docs/cli.md"), []);
});

test("every fetch passes the tool's AbortSignal, and an aborted call rejects with AbortError", async () => {
  assert.deepEqual(staticProblems(readShipped()), []);
  assert.deepEqual(await signalProblems(readShipped(), SITE_DIR), []);
});

test("bad input resolves with an error object that names the valid choices, within the budget", async () => {
  const { tools } = await executeAll(readShipped(), SITE_DIR);
  assert.deepEqual(await badInputProblems(tools), []);
});

test("with no modelContext the script registers nothing and throws nothing", async () => {
  const { tools, warnings } = await loadScript({ source: readShipped(), document: { currentScript: { src: "https://stoop.build/webmcp.js" } }, navigator: {} });
  assert.equal(tools.length, 0);
  assert.equal(warnings.length, 0);
});

test("navigator.modelContext is used only when document.modelContext is absent", async () => {
  const onNavigator = [];
  await loadScript({
    source: readShipped(),
    document: { currentScript: { src: "https://stoop.build/webmcp.js" } },
    navigator: { modelContext: { registerTool: (t) => (onNavigator.push(t), Promise.resolve()) } },
  });
  assert.equal(onNavigator.length, 5, "the navigator alias receives all five tools when the document has none");

  const onDocument = [];
  const navigatorStill = [];
  await loadScript({
    source: readShipped(),
    document: { currentScript: { src: "https://stoop.build/webmcp.js" }, modelContext: { registerTool: (t) => (onDocument.push(t), Promise.resolve()) } },
    navigator: { modelContext: { registerTool: (t) => (navigatorStill.push(t), Promise.resolve()) } },
  });
  assert.equal(onDocument.length, 5, "the document receives all five tools when it has modelContext");
  assert.equal(navigatorStill.length, 0, "the navigator alias is ignored when the document has modelContext");
});

// ---- Mutation proofs: each broken variant must trip the guard meant to catch it.

test("the budget guard fails: a name over 30 characters, a description over 500, a parameter over 150", async () => {
  const tools = await registeredTools();
  assert.deepEqual(contractProblems(tools), []);
  const longName = withTool(tools, "list_pages", () => ({ name: "list_pages_with_a_name_that_is_too_long" }));
  assert.ok(contractProblems(longName).some((p) => /the name is \d+ characters, over 30/.test(p)));
  const longDescription = withTool(tools, "list_pages", () => ({ description: `Returns ${"x".repeat(500)}` }));
  assert.ok(contractProblems(longDescription).some((p) => /over 500/.test(p)));
  const longParam = withTool(tools, "read_page", (t) => ({ inputSchema: { ...t.inputSchema, properties: { ...t.inputSchema.properties, path: { type: "string", description: `Returns ${"y".repeat(150)}` } } } }));
  assert.ok(contractProblems(longParam).some((p) => /description of path is \d+ characters, over 150/.test(p)));
  const longParamName = withTool(tools, "search_docs", (t) => ({ inputSchema: { ...t.inputSchema, properties: { ["q".repeat(31)]: { type: "string", description: "Returns words." } } } }));
  assert.ok(contractProblems(longParamName).some((p) => /the parameter q+ is 31 characters, over 30/.test(p)));
});

test("the budget guard fails: a result over 1500 serialised characters, and fewer than five tools", async () => {
  const tools = await registeredTools();
  assert.ok(contractProblems(tools, { list_pages: { pad: "x".repeat(LIMITS.output) } }).some((p) => /serialised result is \d+ characters, over 1500/.test(p)));
  assert.ok(contractProblems(tools.slice(0, 4)).some((p) => /only 4 tools/.test(p)));
});

test("the result guard fails: a result that is JSON text rather than an object", async () => {
  const tools = await registeredTools();
  assert.ok(contractProblems(tools, { list_pages: JSON.stringify({ total_pages: 1 }) }).some((p) => /must be an object/.test(p)));
});

test("the wording guard fails: a description that does not start with Returns, or uses negative wording", async () => {
  const tools = await registeredTools();
  assert.ok(contractProblems(withTool(tools, "get_install_command", () => ({ description: "Gives the install line." }))).some((p) => /must start with "Returns"/.test(p)));
  assert.ok(contractProblems(withTool(tools, "get_install_command", () => ({ description: "Returns the command. It does not install anything." }))).some((p) => /negative wording/.test(p)));
});

test("the annotation guard fails: a missing annotation, and a tool that is both read-only and consequential", async () => {
  const tools = await registeredTools();
  const missing = withTool(tools, "search_docs", () => ({ annotations: { readOnlyHint: true, untrustedContentHint: false } }));
  assert.ok(contractProblems(missing).some((p) => /consequentialHint is not stated/.test(p)));
  const both = withTool(tools, "search_docs", () => ({ annotations: { readOnlyHint: true, untrustedContentHint: false, consequentialHint: true } }));
  assert.ok(contractProblems(both).some((p) => /both read-only and consequential/.test(p)));
});

test("the signal guard fails: a fetch that drops the signal, and a helper that fetches without it", async () => {
  const dropped = mutate("const response = await fetch(url, { signal });", "const response = await fetch(url);");
  assert.ok(staticProblems(dropped).some((p) => /does not pass the tool's signal/.test(p)));
  assert.ok((await signalProblems(dropped, SITE_DIR)).length > 0, "the runtime guard sees the dropped signal too");

  const unsignedIndex = mutate('if (!index) index = JSON.parse(await getText("docs-index.json", signal));', 'if (!index) index = JSON.parse(await getText("docs-index.json", undefined));');
  assert.ok((await signalProblems(unsignedIndex, SITE_DIR)).some((p) => /without the signal it was given/.test(p)));
});

test("the dash guard fails: an en or em dash anywhere in the script", () => {
  assert.ok(staticProblems(`${readShipped()}\n// a dash \u2014 here`).some((p) => /en or em dash/.test(p)));
});

test("the output guard fails: a raised LIMIT lets results exceed the budget", async () => {
  const raised = mutate("const LIMIT = 1500;", "const LIMIT = 5000;");
  const { tools, outputs, errors } = await executeAll(raised, SITE_DIR);
  assert.ok(budgetProblems(tools, outputs, errors).some((p) => /over 1500/.test(p)));
});

test("the result guard fails: a tool that returns JSON text, serialised twice", async () => {
  const doubled = mutate("return at(cut);", "return JSON.stringify(at(cut));");
  const { tools, outputs, errors } = await executeAll(doubled, SITE_DIR);
  assert.ok(budgetProblems(tools, outputs, errors).some((p) => /must be an object/.test(p)));
});

test("the error guard fails: a bad page that rejects instead of resolving with an error object", async () => {
  const thrown = mutate("if (!page) return missingPage(idx, input.path);", 'if (!page) throw new DOMException("Not found", "OperationError");');
  const { tools } = await executeAll(thrown, SITE_DIR);
  assert.ok((await badInputProblems(tools)).some((p) => /rejected with OperationError/.test(p)));
});

test("the echo guard fails: an unknown section whose name is echoed without a bound", async () => {
  const unbounded = mutate("No section ${echo(String(wanted).trim())} on", "No section ${String(wanted).trim()} on");
  const { tools } = await executeAll(unbounded, SITE_DIR);
  assert.ok((await badInputProblems(tools)).some((p) => /error object serialises to \d+ characters/.test(p)));
});

test("the content guard fails: a read_page that returns the wrong section", async () => {
  const wrong = mutate("const section = sectionNamed(page, input.section);", 'const section = sectionNamed(page, "options");');
  const { outputs } = await executeAll(wrong, SITE_DIR);
  assert.ok(contentProblems(outputs, readIndex(SITE_DIR)).some((p) => /did not return the changed-hook section/.test(p)));
});
