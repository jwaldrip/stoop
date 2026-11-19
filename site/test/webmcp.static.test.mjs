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
  readShipped, readIndex, staticProblems, signalProblems, executeAll, budgetProblems, contentProblems, paginationProblems,
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

test("each tool returns the content it promises, within the output budget", async () => {
  const { outputs } = await executeAll(readShipped(), SITE_DIR);
  for (const [name, output] of Object.entries(outputs)) assert.ok(output.length <= LIMITS.output, `${name} is ${output.length} characters`);
  assert.deepEqual(contentProblems(outputs, readIndex(SITE_DIR), SITE_DIR), []);
});

test("following next_offset rebuilds a long page exactly", async () => {
  assert.deepEqual(await paginationProblems(readShipped(), SITE_DIR, "docs/ci.md"), []);
  assert.deepEqual(await paginationProblems(readShipped(), SITE_DIR, "docs/cli.md"), []);
});

test("every fetch passes the tool's AbortSignal, and an aborted call rejects with AbortError", async () => {
  assert.deepEqual(staticProblems(readShipped()), []);
  assert.deepEqual(await signalProblems(readShipped(), SITE_DIR), []);
});

test("bad input rejects with a short message: an unknown page, section, provider, query or offset", async () => {
  const { tools } = await executeAll(readShipped(), SITE_DIR);
  const run = (name, input) => tools.find((t) => t.name === name).execute(input, { signal: new AbortController().signal });
  await assert.rejects(run("read_page", { path: "docs/missing" }), (e) => /No page at docs\/missing\.md/.test(e.message) && e.message.length <= LIMITS.output);
  await assert.rejects(run("read_page", { path: "docs/cli.md", section: "no-such-section" }), (e) => /No section no-such-section/.test(e.message) && e.message.length <= LIMITS.output);
  await assert.rejects(run("read_page", { path: "docs/cli.md", offset: -1 }), /offset must be a whole number/);
  await assert.rejects(run("get_ci_recipe", { provider: "travis" }), /provider must be one of/);
  await assert.rejects(run("search_docs", { query: "a" }), /two or more letters/);
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

test("the budget guard fails: an output over 1500 characters, and fewer than five tools", async () => {
  const tools = await registeredTools();
  assert.ok(contractProblems(tools, { list_pages: "x".repeat(LIMITS.output + 1) }).some((p) => /output is \d+ characters, over 1500/.test(p)));
  assert.ok(contractProblems(tools.slice(0, 4)).some((p) => /only 4 tools/.test(p)));
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

test("the output guard fails: a raised LIMIT lets outputs exceed the budget", async () => {
  const raised = mutate("const LIMIT = 1500;", "const LIMIT = 5000;");
  const { tools, outputs, errors } = await executeAll(raised, SITE_DIR);
  assert.ok(budgetProblems(tools, outputs, errors).some((p) => /over 1500/.test(p)));
});

test("the content guard fails: a read_page that returns the wrong section", async () => {
  const wrong = mutate("const section = findSection(page, input.section);", 'const section = findSection(page, "options");');
  const { outputs } = await executeAll(wrong, SITE_DIR);
  assert.ok(contentProblems(outputs, readIndex(SITE_DIR), SITE_DIR).some((p) => /did not return the changed-hook section/.test(p)));
});
