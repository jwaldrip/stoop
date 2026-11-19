// The WebMCP tools in an isolated headless Chrome, on the built site served over loopback.
// A stub document.modelContext is installed before the page's scripts run, so the shipped
// webmcp.js registers its tools against it. Each tool is then executed in the page, and the
// same budget, content and error guards as the in-memory tests run on what it resolves with.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ensureBuilt, SITE_DIR } from "./support/build.mjs";
import { findChrome, launchChrome, newTarget, serveSite } from "./support/chrome.mjs";
import { LIMITS } from "./support/contract.mjs";
import { CALLS, budgetProblems, contentProblems, readIndex } from "./support/guards.mjs";

const NAMES = ["list_pages", "read_page", "search_docs", "get_install_command", "get_ci_recipe"];

// The size of a result as the agent receives it: the JSON text of the object a tool resolved with.
const serialised = (value) => JSON.stringify(value).length;

// Records every tool the page registers. It runs before any page script, so webmcp.js
// sees document.modelContext exactly as a browser with the origin trial would.
const DOCUMENT_STUB = `(() => {
  const tools = new Map();
  window.__tools = tools;
  const modelContext = {
    registerTool(tool) {
      if (tools.has(tool.name)) return Promise.reject(new Error("duplicate " + tool.name));
      tools.set(tool.name, tool);
      return Promise.resolve({ unregister() { tools.delete(tool.name); } });
    },
  };
  Object.defineProperty(document, "modelContext", { value: modelContext, configurable: true });
})();`;

// The deprecated location, used only when the document has no modelContext.
const NAVIGATOR_STUB = `(() => {
  const tools = new Map();
  window.__tools = tools;
  const modelContext = { registerTool(tool) { tools.set(tool.name, tool); return Promise.resolve(); } };
  Object.defineProperty(navigator, "modelContext", { value: modelContext, configurable: true });
})();`;

let chrome;
let site;
before(async () => {
  ensureBuilt();
  chrome = await launchChrome(findChrome());
  site = await serveSite(SITE_DIR);
});
after(async () => {
  await site?.close();
  await chrome?.close();
});

// Opens a new isolated target, installs the stub, loads the path, and returns the client.
async function openPage(path, stub = DOCUMENT_STUB) {
  const cdp = await newTarget(chrome);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  const problems = cdp.trackProblems();
  if (stub) await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: stub });
  const loaded = cdp.nextEvent("Page.loadEventFired");
  await cdp.send("Page.navigate", { url: `${site.origin}/${path}` });
  await loaded;
  return { cdp, problems };
}

const toolDefinitions = (cdp) => cdp.evaluate(`JSON.parse(JSON.stringify([...window.__tools.values()].map(({ execute, ...tool }) => tool)))`);

// Runs one tool in the page with an input, and returns what it resolved with.
const callTool = (cdp, name, input) => cdp.evaluate(`window.__tools.get(${JSON.stringify(name)}).execute(${JSON.stringify(input)}, { signal: new AbortController().signal })`);

test("the script registers the five read-only tools on a docs page and on the home page", async () => {
  for (const path of ["docs/cli.html", "index.html"]) {
    const { cdp, problems } = await openPage(path);
    const tools = await toolDefinitions(cdp);
    assert.deepEqual(tools.map((t) => t.name), NAMES, `${path} registers the tools in order`);
    assert.deepEqual(budgetProblems(tools, {}), [], `${path} meets the contract`);
    assert.deepEqual(problems, [], `${path} throws nothing while loading`);
    cdp.close();
  }
});

test("every tool runs in the page, resolves with an object within the budget, and returns the right content", async () => {
  const { cdp, problems } = await openPage("docs/cli.html");
  const tools = await toolDefinitions(cdp);
  const outputs = {};
  const errors = {};
  for (const name of NAMES) {
    try {
      outputs[name] = await callTool(cdp, name, CALLS[name]);
    } catch (error) {
      errors[name] = error.message;
    }
  }
  assert.deepEqual(budgetProblems(tools, outputs, errors), []);
  assert.deepEqual(contentProblems(outputs, readIndex(SITE_DIR)), []);
  for (const name of NAMES) assert.ok(serialised(outputs[name]) <= LIMITS.output, `${name} serialises to ${serialised(outputs[name])} characters`);
  assert.deepEqual(problems, []);
  cdp.close();
});

test("bad input resolves with an error object that names the valid choices, within the budget", async () => {
  const { cdp, problems } = await openPage("docs/cli.html");
  const cli = readIndex(SITE_DIR).pages.find((p) => p.path === "docs/cli.md");

  const missing = await callTool(cdp, "read_page", { path: "docs/missing" });
  assert.match(missing.error, /No page at docs\/missing\.md/);
  assert.ok(missing.pages.includes("docs/cli.md"), "the error lists the pages");
  assert.ok(serialised(missing) <= LIMITS.output, "the error fits the budget");

  const longPath = await callTool(cdp, "read_page", { path: "x".repeat(50000) });
  assert.ok(serialised(longPath) <= LIMITS.output, "a 50000-character path stays within the budget");
  assert.ok(longPath.error.length < 300, "the echoed path is cut");

  const section = await callTool(cdp, "read_page", { path: "docs/cli.md", section: "no-such-section" });
  assert.match(section.error, /No section no-such-section on docs\/cli\.md/);
  assert.ok(section.sections.includes("changed-hook"), "the error lists the sections");

  const longSection = await callTool(cdp, "read_page", { path: "docs/cli.md", section: "y".repeat(50000) });
  assert.ok(serialised(longSection) <= LIMITS.output, "a 50000-character section stays within the budget");

  const offset = await callTool(cdp, "read_page", { path: "docs/cli.md", offset: -1 });
  assert.match(offset.error, /offset must be a whole number/);
  assert.deepEqual(offset.valid_range, [0, cli.body_length]);

  const provider = await callTool(cdp, "get_ci_recipe", { provider: "travis" });
  assert.match(provider.error, /provider must be one of/);
  assert.deepEqual(provider.providers, ["github", "gitlab", "circleci", "buildkite"]);

  const query = await callTool(cdp, "search_docs", { query: "a" });
  assert.match(query.error, /two or more letters/);
  assert.ok(serialised(query) <= LIMITS.output);
  assert.deepEqual(problems, []);
  cdp.close();
});

test("following next_offset in the page rebuilds the long CI page exactly", async () => {
  const { cdp } = await openPage("docs/cli.html");
  const parts = [];
  let offset = 0;
  for (let turn = 0; turn < 60; turn++) {
    const out = await callTool(cdp, "read_page", { path: "docs/ci.md", offset });
    parts.push(out.markdown);
    assert.ok(serialised(out) <= LIMITS.output, "each window fits the budget");
    if (!out.truncated) break;
    assert.ok(Number.isInteger(out.next_offset), "a truncated window names where to continue");
    offset = out.next_offset;
  }
  const twin = readFileSync(join(SITE_DIR, "docs", "ci.md"), "utf8");
  assert.equal(parts.join(""), twin.slice(twin.indexOf("\n\n") + 2));
  cdp.close();
});

test("an aborted signal rejects every tool with AbortError, and each page gets a fresh index", async () => {
  for (const name of NAMES) {
    const { cdp } = await openPage("docs/cli.html");
    const outcome = await cdp.evaluate(`(async () => {
      const controller = new AbortController();
      controller.abort();
      try {
        await window.__tools.get(${JSON.stringify(name)}).execute(${JSON.stringify(CALLS[name])}, { signal: controller.signal });
        return "resolved";
      } catch (error) {
        return error.name;
      }
    })()`);
    assert.equal(outcome, "AbortError", `${name} honours an aborted signal`);
    cdp.close();
  }
});

test("without any modelContext the script does nothing and throws nothing", async () => {
  const { cdp, problems } = await openPage("docs/cli.html", null);
  const kinds = await cdp.evaluate("typeof document.modelContext + ' ' + typeof navigator.modelContext");
  assert.equal(kinds, "undefined undefined", "this browser exposes no modelContext without a trial");
  assert.deepEqual(problems, []);
  cdp.close();
});

test("the deprecated navigator.modelContext receives the tools when the document has none", async () => {
  const { cdp, problems } = await openPage("docs/cli.html", NAVIGATOR_STUB);
  const names = await cdp.evaluate("[...window.__tools.keys()]");
  assert.deepEqual(names, NAMES);
  assert.deepEqual(problems, []);
  cdp.close();
});
