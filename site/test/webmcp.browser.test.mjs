// The WebMCP tools in an isolated headless Chrome, on the built site served over loopback.
// A stub document.modelContext is installed before the page's scripts run, so the shipped
// webmcp.js registers its tools against it. Each tool is then executed in the page, and
// the same budget, content and pagination guards as the in-memory tests run on the results.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ensureBuilt, SITE_DIR } from "./support/build.mjs";
import { findChrome, launchChrome, newTarget, serveSite } from "./support/chrome.mjs";
import { contractProblems, LIMITS } from "./support/contract.mjs";
import { CALLS, budgetProblems, contentProblems, readIndex } from "./support/guards.mjs";

const NAMES = ["list_pages", "read_page", "search_docs", "get_install_command", "get_ci_recipe"];

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

test("the script registers the five read-only tools on a docs page and on the home page", async () => {
  for (const path of ["docs/cli.html", "index.html"]) {
    const { cdp, problems } = await openPage(path);
    const tools = await toolDefinitions(cdp);
    assert.deepEqual(tools.map((t) => t.name), NAMES, `${path} registers the tools in order`);
    assert.deepEqual(contractProblems(tools), [], `${path} meets the contract`);
    assert.deepEqual(problems, [], `${path} throws nothing while loading`);
    cdp.close();
  }
});

test("every tool runs in the page, stays within the output budget, and returns the right content", async () => {
  const { cdp, problems } = await openPage("docs/cli.html");
  const tools = await toolDefinitions(cdp);
  const outputs = {};
  const errors = {};
  for (const name of NAMES) {
    try {
      outputs[name] = await cdp.evaluate(`window.__tools.get(${JSON.stringify(name)}).execute(${JSON.stringify(CALLS[name])}, { signal: new AbortController().signal })`);
    } catch (error) {
      errors[name] = error.message;
    }
  }
  assert.deepEqual(budgetProblems(tools, outputs, errors), []);
  assert.deepEqual(contentProblems(outputs, readIndex(SITE_DIR), SITE_DIR), []);
  for (const name of NAMES) assert.ok(outputs[name].length <= LIMITS.output, `${name} is ${outputs[name].length} characters`);
  assert.deepEqual(problems, []);
  cdp.close();
});

test("bad input rejects in the page with a message that fits the budget", async () => {
  const { cdp } = await openPage("docs/cli.html");
  const rejects = async (name, input) => {
    try {
      await cdp.evaluate(`window.__tools.get(${JSON.stringify(name)}).execute(${JSON.stringify(input)}, { signal: new AbortController().signal })`);
      return null;
    } catch (error) {
      return error.message;
    }
  };
  const missing = await rejects("read_page", { path: "docs/missing" });
  assert.match(missing, /No page at docs\/missing\.md/);
  assert.ok(missing.length <= LIMITS.output);
  assert.match(await rejects("get_ci_recipe", { provider: "travis" }), /provider must be one of/);
  cdp.close();
});

test("following next_offset in the page rebuilds the long CI page exactly", async () => {
  const { cdp } = await openPage("docs/cli.html");
  const parts = [];
  let offset = 0;
  for (let turn = 0; turn < 60; turn++) {
    const out = JSON.parse(await cdp.evaluate(`window.__tools.get("read_page").execute({ path: "docs/ci.md", offset: ${offset} }, { signal: new AbortController().signal })`));
    parts.push(out.markdown);
    assert.ok(out.markdown.length <= LIMITS.output, "each window fits the budget");
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
