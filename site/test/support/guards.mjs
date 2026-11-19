// Guards for the WebMCP script, shared by the in-memory tests and the browser test. Each
// guard returns a list of problems: an empty list means it holds, and a broken copy of
// the script must produce a non-empty list (the mutation tests prove that).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadScript, siteFetch, SCRIPT } from "./vm-host.mjs";
import { contractProblems, LIMITS } from "./contract.mjs";

export const CALLS = {
  list_pages: {},
  read_page: { path: "docs/cli.md", section: "changed-hook" },
  search_docs: { query: "probe" },
  get_install_command: {},
  get_ci_recipe: { provider: "github" },
};

const DASH = /[\u2013\u2014]/;

export const readShipped = () => readFileSync(SCRIPT, "utf8");

export function readIndex(siteDir) {
  return JSON.parse(readFileSync(join(siteDir, "docs-index.json"), "utf8"));
}

// Static: every fetch names the signal, the script checks modelContext before anything
// else, and it contains no dash.
export function staticProblems(source) {
  const problems = [];
  for (const m of source.matchAll(/\bfetch\(([^)]*)\)/g)) {
    if (!/\bsignal\b/.test(m[1])) problems.push(`fetch(${m[1].trim()}) does not pass the tool's signal`);
  }
  if (!source.includes("document.modelContext || navigator.modelContext")) {
    problems.push("the script does not feature-detect document.modelContext and fall back to navigator.modelContext");
  }
  if (DASH.test(source)) problems.push("the script contains an en or em dash");
  return problems;
}

// Registers the tools from a fresh load of the script and returns them with the fetch log.
async function freshTools(source, siteDir) {
  const fetched = siteFetch(siteDir);
  const { tools } = await loadScript({ source, fetch: fetched.fetch });
  return { tools, calls: fetched.calls };
}

// Runtime: an aborted signal makes every tool reject with AbortError, and every fetch a
// tool makes receives the signal that the caller passed.
export async function signalProblems(source, siteDir) {
  const problems = [];
  const names = (await freshTools(source, siteDir)).tools.map((t) => t.name);
  for (const name of names) {
    const aborted = new AbortController();
    aborted.abort();
    const first = await freshTools(source, siteDir);
    try {
      await first.tools.find((t) => t.name === name).execute(CALLS[name] ?? {}, { signal: aborted.signal });
      problems.push(`${name} resolved although its signal was already aborted`);
    } catch (error) {
      if (error?.name !== "AbortError") problems.push(`${name} rejected with ${error?.name}, not AbortError`);
    }
    const live = new AbortController();
    const second = await freshTools(source, siteDir);
    await second.tools.find((t) => t.name === name).execute(CALLS[name] ?? {}, { signal: live.signal });
    if (second.calls.length === 0) problems.push(`${name} made no fetch on a fresh load, so its signal is untested`);
    for (const call of second.calls) {
      if (call.init.signal !== live.signal) problems.push(`${name} fetched ${call.url} without the signal it was given`);
    }
  }
  return problems;
}

// Executes every tool once against the built site and returns its output string.
export async function executeAll(source, siteDir, inputs = CALLS) {
  const { tools } = await freshTools(source, siteDir);
  const outputs = {};
  const errors = {};
  for (const tool of tools) {
    try {
      outputs[tool.name] = await tool.execute(inputs[tool.name] ?? {}, { signal: new AbortController().signal });
    } catch (error) {
      errors[tool.name] = error?.message ?? String(error);
    }
  }
  return { tools, outputs, errors };
}

// The contract (names, descriptions, annotations, and the 1500-character output budget).
export function budgetProblems(tools, outputs, errors = {}) {
  const problems = contractProblems(tools, outputs);
  for (const [name, message] of Object.entries(errors)) problems.push(`${name} threw on its sample input: ${message}`);
  for (const [name, message] of Object.entries(errors)) {
    if (message.length > LIMITS.output) problems.push(`${name} error message is ${message.length} characters, over ${LIMITS.output}`);
  }
  return problems;
}

// What each tool returns must be the right content, not merely short.
export function contentProblems(outputs, index, siteDir) {
  const problems = [];
  const parse = (name) => {
    try {
      return JSON.parse(outputs[name]);
    } catch {
      problems.push(`${name} did not return JSON`);
      return null;
    }
  };

  const list = parse("list_pages");
  if (list) {
    if (JSON.stringify(list.fields) !== JSON.stringify(["path", "title", "summary"])) problems.push("list_pages does not name its fields");
    if (list.truncated || list.returned_pages !== index.pages.length) problems.push(`list_pages returned ${list.returned_pages} of ${index.pages.length} pages`);
    const paths = list.pages.map((row) => row[0]);
    if (JSON.stringify(paths) !== JSON.stringify(index.pages.map((p) => p.path))) problems.push("list_pages does not list every page in index order");
  }

  const read = parse("read_page");
  if (read) {
    const cli = index.pages.find((p) => p.path === "docs/cli.md");
    if (read.path !== "docs/cli.md" || read.section !== "changed-hook") problems.push("read_page did not echo the page and section");
    if (!read.markdown.startsWith("## Changed-unit hook") || !read.markdown.includes("'{changed}'")) problems.push("read_page did not return the changed-hook section");
    const section = cli.sections.find((s) => s.id === "changed-hook");
    if (read.total_chars !== section.tree_end - section.start) problems.push(`read_page total_chars ${read.total_chars} is not the section length`);
  }

  const search = parse("search_docs");
  if (search) {
    if (!search.hits.length) problems.push("search_docs found nothing for probe");
    if (!search.hits.some((h) => h.path === "docs/blind-spots.md")) problems.push("search_docs did not find the blind-spots page for probe");
    if (search.hits.length > 5) problems.push("search_docs returned more than five hits");
    if (search.total_hits < search.hits.length) problems.push("search_docs total_hits is below the hits returned");
  }

  const install = parse("get_install_command");
  if (install && install.command !== index.install.command) problems.push("get_install_command returned a different command");

  const recipe = parse("get_ci_recipe");
  if (recipe) {
    if (!recipe.code.includes("stoop sh {0}")) problems.push("get_ci_recipe github lacks the defaults shell line");
    if (recipe.total_chars !== index.recipes.github.code.length) problems.push("get_ci_recipe total_chars is not the recipe length");
  }
  return problems;
}

// Pages longer than one window must be readable to the end by following next_offset.
export async function paginationProblems(source, siteDir, path = "docs/ci.md") {
  const problems = [];
  const { tools } = await freshTools(source, siteDir);
  const readPage = tools.find((t) => t.name === "read_page");
  const parts = [];
  let offset = 0;
  let total = null;
  for (let turn = 0; turn < 50; turn++) {
    const out = JSON.parse(await readPage.execute({ path, offset }, { signal: new AbortController().signal }));
    total ??= out.total_chars;
    if (out.total_chars !== total) problems.push("total_chars changed between windows");
    parts.push(out.markdown);
    if (!out.truncated) break;
    if (out.next_offset !== offset + out.markdown.length) problems.push("next_offset does not continue where the window ended");
    if (out.next_offset === undefined) problems.push("a truncated window has no next_offset");
    offset = out.next_offset;
  }
  const whole = parts.join("");
  const twin = readFileSync(join(siteDir, path), "utf8");
  const body = twin.slice(twin.indexOf("\n\n") + 2);
  if (whole !== body) problems.push(`following next_offset rebuilt ${whole.length} characters, not the ${body.length} in the page`);
  return problems;
}
