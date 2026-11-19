// Runs the shipped webmcp.js in a Node VM context with a stub document.modelContext, so
// the tests can capture what the script registers and call each tool's execute() with
// a fetch that reads the built site from disk. The browser test runs the same script in
// a real headless Chrome; this host covers the contract and the signal threading fast.
// A `source` override lets the mutation tests run a deliberately broken copy.
import { readFileSync, existsSync, statSync } from "node:fs";
import { join, normalize, sep } from "node:path";
import { createContext, runInContext } from "node:vm";

export const SCRIPT = new URL("../../static/webmcp.js", import.meta.url);

// Loads the script with the given page globals and returns the tools it registered.
// The script registers tools in a promise chain, so this waits one event-loop turn.
export async function loadScript({ source = readFileSync(SCRIPT, "utf8"), document, navigator = {}, fetch, location = "https://stoop.build/docs/cli.html" } = {}) {
  const registered = [];
  const modelContextStub = {
    registerTool(tool) {
      registered.push(tool);
      return Promise.resolve({ unregister() {} });
    },
  };
  const doc = document ?? {
    modelContext: modelContextStub,
    currentScript: { src: "https://stoop.build/webmcp.js" },
  };
  const warnings = [];
  const sandbox = {
    document: doc,
    navigator,
    location: { href: location },
    fetch: fetch ?? (async () => { throw new Error("no fetch in this test"); }),
    DOMException: globalThis.DOMException,
    URL,
    console: { warn: (message) => warnings.push(message), log() {}, error() {} },
  };
  createContext(sandbox);
  runInContext(source, sandbox);
  await new Promise((resolve) => setTimeout(resolve, 0));
  return { tools: registered, warnings };
}

// A fetch that serves files from the built site root. It records every call and its
// init object, so a test can prove the AbortSignal reached each request.
export function siteFetch(siteDir) {
  const calls = [];
  const fetch = async (input, init = {}) => {
    calls.push({ url: String(input), init });
    if (init.signal?.aborted) throw new DOMException("aborted", "AbortError");
    const url = new URL(String(input));
    let path = decodeURIComponent(url.pathname);
    if (path.endsWith("/")) path += "index.html";
    const file = normalize(join(siteDir, path));
    if (!file.startsWith(normalize(siteDir) + sep) || !existsSync(file) || statSync(file).isDirectory()) {
      return { ok: false, status: 404, text: async () => "", json: async () => { throw new Error("404"); } };
    }
    const text = readFileSync(file, "utf8");
    return { ok: true, status: 200, text: async () => text, json: async () => JSON.parse(text) };
  };
  return { fetch, calls };
}
