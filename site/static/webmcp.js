// WebMCP tools for stoop.build, registered with the imperative API on document.modelContext.
// The tools read the same build as the pages: the Markdown twins and docs-index.json,
// by same-origin fetch. Nothing is written, sent or stored. Where the browser exposes no
// modelContext (Chrome needs an origin trial for WebMCP), this file does nothing.
//
// The browser serialises each value that execute() resolves with, once. So every result is
// an object, measured as the JSON text the agent receives, and kept within LIMIT characters.
// Bad input resolves with an error object that names the valid choices. Only a failed
// request or an aborted signal rejects.
(() => {
  "use strict";

  const modelContext = document.modelContext || navigator.modelContext;
  if (!modelContext || typeof modelContext.registerTool !== "function") return;

  // The most characters one tool result may serialise to.
  const LIMIT = 1500;
  // Input that a tool echoes back (a path, a section name, a query) is cut to this length.
  const ECHO = 100;
  const script = document.currentScript || document.querySelector('script[src$="webmcp.js"]');
  const base = new URL("./", script ? script.src : location.href);
  let index = null;

  const measure = (value) => JSON.stringify(value).length;
  const echo = (value) => String(value ?? "").slice(0, ECHO);

  const aborted = (signal) => {
    if (signal && signal.aborted) throw new DOMException("The tool call was aborted.", "AbortError");
  };

  const getText = async (path, signal) => {
    aborted(signal);
    const url = new URL(path, base);
    const response = await fetch(url, { signal });
    if (!response.ok) throw new Error(`Could not read ${url.pathname}: HTTP ${response.status}.`);
    return response.text();
  };

  const getIndex = async (signal) => {
    if (!index) index = JSON.parse(await getText("docs-index.json", signal));
    return index;
  };

  // The body of a twin is the text after its canonical line and the blank line that follows.
  const bodyOf = (text) => (text.startsWith("Canonical: ") ? text.slice(text.indexOf("\n\n") + 2) : text);

  // The result for the longest prefix of `text` whose serialised result fits LIMIT.
  // make(slice, truncated) builds the result object for a prefix of `text`.
  const fitWindow = (text, make) => {
    const at = (n) => make(text.slice(0, n), n < text.length);
    if (measure(at(text.length)) <= LIMIT) return at(text.length);
    let lo = 0;
    let hi = text.length;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (measure(at(mid)) <= LIMIT) lo = mid;
      else hi = mid - 1;
    }
    let cut = lo;
    const newline = cut > 0 ? text.lastIndexOf("\n", cut - 1) : -1;
    if (newline >= 0 && newline > cut - 200) cut = newline + 1;
    if (cut > 0 && /[\ud800-\udbff]/.test(text[cut - 1])) cut -= 1;
    return at(cut);
  };

  // The result for as many leading items as fit LIMIT. make(shown, truncated).
  const fitList = (items, make) => {
    for (let n = items.length; n > 0; n--) {
      const result = make(items.slice(0, n), n < items.length);
      if (measure(result) <= LIMIT) return result;
    }
    return make([], items.length > 0);
  };

  // The offset a tool was given, or null when it is not a whole number from 0 to length.
  const offsetOf = (value, length) => {
    if (value === undefined) return 0;
    const n = Number(value);
    return Number.isInteger(n) && n >= 0 && n <= length ? n : null;
  };

  const offsetError = (length) => ({
    error: `offset must be a whole number from 0 to ${length}.`,
    valid_range: [0, length],
  });

  const normalisePath = (raw) => {
    let path = String(raw ?? "").trim().replace(/^https?:\/\/stoop\.build\//i, "").replace(/^\/+/, "");
    if (path === "" || path === "index" || path === "index.html" || path === "index.md") path = "index.md";
    if (path === "AGENTS") path = "AGENTS.md";
    if (path.endsWith(".html")) path = `${path.slice(0, -5)}.md`;
    if (path !== "AGENTS.md" && !path.endsWith(".md")) path += ".md";
    return path;
  };

  const pageNamed = (idx, raw) => {
    const path = normalisePath(raw);
    return idx.pages.find((p) => p.path === path) ?? null;
  };

  const missingPage = (idx, raw) => fitList(idx.pages.map((p) => p.path), (shown, truncated) => ({
    error: `No page at ${echo(normalisePath(raw))}. Use one of the paths in pages.`,
    pages: shown,
    truncated,
  }));

  const sectionNamed = (page, wanted) => {
    const key = String(wanted).trim();
    const lower = key.toLowerCase();
    return page.sections.find((s) => s.id === key) ?? page.sections.find((s) => s.title.toLowerCase() === lower) ?? null;
  };

  const missingSection = (page, wanted) => fitList(page.sections.map((s) => s.id ?? s.title), (shown, truncated) => ({
    error: `No section ${echo(String(wanted).trim())} on ${page.path}. Use one of the sections listed.`,
    sections: shown,
    truncated,
  }));

  const snippetAt = (text, at) => {
    const from = Math.max(0, at - 60);
    const to = Math.min(text.length, at + 90);
    return `${from > 0 ? "..." : ""}${text.slice(from, to).trim()}${to < text.length ? "..." : ""}`;
  };

  const TOOLS = [
    {
      name: "list_pages",
      description: "Returns every page of the stoop docs as rows of path, title and one-line summary. Start here to choose a page for read_page.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true, untrustedContentHint: false, consequentialHint: false },
      execute: async (_input, { signal } = {}) => {
        const idx = await getIndex(signal);
        const rows = idx.pages.map((p) => [p.path, p.title, p.summary]);
        return fitList(rows, (shown, truncated) => ({ total_pages: rows.length, returned_pages: shown.length, truncated, fields: ["path", "title", "summary"], pages: shown }));
      },
    },
    {
      name: "read_page",
      description: "Returns one page of the stoop docs as Markdown, or one section of it. Long text is cut to fit and reports total_chars, with next_offset or next_section to continue. An unknown path or section returns an error that lists the valid choices.",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Page path such as docs/cli.md or index.md. list_pages returns every path." },
          section: { type: "string", description: "Section id or heading title on that page, such as changed-hook or Options." },
          offset: { type: "integer", minimum: 0, description: "Character offset to continue from, taken from next_offset in an earlier result." },
        },
        required: ["path"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, untrustedContentHint: false, consequentialHint: false },
      execute: async (input = {}, { signal } = {}) => {
        const idx = await getIndex(signal);
        const page = pageNamed(idx, input.path);
        if (!page) return missingPage(idx, input.path);
        const text = bodyOf(await getText(page.path, signal));
        if (text.length !== page.body_length) throw new Error(`${page.path} changed after the index was built. Reload the page and try again.`);
        let start = 0;
        let end = text.length;
        let label = null;
        if (input.section !== undefined) {
          const section = sectionNamed(page, input.section);
          if (!section) return missingSection(page, input.section);
          start = section.start;
          end = section.tree_end;
          label = section.id ?? section.title;
        }
        const selected = text.slice(start, end);
        const offset = offsetOf(input.offset, selected.length);
        if (offset === null) return offsetError(selected.length);
        return fitWindow(selected.slice(offset), (slice, truncated) => {
          const cut = start + offset + slice.length;
          const result = { path: page.path, total_chars: selected.length, offset, returned_chars: slice.length, truncated };
          if (label !== null) result.section = label;
          if (truncated) {
            result.next_offset = offset + slice.length;
            const after = page.sections.find((s) => s.start >= cut);
            if (after) result.next_section = after.id ?? after.title;
          }
          result.markdown = slice;
          return result;
        });
      },
    },
    {
      name: "search_docs",
      description: "Returns up to five sections of the stoop docs that match a query, ranked by title and text matches, each with a snippet and the path to read with read_page. A query with only one-letter words returns an error.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", minLength: 1, description: "Words to find in section titles and text. Words shorter than two letters are ignored." },
        },
        required: ["query"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, untrustedContentHint: false, consequentialHint: false },
      execute: async (input = {}, { signal } = {}) => {
        const idx = await getIndex(signal);
        const query = String(input.query ?? "");
        const terms = query.toLowerCase().split(/\s+/).filter((t) => t.length >= 2).slice(0, 10);
        if (!terms.length) return { error: "query needs at least one word of two or more letters.", received: echo(query) };
        const hits = [];
        for (const page of idx.pages) {
          for (const section of page.sections) {
            const title = section.title.toLowerCase();
            const text = section.text.toLowerCase();
            let score = 0;
            let at = -1;
            for (const term of terms) {
              if (title.includes(term)) score += 5;
              const count = text.split(term).length - 1;
              if (count > 0) {
                score += Math.min(count, 5);
                if (at < 0) at = text.indexOf(term);
              }
            }
            if (score > 0) hits.push({ score, page, section, text: section.text, at: Math.max(at, 0) });
          }
        }
        hits.sort((a, b) => b.score - a.score);
        const top = hits.slice(0, 5).map(({ page, section, text, at }) => ({
          path: page.path,
          section: section.id ?? section.title,
          heading: section.title,
          snippet: snippetAt(text, at),
        }));
        return fitList(top, (shown, truncated) => ({ query: echo(query), total_hits: hits.length, truncated, hits: shown }));
      },
    },
    {
      name: "get_install_command",
      description: "Returns the one-line command that installs the stoop binary, with the platform support note and the install docs link.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true, untrustedContentHint: false, consequentialHint: false },
      execute: async (_input, { signal } = {}) => {
        const idx = await getIndex(signal);
        return { command: idx.install.command, platform: idx.install.platform, docs: idx.install.docs };
      },
    },
    {
      name: "get_ci_recipe",
      description: "Returns the copyable CI recipe for one provider from the stoop CI page, cut to fit with total_chars and next_offset when it is long. An unknown provider returns an error that lists the providers.",
      inputSchema: {
        type: "object",
        properties: {
          provider: { type: "string", enum: ["github", "gitlab", "circleci", "buildkite"], description: "CI provider: github, gitlab, circleci or buildkite." },
          offset: { type: "integer", minimum: 0, description: "Character offset to continue from, taken from next_offset in an earlier result." },
        },
        required: ["provider"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, untrustedContentHint: false, consequentialHint: false },
      execute: async (input = {}, { signal } = {}) => {
        const idx = await getIndex(signal);
        const provider = String(input.provider ?? "").toLowerCase();
        if (!Object.hasOwn(idx.recipes, provider)) {
          return { error: "provider must be one of github, gitlab, circleci or buildkite.", providers: Object.keys(idx.recipes), received: echo(input.provider) };
        }
        const recipe = idx.recipes[provider];
        const offset = offsetOf(input.offset, recipe.code.length);
        if (offset === null) return offsetError(recipe.code.length);
        return fitWindow(recipe.code.slice(offset), (slice, truncated) => {
          const result = { provider, title: recipe.title, language: recipe.language, docs: recipe.docs, total_chars: recipe.code.length, offset, returned_chars: slice.length, truncated };
          if (truncated) result.next_offset = offset + slice.length;
          result.code = slice;
          return result;
        });
      },
    },
  ];

  for (const tool of TOOLS) {
    Promise.resolve()
      .then(() => modelContext.registerTool(tool))
      .catch((error) => console.warn(`stoop WebMCP: ${tool.name} was not registered: ${error.message}`));
  }
})();
