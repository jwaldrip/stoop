# stoop website and field guide

The source for https://stoop.build/: the landing page and the documentation, one static site with no dependencies.

```
site/
  build.mjs      builds into site/_site, writes the discovery files, and fails on any check
  lib/           HTML reader, Markdown converter, text checks, origin-trial check, discovery builders
  pages/         index.html (whole page) and docs/*.html (fragments wrapped in the docs layout)
  static/        styles.css, chrome.js, copy.js, webmcp.js, AGENTS.md (agent guide), fonts/, images/
  test/          unit, build and browser tests (node --test)
```

```sh
node site/build.mjs                                   # Node 18+
python3 -m http.server -d site/_site 8000             # preview at http://localhost:8000/
node --test --test-concurrency=1 site/test/*.test.mjs # tests; the browser tests need Node 22 and a headless Chrome
```

The browser tests use Node's built-in WebSocket client, which needs Node 22. They look for a headless Chrome in `STOOP_SITE_CHROME`, then a `chrome-headless-shell` on `PATH`, then the Playwright cache. They launch their own copy with a throwaway profile and never use a browser that is already running. `STOOP_SITE_TOKEN_FILE` points the build at another origin-trial token file; the build tests use it to exercise a configured token without touching the real one.

## Pages

Each page starts with a `<!--meta {...}-->` header: `title`, `description`, and for docs `lede`, `image` and `alt`. To add a docs page, write `pages/docs/<slug>.html`, add it to `DOCS` in `build.mjs`, and give it a one-line summary in `SUMMARY` (the build fails without one). Give every `h2` an `id`: the docs layout lists them beside the page on wide screens.

The build also prepares markup for reading: each table cell gets a `data-label` with its column name, so a table stacked on a narrow screen keeps its headings, and short flags or bracketed options in inline code (`[--store DIR]`) are kept from breaking across lines.

`.github/workflows/pages.yml` builds the site and runs the tests on pull requests that touch it, and deploys it to GitHub Pages from `main`.

Every terminal transcript on the site is output captured from a real run. Keep it that way: when behavior changes, capture again rather than editing numbers by hand. Images are generated, then resized into `static/images/` as `NAME.webp` (1536 wide) and `NAME-800.webp`.

Fonts: Bodoni Moda, IBM Plex Sans and IBM Plex Mono, all under the SIL Open Font License (`static/fonts/OFL.txt`).

## Discovery files

Every page is also served as Markdown at the same path with a `.md` suffix (`/index.md`, `/docs/cli.md`). Each HTML page advertises its twin with `<link rel="alternate" type="text/markdown">`. The twins are generated from the built HTML, never written by hand. The converter handles only the elements the pages use and fails the build on any other, so no text is dropped silently. The navigation, skip link, theme toggle, logo lockup and maker mark are chrome and are left out; everything else must appear in the twin, and a check compares the visible words of each page with its twin.

The build also writes:

- `llms.txt`, following https://llmstxt.org: the docs, the agent guide, the install line, the source links, and an Optional section.
- `llms-full.txt`: the agent guide and every docs page, one after another, each under its source URL.
- `docs-index.json`: the sections, install command and CI recipes that the WebMCP tools read.
- `sitemap.xml` (every HTML page) and `robots.txt` (allows every crawler and points at the sitemap).

`site/static/AGENTS.md` is the agent guide. It is copied verbatim, and the build needs it. The build checks every same-site link in these files, that each link naming an anchor finds it, that the sitemap and canonical links agree, and that no en or em dash appears in generated text.

## WebMCP

`static/webmcp.js` registers five read-only tools with the imperative API (`document.modelContext.registerTool`): `list_pages`, `read_page`, `search_docs`, `get_install_command` and `get_ci_recipe`. Where the browser exposes no `modelContext`, the script does nothing. The tools read the same build as the pages with same-origin fetches, honour the AbortSignal in every fetch, and keep each output within 1500 characters, reporting `total_chars` and `next_offset` when they cut text.

Chrome needs an origin-trial token for WebMCP. The trial's feature is `WebMCP`. To enable it for stoop.build:

1. Open https://developer.chrome.com/origintrials and register the origin `https://stoop.build` for the `WebMCP` trial. Copy the token it issues.
2. Save the token, on one line and nothing else, in `site/webmcp-origin-trial.txt`.
3. Run `node site/build.mjs`. The build writes the token into the head of every page as `<meta http-equiv="origin-trial">`, and checks it: the origin must cover stoop.build, the feature must be `WebMCP`, and the token must not expire within 21 days. Without a token the file is absent, the build writes no tag, and the tools stay off for visitors in Chrome.
4. Renew before expiry: register again at the same URL, replace the file, and rebuild. The build fails within 21 days of expiry and names the registration URL.

The token is public, since it is served on every page. Do not put anything secret in that file.

## Testing a change

The discovery and WebMCP tests read the built output. The unit tests check the converter, the token rules and each guard against a broken copy of the script, so a green run means each guard can fail. The browser tests run the shipped script in an isolated headless Chrome against the built site, with a stub `modelContext`, and check every tool's output against the budget and the expected content.
