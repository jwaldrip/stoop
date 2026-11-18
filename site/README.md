# stoop website and field guide

The source for https://jwaldrip.github.io/stoop/: the landing page and the documentation, one static site with no dependencies.

```
site/
  build.mjs      builds into site/_site and fails on any broken local link
  pages/         index.html (whole page) and docs/*.html (fragments wrapped in the docs layout)
  static/        styles.css, chrome.js, copy.js, fonts/ (self-hosted, OFL), images/
```

```sh
node site/build.mjs                                   # Node 18+
python3 -m http.server -d site/_site 8000             # preview at http://localhost:8000/
```

Each page starts with a `<!--meta {...}-->` header: `title`, `description`, and for docs `lede`, `image` and `alt`. To add a docs page, write `pages/docs/<slug>.html` and add it to `DOCS` in `build.mjs`. Give every `h2` an `id`: the docs layout lists them beside the page on wide screens.

The build also prepares markup for reading: each table cell gets a `data-label` with its column name, so a table stacked on a narrow screen keeps its headings, and short flags or bracketed options in inline code (`[--store DIR]`) are kept from breaking across lines.

`.github/workflows/pages.yml` builds the site on pull requests that touch it and deploys it to GitHub Pages from `main`.

Every terminal transcript on the site is output captured from a real run. Keep it that way: when behavior changes, capture again rather than editing numbers by hand. Images are generated, then resized into `static/images/` as `NAME.webp` (1536 wide) and `NAME-800.webp`.

Fonts: Bodoni Moda, IBM Plex Sans and IBM Plex Mono, all under the SIL Open Font License (`static/fonts/OFL.txt`).
