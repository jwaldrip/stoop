// Pure builders for the discovery files: llms.txt (https://llmstxt.org), llms-full.txt,
// the sitemap, robots.txt and docs-index.json, which the WebMCP tools search. Each takes
// the page model that build.mjs assembles, so the build checks can rebuild and compare.
import { plainText } from "./text.mjs";

export const SITE = "https://stoop.build";
export const REPO = "https://github.com/jwaldrip/stoop";
export const INSTALL_COMMAND = `curl -fsSL ${SITE}/install.sh | sh`;

export const ROBOTS = `User-agent: *\nAllow: /\nSitemap: ${SITE}/sitemap.xml\n`;

export function sitemapXml(urls) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map((url) => `<url><loc>${url}</loc></url>`).join("")}</urlset>\n`;
}

export function llmsTxt({ home, guide, docs, install }) {
  return [
    "# stoop",
    "",
    "> stoop wraps a command, traces every file it reads, and skips it when none of them changed since it last passed.",
    "",
    "stoop is a Rust command-line tool. On Linux it records the files a command reads, and on the next run it skips the command when every recorded file still matches. Tracing needs Linux on x86-64 or arm64. Elsewhere stoop runs the command untraced and never skips it.",
    "",
    "Each page is also served as Markdown at the same address with a .md suffix. llms-full.txt holds the agent guide and every docs page in one file.",
    "",
    "## Docs",
    "",
    ...docs.map((page) => `- [${page.title}](${page.url}): ${page.summary}`),
    "",
    "## Guide",
    "",
    `- [${guide.title}](${guide.url}): ${guide.summary}`,
    "",
    "## Install",
    "",
    `- [Install script](${SITE}/install.sh): Run \`${install.command}\` to install the prebuilt binary into ~/.local/bin by default. Linux and macOS, x86-64 and arm64.`,
    "",
    "## Source",
    "",
    `- [GitHub repository](${REPO}): Rust source, issues, and the MIT license.`,
    `- [Releases](${REPO}/releases): Prebuilt archives with SHA-256 checksums.`,
    "",
    "## Optional",
    "",
    `- [Home page](${home.url}): The pitch, the install line, and links into the field guide.`,
    `- [Full text](${SITE}/llms-full.txt): The agent guide and every docs page in one file.`,
    "",
  ].join("\n");
}

export function llmsFull({ guide, docs }) {
  const rule = "=".repeat(72);
  const pages = [guide, ...docs];
  const parts = [
    "# stoop: full text",
    "",
    "> The agent guide and every docs page of stoop, one after another. Each page starts with its source URLs.",
    "",
  ];
  pages.forEach((page, i) => {
    parts.push(rule, `${i + 1} of ${pages.length}: ${page.title}`, `Source: ${page.url}`, ...(page.canonicalUrl !== page.url ? [`Canonical: ${page.canonicalUrl}`] : []), rule, "", page.body.trimEnd(), "");
  });
  return parts.join("\n");
}

export function docsIndex({ pages, install, recipes }) {
  return {
    site: `${SITE}/`,
    install,
    recipes,
    pages: pages.map((page) => ({
      path: page.path,
      url: page.url,
      canonical: page.canonicalUrl,
      title: page.title,
      summary: page.summary,
      body_length: page.body.length,
      sections: page.sections.map((s) => ({
        id: s.id,
        title: s.title,
        level: s.level,
        start: s.start,
        end: s.end,
        tree_end: s.tree_end,
        text: plainText(page.body.slice(s.start, s.end)),
      })),
    })),
  };
}
