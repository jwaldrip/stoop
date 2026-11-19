// Builds the site once per test process, so every test reads the output of the build
// that is under test. A failing build stops the test run with the build's own messages.
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const SITE = join(here, "..", "..");
export const SITE_DIR = join(SITE, "_site");

let built = false;
export function ensureBuilt() {
  if (built) return;
  const result = spawnSync(process.execPath, [join(SITE, "build.mjs")], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`site/build.mjs failed:\n${result.stdout}${result.stderr}`);
  built = true;
}
