// An isolated headless Chrome for the site tests. Every launch has its own DevTools
// port and a throwaway profile, is headless, and is stopped by its own process handle.
// It never attaches to a browser the user runs. The binary comes from STOOP_SITE_CHROME,
// or from a headless shell on PATH or in the Playwright cache. A full Chrome on PATH is
// deliberately not searched for, so a machine's own browser is never picked up.
import { spawn } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, extname, normalize, sep } from "node:path";
import net from "node:net";

const TYPES = {
  ".html": "text/html; charset=utf-8", ".md": "text/markdown; charset=utf-8", ".txt": "text/plain; charset=utf-8",
  ".json": "application/json", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".woff2": "font/woff2",
  ".xml": "application/xml", ".sh": "text/plain; charset=utf-8",
};

function which(name) {
  for (const dir of (process.env.PATH ?? "").split(":")) {
    const candidate = join(dir, name);
    if (dir && existsSync(candidate)) return candidate;
  }
  return null;
}

function playwrightShell() {
  const caches = [join(homedir(), "Library", "Caches", "ms-playwright"), join(homedir(), ".cache", "ms-playwright")];
  for (const cache of caches) {
    if (!existsSync(cache)) continue;
    const dirs = readdirSync(cache).filter((d) => d.startsWith("chromium_headless_shell-")).sort().reverse();
    for (const dir of dirs) {
      for (const sub of readdirSync(join(cache, dir))) {
        const bin = join(cache, dir, sub, "chrome-headless-shell");
        if (sub.startsWith("chrome-headless-shell-") && existsSync(bin) && statSync(bin).isFile()) return bin;
      }
    }
  }
  return null;
}

export function findChrome() {
  if (process.env.STOOP_SITE_CHROME) {
    const bin = process.env.STOOP_SITE_CHROME;
    if (!existsSync(bin) && !which(bin)) throw new Error(`STOOP_SITE_CHROME=${bin} is not an executable`);
    return existsSync(bin) ? bin : which(bin);
  }
  const found = which("chrome-headless-shell") ?? playwrightShell();
  if (!found) {
    throw new Error("No headless Chrome found. Set STOOP_SITE_CHROME to a chrome-headless-shell or Chrome binary, or run: bunx playwright install chromium-headless-shell");
  }
  return found;
}

export const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.unref();
  server.on("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const { port } = server.address();
    server.close(() => resolve(port));
  });
});

export async function launchChrome(bin = findChrome()) {
  const port = await freePort();
  const profile = await mkdtemp(join(tmpdir(), "stoop-site-chrome-"));
  const args = [
    `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
    "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
    "--disable-gpu", "--disable-dev-shm-usage", "--no-sandbox", "--hide-scrollbars",
    "--force-color-profile=srgb", "--font-render-hinting=none", "about:blank",
  ];
  if (!bin.includes("chrome-headless-shell")) args.unshift("--headless=new");
  const proc = spawn(bin, args, { stdio: "ignore" });
  let exited = false;
  proc.on("exit", () => { exited = true; });
  const version = await waitFor(async () => {
    if (exited) throw new Error(`${bin} exited before DevTools came up`);
    return (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  }, 20000);
  return {
    port,
    version: version.Browser,
    async close() {
      if (!exited) proc.kill("SIGTERM");
      await rm(profile, { recursive: true, force: true }).catch(() => {});
    },
  };
}

// Polls fn until it returns a value (or times out). Used only for start-up of the
// browser and its server, never for a CI result.
export async function waitFor(fn, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error(`timed out after ${timeoutMs} ms: ${lastError?.message ?? "no result"}`);
}

export async function newTarget(chrome) {
  const base = `http://127.0.0.1:${chrome.port}`;
  let response = await fetch(`${base}/json/new?about:blank`, { method: "PUT" });
  if (!response.ok) response = await fetch(`${base}/json/new?about:blank`);
  const target = await response.json();
  return new Cdp(target.webSocketDebuggerUrl);
}

// A small CDP client over the page's own WebSocket.
export class Cdp {
  constructor(url) {
    this.socket = new WebSocket(url);
    this.nextId = 0;
    this.pending = new Map();
    this.listeners = [];
    this.opened = new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener("error", () => reject(new Error(`cannot open ${url}`)), { once: true });
    });
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== undefined && this.pending.has(message.id)) {
        const { resolve, reject } = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) reject(new Error(`${message.error.message}`));
        else resolve(message.result);
      } else if (message.method) {
        for (const listener of this.listeners) listener(message);
      }
    });
  }

  async send(method, params = {}) {
    await this.opened;
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  // Resolves with the next event of the given method, or rejects on timeout.
  nextEvent(method, timeoutMs = 20000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no ${method} within ${timeoutMs} ms`)), timeoutMs);
      const listener = (message) => {
        if (message.method !== method) return;
        clearTimeout(timer);
        this.listeners.splice(this.listeners.indexOf(listener), 1);
        resolve(message.params);
      };
      this.listeners.push(listener);
    });
  }

  // Thrown exceptions and console errors during the page's life, for assertions.
  trackProblems() {
    const problems = [];
    this.listeners.push((message) => {
      if (message.method === "Runtime.exceptionThrown") {
        problems.push(message.params.exceptionDetails.exception?.description ?? message.params.exceptionDetails.text);
      }
    });
    return problems;
  }

  async evaluate(expression, { awaitPromise = true } = {}) {
    const result = await this.send("Runtime.evaluate", { expression, awaitPromise, returnByValue: true });
    if (result.exceptionDetails) {
      const detail = result.exceptionDetails.exception?.description ?? result.exceptionDetails.text;
      throw new Error(`page threw: ${detail}`);
    }
    return result.result.value;
  }

  close() {
    this.socket.close();
  }
}

// Serves a built site on loopback with the content types a browser expects.
export async function serveSite(root) {
  const server = createServer(async (req, res) => {
    let path = decodeURIComponent(new URL(req.url, "http://127.0.0.1").pathname);
    if (path.endsWith("/")) path += "index.html";
    const file = normalize(join(root, path));
    if (file !== normalize(root) && !file.startsWith(normalize(root) + sep)) {
      res.writeHead(403).end();
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" }).end(body);
    } catch {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    }
  });
  const port = await freePort();
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  return { origin: `http://127.0.0.1:${port}`, close: () => new Promise((resolve) => server.close(resolve)) };
}
