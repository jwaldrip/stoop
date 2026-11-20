<p align="center">
  <img alt="stoop" src="assets/stoop-logo-on-light.svg#gh-light-mode-only" width="300">
  <img alt="stoop" src="assets/stoop-logo-on-dark.svg#gh-dark-mode-only" width="300">
</p>

<h3 align="center">Run only what matters.</h3>

<p align="center">
  Wrap a command. <b>stoop</b> traces its file activity and can skip it when its recorded inputs and outputs still match.<br>
  No input lists to write, and none to keep current.
</p>

<p align="center">
  <a href="https://stoop.build/">Website</a> &middot;
  <a href="https://stoop.build/docs/getting-started.html">Field guide</a> &middot;
  <a href="https://stoop.build/docs/ci.html">CI recipes</a> &middot;
  <a href="https://stoop.build/docs/cli.html">CLI reference</a>
</p>

<p align="center">
  <a href="https://github.com/jwaldrip/stoop/actions/workflows/ci.yml"><img src="https://github.com/jwaldrip/stoop/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/tracing-Linux%20x86--64%20%7C%20arm64-4b5868" alt="Tracing: Linux x86-64 and arm64">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4b5868" alt="MIT license"></a>
</p>

<p align="center">
  <img src="assets/readme-hero-light.jpg#gh-light-mode-only" alt="A murmuration of thousands of starlings over a frosted marsh, and one peregrine diving at a single bird at its edge." width="100%">
  <img src="assets/readme-hero-dark.jpg#gh-dark-mode-only" alt="A murmuration of thousands of starlings over a frosted marsh, and one peregrine diving at a single bird at its edge." width="100%">
</p>

## Most of a pipeline has nothing new to say

CI reruns every step on every push. Most of those steps read the same files they read last time and reach the same answer. When agents push all day, that waste compounds.

A stoop is a peregrine's hunting dive: it folds in, ignores the rest of the sky, and drops on the one thing that matters. **stoop** does that for CI. It picks out the step whose inputs moved and skips the rest.

<p align="center">
  <img src="assets/demo-terminal-light.png#gh-light-mode-only" alt="Terminal: stoop runs cargo build and records 668 inputs, skips the same build in 289 ms, then explains that an edit to src/ignore.rs means the build would run." width="760">
  <img src="assets/demo-terminal-dark.png#gh-dark-mode-only" alt="Terminal: stoop runs cargo build and records 668 inputs, skips the same build in 289 ms, then explains that an edit to src/ignore.rs means the build would run." width="760">
</p>

<p align="center"><sub>Captured, not typed: a fresh clone of stoop building itself, Linux arm64 in a throwaway container, stoop at <code>c9082e1</code>. Only cargo's progress lines are cut.</sub></p>

## How it works

1. **Watch.** The command runs under a tracer (ptrace plus a seccomp filter, so only file system calls stop). Every path the process tree opens, executes, looks up or lists is noted.
2. **Record.** When the command passes, stoop writes a proof: each path with a hash of every byte, files looked for and absent, directory listings, symlink targets, the environment, and what the run wrote inside the repository.
3. **Compare.** Next time it hashes the same paths. If all of them match and the outputs are still in place, the command is skipped.
4. **When unsure, run.** No proof, an expired proof, a trace that might be incomplete, a read of `.git`, or use of the network: the command runs and nothing is recorded.

By default, the proof key includes the command and its working directory relative to the repository root. The root is the nearest ancestor containing a `.git` directory or file, so a nested repository uses its own root. Without `.git`, the working directory is the root. `--root DIR` chooses a root explicitly. Paths inside it are stored relative to it, so a proof stored with the checkout can move with it.

Proofs live in `<root>/.stoop` unless `--store DIR` or `STOOP_STORE` chooses another store. An external store includes the Git origin URL in automatic keys, keeping different repositories apart while allowing checkouts of the same origin to share proofs. Without an origin, stoop uses the root's absolute path, so moving that root gives it a cold cache in an external store. Explicit `--key` names remain unchanged, but a proof still has to match the working directory and repository scope.

Proofs are specific to their operating system, architecture, tracer and tracer version. A Linux x86-64 proof cannot skip a Linux arm64 command, even in a shared store. Older proofs without this information are treated as cold; run the command on a supported Linux platform to record a fresh proof. New proofs use a format older stoop versions cannot read, so update runners sharing a store. `stoop ls` shows each proof's platform. macOS runs commands without tracing and never skips.

Up to 8 proofs are kept per key, so steps that leave no output in the repository (tests, lint, type checks) can also skip after a revert.

## Two lines in GitHub Actions

Put this at the top of a workflow and every `run:` step goes through stoop:

```yaml
defaults:
  run:
    shell: stoop sh {0}
```

Each step is keyed by its script, arguments, workflow, job and working directory. Steps that use an action run as usual; the step that installs stoop sets `shell: bash` for itself. Share proofs between runs through your own git remote (`--sync git`, no server to host) or by caching `.stoop/` with the CI's own cache. Pull requests read; only the default branch writes.

Full workflows for GitHub Actions, GitLab CI, CircleCI and Buildkite are in the [CI recipes](https://stoop.build/docs/ci.html).

## Experimental job planning

`stoop plan` can evaluate recorded job proofs before other runners start. **Do not enable plan-skips in workflow gates yet.** At recording, stoop compares each downloaded action tree with the runner's copy and follows nested composite refs. At planning, it resolves refs and downloads the trees again; a moved ref, changed content, or failed verification makes the job run. `STOOP_STRICT_ACTIONS=1` also makes floating remote refs unplannable.

The action check is a snapshot. It covers committed files, including committed `node_modules`, but not dependencies installed or modified later, the runner's tool cache, preinstalled actions, or tools downloaded by actions. Reusable-workflow jobs remain unplannable.

The planner requires an attested record from the planned workflow's own job, a protected branch, a GitHub-hosted runner and the same repository and owner IDs. It fails wide when it cannot establish a match. Publishing jobs need `id-token: write` and access to the shared git proof store. Any code in a publishing job that can request an OIDC token can attest records for another job in that workflow. Records whose signing key is no longer published are rejected.

The plan job must be in the top-level workflow. Set `STOOP_JOB_WORKFLOW_REF: ${{ job.workflow_ref }}` on the plan step; the planner refuses a missing or mismatched value in Actions. Container image `ENV` must not set `STOOP_*` controls, and neutral setup must not change them through `GITHUB_ENV`. These are assumptions, not checks. Jobs with nonempty `container.options` are unplannable.

Set `STOOP_ALLOW_USES` in workflow or job environment to a comma- or newline-separated list of exact `owner/repo` or `owner/repo@ref` actions. This asserts that each listed action is side-effect free; the workflow author is responsible for that assertion. Refs are still resolved and checked, and `STOOP_STRICT_ACTIONS` still applies. The `--allow-uses` flag is for local dry runs only. Supply `STOOP_ENV_SALT` to the plan job and recorded jobs alike when using salted proofs.

| Input | Plan-time handling |
|---|---|
| Repository inputs | Compared against the selected git tree and earlier recorded step outputs |
| State before a recorded write | Compared before applying its outputs; unknown prior state makes the job run |
| Files outside the repository and most runner environment | Assumed under the job definition and maximum age, not checked on the plan runner |
| GitHub event payload and known GitHub variables | Compared with the plan job's values |
| Probe or unknown setup | The job runs |

The default maximum age is seven days; `stoop plan --max-age` can set a shorter, positive ceiling. A trusted full run should re-prove jobs regularly. The planner does not restore outputs or run probes.

JSON output has schema `stoop.plan/1`: top-level `workflow`, `path`, `rev`, `plan_job`, `full`, `skip` and `jobs`. Each job has `id`, `gated`, `decision`, `code`, `detail` and `legs`. Each leg includes its key, decision, record, checked counts, assumed input counts and the first mismatch when available. In GitHub format, `skip` is a comma-delimited output such as `,test,`; the full JSON is also emitted when it fits the output limit.

## Install

```sh
curl -fsSL https://stoop.build/install.sh | sh
```

The installer places the binary in `~/.local/bin`. Set `STOOP_INSTALL_DIR` to another user-owned directory or `STOOP_VERSION=v0.1.0` to pin a release. Run the saved script with `--help`, `--dry-run`, or `--uninstall` for more options. `STOOP_RELEASE_BASE` is only for a local loopback test server.

The SHA-256 check detects corruption and a tampered mirror, but a compromised release could replace both the archive and its checksum. When `gh` is installed, the installer verifies GitHub build provenance; otherwise it reports that the check was skipped. Provenance identifies the build, not whether its source is safe. `curl | sh` trusts the domain and TLS to deliver the installer.

Tracing needs Linux on x86-64 or arm64. On macOS and Windows stoop runs commands untraced, never records, and never skips. macOS has one opt-in diagnostic: set `STOOP_DTRACE_DIAGNOSTIC=1` on a macOS runner with passwordless `sudo` to run the command once under DTrace and print what it did; that report is never recorded. The blind spots section says what it cannot show. There is no Windows installer yet: build it with `cargo build --release`. On Windows, `stoop mcp`, `stoop plan` and `--status-fd` are not available, and `stoop sh` needs Git for Windows' `bash` on `PATH`: it skips the WSL launcher in System32 when it finds another `bash.exe` on an absolute `PATH` entry, and uses the bare name otherwise, which Windows can resolve to that launcher.

```sh
stoop run -- cargo test        # skip or run
stoop explain -- cargo test    # say what would run and why (exit 1 if it would run)
stoop ls                       # list proofs
```

On a traced `stoop run`, a recognized test, lint or build runner may produce a
line such as `stoop: observed jest via npm (diagnostic only)`. This names
successful launches seen through wrappers. It does not change the command or
split its tests, and the observation is not saved in the proof. Warm skips,
`--quiet`, `--no-record`, `stoop sh`, and `stoop explain` omit the line.
Observation stops after 1,024 captured execs, 1,024 tracked tasks or 1,024
pending child stops, or when an exec has more than 128 arguments or 16 KiB of
argument bytes. Runners observed before a limit can still be reported; the
command continues unchanged.

## Changed-unit hook

Put `'{changed}'` where a test command takes test files, and name which files are tests:

```sh
stoop run -- npx jest '{changed:*.test.ts}'
```

Always single-quote the placeholder. Stoop refuses the shell-mangled forms before anything runs. In this release the placeholder runs the full command, with the placeholder and its option removed, so it never runs a subset. When it runs the command, stoop prints the words it removed. The [CLI reference](https://stoop.build/docs/cli.html#changed-hook) has the quoting table, the option rules and the premise.

## What it sees, and what it can't

| Counts as an input | How |
|---|---|
| Files read, executed, looked up or listed | Traced; every byte hashed, inside the repository and out |
| A file that was absent and appears | Recorded as absent inside the repository |
| Changes detected while the command runs | Not recorded; see the [limits of this check](https://stoop.build/docs/blind-spots.html#edits-while-running) |
| The environment | Every variable, minus runner bookkeeping, a curated list of per-run and per-commit variables, and any variable learned to change on every run while it holds an identifier; `--ignore-env NAME` exempts one, `--env NAME` counts one back |
| External state you can check | `--probe CMD`: its output must match for a skip |
| What the run wrote in the repository | Must still be in place for a skip; throwaway output goes in `.stoopignore` |

stoop sees files. It can't see:

- **The network.** A run that connects out isn't recorded, and stoop names where it connected. Cover it with `--probe`, or pass `--allow-network`.
- **The clock and randomness.** Proofs expire after 7 days (`--max-age`), and `STOOP_FULL=1` re-proves everything. Run that nightly.
- **Services outside the process tree**, and output written outside the repository.

[Blind spots and how to cover them](https://stoop.build/docs/blind-spots.html)

## Declared inputs, observed inputs

Build caches have to know what a task depends on. Most are told; stoop finds out.

| Tool | How it learns what a task depends on |
|---|---|
| Bazel | Each target declares its sources and dependencies in BUILD files ([docs](https://bazel.build/concepts/dependencies)) |
| Nx | Hashes a target's configured inputs: file sets, runtime values and environment variables ([docs](https://nx.dev/docs/reference/inputs)) |
| Turborepo | Hashes every git-tracked file in the package by default; `inputs` narrows it ([docs](https://turborepo.dev/docs/crafting-your-repository/configuring-tasks)) |
| `actions/cache` | You compose the key, usually from `hashFiles()` over globs you choose ([docs](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)) |
| **stoop** | Traces the files the command actually opened, executed, looked up or listed |

Those tools do things stoop doesn't, like task graphs, restoring cached outputs and, in Bazel's case, remote execution. stoop is one binary around one command, and it works inside any of them.

## Let an agent use it

`stoop mcp` serves stoop to an MCP client such as Claude Code, Cursor or VS Code. An agent can ask what would run and why (`explain`), read the recorded proofs, drop one, and read the agent guide. It runs a command only if you start the server with `--allow-run`.

```sh
stoop mcp --print-config    # the config to paste into your client
```

The [MCP reference](https://stoop.build/docs/mcp.html) covers the tools, the scope, and what the server never does. The guide agents read first is at [stoop.build/AGENTS.md](https://stoop.build/AGENTS.md).

## Roadmap

Not built yet. Today a skip needs byte-equal inputs; the plan loosens that only where it can be shown not to hide a change:

- **Equal build artifacts:** skip downstream steps when a rebuild produced the same bytes.
- **Normalized source:** ignore comment and whitespace edits, per language.
- **Coverage granularity:** tie a test to the code it actually ran.
- **A determinism check:** run twice at record time and refuse to record a step that disagrees with itself.
- **Static vetoes:** refuse to skip a step whose code calls the clock or a random source.
- **Restored outputs:** let a skip put back what the command produced.

[The roadmap, with the reasoning](https://stoop.build/docs/roadmap.html)

## Documentation

The [field guide](https://stoop.build/docs/getting-started.html) covers [getting started](https://stoop.build/docs/getting-started.html), [how it works](https://stoop.build/docs/how-it-works.html), [CI recipes](https://stoop.build/docs/ci.html), [every flag](https://stoop.build/docs/cli.html), [the MCP server](https://stoop.build/docs/mcp.html), [`.stoopignore`](https://stoop.build/docs/stoopignore.html), [blind spots](https://stoop.build/docs/blind-spots.html) and the [FAQ](https://stoop.build/docs/faq.html). The site's source is in [`site/`](site/).

## Build

```sh
cargo build --release
cargo test        # the end-to-end tests need Linux
```

MIT licensed.

<p align="center">
  <img alt="The Bushido Collective seal" src="assets/bushido-seal-on-light.svg#gh-light-mode-only" width="32">
  <img alt="The Bushido Collective seal" src="assets/bushido-seal-on-dark.svg#gh-dark-mode-only" width="32">
</p>
