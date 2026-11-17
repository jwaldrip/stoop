# stoop

Run only what matters.

`stoop` wraps a command. If everything the command read the last time it passed is unchanged, it skips the command. If not, it runs it and records what it read. There are no input lists to write and none to keep current.

```
$ stoop run -- cargo test
stoop: run cargo-184b0d9cbc5273d9: no proof yet
...
stoop: recorded 167 inputs for cargo-184b0d9cbc5273d9

$ stoop run -- cargo test
stoop: skip cargo-184b0d9cbc5273d9: 167 inputs unchanged since 12s ago (2ms)

$ echo "// x" >> src/main.rs
$ stoop explain -- cargo test
stoop: would run cargo-184b0d9cbc5273d9: src/main.rs changed
```

The name is the peregrine's hunting dive: fold in, drop on the one thing that matters.

## How it decides

The command runs under a tracer (ptrace plus a seccomp filter, so only file syscalls stop). The tracer records every path the process tree opened, looked up, listed or executed. When the command passes, `stoop` stores a proof: each of those paths with a content hash, plus the files the run produced inside the repository.

Next time, it hashes the same paths. If every one matches, and the outputs are still in place, the command is skipped. A file that did not exist and now does, a new entry in a directory the command listed, a changed toolchain binary or a changed lockfile all count as changes, because the command looked at them.

Proofs are content-addressed, so they do not care which branch or commit produced them. Reverting an edit finds the proof from before it. Up to eight proofs are kept per command.

When it cannot be sure, it runs. No proof, an expired proof, a trace that may be incomplete, a read of `.git`, use of the network: the command runs and nothing is recorded.

## Use it in GitHub Actions

Put this at the top of a workflow and every `run:` step is wrapped, with no per-step edits:

```yaml
defaults:
  run:
    shell: stoop sh {0}
```

Each step's script is keyed by its contents, the workflow and the job. Restore the proof store (`.stoop/`) from the default branch before the steps and save it after merges, so branches reuse what main already proved. Untrusted jobs should pass `--no-record` so only trusted runs write proofs.

Steps that are not `run:` steps (checkout, setup actions) run as usual.

## What counts as an input

| Counts | How |
|---|---|
| Files read, executed, looked up or listed | traced; content hashed (toolchain-sized files outside the repo are sampled) |
| A file that was absent and appears | recorded as absent inside the repo |
| The whole environment | every variable, minus runner bookkeeping and per-start noise; `--ignore-env NAME` exempts one |
| Output the run wrote inside the repo | must still be present and unchanged for a skip; list throwaway output in `.stoopignore` |

## Blind spots

`stoop` sees files. It cannot see:

- **The network.** A run that connects to an IP address or an unlisted local socket is not recorded (`--allow-network` overrides).
- **The clock and randomness.** Proofs expire after 7 days (`--max-age`), and `STOOP_FULL=1` re-proves everything. Run it nightly.
- **Services outside the process tree** that the command talks to through files or sockets it does not open itself.

Output outside the repository is not tracked. A step whose job is to produce files elsewhere should not be wrapped.

Tracing needs Linux (x86-64 or arm64). On other systems `stoop` runs the command untraced and records nothing.

## `.stoopignore`

One pattern per line, relative to the repository root.

```
# a component name matches anywhere
node_modules
# a path with a slash is anchored to the root and covers what is under it
reports/junit.xml
# * stays inside a component, ** crosses them
docs/**/generated
```

Add `.git` if a command reads it and the read cannot change the result. By default a read of `.git` means the proof is not recorded.

## Commands

```
stoop run [options] -- <command>      skip or run
stoop explain [options] -- <command>  say what would run and why (exit 1 if it would run)
stoop sh <script>                     shell mode for CI
stoop ls                              list proofs
stoop forget <key>                    drop a proof
```

`stoop --help` has the options.

## Roadmap

The goal is to skip when the effective input is equal, not just when the bytes are. From strictest to loosest:

1. **Byte-equal inputs.** Done.
2. **Equal build artifacts (early cutoff).** Works already when builds are reproducible: the build step reruns, and a downstream step that only reads its output sees the same bytes and skips. Next: hash executables by loaded segments, ignoring build ids, timestamps and debug sections. Line-number strings still change the output when an edit shifts lines.
3. **Normalized source.** Hash a file with comments and whitespace removed, per language, conservatively (keep directives such as `//go:build`, pragmas and docstrings that are runtime values).
4. **Static vetoes.** Scan the files a step read for clock, randomness and network calls and refuse to skip. A static signal can only make `stoop` run more, never less.
5. **Remote proofs and restored outputs**, so a skip can also restore what the command produced.

## Build

```
cargo build --release
cargo test        # the end-to-end tests need Linux
```

MIT licensed.
