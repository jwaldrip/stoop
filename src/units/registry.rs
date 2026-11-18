//! Names for successful exec observations. These rows confer no execution authority.

use crate::trace::ExecEvent;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Runner,
    Wrapper,
}

#[derive(Clone, Copy)]
enum Match {
    Executable(&'static [&'static str]),
    Subcommand(&'static [&'static str], &'static str),
    TestTask(&'static [&'static str]),
    PythonModule(&'static str),
    NodeEntry(&'static [&'static str]),
    Shell,
}

struct Row {
    label: &'static str,
    kind: Kind,
    matches: Match,
}

// More specific driver modes precede their wrapper rows. Adding a candidate here only
// names an observed invocation; it does not assert a version, transport, or unit policy.
static ROWS: &[Row] = &[
    Row {
        label: "pytest",
        kind: Kind::Runner,
        matches: Match::Executable(&["pytest", "py.test"]),
    },
    Row {
        label: "pytest",
        kind: Kind::Runner,
        matches: Match::PythonModule("pytest"),
    },
    Row {
        label: "jest",
        kind: Kind::Runner,
        matches: Match::Executable(&["jest"]),
    },
    Row {
        label: "jest",
        kind: Kind::Runner,
        matches: Match::NodeEntry(&["jest", "jest.js"]),
    },
    Row {
        label: "vitest",
        kind: Kind::Runner,
        matches: Match::Executable(&["vitest"]),
    },
    Row {
        label: "vitest",
        kind: Kind::Runner,
        matches: Match::NodeEntry(&["vitest", "vitest.js", "vitest.mjs"]),
    },
    Row {
        label: "mocha",
        kind: Kind::Runner,
        matches: Match::Executable(&["mocha", "_mocha"]),
    },
    Row {
        label: "mocha",
        kind: Kind::Runner,
        matches: Match::NodeEntry(&["mocha", "mocha.js", "_mocha"]),
    },
    Row {
        label: "go test",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["go"], "test"),
    },
    Row {
        label: "go build",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["go"], "build"),
    },
    Row {
        label: "go vet",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["go"], "vet"),
    },
    Row {
        label: "cargo test",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["cargo"], "test"),
    },
    Row {
        label: "cargo nextest",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["cargo"], "nextest"),
    },
    Row {
        label: "cargo nextest",
        kind: Kind::Runner,
        matches: Match::Executable(&["cargo-nextest"]),
    },
    Row {
        label: "cargo build",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["cargo"], "build"),
    },
    Row {
        label: "cargo clippy",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["cargo"], "clippy"),
    },
    Row {
        label: "gradle test",
        kind: Kind::Runner,
        matches: Match::TestTask(&["gradle", "gradlew"]),
    },
    Row {
        label: "maven test",
        kind: Kind::Runner,
        matches: Match::TestTask(&["mvn", "mvnw"]),
    },
    Row {
        label: "rspec",
        kind: Kind::Runner,
        matches: Match::Executable(&["rspec"]),
    },
    Row {
        label: "phpunit",
        kind: Kind::Runner,
        matches: Match::Executable(&["phpunit"]),
    },
    Row {
        label: "dotnet test",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["dotnet"], "test"),
    },
    Row {
        label: "mix test",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["mix"], "test"),
    },
    Row {
        label: "bun test",
        kind: Kind::Runner,
        matches: Match::Subcommand(&["bun"], "test"),
    },
    Row {
        label: "eslint",
        kind: Kind::Runner,
        matches: Match::Executable(&["eslint"]),
    },
    Row {
        label: "eslint",
        kind: Kind::Runner,
        matches: Match::NodeEntry(&["eslint.js"]),
    },
    Row {
        label: "tsc",
        kind: Kind::Runner,
        matches: Match::Executable(&["tsc"]),
    },
    Row {
        label: "tsc",
        kind: Kind::Runner,
        matches: Match::NodeEntry(&["tsc.js"]),
    },
    Row {
        label: "npm",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["npm"]),
    },
    Row {
        label: "pnpm",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["pnpm"]),
    },
    Row {
        label: "yarn",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["yarn"]),
    },
    Row {
        label: "bun",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["bun", "bunx"]),
    },
    Row {
        label: "npx",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["npx"]),
    },
    Row {
        label: "make",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["make", "gmake"]),
    },
    Row {
        label: "just",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["just"]),
    },
    Row {
        label: "task",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["task"]),
    },
    Row {
        label: "mise",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["mise"]),
    },
    Row {
        label: "tox",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["tox"]),
    },
    Row {
        label: "tox",
        kind: Kind::Wrapper,
        matches: Match::PythonModule("tox"),
    },
    Row {
        label: "nox",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["nox"]),
    },
    Row {
        label: "nox",
        kind: Kind::Wrapper,
        matches: Match::PythonModule("nox"),
    },
    Row {
        label: "bundle",
        kind: Kind::Wrapper,
        matches: Match::Executable(&["bundle", "bundler"]),
    },
    Row {
        label: "sh",
        kind: Kind::Wrapper,
        matches: Match::Shell,
    },
];

fn base(path: &OsStr) -> Option<&str> {
    Path::new(path).file_name()?.to_str()
}

fn named(name: Option<&str>, names: &[&str]) -> bool {
    name.is_some_and(|name| names.contains(&name))
}

fn is_python(name: Option<&str>) -> bool {
    name.and_then(|name| name.strip_prefix("python"))
        .is_some_and(|suffix| suffix.bytes().all(|c| c.is_ascii_digit() || c == b'.'))
}

fn matches(row: &Row, event: &ExecEvent) -> bool {
    let name = base(event.requested.as_os_str());
    let args = &event.argv;
    let arg = |i: usize| args.get(i).and_then(|s| s.to_str());
    match row.matches {
        Match::Executable(names) => named(name, names),
        Match::Subcommand(names, command) => {
            named(name, names)
                && (arg(1) == Some(command)
                    || (name == Some("go") && arg(1) == Some("-C") && arg(3) == Some(command)))
        }
        Match::TestTask(names) => {
            named(name, names)
                && args
                    .iter()
                    .skip(1)
                    .filter_map(|a| a.to_str())
                    .any(|a| a == "test" || (!a.starts_with('-') && a.ends_with(":test")))
        }
        Match::PythonModule(module) => {
            is_python(name) && arg(1) == Some("-m") && arg(2) == Some(module)
        }
        Match::NodeEntry(names) => {
            named(name, &["node", "nodejs"])
                && args.get(1).is_some_and(|entry| named(base(entry), names))
        }
        Match::Shell => {
            named(name, &["sh", "dash", "bash", "zsh", "ash"])
                && args
                    .iter()
                    .skip(1)
                    .filter_map(|a| a.to_str())
                    .take_while(|a| a.starts_with('-') && *a != "--")
                    .any(|a| a[1..].contains('c'))
        }
    }
}

fn row(event: &ExecEvent) -> Option<&'static Row> {
    ROWS.iter().find(|row| matches(row, event))
}

/// One redacted line for the successfully observed runners, or none if there are none.
pub(crate) fn diagnostic(events: &[ExecEvent]) -> Option<String> {
    // Invalid ancestry or an incomplete exec image cannot support even a diagnostic chain.
    if events.iter().enumerate().any(|(i, event)| {
        event.parent.is_some_and(|parent| parent >= i)
            || !event.cwd.is_absolute()
            || !event.executable.is_absolute()
            || event.effective_argv.is_empty()
    }) {
        return None;
    }
    let mut descriptions = BTreeSet::new();
    for event in events {
        let Some(runner) = row(event).filter(|row| row.kind == Kind::Runner) else {
            continue;
        };
        let mut wrappers = Vec::new();
        let mut parent = event.parent;
        while let Some(index) = parent {
            let ancestor = &events[index];
            if let Some(wrapper) = row(ancestor).filter(|row| row.kind == Kind::Wrapper) {
                wrappers.push(wrapper.label);
            }
            parent = ancestor.parent;
        }
        wrappers.reverse();
        // JS package managers normally launch their script through a shell. Keep the
        // manager as the visible delegation hop, while retaining shells under task runners.
        let mut visible = Vec::new();
        for wrapper in wrappers {
            if wrapper == "sh"
                && visible
                    .last()
                    .is_some_and(|last| matches!(*last, "npm" | "pnpm" | "yarn" | "bun" | "npx"))
            {
                continue;
            }
            if visible.last() != Some(&wrapper) {
                visible.push(wrapper);
            }
        }
        let description = if visible.is_empty() {
            runner.label.to_string()
        } else {
            format!("{} via {}", runner.label, visible.join(" > "))
        };
        descriptions.insert(description);
    }
    if descriptions.is_empty() {
        return None;
    }
    // Keep the user-facing line bounded even if the tree starts many different chains.
    if descriptions.len() > 16 {
        return Some("stoop: observed multiple runners (diagnostic only)".to_string());
    }
    Some(format!(
        "stoop: observed {} (diagnostic only)",
        descriptions.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn event(parent: Option<usize>, requested: &str, argv: &[&str]) -> ExecEvent {
        ExecEvent {
            parent,
            requested: PathBuf::from(requested),
            argv: argv.iter().map(OsString::from).collect(),
            executable: PathBuf::from("/usr/bin/fixture"),
            effective_argv: vec![OsString::from("fixture")],
            cwd: PathBuf::from("/fixture"),
        }
    }

    fn runner(requested: &str, args: &[&str], expected: Option<&str>) {
        let observed = diagnostic(&[event(None, requested, args)]);
        assert_eq!(observed.as_deref(), expected);
    }

    #[test]
    fn runner_grammars_are_specific() {
        for (program, args, name) in [
            ("pytest", vec!["pytest"], "pytest"),
            (
                "python3.12",
                vec!["python3.12", "-m", "pytest", "-q"],
                "pytest",
            ),
            (
                "node",
                vec!["node", "node_modules/jest/bin/jest.js"],
                "jest",
            ),
            (
                "node",
                vec!["node", "node_modules/vitest/vitest.mjs"],
                "vitest",
            ),
            ("mocha", vec!["mocha"], "mocha"),
            ("go", vec!["go", "test", "./..."], "go test"),
            ("go", vec!["go", "-C", "sub", "test"], "go test"),
            ("cargo", vec!["cargo", "test"], "cargo test"),
            ("cargo", vec!["cargo", "nextest", "run"], "cargo nextest"),
            (
                "cargo-nextest",
                vec!["cargo-nextest", "nextest", "run"],
                "cargo nextest",
            ),
            ("gradlew", vec!["gradlew", ":api:test"], "gradle test"),
            ("mvn", vec!["mvn", "-B", "test"], "maven test"),
            ("rspec", vec!["rspec"], "rspec"),
            ("phpunit", vec!["phpunit"], "phpunit"),
            ("dotnet", vec!["dotnet", "test"], "dotnet test"),
            ("mix", vec!["mix", "test"], "mix test"),
            ("bun", vec!["bun", "test"], "bun test"),
            ("cargo", vec!["cargo", "clippy"], "cargo clippy"),
            ("eslint", vec!["eslint", "."], "eslint"),
        ] {
            let expected = format!("stoop: observed {name} (diagnostic only)");
            runner(program, &args, Some(&expected));
        }
        runner("python", &["python", "-c", "import pytest"], None);
        runner("python-helper", &["python-helper", "-m", "pytest"], None);
        runner("go", &["go", "run", "test"], None);
        runner("cargo", &["cargo", "run", "test"], None);
        runner("mvn", &["mvn", "-Dname=test", "verify"], None);
        runner("sh", &["sh", "-c", "pytest"], None);
        runner("npx", &["npx", "jest"], None);
    }

    #[test]
    fn shell_and_wrapper_ancestry_comes_from_successful_images() {
        let events = vec![
            event(None, "/usr/bin/make", &["make", "test"]),
            event(Some(0), "/bin/sh", &["sh", "-c", "cd sub && pytest"]),
            event(Some(1), "/venv/bin/pytest", &["pytest"]),
        ];
        assert_eq!(
            diagnostic(&events).as_deref(),
            Some("stoop: observed pytest via make > sh (diagnostic only)")
        );
        let npm = vec![
            event(None, "/bin/sh", &["sh", "-c", "cd sub && npm test"]),
            event(Some(0), "/bin/npm", &["npm", "test"]),
            event(Some(1), "/bin/sh", &["sh", "-c", "jest"]),
            event(Some(2), "/bin/jest", &["jest"]),
        ];
        assert_eq!(
            diagnostic(&npm).as_deref(),
            Some("stoop: observed jest via sh > npm (diagnostic only)")
        );
        let npx = vec![
            event(None, "npx", &["npx", "jest"]),
            event(Some(0), "jest", &["jest"]),
        ];
        assert_eq!(
            diagnostic(&npx).as_deref(),
            Some("stoop: observed jest via npx (diagnostic only)")
        );
        let pnpm = vec![
            event(None, "pnpm", &["pnpm", "exec", "vitest"]),
            event(Some(0), "vitest", &["vitest"]),
        ];
        assert_eq!(
            diagnostic(&pnpm).as_deref(),
            Some("stoop: observed vitest via pnpm (diagnostic only)")
        );
        let tox = vec![
            event(None, "python", &["python", "-m", "tox"]),
            event(Some(0), "python", &["python", "-m", "pytest"]),
        ];
        assert_eq!(
            diagnostic(&tox).as_deref(),
            Some("stoop: observed pytest via tox (diagnostic only)")
        );
    }

    #[test]
    fn separate_branches_never_borrow_each_others_wrappers() {
        let events = vec![
            event(None, "sh", &["sh", "-c", "npm test; pytest"]),
            event(Some(0), "npm", &["npm", "test"]),
            event(Some(1), "jest", &["jest"]),
            event(Some(0), "pytest", &["pytest"]),
        ];
        assert_eq!(
            diagnostic(&events).as_deref(),
            Some("stoop: observed jest via sh > npm, pytest via sh (diagnostic only)")
        );
        let invalid = vec![
            event(Some(1), "pytest", &["pytest"]),
            event(None, "make", &["make"]),
        ];
        assert!(diagnostic(&invalid).is_none());
    }
}
