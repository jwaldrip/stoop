//! Compare the real CLI with the independently captured v0.2.0 argv corpus.
//! Baseline: main commit 3f79a6d, captured by Actions run 44763096897. The
//! independent corpus uses seed 211 and records every argv, status and stdout.
//! The 18 explicitly stored exceptions are the approved delimiter safety rule.
#![cfg(unix)]

use serde::Deserialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

#[derive(Deserialize)]
struct Expected {
    code: i32,
    stdout: String,
}

#[derive(Deserialize)]
struct Case {
    argv: Vec<String>,
    code: i32,
    stdout: String,
    exception: Option<Expected>,
}

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("stoop-2a-differential-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let runner = root.join("runner");
        fs::write(
            &runner,
            "#!/bin/sh\ncase \"$*\" in *--files=base*) printf \"restricted\\n\";; *) printf \"%s\\n\" \"$#\"; for i do printf \"[%s]\\n\" \"$i\"; done;; esac\n",
        )
        .unwrap();
        fs::set_permissions(runner, fs::Permissions::from_mode(0o755)).unwrap();
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn matches_v020_for_786_cases_except_the_18_approved_delimiter_outcomes() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("fixtures/legacy_2a_differential.json")).unwrap();
    assert_eq!(cases.len(), 786);
    assert_eq!(
        cases.iter().filter(|case| case.exception.is_some()).count(),
        18
    );
    let fixture = Fixture::new();
    for case in cases {
        if let Some(expected) = &case.exception {
            assert!(case.argv.iter().any(|word| word == "--"), "{:?}", case.argv);
            assert_ne!(
                (case.code, case.stdout.as_str()),
                (expected.code, expected.stdout.as_str())
            );
        }
        let output = Command::new(env!("CARGO_BIN_EXE_stoop"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &fixture.0)
            .env("STOOP_OFF", "1")
            .current_dir(&fixture.0)
            .args(["run", "--no-record", "--"])
            .args(&case.argv)
            .output()
            .unwrap();
        let (code, stdout) = match &case.exception {
            Some(expected) => (expected.code, expected.stdout.as_str()),
            None => (case.code, case.stdout.as_str()),
        };
        assert_eq!(
            output.status.code(),
            Some(code),
            "argv={:?} stderr={}",
            case.argv,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            stdout,
            "argv={:?} stderr={}",
            case.argv,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
