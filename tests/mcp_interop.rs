//! Runs tests/mcp_client.py, a second MCP client written in Python with the standard library
//! and sharing no code with the Rust harness, against the built binary. It is skipped, with a
//! note, where python3 is not installed.

mod common;

use common::repo;
use std::path::Path;
use std::process::Command;

#[test]
fn an_independent_client_passes_its_checks() {
    let python_present = Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !python_present {
        eprintln!("python3 is not installed; skipping the independent client check");
        return;
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mcp_client.py");
    // The server refuses to start outside a repository without --root, so the client runs in one.
    let dir = repo("interop", &[("in.txt", "one\n")]);
    let out = Command::new("python3")
        .arg(&script)
        .arg(env!("CARGO_BIN_EXE_stoop"))
        .arg(&dir)
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
