//! A tracer failure after exec must not run a command a second time.
#![cfg(target_os = "linux")]

use std::fs;
use std::process::Command;

#[test]
fn wait_failure_after_exec_never_runs_the_command_twice() {
    let root = std::env::temp_dir().join(format!("stoop-wait-failure-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let source = root.join("wait.c");
    let library = root.join("wait.so");
    let marker = root.join("marker");
    fs::write(
        &source,
        r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

pid_t waitpid(pid_t pid, int *status, int options) {
    static pid_t (*real_waitpid)(pid_t, int *, int);
    static int injected;
    if (!real_waitpid) real_waitpid = dlsym(RTLD_NEXT, "waitpid");
    if (pid == -1 && !injected) {
        char exe[4096];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        const char *marker = getenv("STOOP_TEST_WAIT_MARKER");
        struct stat st;
        if (n > 0 && marker) {
            exe[n] = 0;
            const char *name = strrchr(exe, '/');
            if (name && strcmp(name + 1, "stoop") == 0 && stat(marker, &st) == 0 && st.st_size > 0) {
                injected = 1;
                errno = EIO;
                return -1;
            }
        }
    }
    return real_waitpid(pid, status, options);
}
"#,
    )
    .unwrap();
    let compiled = Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&library)
        .arg(&source)
        .arg("-ldl")
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .current_dir(&root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LD_PRELOAD", &library)
        .env("STOOP_TEST_WAIT_MARKER", &marker)
        .args([
            "run",
            "--root",
            ".",
            "--",
            "sh",
            "-c",
            "printf x >> marker; sleep 1",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(
        fs::read_to_string(&marker).unwrap(),
        "x",
        "the command ran twice: {stderr}"
    );
    assert!(
        stderr.contains("not recorded") && stderr.contains("wait"),
        "{stderr}"
    );
    assert!(!root.join(".stoop/proofs").exists());
    fs::remove_dir_all(&root).unwrap();
}
