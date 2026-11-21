//! Compare the prepared command with an independently built origin/main binary.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoop-head-compat-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("runner"), "#!/bin/sh\nprintf 'argc=%s\\n' \"$#\"\nfor arg do printf '<%s>\\n' \"$arg\"; done\nprintf 'changed=<%s>\\n' \"${STOOP_CHANGED-UNSET}\"\n").unwrap();
        fs::set_permissions(root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
        Self(root)
    }

    fn invoke(&self, binary: &Path, args: &[&str]) -> (Option<i32>, Vec<u8>) {
        let output = Command::new(binary)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.0)
            .env("STOOP_OFF", "1")
            .current_dir(&self.0)
            .args(["run", "--no-record", "--", "./runner"])
            .args(args)
            .output()
            .unwrap();
        (output.status.code(), output.stdout)
    }

    fn invoke_shell(
        &self,
        binary: &Path,
        shell: &str,
        code: &str,
        args: &[&str],
    ) -> (Option<i32>, Vec<u8>) {
        let output = Command::new(binary)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.0)
            .env("STOOP_OFF", "1")
            .current_dir(&self.0)
            .args(["run", "--no-record", "--", shell, "-c", code, "sentinel"])
            .args(args)
            .output()
            .unwrap();
        (output.status.code(), output.stdout)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "requires STOOP_BASE_BIN built independently from origin/main"]
fn origin_main_and_head_prepare_the_same_argv_for_existing_hook_forms() {
    let base =
        std::env::var_os("STOOP_BASE_BIN").expect("build origin/main and set STOOP_BASE_BIN");
    let base = PathBuf::from(base);
    let head = Path::new(env!("CARGO_BIN_EXE_stoop"));
    let f = Fixture::new();
    let prefixes: &[&[&str]] = &[
        &[],
        &["--zero"],
        &["--one", "v"],
        &["--many", "v"],
        &["--many", "v", "v"],
        &["--"],
        &["v"],
        &["-foo", "v"],
        &["--other=old"],
    ];
    let forms: &[&[&str]] = &[
        &["{changed}"],
        &["{changed:*.t}"],
        &["${STOOP_UNITS:*.t}"],
        &["--one", "{unit:root}"],
        &["--many", "{changed:*.t:comma}"],
        &["--many={changed}"],
        &["-m{changed}"],
        &["--", "--many={changed}"],
        &["--other", "{changed}"],
        &["--other={changed}"],
        &["@{changed:file}"],
        &["--many-extra", "keep", "--many", "{changed}"],
        &["--zero={changed}", "--zero", "keep"],
    ];
    let suffixes: &[&[&str]] = &[
        &[],
        &["tail"],
        &["--zero"],
        &["--", "tail"],
        &["--one", "v"],
        &["--many", "v"],
    ];
    let mut checked = 0;
    for prefix in prefixes {
        for form in forms {
            for suffix in suffixes {
                let args: Vec<&str> = prefix.iter().chain(*form).chain(*suffix).copied().collect();
                let matches = std::iter::repeat_n("\"*\"", args.len())
                    .collect::<Vec<_>>()
                    .join(", ");
                fs::write(f.0.join(".stoop.toml"), format!(
                    "[[units.suite]]\nid = 'generated'\nmatch = [\"./runner\", {matches}]\noptions = [{{ names = [\"--zero\"], values = 0 }}, {{ names = [\"--one\"], values = 1 }}, {{ names = [\"--many\", \"-m\"], values = \"many\" }}, {{ names = [\"-foo\"], values = 1 }}]\n"
                )).unwrap();
                assert_eq!(
                    f.invoke(&base, &args),
                    f.invoke(head, &args),
                    "argv={args:?}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 702);
}

#[test]
#[ignore = "requires STOOP_BASE_BIN built independently from origin/main"]
fn origin_main_and_head_agree_on_native_shell_expansions() {
    let base = PathBuf::from(
        std::env::var_os("STOOP_BASE_BIN").expect("build origin/main and set STOOP_BASE_BIN"),
    );
    let head = Path::new(env!("CARGO_BIN_EXE_stoop"));
    let f = Fixture::new();
    let expressions = [
        "${STOOP_CHANGED:-fallback}",
        "${STOOP_CHANGED-fallback}",
        "${STOOP_CHANGED:=fallback}",
        "${STOOP_CHANGED=fallback}",
        "${STOOP_CHANGED:+alternate}",
        "${STOOP_CHANGED+alternate}",
        "${STOOP_CHANGED:?required}",
        "${STOOP_CHANGED?required}",
        "${#STOOP_CHANGED}",
        "${STOOP_CHANGED%tail}",
        "${STOOP_CHANGED%%tail}",
        "${STOOP_CHANGED#head}",
        "${STOOP_CHANGED##head}",
        "${STOOP_CHANGED:1}",
        "${STOOP_CHANGED:3}",
        "${STOOP_CHANGED:foo}",
        "${STOOP_CHANGED:foo:2}",
        "${STOOP_CHANGED: -1}",
        "${STOOP_CHANGED:1*2}",
        "${STOOP_CHANGED:foo/bar}",
        "${STOOP_CHANGED:!foo}",
        r"\${STOOP_CHANGED:*.t}",
        "${STOOP_CHANGED/a/b}",
        "$(printf command)",
        "$((1+2))",
        "{a,b}",
    ];
    let selectors: &[&[&str]] = &[
        &["--files", "{changed:*.t}"],
        &["--files={changed:*.t}"],
        &["{changed:*.t}"],
        &["--", "{changed:*.t}"],
    ];
    let shells = ["sh", "bash", "dash"];
    let mut checked = 0;
    for shell in shells {
        for expression in expressions {
            let code = format!("printf '<%s>\\n' \"{expression}\" \"$@\"");
            for args in selectors {
                assert_eq!(
                    f.invoke_shell(&base, shell, &code, args),
                    f.invoke_shell(head, shell, &code, args),
                    "shell={shell} code={code:?} args={args:?}"
                );
                checked += 1;
            }
        }
    }
    let quoted_codes = [
        "printf '<%s>\\n' '${STOOP_CHANGED:*.u}' \"$@\"",
        "printf '<%s>\\n' pre'${STOOP_CHANGED:*.u}'post \"$@\"",
        "printf '<%s>\\n' \\${STOOP_CHANGED:*.u} \"$@\"",
        "printf '<%s>\\n' \"${STOOP_CHANGED: a[\"0\"]}\" \"$@\"",
        "printf '<%s>\\n' \"${STOOP_CHANGED: 1\n + 1}\" \"$@\"",
    ];
    for shell in shells {
        for code in quoted_codes {
            for args in selectors {
                assert_eq!(
                    f.invoke_shell(&base, shell, code, args),
                    f.invoke_shell(head, shell, code, args),
                    "shell={shell} code={code:?} args={args:?}"
                );
                checked += 1;
            }
        }
    }
    for shell in shells {
        for byte in 0x20u8..=0x7e {
            let expansion = format!("${{STOOP_CHANGED:{}foo}}", byte as char);
            for code in [
                format!("printf '<%s>\\n' {expansion} \"$@\""),
                format!("printf '<%s>\\n' \"{expansion}\" \"$@\""),
                format!("printf '<%s>\\n' '{expansion}' \"$@\""),
                format!("printf '<%s>\\n' \\{expansion} \"$@\""),
            ] {
                let args = ["--files", "{changed}"];
                assert_eq!(
                    f.invoke_shell(&base, shell, &code, &args),
                    f.invoke_shell(head, shell, &code, &args),
                    "shell={shell} code={code:?} args={args:?}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 1512);
}
