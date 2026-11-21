//! Compare the prepared command with an independently built origin/main binary.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("stoop-head-compat-{}", std::process::id()));
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
