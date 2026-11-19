//! Real shells decide what stoop receives. Each case runs a script in the named shell and
//! checks what the fake runner received. Linux CI installs zsh, fish and dash, and a missing
//! shell fails the test instead of skipping it.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use yaml_rust2::YamlLoader;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Dir {
    root: PathBuf,
}

impl Dir {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoop-shells-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("bin")).unwrap();
        symlink(env!("CARGO_BIN_EXE_stoop"), root.join("bin/stoop")).unwrap();
        fs::write(
            root.join("runner"),
            "#!/bin/sh\n: > \"$LOG\"\nfor arg do printf 'arg=<%s>\\n' \"$arg\" >> \"$LOG\"; done\nprintf 'changed=<%s>\\n' \"${STOOP_CHANGED-UNSET}\" >> \"$LOG\"\n",
        )
        .unwrap();
        fs::set_permissions(root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(root.join("a.t"), "").unwrap();
        fs::write(root.join("b.t"), "").unwrap();
        Self { root }
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("HOME", &self.root)
            .env("PATH", format!("{}/bin:/usr/bin:/bin", self.root.display()))
            .env("LOG", self.root.join("log"))
            .env("STOOP_STORE", self.root.join("store"))
            .current_dir(&self.root);
        command
    }

    /// Run `script` with `shell` and its flags. A missing shell panics, which fails the test.
    fn shell(&self, shell: &str, flags: &[&str], script: &str) -> Output {
        self.command(shell)
            .args(flags)
            .arg(script)
            .output()
            .unwrap_or_else(|error| {
                panic!("{shell} must be installed for the shell tests: {error}")
            })
    }

    fn log(&self) -> Option<String> {
        fs::read_to_string(self.root.join("log")).ok()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.root.join("store"), fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn single_quoted_placeholders_arrive_intact_in_every_shell() {
    for shell in ["bash", "dash", "zsh", "fish"] {
        let dir = Dir::new();
        let out = dir.shell(shell, &["-c"], "stoop run -- ./runner '{changed:*.t}'");
        assert!(out.status.success(), "{shell}: {}", err(&out));
        assert_eq!(dir.log().as_deref(), Some("changed=<>\n"), "{shell}");
    }
}

#[test]
fn single_quoted_environment_form_runs_the_full_command_in_every_shell() {
    for shell in ["bash", "dash", "zsh", "fish"] {
        let dir = Dir::new();
        let out = dir.shell(
            shell,
            &["-c"],
            "stoop run -- ./runner --files '$STOOP_CHANGED'",
        );
        assert!(out.status.success(), "{shell}: {}", err(&out));
        assert_eq!(dir.log().as_deref(), Some("changed=<>\n"), "{shell}");
    }
}

#[test]
fn zsh_and_fish_refuse_an_unquoted_placeholder_before_stoop_starts() {
    for shell in ["zsh", "fish"] {
        let dir = Dir::new();
        let out = dir.shell(shell, &["-c"], "stoop run -- ./runner {changed:*.t}");
        assert!(
            !out.status.success(),
            "{shell} must refuse the wildcard: {}",
            err(&out)
        );
        assert_eq!(dir.log(), None, "{shell} must not launch the runner");
    }
}

#[test]
fn bash_brace_expansion_is_refused_by_stoop_before_launch() {
    let dir = Dir::new();
    let out = dir.shell("bash", &["-c"], "stoop run -- ./runner {changed:*.t,*.u}");
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(err(&out).contains("expanded"), "{}", err(&out));
    assert_eq!(dir.log(), None);
}

#[test]
fn dash_pipe_in_an_unquoted_placeholder_is_cut_off_before_launch() {
    let dir = Dir::new();
    let out = dir.shell("dash", &["-c"], "stoop run -- ./runner {changed:*.t|*.u}");
    assert!(!out.status.success(), "{}", err(&out));
    assert!(err(&out).contains("cut off"), "{}", err(&out));
    assert_eq!(dir.log(), None);
}

#[test]
fn zsh_brace_ccl_expansion_of_a_recorded_hook_runs_the_full_command() {
    let dir = Dir::new();
    let out = dir.shell("bash", &["-c"], "stoop run -- ./runner '{changed}'");
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(dir.log().as_deref(), Some("changed=<>\n"));
    let out = dir.shell(
        "zsh",
        &["-o", "braceccl", "-c"],
        "stoop run -- ./runner {changed}",
    );
    assert!(out.status.success(), "{}", err(&out));
    assert!(err(&out).contains("expanded"), "{}", err(&out));
    assert!(!err(&out).contains("stoop: skip"), "{}", err(&out));
    assert_eq!(dir.log().as_deref(), Some("changed=<>\n"));
}

#[test]
fn make_recipe_quoting_reaches_stoop_as_the_full_command() {
    let dir = Dir::new();
    fs::write(
        dir.root.join("Makefile"),
        "test:\n\tstoop run -- ./runner --files '$$STOOP_CHANGED'\n",
    )
    .unwrap();
    let out = dir
        .command("make")
        .args(["-f", "Makefile", "test"])
        .output()
        .unwrap_or_else(|error| panic!("make must be installed for the shell tests: {error}"));
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(dir.log().as_deref(), Some("changed=<>\n"));
}

#[test]
fn github_actions_steps_run_in_the_actions_bash_shell() {
    let dir = Dir::new();
    let workflow = "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - name: changed tests\n        shell: bash\n        run: |\n          stoop run -- ./runner '{changed:*.t}'\n      - name: changed tests, plain scalar\n        run: stoop run -- ./runner --files '{changed}'\n      - name: changed tests, environment spelling\n        shell: bash\n        run: |\n          stoop run -- ./runner --files '$STOOP_CHANGED'\n";
    let document = YamlLoader::load_from_str(workflow).unwrap();
    let steps = document[0]["jobs"]["test"]["steps"].as_vec().unwrap();
    for (index, step) in steps.iter().enumerate() {
        let file = format!("step{index}.sh");
        fs::write(dir.root.join(&file), step["run"].as_str().unwrap()).unwrap();
        // GitHub Actions runs `shell: bash` as `bash --noprofile --norc -eo pipefail {0}`.
        let out = dir.shell("bash", &["--noprofile", "--norc", "-eo", "pipefail"], &file);
        assert!(out.status.success(), "step {index}: {}", err(&out));
        assert_eq!(dir.log().as_deref(), Some("changed=<>\n"), "step {index}");
    }
}

#[test]
fn a_placeholder_inside_a_shell_string_is_refused_only_when_the_shell_is_recognized() {
    let dir = Dir::new();
    let out = dir.shell(
        "bash",
        &["-c"],
        "stoop run -- sh -c 'printf %s {changed:*.t}'",
    );
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(
        err(&out).contains("substituted into shell code"),
        "{}",
        err(&out)
    );
    assert_eq!(dir.log(), None);
    // Not shell code: the same brace placeholder as an option value is a placeholder.
    let out = dir.shell("bash", &["-c"], "stoop run -- ./runner -c '{changed:*.t}'");
    assert!(out.status.success(), "{}", err(&out));
    assert!(!err(&out).contains("substituted"), "{}", err(&out));
    assert_eq!(dir.log().as_deref(), Some("changed=<>\n"));
}

#[test]
fn bash_dash_e_runs_each_spelling_of_a_run_step() {
    for (index, step) in [
        "stoop run -- ./runner '{changed:*.t}'",
        "stoop run -- ./runner --files '$STOOP_CHANGED'",
    ]
    .iter()
    .enumerate()
    {
        let dir = Dir::new();
        let file = format!("run{index}.sh");
        fs::write(dir.root.join(&file), format!("{step}\n")).unwrap();
        let out = dir.shell("bash", &["-e"], &file);
        assert!(out.status.success(), "step {index}: {}", err(&out));
        assert_eq!(dir.log().as_deref(), Some("changed=<>\n"), "step {index}");
    }
}
