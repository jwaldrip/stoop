//! Volatile environment variables, end to end through the real recorder and binary. Tracing needs
//! Linux, so these only run there.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const SCRIPT: &str = "cat in.txt > /dev/null";

struct Ws {
    root: PathBuf,
}

impl Ws {
    fn new(name: &str) -> Ws {
        let root =
            std::env::temp_dir().join(format!("stoop-volatile-e2e-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("repo/.git")).unwrap();
        fs::write(root.join("repo/in.txt"), "one").unwrap();
        Ws { root }
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    fn store(&self) -> PathBuf {
        self.root.join("store")
    }

    /// Run stoop in the repository with `env` set. Returns (exit code, stderr).
    fn stoop(&self, env: &[(&str, &str)], args: &[&str]) -> (i32, String) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
            .args(args)
            .current_dir(self.repo())
            .env("STOOP_STORE", self.store())
            .env_remove("STOOP_FULL")
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_LEARN_VOLATILE")
            .env_remove("GITHUB_ACTIONS")
            .env_remove("RUNNER_TEMP")
            .env_remove("STOOP_MATRIX")
            .env_remove("STOOP_SYNC")
            .env_remove("STOOP_SYNC_WRITE")
            .env_remove("STOOP_ENV_SALT")
            .env_remove("CI_COMMIT_SHA")
            .env_remove("NODE_ENV")
            .env_remove("SESSION_MARK_LEARN")
            .env_remove("JENKINS_URL")
            .env_remove("TEAMCITY_VERSION")
            .env_remove("TF_BUILD")
            .env_remove("STY")
            .env_remove("BUILD_NUMBER")
            .env_remove("SOURCE_DATE_EPOCH");
        for (name, value) in env {
            command.env(name, value);
        }
        let out = command.output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// `stoop run` of the shared script under key `v`, with `env` set.
    fn run(&self, env: &[(&str, &str)]) -> String {
        self.stoop(
            env,
            &["run", "--root", ".", "--key", "v", "--", "sh", "-c", SCRIPT],
        )
        .1
    }

    /// The `env_excluded` names of the newest proof stored under key `v`.
    fn stored_excluded(&self) -> Vec<String> {
        let bytes = fs::read(self.store().join("proofs/v.json")).unwrap();
        let file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        file["proofs"][0]["env_excluded"]
            .as_array()
            .map(|names| {
                names
                    .iter()
                    .map(|name| name.as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn skipped(stderr: &str) -> bool {
    stderr.contains("stoop: skip")
}

/// A value that is opaque (it mixes letters and digits) and different for each `i`.
fn opaque(i: u64) -> String {
    format!("c0ffee{i:08x}")
}

#[test]
fn a_curated_ci_commit_sha_does_not_defeat_a_skip() {
    let w = Ws::new("ci-sha");
    let first = w.run(&[("CI_COMMIT_SHA", "1111111")]);
    assert!(first.contains("recorded"), "{first}");
    let second = w.run(&[("CI_COMMIT_SHA", "2222222")]);
    assert!(skipped(&second), "{second}");
}

#[test]
fn the_recorder_stores_the_names_it_excluded() {
    let w = Ws::new("stored");
    w.run(&[("CI_COMMIT_SHA", "1111111")]);
    assert!(
        w.stored_excluded().contains(&"CI_COMMIT_SHA".to_string()),
        "{:?}",
        w.stored_excluded()
    );
}

#[test]
fn a_behavioural_flag_still_forces_a_rerun() {
    let w = Ws::new("flag");
    w.run(&[("NODE_ENV", "test")]);
    let second = w.run(&[("NODE_ENV", "production")]);
    assert!(!skipped(&second), "{second}");
}

#[test]
fn a_name_the_command_text_mentions_still_counts() {
    let w = Ws::new("mention");
    let script = "cat in.txt > /dev/null; echo $CI_COMMIT_SHA > /dev/null";
    let run = |sha: &str| {
        w.stoop(
            &[("CI_COMMIT_SHA", sha)],
            &["run", "--root", ".", "--key", "v", "--", "sh", "-c", script],
        )
        .1
    };
    run("1111111");
    let second = run("2222222");
    assert!(!skipped(&second), "{second}");
}

#[test]
fn env_forces_a_curated_name_to_count() {
    let w = Ws::new("forced");
    let run = |sha: &str| {
        w.stoop(
            &[("CI_COMMIT_SHA", sha)],
            &[
                "run",
                "--root",
                ".",
                "--key",
                "v",
                "--env",
                "CI_COMMIT_SHA",
                "--",
                "sh",
                "-c",
                SCRIPT,
            ],
        )
        .1
    };
    run("1111111");
    let second = run("2222222");
    assert!(!skipped(&second), "{second}");
}

#[test]
fn explain_names_each_curated_exclusion_with_its_reason() {
    let w = Ws::new("explain");
    let (_, stderr) = w.stoop(
        &[("CI_COMMIT_SHA", "1111111")],
        &[
            "explain", "--root", ".", "--key", "v", "--", "sh", "-c", SCRIPT,
        ],
    );
    assert!(
        stderr.contains("stoop: ignoring env CI_COMMIT_SHA: GitLab per-commit value"),
        "{stderr}"
    );
}

#[test]
fn a_learned_name_is_ignored_from_its_fourth_run_and_skips_on_the_fifth() {
    let w = Ws::new("learn");
    let mut stderrs = Vec::new();
    for i in 0..5 {
        stderrs.push(w.run(&[("SESSION_MARK_LEARN", &opaque(i))]));
    }
    for (i, stderr) in stderrs.iter().enumerate().take(3) {
        assert!(!skipped(stderr), "run {}: {stderr}", i + 1);
    }
    assert!(
        stderrs[3].contains(
            "stoop: ignoring env SESSION_MARK_LEARN: changes on every run (learned after 4 runs)"
        ),
        "{}",
        stderrs[3]
    );
    assert!(skipped(&stderrs[4]), "{}", stderrs[4]);
}

#[test]
fn a_value_that_returns_after_learning_is_counted_again_and_never_learned_again() {
    let w = Ws::new("revoke");
    for i in 0..4 {
        w.run(&[("SESSION_MARK_LEARN", &opaque(i))]);
    }
    let back = w.run(&[("SESSION_MARK_LEARN", &opaque(0))]);
    // The back run may skip: proof 0 recorded this exact value with the same inputs, so that skip
    // is sound. What must hold is that the value counts again, and that fresh values still count.
    assert!(
        back.contains("counting env SESSION_MARK_LEARN again"),
        "{back}"
    );
    for i in 10..14 {
        let stderr = w.run(&[("SESSION_MARK_LEARN", &opaque(i))]);
        assert!(!skipped(&stderr), "{stderr}");
    }
}

#[test]
fn a_repeat_on_a_skipped_run_blocks_learning() {
    // a, b, a (a skip: it matches the first proof), c, d. The repeat of a must be seen, so the
    // name is not learned at d, and a fresh e must still count.
    let w = Ws::new("skip-repeat");
    let a = opaque(0);
    let b = opaque(1);
    let c = opaque(2);
    let d = opaque(3);
    let e = opaque(4);
    let mark = |value: &str| w.run(&[("SESSION_MARK_LEARN", value)]);
    assert!(mark(&a).contains("recorded"));
    assert!(mark(&b).contains("recorded"));
    assert!(
        skipped(&mark(&a)),
        "the repeat must skip against the first proof"
    );
    assert!(mark(&c).contains("recorded"));
    assert!(mark(&d).contains("recorded"));
    let after = mark(&e);
    assert!(!skipped(&after), "a learned name would skip here: {after}");
}

#[test]
fn no_learn_volatile_turns_learning_off() {
    let w = Ws::new("no-learn");
    let run = |i: u64| {
        w.stoop(
            &[("SESSION_MARK_LEARN", &opaque(i))],
            &[
                "run",
                "--root",
                ".",
                "--key",
                "v",
                "--no-learn-volatile",
                "--",
                "sh",
                "-c",
                SCRIPT,
            ],
        )
        .1
    };
    for i in 0..4 {
        run(i);
    }
    assert!(!skipped(&run(4)));
}

#[test]
fn stoop_learn_volatile_zero_turns_learning_off() {
    let w = Ws::new("env-off");
    for i in 0..4 {
        w.run(&[
            ("SESSION_MARK_LEARN", &opaque(i)),
            ("STOOP_LEARN_VOLATILE", "0"),
        ]);
    }
    let fifth = w.run(&[
        ("SESSION_MARK_LEARN", &opaque(4)),
        ("STOOP_LEARN_VOLATILE", "0"),
    ]);
    assert!(!skipped(&fifth), "{fifth}");
}

#[test]
fn forget_volatile_resets_what_was_learned() {
    let w = Ws::new("forget");
    for i in 0..5 {
        w.run(&[("SESSION_MARK_LEARN", &opaque(i))]);
    }
    let (code, stderr) = w.stoop(&[], &["forget", "--volatile", "--root", ".", "v"]);
    assert_eq!(code, 0, "{stderr}");
    let after = w.run(&[("SESSION_MARK_LEARN", &opaque(5))]);
    assert!(!skipped(&after), "{after}");
}

#[test]
fn ls_lists_the_excluded_names_of_each_proof() {
    let w = Ws::new("ls");
    w.run(&[("CI_COMMIT_SHA", "1111111")]);
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args(["ls", "--root", "."])
        .current_dir(w.repo())
        .env("STOOP_STORE", w.store())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ignores CI_COMMIT_SHA"), "{stdout}");
}

#[test]
fn a_damaged_learner_state_warns_and_counts_everything() {
    let w = Ws::new("damaged");
    fs::create_dir_all(w.store()).unwrap();
    fs::write(w.store().join("volatile-v1.json"), b"{not json").unwrap();
    let stderr = w.run(&[("SESSION_MARK_LEARN", &opaque(0))]);
    assert!(stderr.contains("volatile env records"), "{stderr}");
    assert!(stderr.contains("recorded"), "{stderr}");
}

#[test]
fn a_learned_name_whose_value_stops_looking_like_an_id_is_counted_again() {
    let w = Ws::new("plain-after-learning");
    for i in 0..4 {
        w.run(&[("SESSION_MARK_LEARN", &opaque(i))]);
    }
    let plain = w.run(&[("SESSION_MARK_LEARN", "production")]);
    assert!(!skipped(&plain), "{plain}");
    assert!(
        plain.contains("counting env SESSION_MARK_LEARN again"),
        "{plain}"
    );
}

#[test]
fn an_unset_learned_name_counts() {
    let w = Ws::new("unset-after-learning");
    for i in 0..4 {
        w.run(&[("SESSION_MARK_LEARN", &opaque(i))]);
    }
    let unset = w.run(&[]);
    assert!(!skipped(&unset), "{unset}");
}

#[test]
fn forgetting_the_learning_stops_an_old_exclusion_from_matching() {
    let w = Ws::new("forget-exclusion");
    for i in 0..4 {
        w.run(&[("SESSION_MARK_LEARN", &opaque(i))]);
    }
    let (code, stderr) = w.stoop(&[], &["forget", "--volatile", "--root", ".", "v"]);
    assert_eq!(code, 0, "{stderr}");
    let after = w.run(&[]);
    assert!(!skipped(&after), "{after}");
}

#[test]
fn source_date_epoch_is_never_learned() {
    let w = Ws::new("epoch");
    for i in 0..6u64 {
        let stderr = w.run(&[("SOURCE_DATE_EPOCH", &format!("{}", 1_700_000_000 + i))]);
        assert!(!skipped(&stderr), "run {}: {stderr}", i + 1);
    }
}

#[test]
fn build_number_counts_outside_its_provider() {
    let w = Ws::new("build-number");
    w.run(&[("BUILD_NUMBER", "101")]);
    let second = w.run(&[("BUILD_NUMBER", "102")]);
    assert!(!skipped(&second), "{second}");
}

#[test]
fn build_number_is_excluded_under_jenkins() {
    let w = Ws::new("build-number-jenkins");
    w.run(&[
        ("BUILD_NUMBER", "101"),
        ("JENKINS_URL", "https://ci.example/"),
    ]);
    let second = w.run(&[
        ("BUILD_NUMBER", "102"),
        ("JENKINS_URL", "https://ci.example/"),
    ]);
    assert!(skipped(&second), "{second}");
}
