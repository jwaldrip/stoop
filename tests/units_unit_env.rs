//! A suite's unit-only environment, exercised through the traced CLI.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use std::fs;
use std::process::Output;
use units_common::*;

const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");
const CACHE: (&str, &str) = ("T_CACHE", ".tcache");
const OVERLAY: &str = "unit_env = { T_CACHE = '/dev/null/t' }";

fn setup(overlay: Option<&str>, ignore_cache: bool) -> Suite {
    let s = Suite::new();
    fs::create_dir(s.path(".tcache")).unwrap();
    let cache_rule = if ignore_cache { ".tcache\n" } else { "" };
    s.write(
        ".stoopignore",
        &format!(".stoop.toml\n.stoopignore\n{cache_rule}"),
    );
    if let Some(overlay) = overlay {
        s.config(&format!(
            "[[units.suite]]\nid = 'tests'\nmatch = ['./t', '{HOOK}']\n{overlay}\n"
        ));
    }
    s
}

fn run(s: &Suite, extra: &[(&str, &str)]) -> Output {
    let mut env = vec![SPLIT, CACHE];
    env.extend_from_slice(extra);
    s.hook(&env)
}

fn ok(out: &Output) {
    assert_eq!(code(out), 0, "{}", text(&out.stderr));
    assert!(
        !text(&out.stderr).contains("ignoring the unit configuration"),
        "{}",
        text(&out.stderr)
    );
}

fn launches(s: &Suite) -> Vec<Vec<String>> {
    s.launches().into_iter().map(|launch| launch.args).collect()
}

fn unit_count(s: &Suite) -> usize {
    s.bundle().unwrap()["units"].as_object().unwrap().len()
}

fn cache_values(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .map(|launch| {
            launch
                .lines
                .iter()
                .find_map(|line| line.strip_prefix("cache="))
                .expect("cache line")
                .to_owned()
        })
        .collect()
}

fn config_overlay(s: &Suite, overlay: &str) {
    s.config(&format!(
        "[[units.suite]]\nid = 'tests'\nmatch = ['./t', '{HOOK}']\n{overlay}\n"
    ));
}

fn assert_full_and_all_units(s: &Suite, out: &Output) {
    ok(out);
    assert_eq!(
        launches(s),
        [
            vec![],
            vec!["tests/a.t"],
            vec!["tests/b.t"],
            vec!["tests/c.t"]
        ],
        "{}",
        text(&out.stderr)
    );
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["residue"]["state"], "confirmed", "{bundle}");
    assert_eq!(bundle["residue"]["count"], 0, "{bundle}");
}

const FIT_REASON: &str = "the unit launch environment does not fit on the command line";

fn large_overlay() -> String {
    let entries = (0..8)
        .map(|index| format!("UNIT_PAD_{index} = '{}'", "u".repeat(4000)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("unit_env = {{ {entries} }}")
}

fn fit_run(s: &Suite, split: bool, group: bool, small_stack: bool, explain: bool) -> Output {
    fit_run_with_padding(s, split, group, small_stack, explain, 56_000)
}

fn fit_run_with_padding(
    s: &Suite,
    split: bool,
    group: bool,
    small_stack: bool,
    explain: bool,
    padding: usize,
) -> Output {
    use std::os::unix::process::CommandExt;
    let mut command = s.stoop(&s.root);
    command
        .arg(if explain { "explain" } else { "run" })
        .arg("--root")
        .arg(&s.root)
        .args(["--", "./t", HOOK])
        .env("STOOP_SPLIT", if split { "1" } else { "0" })
        .env("STOOP_SPLIT_GROUP", if group { "1" } else { "0" })
        .env("RUNNER_PAD_A", "e".repeat(padding))
        .env("RUNNER_PAD_B", "e".repeat(padding));
    if small_stack {
        unsafe {
            command.pre_exec(|| {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_STACK, &mut limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                limit.rlim_cur = limit.rlim_cur.min(512 * 1024);
                if libc::setrlimit(libc::RLIMIT_STACK, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    spawning(|| command.output()).unwrap()
}

#[test]
fn test_rvw_valid_overlay_overfills_singleton_aggregate_environment() {
    let s = setup(Some(&large_overlay()), true);
    ok(&fit_run(&s, false, false, true, false));
    s.write("src/shared.src", "changed\n");
    let explained = fit_run(&s, false, false, true, true);
    assert!(
        text(&explained.stderr).contains(FIT_REASON),
        "{}",
        text(&explained.stderr)
    );
    s.clear_log();
    let out = fit_run(&s, false, false, true, false);
    ok(&out);
    assert_eq!(
        launches(&s),
        [Vec::<String>::new()],
        "{}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains(FIT_REASON),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(code(&s.direct(&s.root, &[], &[])), 0);

    let no_overlay = setup(Some(""), true);
    ok(&fit_run(&no_overlay, false, false, true, false));
    no_overlay.write("src/shared.src", "changed\n");
    no_overlay.clear_log();
    let control = fit_run(&no_overlay, false, false, true, false);
    ok(&control);
    assert_eq!(
        launches(&no_overlay),
        [vec!["tests/a.t"], vec!["tests/b.t"], vec!["tests/c.t"]],
        "{}",
        text(&control.stderr)
    );
    assert!(!text(&control.stderr).contains(FIT_REASON));
}

#[test]
fn uenv_singleton_fit_excludes_overridden_inherited_values() {
    let s = setup(
        Some("unit_env = { RUNNER_PAD_A = 'a', RUNNER_PAD_B = 'b' }"),
        true,
    );
    let out = fit_run(&s, true, false, true, false);
    assert_full_and_all_units(&s, &out);
    assert!(!text(&out.stderr).contains(FIT_REASON));
}

#[test]
fn uenv_subset_fit_checks_the_actual_inherited_environment() {
    let s = setup(Some(&large_overlay()), true);
    ok(&fit_run(&s, true, false, false, false));
    assert_eq!(unit_count(&s), 3);
    s.write("src/shared.src", "changed\n");
    let explained = fit_run(&s, true, false, true, true);
    assert!(
        text(&explained.stderr).contains(FIT_REASON),
        "{}",
        text(&explained.stderr)
    );
    s.clear_log();
    let out = fit_run(&s, true, false, true, false);
    ok(&out);
    assert_eq!(
        launches(&s),
        [Vec::<String>::new()],
        "{}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains(FIT_REASON),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(s.bundle().unwrap()["residue"]["state"], "none");
}

#[test]
fn uenv_completion_fit_keeps_full_status_and_unknown_residue() {
    let s = setup(Some(&large_overlay()), true);
    let out = fit_run(&s, true, false, true, false);
    ok(&out);
    assert_eq!(
        launches(&s),
        [Vec::<String>::new()],
        "{}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains(FIT_REASON),
        "{}",
        text(&out.stderr)
    );
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["residue"]["state"], "none", "{bundle}");
    assert!(bundle["units"].as_object().unwrap().is_empty(), "{bundle}");
    s.write("src/shared.src", "changed\n");
    let explained = fit_run(&s, true, false, true, true);
    assert!(
        text(&explained.stderr).contains(FIT_REASON),
        "{}",
        text(&explained.stderr)
    );
}

#[test]
fn uenv_grouped_fit_uses_the_same_effective_environment() {
    let s = setup(Some(&large_overlay()), true);
    ok(&fit_run(&s, true, true, false, false));
    assert_eq!(unit_count(&s), 3);
    s.write("src/shared.src", "changed\n");
    let explained = fit_run(&s, true, true, true, true);
    assert!(
        text(&explained.stderr).contains("do not fit on the command line"),
        "{}",
        text(&explained.stderr)
    );
    s.clear_log();
    let out = fit_run(&s, true, true, true, false);
    ok(&out);
    assert_eq!(
        launches(&s),
        [Vec::<String>::new()],
        "{}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("do not fit on the command line"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn test_rvw_unit_env_name_must_fit_a_linux_environment_entry() {
    let overlay = format!("unit_env = {{ {} = 'x' }}", "A".repeat(131_072));
    let s = setup(Some(&overlay), true);
    let first = s.hook(&[]);
    assert_eq!(code(&first), 0, "{}", text(&first.stderr));
    assert!(
        text(&first.stderr).contains("unit_env names hold at most 255 bytes"),
        "{}",
        text(&first.stderr)
    );
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = s.hook(&[]);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("unit_env names hold at most 255 bytes"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(
        launches(&s),
        [Vec::<String>::new()],
        "{}",
        text(&out.stderr)
    );
    assert!(!text(&out.stderr).contains("attribution pass"));
    let direct = s.direct(&s.root, &[], &[]);
    assert_eq!(code(&direct), 0, "{}", text(&direct.stderr));
}

#[test]
fn uenv_adding_an_overlay_relearns_versions_written_without_one() {
    let s = setup(Some(""), true);
    ok(&s.hook(&[SPLIT]));
    assert_eq!(s.bundle().unwrap()["residue"]["state"], "confirmed");
    config_overlay(&s, "unit_env = { MODE = 'pass' }");
    s.clear_log();
    let out = s.hook(&[SPLIT]);
    assert_full_and_all_units(&s, &out);
}

#[test]
fn uenv_removing_an_overlay_relearns_versions_written_with_one() {
    let s = setup(Some("unit_env = { MODE = 'pass' }"), true);
    ok(&s.hook(&[SPLIT]));
    assert_eq!(s.bundle().unwrap()["residue"]["state"], "confirmed");
    config_overlay(&s, "");
    s.clear_log();
    let out = s.hook(&[SPLIT]);
    assert_full_and_all_units(&s, &out);
    let bundle = s.bundle().unwrap();
    assert!(bundle["guard"].get("unit_env").is_none());
    for versions in bundle["units"].as_object().unwrap().values() {
        assert!(versions[0].get("unit_env").is_none(), "{versions}");
    }
}

#[test]
fn uenv_mixed_version_stamps_relearn_only_the_stale_unit() {
    let s = setup(Some("unit_env = { MODE = 'pass' }"), true);
    ok(&s.hook(&[SPLIT]));
    let mut bundle = s.bundle().unwrap();
    bundle["units"]["tests/b.t"][0]["unit_env"] = "older overlay".into();
    fs::write(
        s.bundle_path().unwrap(),
        serde_json::to_vec(&bundle).unwrap(),
    )
    .unwrap();
    s.clear_log();
    let out = s.hook(&[SPLIT, ("STOOP_FULL", "1")]);
    ok(&out);
    assert_eq!(
        launches(&s),
        [vec![], vec!["tests/b.t"]],
        "{}",
        text(&out.stderr)
    );
    let after = s.bundle().unwrap();
    assert_eq!(after["residue"]["state"], "confirmed", "{after}");
    assert_eq!(
        after["units"]["tests/b.t"][0]["unit_env"],
        after["guard"]["unit_env"]
    );
}

#[test]
fn uenv_switch_off_cannot_keep_a_residue_from_the_old_overlay() {
    let s = setup(Some("unit_env = { MODE = 'old' }"), true);
    ok(&s.hook(&[SPLIT]));
    assert_eq!(s.bundle().unwrap()["residue"]["state"], "confirmed");
    config_overlay(&s, "unit_env = { MODE = 'new' }");
    s.clear_log();
    ok(&s.hook(&[]));
    assert_eq!(s.bundle().unwrap()["residue"]["state"], "none");
    s.clear_log();
    let cached = s.hook(&[SPLIT]);
    ok(&cached);
    assert!(launches(&s).is_empty(), "{}", text(&cached.stderr));
    s.clear_log();
    let out = s.hook(&[SPLIT, ("STOOP_FULL", "1")]);
    assert_full_and_all_units(&s, &out);
}

#[test]
fn uenv_u0_a_cached_test_without_unit_env_is_never_evidence() {
    let s = setup(None, true);
    ok(&s.hook(&[CACHE]));
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = s.hook(&[CACHE]);
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["state"]["status"], "disabled", "{bundle}");
    assert_eq!(unit_count(&s), 0);
    assert!(
        text(&out.stderr).contains("never read"),
        "{}",
        text(&out.stderr)
    );
    assert!(s.launches()[0]
        .lines
        .iter()
        .any(|line| line.starts_with("cache_hit=")));
}

#[test]
fn uenv_u1_completion_reads_each_test_under_unit_env() {
    let s = setup(Some(OVERLAY), true);
    let out = run(&s, &[]);
    ok(&out);
    assert_eq!(unit_count(&s), 3, "{}", text(&out.stderr));
    assert_eq!(
        launches(&s),
        [
            vec![],
            vec!["tests/a.t"],
            vec!["tests/b.t"],
            vec!["tests/c.t"]
        ]
    );
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["residue"]["state"], "confirmed", "{bundle}");
    assert_eq!(bundle["residue"]["count"], 0, "{bundle}");
}

#[test]
fn uenv_u2_the_full_command_never_sees_unit_env() {
    let s = setup(Some(OVERLAY), true);
    ok(&run(&s, &[]));
    assert_eq!(
        cache_values(&s),
        [".tcache", "/dev/null/t", "/dev/null/t", "/dev/null/t"]
    );
    s.clear_log();
    ok(&run(&s, &[("STOOP_FULL", "1")]));
    assert_eq!(cache_values(&s)[0], ".tcache");
}

#[test]
fn uenv_u3_a_subset_launch_reads_its_test_under_unit_env() {
    let s = setup(Some(OVERLAY), true);
    ok(&run(&s, &[]));
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = run(&s, &[]);
    ok(&out);
    assert_eq!(
        launches(&s),
        [vec!["tests/a.t"], vec!["tests/b.t"]],
        "{}",
        text(&out.stderr)
    );
    assert_eq!(cache_values(&s), ["/dev/null/t", "/dev/null/t"]);
    assert!(!text(&out.stderr).contains("the environment changed since the last full run"));
    assert_eq!(unit_count(&s), 3);
}

#[test]
fn uenv_u4_switch_off_attribution_and_switch_on_completion_share_unit_env() {
    let s = setup(Some(OVERLAY), true);
    ok(&s.hook(&[CACHE]));
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    ok(&s.hook(&[CACHE]));
    assert_eq!(unit_count(&s), 3);
    assert_eq!(
        cache_values(&s),
        ["/dev/null/t", "/dev/null/t", "/dev/null/t"]
    );
    s.write("tests/d.t", "src/c.src\n");
    s.clear_log();
    let completed = run(&s, &[]);
    ok(&completed);
    assert_eq!(
        launches(&s),
        [vec![], vec!["tests/d.t"]],
        "{}",
        text(&completed.stderr)
    );
    assert_eq!(cache_values(&s), [".tcache", "/dev/null/t"]);
    assert_eq!(unit_count(&s), 4);
    s.write("src/shared.src", "changed again\n");
    s.clear_log();
    let out = run(&s, &[]);
    ok(&out);
    assert_eq!(
        launches(&s),
        [vec!["tests/a.t"], vec!["tests/b.t"]],
        "{}",
        text(&out.stderr)
    );
    assert_eq!(cache_values(&s), ["/dev/null/t", "/dev/null/t"]);
}

#[test]
fn uenv_u5_changing_unit_env_retires_every_proof() {
    let s = setup(Some(OVERLAY), true);
    ok(&run(&s, &[]));
    s.clear_log();
    let unchanged = run(&s, &[]);
    ok(&unchanged);
    assert!(launches(&s).is_empty(), "{}", text(&unchanged.stderr));
    let before = s.bundle().unwrap();
    let old_guard = before["guard_digest"].as_str().unwrap().to_owned();
    s.config(&format!(
        "[[units.suite]]\nid = 'tests'\nmatch = ['./t', '{HOOK}']\n{OVERLAY}\n# harmless config edit\n"
    ));
    s.clear_log();
    let control = run(&s, &[]);
    ok(&control);
    assert_eq!(
        launches(&s),
        [Vec::<String>::new()],
        "{}",
        text(&control.stderr)
    );
    let preserved = s.bundle().unwrap();
    assert_ne!(before["whole_key_digest"], preserved["whole_key_digest"]);
    assert_eq!(before["guard_digest"], preserved["guard_digest"]);
    assert_eq!(before["units"], preserved["units"]);

    s.config(&format!(
        "[[units.suite]]\nid = 'tests'\nmatch = ['./t', '{HOOK}']\nunit_env = {{ T_CACHE = '/dev/null/t', MODE = 'pass' }}\n"
    ));
    s.clear_log();
    let out = run(&s, &[]);
    ok(&out);
    assert_eq!(
        launches(&s),
        [
            vec![],
            vec!["tests/a.t"],
            vec!["tests/b.t"],
            vec!["tests/c.t"]
        ],
        "{}",
        text(&out.stderr)
    );
    let after = s.bundle().unwrap();
    assert_ne!(after["guard_digest"], old_guard);
    assert_ne!(before["guard"]["unit_env"], after["guard"]["unit_env"]);
    assert_eq!(after["residue"]["state"], "confirmed", "{after}");
    assert_eq!(after["residue"]["count"], 0, "{after}");
    for versions in after["units"].as_object().unwrap().values() {
        assert!(
            versions
                .as_array()
                .unwrap()
                .iter()
                .any(|version| version["guard"] == after["guard_digest"]
                    && version["unit_env"] == after["guard"]["unit_env"]),
            "{versions}"
        );
    }
}

#[test]
fn uenv_u6_a_grouped_launch_runs_under_unit_env() {
    let s = setup(Some(OVERLAY), true);
    ok(&run(&s, &[("STOOP_SPLIT_GROUP", "1")]));
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = run(&s, &[("STOOP_SPLIT_GROUP", "1")]);
    ok(&out);
    assert_eq!(
        launches(&s),
        [vec!["tests/a.t", "tests/b.t"]],
        "{}",
        text(&out.stderr)
    );
    assert_eq!(cache_values(&s), ["/dev/null/t"]);
    let bundle = s.bundle().unwrap();
    for unit in ["tests/a.t", "tests/b.t"] {
        assert!(
            bundle["units"][unit]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["exact"] == false),
            "{bundle}"
        );
    }
}

#[test]
fn uenv_u7_an_unignored_cache_is_named_as_residue() {
    let s = setup(Some(OVERLAY), false);
    ok(&run(&s, &[]));
    s.clear_log();
    ok(&run(&s, &[("STOOP_FULL", "1")]));
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["residue"]["state"], "confirmed", "{bundle}");
    assert!(bundle["residue"]["count"].as_u64().unwrap() > 0, "{bundle}");
    assert!(
        bundle["residue"]["paths"].to_string().contains(".tcache/"),
        "{bundle}"
    );
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = run(&s, &[]);
    ok(&out);
    assert_eq!(launches(&s).first(), Some(&vec![]), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains(".tcache/"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn uenv_u8_cache_paths_of_the_full_command_are_not_residue() {
    let s = setup(Some(OVERLAY), true);
    ok(&run(&s, &[]));
    ok(&run(&s, &[("STOOP_FULL", "1")]));
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["residue"]["state"], "confirmed", "{bundle}");
    assert_eq!(bundle["residue"]["count"], 0, "{bundle}");
    assert!(!bundle["residue"]["paths"].to_string().contains(".tcache/"));
}

#[test]
fn uenv_u9_a_unit_env_variable_a_test_reads_is_the_documented_premise() {
    let s = setup(
        Some("unit_env = { T_CACHE = '/dev/null/t', MODE = 'pass' }"),
        true,
    );
    let mode = [("MODE", "fail")];
    ok(&run(&s, &mode));
    s.write("tests/a.t", "src/shared.src\nenv:MODE\n");
    s.clear_log();
    let subset = run(&s, &mode);
    ok(&subset);
    assert_eq!(
        launches(&s),
        [vec!["tests/a.t"]],
        "{}",
        text(&subset.stderr)
    );
    let direct = s.direct(&s.root, &[], &[CACHE, mode[0]]);
    assert_eq!(code(&direct), 1, "{}", text(&direct.stderr));
    let forced = run(&s, &[("MODE", "fail"), ("STOOP_FULL", "1")]);
    assert_eq!(code(&forced), 1, "{}", text(&forced.stderr));
    assert_eq!(s.bundle().unwrap()["state"]["status"], "disabled");
}

#[test]
fn uenv_f1_unit_env_counts_toward_the_grouped_fit() {
    let s = setup(Some(&large_overlay()), true);
    ok(&fit_run_with_padding(&s, true, true, false, false, 20_000));
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = fit_run_with_padding(&s, true, true, true, false, 20_000);
    ok(&out);
    assert!(
        text(&out.stderr).contains("do not fit on the command line"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(launches(&s).first(), Some(&vec![]), "{}", text(&out.stderr));
}

#[test]
fn uenv_f1_replacing_large_inherited_values_allows_grouping() {
    // Bound the child's stack so Linux's ARG_MAX leaves room for at most 31 overridden names.
    const CHILD: &str = "STOOP_UENV_FIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "uenv_f1_replacing_large_inherited_values_allows_grouping",
            ])
            .env(CHILD, "1");
        unsafe {
            child.pre_exec(|| {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_STACK, &mut limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                limit.rlim_cur = limit.rlim_cur.min(8 * 1024 * 1024);
                if libc::setrlimit(libc::RLIMIT_STACK, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = child.output().unwrap();
        assert!(
            out.status.success() && text(&out.stdout).contains("1 passed"),
            "{}\n{}",
            text(&out.stdout),
            text(&out.stderr)
        );
        return;
    }
    let limit = unsafe { libc::sysconf(libc::_SC_ARG_MAX) } as usize / 2;
    assert!(
        limit > 150_000 && limit < 1_700_000,
        "unexpected ARG_MAX: {limit}"
    );
    let mut padding = Vec::new();
    let mut remaining = limit + 65_536;
    while remaining > 0 {
        let len = remaining.min(60_000);
        padding.push((format!("OVERRIDE_{}", padding.len()), "p".repeat(len)));
        remaining -= len;
    }
    assert!(padding.len() <= 31);
    let mut fields = vec!["T_CACHE = '/dev/null/t'".to_owned()];
    fields.extend(padding.iter().map(|(name, _)| format!("{name} = 'small'")));
    let s = setup(
        Some(&format!("unit_env = {{ {} }}", fields.join(", "))),
        true,
    );
    let mut env = vec![SPLIT, CACHE, ("STOOP_SPLIT_GROUP", "1")];
    env.extend(
        padding
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    ok(&s.hook(&env));
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = s.hook(&env);
    ok(&out);
    assert_eq!(
        launches(&s),
        [vec!["tests/a.t", "tests/b.t"]],
        "{}",
        text(&out.stderr)
    );
    assert_eq!(cache_values(&s), ["/dev/null/t"]);
}

#[test]
fn uenv_c2_an_empty_unit_env_writes_mains_guard() {
    let s = setup(None, true);
    ok(&s.hook(&[SPLIT]));
    let before = s.bundle().unwrap();
    s.config(&format!(
        "[[units.suite]]\nid = 'tests'\nmatch = ['./t', '{HOOK}']\nunit_env = {{}}\n"
    ));
    let out = s.hook(&[SPLIT, ("STOOP_FULL", "1")]);
    ok(&out);
    let after = s.bundle().unwrap();
    assert_eq!(before["guard"], after["guard"]);
    assert_eq!(before["guard_digest"], after["guard_digest"]);
    assert!(after["guard"].get("unit_env").is_none(), "{after}");
}
