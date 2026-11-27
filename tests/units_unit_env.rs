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
    for versions in after["units"].as_object().unwrap().values() {
        assert!(
            versions
                .as_array()
                .unwrap()
                .iter()
                .any(|version| version["guard"] == after["guard_digest"]),
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
    let mut fields = vec!["T_CACHE = '/dev/null/t'".to_owned()];
    fields.extend((0..31).map(|n| format!("OVERLAY_{n} = '{}'", "x".repeat(4096))));
    let s = setup(
        Some(&format!("unit_env = {{ {} }}", fields.join(", "))),
        true,
    );
    let limit = unsafe { libc::sysconf(libc::_SC_ARG_MAX) } as usize / 2;
    assert!(
        limit > 150_000 && limit < 8_000_000,
        "unexpected ARG_MAX: {limit}"
    );
    let target = limit - 65_536;
    let mut padding = Vec::new();
    let mut remaining = target.saturating_sub(4096);
    while remaining > 0 {
        let len = remaining.min(60_000);
        padding.push((format!("PADDING_{}", padding.len()), "p".repeat(len)));
        remaining -= len;
    }
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
    assert!(
        text(&out.stderr).contains("do not fit on the command line"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(launches(&s).first(), Some(&vec![]), "{}", text(&out.stderr));
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
