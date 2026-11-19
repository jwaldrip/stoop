#![cfg(unix)]
//! The shared agent guide (site/static/AGENTS.md) cannot drift from the binary or the site:
//! the server embeds that exact file, and every command, flag and link it names must exist.

mod common;

use common::*;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn guide_file() -> String {
    std::fs::read_to_string(repo_path("site/static/AGENTS.md"))
        .expect("site/static/AGENTS.md exists and is UTF-8")
}

/// Stdout of a stoop invocation. Help text is printed to stdout.
fn help(args: &[&str]) -> String {
    let dir = temp_dir("drift-help");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
    cmd.args(args).current_dir(&dir);
    clear_env(&mut cmd);
    let out = cmd.output().expect("stoop runs");
    assert!(out.status.success(), "stoop {args:?} failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Every `--flag` token in `text`, without trailing hyphens.
fn flags(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter_map(|token| token.strip_prefix("--"))
        .filter(|name| name.starts_with(|c: char| c.is_ascii_lowercase()))
        .map(|name| format!("--{}", name.trim_end_matches('-')))
        .collect()
}

/// The `stoop <command>` words the guide names, for the words that are commands.
fn commands(text: &str) -> BTreeSet<String> {
    const COMMANDS: [&str; 9] = [
        "run", "explain", "sh", "ls", "forget", "pull", "prune", "plan", "mcp",
    ];
    let mut found = BTreeSet::new();
    for (index, _) in text.match_indices("stoop ") {
        let word: String = text[index + 6..]
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || *c == '-')
            .collect();
        if COMMANDS.contains(&word.as_str()) {
            found.insert(word);
        }
    }
    found
}

/// Every absolute stoop.build link in the guide, without trailing punctuation.
fn site_links(text: &str) -> BTreeSet<String> {
    text.match_indices("https://stoop.build/")
        .map(|(index, _)| {
            let rest = &text[index..];
            let end = rest
                .find(|c: char| c.is_whitespace() || "\")'`<>]".contains(c))
                .unwrap_or(rest.len());
            rest[..end]
                .trim_end_matches(['.', ',', ';', ':'])
                .to_string()
        })
        .collect()
}

/// Where the built site gets a stoop.build path from: pages/, install.sh or static/.
fn site_source(url: &str) -> PathBuf {
    let path = url
        .trim_start_matches("https://stoop.build/")
        .split(['#', '?'])
        .next()
        .unwrap();
    let site = repo_path("site");
    if path.is_empty() {
        return site.join("pages/index.html");
    }
    if path.ends_with(".html") {
        return site.join("pages").join(path);
    }
    if path == "install.sh" {
        return site.join("install.sh");
    }
    site.join("static").join(path)
}

#[test]
fn the_embedded_guide_is_the_shared_static_file() {
    let dir = temp_dir("drift-embedded");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "resources/read",
        modern(json!({"uri": "stoop://guide"})),
    );
    let text = result(&r)["contents"][0]["text"].as_str().unwrap();
    assert_eq!(
        text,
        guide_file(),
        "the server serves a different guide than site/static/AGENTS.md"
    );
    m.finish();
}

#[test]
fn the_guide_tool_returns_every_heading_of_the_shared_file() {
    let dir = temp_dir("drift-sections");
    let mut m = Mcp::spawn(&[], &dir);
    let g = m.call(
        json!(1),
        "tools/call",
        modern(tool_call("guide", json!({}))),
    );
    let joined: String = result(&g)["structuredContent"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["markdown"].as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let guide = guide_file();
    let headings: Vec<&str> = guide.lines().filter(|l| l.starts_with("## ")).collect();
    assert!(!headings.is_empty());
    for heading in headings {
        assert!(
            joined.contains(heading),
            "the guide tool lost the heading {heading:?}"
        );
    }
    m.finish();
}

#[test]
fn every_command_and_flag_the_guide_names_exists_in_the_help() {
    let guide = guide_file();
    let known = format!(
        "{}\n{}\n{}",
        help(&["--help"]),
        help(&["mcp", "--help"]),
        help(&["plan", "--help"])
    );
    for command in commands(&guide) {
        assert!(
            known.contains(&format!("stoop {command}")) || known.contains(&format!("| {command}")),
            "the guide names `stoop {command}`, which no help text lists"
        );
    }
    for flag in flags(&guide) {
        assert!(
            known.contains(&flag),
            "the guide names {flag}, which no help text shows"
        );
    }
}

#[test]
fn every_link_the_guide_makes_exists_in_the_site_source() {
    let links = site_links(&guide_file());
    assert!(!links.is_empty(), "the guide links nothing on the site");
    for link in links {
        let source = site_source(&link);
        assert!(
            source.is_file(),
            "{link} has no source at {}",
            source.display()
        );
    }
}

#[test]
fn the_docs_index_lists_exactly_the_docs_pages_the_site_builds() {
    let build = std::fs::read_to_string(repo_path("site/build.mjs")).expect("site/build.mjs");
    let block = build
        .split("const DOCS = [")
        .nth(1)
        .and_then(|rest| rest.split("];").next())
        .expect("site/build.mjs declares DOCS");
    let built: Vec<&str> = block
        .lines()
        .filter_map(|line| line.trim().strip_prefix("[\"")?.split('"').next())
        .collect();
    let dir = temp_dir("drift-docs-index");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "resources/read",
        modern(json!({"uri": "stoop://docs/index"})),
    );
    let text = result(&r)["contents"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    let listed: Vec<&str> = text
        .lines()
        .filter_map(|line| line.split("https://stoop.build/docs/").nth(1))
        .filter_map(|tail| tail.strip_suffix(".html)"))
        .collect();
    assert_eq!(
        listed, built,
        "stoop://docs/index and site/build.mjs DOCS disagree"
    );
    m.finish();
}

#[test]
fn the_mcp_docs_page_is_in_the_site_build() {
    let build = std::fs::read_to_string(repo_path("site/build.mjs")).expect("site/build.mjs");
    assert!(
        build.contains("[\"mcp\""),
        "site/build.mjs does not list the mcp docs page"
    );
    assert!(repo_path("site/pages/docs/mcp.html").is_file());
}
