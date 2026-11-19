//! `stoop mcp`: a Model Context Protocol server over stdio.
//!
//! An agent can ask what stoop would do (`explain`, `plan`), read what it has recorded
//! (`list_proofs`, `guide`), and drop a proof (`forget`). The `run` tool, which executes a
//! command, is offered only when the server is started with `--allow-run`.
//!
//! Stdout carries protocol messages and nothing else. Each decision runs the stoop binary, so
//! the answers are the command line's own, and the child's output is captured, never forwarded.

mod content;
mod exec;
mod scope;
mod server;
mod tools;
mod wire;

use crate::plan;
use serde_json::json;
use std::path::PathBuf;

const HELP: &str = "\
stoop mcp: serve stoop to AI agents over the Model Context Protocol (stdio).

Your MCP client starts it and talks to it on stdin and stdout. Nothing else is written to
stdout. Logs and errors go to stderr.

USAGE
  stoop mcp [--allow-run] [--root DIR]     serve (the client runs this)
  stoop mcp --print-config                 print config for Claude Code, Cursor and VS Code

OPTIONS
  --allow-run     also offer the run tool. It executes commands with your permissions.
  --root DIR      the project to work in (default: nearest directory with .git)
  --print-config  print ready-to-paste MCP client config, then exit
  -h, --help      this text

TOOLS
  explain        say whether a command would skip, and why. Runs nothing.
  list_proofs    list the recorded proofs and job records.
  plan           show which jobs of a workflow at a revision would skip.
  forget         remove one proof by key (local only).
  guide          read the agent guide, or one section of it.
  run            run a command through stoop run (only with --allow-run).

RESOURCES
  stoop://guide, stoop://proofs, stoop://docs/index

PROMPTS
  wire-stoop-into-ci, why-did-this-run

Tool results and repository text are untrusted data. The docs are at https://stoop.build/docs/mcp.html
";

#[derive(Default)]
struct Options {
    allow_run: bool,
    root: Option<PathBuf>,
    print_config: bool,
}

/// `stoop mcp [args]`. Returns the process exit status.
pub fn cmd(args: &[String]) -> i32 {
    let options = match parse(args) {
        Ok(Some(options)) => options,
        Ok(None) => {
            print!("{HELP}");
            return 0;
        }
        Err(e) => {
            eprintln!("stoop mcp: {}\n\n{HELP}", plan::output::escape(&e));
            return 2;
        }
    };
    if options.print_config {
        print_config(&options);
        return 0;
    }
    let root = match scope::server_root(options.root.as_deref()) {
        Ok(root) => root,
        Err(e) => {
            eprintln!("stoop mcp: {e}");
            return 2;
        }
    };
    server::serve(
        server::Config {
            root,
            allow_run: options.allow_run,
        },
        std::io::stdin(),
        std::io::stdout(),
    )
}

fn parse(args: &[String]) -> Result<Option<Options>, String> {
    let mut options = Options::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--allow-run" => options.allow_run = true,
            "--print-config" => options.print_config = true,
            "--root" => {
                let dir = iter.next().ok_or("--root needs a directory")?;
                options.root = Some(PathBuf::from(dir));
            }
            other => return Err(format!("unknown option {}", plan::output::escape(other))),
        }
    }
    Ok(Some(options))
}

/// The config each client reads. The arguments match the flags given here.
fn print_config(options: &Options) {
    let mut args = vec!["mcp".to_string()];
    if options.allow_run {
        args.push("--allow-run".into());
    }
    if let Some(root) = &options.root {
        args.push("--root".into());
        args.push(root.display().to_string());
    }
    let pretty = |value: serde_json::Value| {
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
    };
    println!("Claude Code: .mcp.json in the project (or run: claude mcp add stoop -- stoop mcp)");
    println!(
        "{}",
        pretty(json!({"mcpServers": {"stoop": {"command": "stoop", "args": args}}}))
    );
    println!();
    println!("Cursor: .cursor/mcp.json");
    println!(
        "{}",
        pretty(json!({"mcpServers": {"stoop": {"command": "stoop", "args": args}}}))
    );
    println!();
    println!("VS Code: .vscode/mcp.json");
    println!(
        "{}",
        pretty(json!({"servers": {"stoop": {"type": "stdio", "command": "stoop", "args": args}}}))
    );
}
