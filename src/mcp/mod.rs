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
use std::ffi::OsString;
use std::path::PathBuf;

const HELP: &str = "\
stoop mcp: serve stoop to AI agents over the Model Context Protocol (stdio).

Your MCP client starts it and talks to it on stdin and stdout. Nothing else is written to
stdout. Logs and errors go to stderr.

USAGE
  stoop mcp [--allow-run] [--root DIR]     serve (the client runs this)
  stoop mcp --print-config [options]       print the config for each client, then exit

OPTIONS
  --allow-run     also offer the run tool. It executes commands with your permissions.
  --root DIR      the project to work in. Default: the nearest directory with .git.
                  Outside a repository the server refuses to start without --root.
  --print-config  print the config for each client, with the flags you gave, and exit
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
pub fn cmd(args: &[OsString]) -> i32 {
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
        return print_config(&options);
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

fn parse(args: &[OsString]) -> Result<Option<Options>, String> {
    let mut options = Options::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("-h") | Some("--help") => return Ok(None),
            Some("--allow-run") => options.allow_run = true,
            Some("--print-config") => options.print_config = true,
            Some("--root") => {
                let dir = iter.next().ok_or("--root needs a directory")?;
                options.root = Some(PathBuf::from(dir));
            }
            _ => {
                return Err(format!(
                    "unknown option {}",
                    plan::output::escape(&arg.to_string_lossy())
                ))
            }
        }
    }
    Ok(Some(options))
}

/// A word a POSIX shell reads back unchanged.
fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// The entry the GitHub Copilot CLI reads from `~/.copilot/mcp-config.json`. The CLI documents a
/// server type and a tools list, where `*` enables every tool, so this entry carries both.
fn copilot_config(args: &[String]) -> serde_json::Value {
    json!({"mcpServers": {"stoop": {"type": "local", "command": "stoop", "args": args, "tools": ["*"]}}})
}

/// The config each client reads. Claude Code and VS Code read `.mcp.json`, and Cursor reads
/// `.cursor/mcp.json`. Both take the first entry. The Copilot CLI has its own entry, printed on its
/// own. The older VS Code `servers` format (`.vscode/mcp.json`) is the Local harness, which is
/// removed in February 2027, so it is not printed.
fn print_config(options: &Options) -> i32 {
    let root = match &options.root {
        Some(root) => match std::fs::canonicalize(root) {
            Ok(path) => Some(path),
            Err(error) => {
                eprintln!(
                    "stoop mcp: cannot use {} as --root: {}",
                    plan::output::escape(&root.display().to_string()),
                    plan::output::escape(&error.to_string())
                );
                return 2;
            }
        },
        None => None,
    };
    let mut args = vec!["mcp".to_string()];
    if options.allow_run {
        args.push("--allow-run".into());
    }
    if let Some(root) = &root {
        match scope::as_arg(root) {
            Ok(text) => {
                args.push("--root".into());
                args.push(text);
            }
            Err(error) => {
                eprintln!("stoop mcp: {error}");
                return 2;
            }
        }
    }
    let servers = json!({"mcpServers": {"stoop": {"command": "stoop", "args": args}}});
    let copilot = copilot_config(&args);
    let copilot_pretty = serde_json::to_string_pretty(&copilot).unwrap_or_else(|_| "{}".into());
    let pretty = serde_json::to_string_pretty(&servers).unwrap_or_else(|_| "{}".into());
    let claude = std::iter::once("claude mcp add stoop -- stoop".to_string())
        .chain(args.iter().map(|word| shell_word(word)))
        .collect::<Vec<_>>()
        .join(" ");
    println!("Paste this entry into the file for your client. Each file has a top-level mcpServers object:");
    println!();
    println!("{pretty}");
    println!();
    println!("Files:");
    println!("  .mcp.json at the project root: Claude Code and VS Code");
    println!("  .cursor/mcp.json: Cursor");
    println!();
    println!(
        "GitHub Copilot CLI reads ~/.copilot/mcp-config.json (or $COPILOT_HOME/mcp-config.json)."
    );
    println!(
        "Its entry names the server type and the tools to enable, so it is printed on its own:"
    );
    println!();
    println!("{copilot_pretty}");
    println!();
    println!("Claude Code can add it from the command line instead:");
    println!("  {claude}");
    println!();
    println!(
        "Not printed: .vscode/mcp.json with a top-level \"servers\" object. That is the VS Code"
    );
    println!("Local harness format, which is deprecated and removed in February 2027.");
    0
}

#[cfg(test)]
mod tests {
    use super::copilot_config;
    use serde_json::json;

    #[test]
    fn the_copilot_cli_entry_names_its_type_and_every_tool() {
        let args = vec!["mcp".to_string(), "--allow-run".to_string()];
        assert_eq!(
            copilot_config(&args)["mcpServers"]["stoop"],
            json!({"type": "local", "command": "stoop", "args": ["mcp", "--allow-run"], "tools": ["*"]})
        );
    }
}
