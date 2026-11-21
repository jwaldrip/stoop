//! Strict configuration for explicit hooks. No field grants permission to split or publish.

use super::hook::{self, Arity, OptionDeclaration};
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::{self, Read};
use std::path::Path;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Document {
    units: Units,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Units {
    enabled: Option<bool>,
    default_branch: Option<String>,
    verify_every: Option<u64>,
    suite: Vec<RawSuite>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSuite {
    id: String,
    cwd: Option<String>,
    #[serde(rename = "match")]
    matches: Vec<String>,
    #[serde(default)]
    options: Vec<RawOption>,
    units: Option<Vec<String>>,
    independent: Option<bool>,
    enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOption {
    names: Vec<String>,
    values: RawArity,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawArity {
    Integer(i64),
    Text(String),
}

pub(crate) struct Suite {
    pub id: String,
    cwd: Option<String>,
    matches: Vec<String>,
    pub options: Vec<OptionDeclaration>,
    #[allow(dead_code)]
    pub units: Option<Vec<String>>,
    pub independent: Option<bool>,
}

#[derive(Default)]
pub(crate) struct Config {
    pub default_branch: Option<String>,
    pub verify_every: Option<u64>,
    suites: Vec<Suite>,
    source: String,
    present: bool,
}

pub(crate) struct ConfigError {
    line: usize,
    col: usize,
    problem: String,
}

impl ConfigError {
    fn at(source: &str, offset: usize, problem: impl Into<String>) -> Self {
        let offset = offset.min(source.len());
        let offset = source.floor_char_boundary(offset);
        let before = &source[..offset];
        Self {
            line: before.bytes().filter(|&byte| byte == b'\n').count() + 1,
            col: before.rsplit('\n').next().unwrap_or("").chars().count() + 1,
            problem: problem.into(),
        }
    }

    fn named(source: &str, name: &str, problem: impl Into<String>) -> Self {
        Self::at(source, source.rfind(name).unwrap_or(0), problem)
    }

    pub fn warning(&self) -> String {
        format!(
            "stoop: .stoop.toml:{}:{}: {}; ignoring the unit configuration and running the full command",
            self.line,
            self.col,
            hook::safe(&self.problem)
        )
    }
}

fn valid_cwd(cwd: &str) -> bool {
    cwd == "."
        || (!cwd.is_empty()
            && !cwd.starts_with('/')
            && !cwd.contains(['\\', ':'])
            && cwd.split('/').all(|part| !matches!(part, "" | "." | "..")))
}

fn valid_pattern(pattern: &str) -> bool {
    let pattern = pattern.strip_prefix('!').unwrap_or(pattern);
    if pattern.is_empty() {
        return false;
    }
    let mut escaped = false;
    let mut bracket = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
        } else {
            match ch {
                '\\' => escaped = true,
                '[' if !bracket => bracket = true,
                ']' if bracket => bracket = false,
                ']' => return false,
                _ => {}
            }
        }
    }
    !escaped && !bracket
}

fn valid_option(name: &str) -> bool {
    name.starts_with('-')
        && name.len() > 1
        && name != "--"
        && !name.contains('=')
        && !name.chars().any(char::is_whitespace)
}

const MAX_CONFIG_BYTES: u64 = 8 * 1024 * 1024;

/// Open only regular files and bound the read, including when the file grows after stat.
/// Nonblocking open prevents a replacement FIFO from hanging between metadata and open.
pub(crate) fn read_regular_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let check = |metadata: std::fs::Metadata| {
        if !metadata.is_file() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a regular file",
            ))
        } else if metadata.len() > limit {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file exceeds size limit",
            ))
        } else {
            Ok(())
        }
    };
    check(std::fs::metadata(path)?)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    check(file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub(crate) fn load(root: &Path) -> Result<Config, ConfigError> {
    let path = root.join(".stoop.toml");
    let source = match read_regular_bounded(&path, MAX_CONFIG_BYTES) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|_| ConfigError::at("", 0, "configuration is not UTF-8"))?,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && std::fs::symlink_metadata(&path)
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            return Ok(Config::default())
        }
        Err(error) => {
            return Err(ConfigError::at(
                "",
                0,
                format!("cannot read configuration: {error}"),
            ))
        }
    };
    let document: Document = toml::from_str(&source).map_err(|error: toml::de::Error| {
        ConfigError::at(
            &source,
            error.span().map_or(0, |span| span.start),
            error.message(),
        )
    })?;
    if document.units.verify_every == Some(0) {
        return Err(ConfigError::named(
            &source,
            "verify_every",
            "verify_every must be at least 1",
        ));
    }
    if document
        .units
        .default_branch
        .as_deref()
        .is_some_and(|s| !super::policy::valid_branch(s))
    {
        return Err(ConfigError::named(
            &source,
            "default_branch",
            "invalid default branch",
        ));
    }
    let mut ids = HashSet::new();
    let mut suites = Vec::new();
    for raw in document.units.suite {
        if raw.id.is_empty() || !ids.insert(raw.id.clone()) {
            return Err(ConfigError::named(
                &source,
                &raw.id,
                "suite id is empty or duplicated",
            ));
        }
        if raw.cwd.as_deref().is_some_and(|cwd| !valid_cwd(cwd)) {
            return Err(ConfigError::named(
                &source,
                "cwd",
                "suite cwd must be root-relative",
            ));
        }
        if raw.matches.is_empty() {
            return Err(ConfigError::named(
                &source,
                "match",
                "suite match must not be empty",
            ));
        }
        if raw
            .units
            .as_ref()
            .is_some_and(|patterns| patterns.iter().any(|p| !valid_pattern(p)))
        {
            return Err(ConfigError::named(&source, "units", "invalid unit pattern"));
        }
        let matches = raw
            .matches
            .iter()
            .map(|word| {
                hook::normalize(word).map_err(|problem| ConfigError::named(&source, word, problem))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut names = HashSet::new();
        let mut options = Vec::new();
        for option in raw.options {
            if option.names.is_empty()
                || option
                    .names
                    .iter()
                    .any(|name| !valid_option(name) || !names.insert(name.clone()))
            {
                return Err(ConfigError::named(
                    &source,
                    "names",
                    "invalid or duplicate option name",
                ));
            }
            let arity = match option.values {
                RawArity::Integer(0) => Arity::Zero,
                RawArity::Integer(1) => Arity::One,
                RawArity::Text(text) if text == "many" => Arity::Many,
                _ => {
                    return Err(ConfigError::named(
                        &source,
                        "values",
                        "option values must be 0, 1, or 'many'",
                    ))
                }
            };
            options.push(OptionDeclaration {
                names: option.names,
                arity,
            });
        }
        // These opt out of splitting, which this slice never performs. They do not lift
        // the wider opt-out, change option declarations, or confer proof authority.
        let _splitting_enabled =
            document.units.enabled.unwrap_or(true) && raw.enabled.unwrap_or(true);
        suites.push(Suite {
            id: raw.id,
            cwd: raw.cwd,
            matches,
            options,
            units: raw.units,
            independent: raw.independent,
        });
    }
    Ok(Config {
        default_branch: document.units.default_branch,
        verify_every: document.units.verify_every,
        suites,
        source,
        present: true,
    })
}

impl Config {
    pub(crate) fn key_source(&self) -> Option<&[u8]> {
        self.present.then_some(self.source.as_bytes())
    }

    pub(crate) fn select(
        &self,
        argv: &[OsString],
        cwd: &str,
    ) -> Result<Option<&Suite>, ConfigError> {
        let cwd = if cwd.is_empty() { "." } else { cwd };
        let mut selected: Option<&Suite> = None;
        for suite in &self.suites {
            if suite.cwd.as_deref().is_some_and(|expected| expected != cwd)
                || suite.matches.len() != argv.len()
            {
                continue;
            }
            let matches = suite.matches.iter().zip(argv).all(|(expected, actual)| {
                expected == "*"
                    || actual.to_str().is_some_and(|word| {
                        hook::normalize(word).is_ok_and(|word| word == *expected)
                    })
            });
            if matches {
                if let Some(previous) = selected {
                    return Err(ConfigError::named(
                        &self.source,
                        &suite.id,
                        format!("suites {} and {} both match", previous.id, suite.id),
                    ));
                }
                selected = Some(suite);
            }
        }
        Ok(selected)
    }
}

pub(crate) struct Prepared {
    pub hook: Option<hook::Hook>,
    pub config: Config,
    pub invalid: bool,
    pub independent_false: bool,
}

/// Shared by the CLI and MCP preflight. The caller emits the warning only once.
pub(crate) fn prepare(
    root: &Path,
    cwd: &str,
    argv: &[OsString],
    literal: bool,
) -> (Option<String>, Result<Prepared, String>) {
    let parsed = if literal {
        None
    } else {
        match hook::parse(argv) {
            Ok(parsed) => parsed,
            Err(error) => return (None, Err(error)),
        }
    };
    let Some(parsed) = parsed else {
        return (
            None,
            Ok(Prepared {
                hook: None,
                config: Config::default(),
                invalid: false,
                independent_false: false,
            }),
        );
    };
    finish(root, cwd, argv, parsed)
}

pub(crate) fn finish(
    root: &Path,
    cwd: &str,
    argv: &[OsString],
    parsed: hook::ParsedHook,
) -> (Option<String>, Result<Prepared, String>) {
    let mut warning = None;
    let mut invalid = false;
    let config = match load(root) {
        Ok(config) => config,
        Err(error) => {
            warning = Some(error.warning());
            invalid = true;
            Config::default()
        }
    };
    let suite = if invalid {
        None
    } else {
        match config.select(argv, cwd) {
            Ok(suite) => suite,
            Err(error) => {
                warning = Some(error.warning());
                invalid = true;
                None
            }
        }
    };
    let independent_false = suite.is_some_and(|suite| suite.independent == Some(false));
    let hook = parsed.finish(argv, suite.map_or(&[], |suite| &suite.options));
    (
        warning,
        hook.map(|hook| Prepared {
            hook: Some(hook),
            config,
            invalid,
            independent_false,
        }),
    )
}
