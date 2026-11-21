//! Explicit changed-unit hooks. Slice 2a executes only their full-command form.

use super::filter::Filter;
use std::ffi::{OsStr, OsString};
use std::path::Path;

#[derive(Clone, Debug)]
pub(crate) struct Hook {
    pub original: Vec<OsString>,
    pub argv: Vec<OsString>,
    pub removed: Vec<OsString>,
    #[allow(dead_code)]
    pub spans: Vec<Vec<(usize, usize)>>,
    pub placeholders: Vec<Vec<Placeholder>>,
    pub environment_placeholders: Vec<Placeholder>,
    pub placeholder: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlaceholderName {
    Changed,
    Units,
    Unit,
    ChangedInputs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Base {
    Cwd,
    Root,
    Abs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Join {
    Comma,
    Space,
    Newline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileMode {
    File,
    Nul,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Placeholder {
    pub name: PlaceholderName,
    pub filter: Option<Filter>,
    pub base: Base,
    pub join: Option<Join>,
    pub file: Option<FileMode>,
    pub each: bool,
}

impl PlaceholderName {
    fn from_name(name: &str) -> Self {
        match name {
            "changed" => Self::Changed,
            "units" => Self::Units,
            "unit" => Self::Unit,
            "changed-inputs" => Self::ChangedInputs,
            _ => unreachable!(),
        }
    }
}

const HINT: &str = "quote it: '{changed:*.test.ts|*.spec.ts}'";
const MANGLED: &str = "the shell expanded {changed:...,...} into separate words; quote it and put | between patterns: '{changed:*.test.ts|*.spec.ts}'; a genuine argument of that shape needs --literal";
/// Placeholder names, each with its environment spelling if it has one (spec section 4.2).
const CHANGED: &[(&str, Option<&str>)] = &[
    ("changed-inputs", Some("STOOP_CHANGED_INPUTS")),
    ("changed", Some("STOOP_CHANGED")),
    ("units", Some("STOOP_UNITS")),
    // `{unit}` has no environment spelling: an affected unit is exported as STOOP_CHANGED.
    ("unit", None),
];

fn option(word: &str) -> bool {
    word.starts_with('-') && word.len() > 1 && word != "--"
}

/// The text the placeholder grammar reads for one argument. UTF-8 is itself, so UTF-8 keeps its
/// behaviour. A word that is not UTF-8 holds no placeholder: its printable ASCII stays, so `-`
/// options and `=` read as they do, while braces and other bytes become `\0` and two hex digits.
/// argv cannot hold NUL, so no escaped word equals a UTF-8 word.
fn shadow(word: &OsStr) -> String {
    if let Some(text) = word.to_str() {
        return text.to_string();
    }
    let mut shown = String::new();
    for &byte in word.as_encoded_bytes() {
        if (0x20..0x7f).contains(&byte) && byte != b'{' && byte != b'}' {
            shown.push(char::from(byte));
        } else {
            shown.push_str(&format!("\u{0}{byte:02x}"));
        }
    }
    shown
}

fn shadows(words: &[OsString]) -> Vec<String> {
    words.iter().map(|word| shadow(word)).collect()
}

/// Shadow text made printable: each escaped byte shows as the replacement character.
fn lossy_shadow(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\u{0}' {
            chars.next();
            chars.next();
            shown.push('\u{fffd}');
        } else {
            shown.push(ch);
        }
    }
    shown
}

fn segments(suffix: &str, name: PlaceholderName) -> Result<Placeholder, String> {
    let mut placeholder = Placeholder {
        name,
        filter: None,
        base: Base::Cwd,
        join: None,
        file: None,
        each: false,
    };
    if suffix.is_empty() {
        return Ok(placeholder);
    }
    if !suffix.starts_with(':') {
        return Err("invalid placeholder".into());
    }
    let mut parts = Vec::new();
    let mut start = 1;
    let mut escaped = false;
    for (idx, byte) in suffix.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b':' {
            parts.push(&suffix[start..idx]);
            start = idx + 1;
        }
    }
    if escaped {
        return Err("trailing escape in placeholder".into());
    }
    parts.push(&suffix[start..]);
    let mut path = false;
    let mut join = false;
    let mut file = false;
    let mut each = false;
    let mut filter = false;
    for part in parts {
        if part.is_empty() {
            return Err("empty placeholder segment or filter".into());
        }
        let group = match part {
            "cwd" | "root" | "abs" => Some(&mut path),
            "comma" | "space" | "newline" => Some(&mut join),
            "file" | "nul" => Some(&mut file),
            "each" => Some(&mut each),
            _ => None,
        };
        if let Some(seen) = group {
            if *seen {
                return Err("conflicting placeholder modifiers".into());
            }
            *seen = true;
            match part {
                "cwd" => placeholder.base = Base::Cwd,
                "root" => placeholder.base = Base::Root,
                "abs" => placeholder.base = Base::Abs,
                "comma" => placeholder.join = Some(Join::Comma),
                "space" => placeholder.join = Some(Join::Space),
                "newline" => placeholder.join = Some(Join::Newline),
                "file" => placeholder.file = Some(FileMode::File),
                "nul" => placeholder.file = Some(FileMode::Nul),
                "each" => placeholder.each = true,
                _ => unreachable!(),
            }
            continue;
        }
        if name == PlaceholderName::ChangedInputs {
            return Err("a changed-inputs placeholder cannot have a filter".into());
        }
        if filter {
            return Err("a placeholder can have only one filter".into());
        }
        filter = true;
        let mut pattern_start = 0;
        let mut slash_escape = false;
        let mut in_class = false;
        for (idx, byte) in part.bytes().enumerate() {
            if slash_escape {
                slash_escape = false;
                continue;
            }
            match byte {
                b'\\' => slash_escape = true,
                b',' => {
                    return Err("use | between patterns: '{changed:*.test.ts|*.spec.ts}'".into())
                }
                b'{' | b'}' => return Err("braces are not allowed inside a filter".into()),
                b'[' if !in_class => in_class = true,
                b']' if in_class => in_class = false,
                b']' => return Err("unmatched ] in filter".into()),
                b'|' if !in_class => {
                    let pattern = &part[pattern_start..idx];
                    if pattern.is_empty() || pattern == "!" {
                        return Err("empty pattern in placeholder filter".into());
                    }
                    pattern_start = idx + 1;
                }
                _ => {}
            }
        }
        if slash_escape || in_class {
            return Err("unterminated escape or character class in filter".into());
        }
        let pattern = &part[pattern_start..];
        if pattern.is_empty() || pattern == "!" {
            return Err("empty pattern in placeholder filter".into());
        }
        placeholder.filter = Some(Filter::inline(part));
    }
    Ok(placeholder)
}

fn shell_code(argv: &[String]) -> Option<(usize, Option<usize>)> {
    let mut command = 0;
    if Path::new(argv.first()?).file_name()?.to_str()? == "env" {
        command = 1;
        while let Some(word) = argv.get(command) {
            if word == "--" {
                command += 1;
                break;
            }
            if word == "-u" || word == "--unset" {
                command += 2;
            } else if word.starts_with('-') || word.contains('=') {
                command += 1;
            } else {
                break;
            }
        }
    }
    let name = Path::new(argv.get(command)?).file_name()?.to_str()?;
    if !matches!(name, "sh" | "bash" | "dash" | "zsh" | "ksh" | "fish") {
        return None;
    }
    let mut i = command + 1;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--" || !arg.starts_with(['-', '+']) || arg == "-" {
            return None;
        }
        if name == "fish" && (arg == "-c" || arg == "--command") {
            return (i + 1 < argv.len()).then_some((i + 1, None));
        }
        if let Some(code) = arg.strip_prefix("--command=") {
            if name == "fish" && !code.is_empty() {
                return Some((i, None));
            }
        }
        if matches!(arg, "--rcfile" | "--init-file" | "-o" | "+o" | "-O" | "+O") {
            i += 2;
            continue;
        }
        if arg.starts_with("--") {
            i += 1;
            continue;
        }
        if arg.starts_with('-') && arg[1..].contains('c') {
            return (i + 1 < argv.len()).then_some((i + 1, Some(i + 2)));
        }
        if (arg.ends_with('o') || arg.ends_with('O')) && arg.len() > 1 {
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

fn end_of(word: &str, start: usize) -> Option<usize> {
    let mut escaped = false;
    for (off, byte) in word.as_bytes()[start..].iter().enumerate() {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'}' {
            return Some(start + off + 1);
        }
    }
    None
}

fn is_boundary(byte: Option<u8>) -> bool {
    !byte.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn spans(word: &str) -> Result<Vec<(usize, usize, Placeholder)>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < word.len() {
        let rest = &word[i..];
        let mut found = None;
        for &(name, env) in CHANGED {
            let primary = format!("{{{name}");
            if rest.starts_with(&primary) {
                let j = i + primary.len();
                if matches!(word.as_bytes().get(j), Some(b':') | Some(b'}') | None) {
                    let end = end_of(word, j).ok_or_else(|| {
                        format!(
                            "{} is cut off; the shell split it at |, ; or a space; {HINT}",
                            quote_word(word)
                        )
                    })?;
                    found = Some((
                        end,
                        segments(&word[j..end - 1], PlaceholderName::from_name(name))?,
                    ));
                    break;
                }
            }
            let Some(env) = env else { continue };
            let env_braced = format!("${{{env}");
            if rest.starts_with(&env_braced) {
                let j = i + env_braced.len();
                if matches!(word.as_bytes().get(j), Some(b':') | Some(b'}') | None) {
                    let end = end_of(word, j)
                        .ok_or_else(|| format!("{} is cut off; {HINT}", quote_word(word)))?;
                    found = Some((
                        end,
                        segments(&word[j..end - 1], PlaceholderName::from_name(name))?,
                    ));
                    break;
                }
            }
            let env_plain = format!("${env}");
            if rest.starts_with(&env_plain) {
                let end = i + env_plain.len();
                if is_boundary(word.as_bytes().get(end).copied()) {
                    found = Some((end, segments("", PlaceholderName::from_name(name))?));
                    break;
                }
            }
        }
        if let Some((end, placeholder)) = found {
            out.push((i, end, placeholder));
            i = end;
        } else {
            i += word[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    Ok(out)
}

fn mangled(word: &str) -> bool {
    if word.contains('{') {
        return false;
    }
    // `name::` is a qualified name, not a brace expansion: an empty segment is a usage error.
    let shaped = |value: &str, name: &str| {
        value.starts_with(&format!("{name}:")) && !value.starts_with(&format!("{name}::"))
    };
    CHANGED.iter().any(|&(name, _)| {
        shaped(word, name)
            || word
                .split_once('=')
                .is_some_and(|(_, value)| shaped(value, name))
            || (word.starts_with('-')
                && !word.starts_with("--")
                && word.get(2..).is_some_and(|rest| shaped(rest, name)))
    })
}

fn legacy_carrier(word: &str, first: usize) -> Option<&str> {
    if word.starts_with("--") {
        return word[..first].split_once('=').map(|(name, _)| name);
    }
    if word.starts_with('-') && word.len() > 2 && first >= 2 {
        return word.get(..2);
    }
    None
}

fn legacy_same_option(word: &str, name: &str) -> bool {
    word == name
        || word.strip_prefix(name).is_some_and(|tail| {
            tail.starts_with('=') || (!name.starts_with("--") && !tail.is_empty())
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arity {
    Zero,
    One,
    Many,
}

#[derive(Clone, Debug)]
pub(crate) struct OptionDeclaration {
    pub names: Vec<String>,
    pub arity: Arity,
}

fn declared_word<'a>(
    options: &'a [OptionDeclaration],
    word: &str,
) -> Option<(&'a OptionDeclaration, &'a str)> {
    options.iter().find_map(|item| {
        item.names
            .iter()
            .find(|name| {
                word == name.as_str()
                    || (name.starts_with("--")
                        && word
                            .strip_prefix(name.as_str())
                            .is_some_and(|tail| tail.starts_with('=')))
            })
            .map(|name| (item, name.as_str()))
    })
}

fn touches_declared(word: &str, name: &str) -> bool {
    word == name
        || word.strip_prefix(name).is_some_and(|tail| {
            !tail.is_empty() && (!name.starts_with("--") || tail.starts_with('='))
        })
}

fn valid_attachment(arity: Arity, attached: bool) -> bool {
    !attached || arity != Arity::Zero
}

fn ambiguous(name: &str) -> String {
    let name = safe(&lossy_shadow(name));
    format!("cannot tell where the values for {name} end; attach the placeholder with =, put it right after {name} or after --, or declare the option in .stoop.toml")
}

pub(crate) struct ParsedHook {
    argv: Vec<String>,
    spans: Vec<Vec<(usize, usize)>>,
    placeholders: Vec<Vec<Placeholder>>,
    environment_placeholders: Vec<Placeholder>,
    placeholder: String,
    start: usize,
}

pub(crate) fn parse(exact: &[OsString]) -> Result<Option<ParsedHook>, String> {
    let argv = shadows(exact);
    let shell = shell_code(&argv);
    let mut all = Vec::with_capacity(argv.len());
    let mut placeholders = Vec::with_capacity(argv.len());
    let mut environment_placeholders = Vec::new();
    let mut found = false;
    let mut env_code = false;
    let mut placeholder = String::new();
    for (idx, word) in argv.iter().enumerate() {
        if exact[idx].to_str().is_some() && mangled(word) {
            return Err(MANGLED.to_string());
        }
        let parsed_parts = spans(word)?;
        let parts: Vec<_> = parsed_parts.iter().map(|(a, b, _)| (*a, *b)).collect();
        let parsed: Vec<_> = parsed_parts
            .into_iter()
            .map(|(_, _, value)| value)
            .collect();
        if let Some((code, zero)) = shell {
            if idx == code {
                if parts.iter().any(|&(a, _)| word.as_bytes()[a] == b'{') {
                    return Err("a brace placeholder cannot be substituted into shell code; pass it as a separate argument".into());
                }
                env_code = CHANGED.iter().filter_map(|&(_, env)| env).any(|env| {
                    word.contains(&format!("${env}")) || word.contains(&format!("${{{env}"))
                }) || word.contains("$STOOP_CHANGED_FILE")
                    || word.contains("${STOOP_CHANGED_FILE")
                    || word.contains("$STOOP_CHANGED_INPUTS_FILE")
                    || word.contains("${STOOP_CHANGED_INPUTS_FILE");
                all.push(Vec::new());
                environment_placeholders = parsed;
                placeholders.push(Vec::new());
                continue;
            }
            if !parts.is_empty() && zero.is_some_and(|zero| idx <= zero) {
                return Err("a placeholder cannot occupy the shell command or its $0".into());
            }
        }
        if !parts.is_empty() {
            if idx == 0 {
                return Err("a placeholder cannot be the executable".into());
            }
            if word.char_indices().any(|(pos, ch)| {
                !parts.iter().any(|&(start, end)| pos >= start && pos < end)
                    && (ch.is_whitespace()
                        || matches!(
                            ch,
                            ';' | '|' | '&' | '<' | '>' | '(' | ')' | '`' | '\'' | '"'
                        ))
            }) {
                return Err("a placeholder cannot be embedded in shell code; pass it as a separate argument".into());
            }
            if placeholder.is_empty() {
                let (a, b) = parts[0];
                placeholder = word[a..b].to_string();
            }
            found = true;
        }
        all.push(parts);
        placeholders.push(parsed);
    }
    if !found && !env_code {
        return Ok(None);
    }
    let start = shell.and_then(|(_, zero)| zero).map_or(1, |zero| zero + 1);
    Ok(Some(ParsedHook {
        argv,
        spans: all,
        placeholders,
        environment_placeholders,
        placeholder,
        start,
    }))
}

#[cfg(all(test, unix))]
pub(crate) fn prepare(exact: &[OsString]) -> Result<Option<Hook>, String> {
    parse(exact)?
        .map(|parsed| parsed.finish(exact, &[], false))
        .transpose()
}

/// Before the first `--`, declared options use their arity and aliases. Undeclared
/// options retain 2a's adjacent-placeholder and carrier rules, including ambiguity
/// refusals. After `--`, words are positional and cannot own a placeholder.
fn removals(
    argv: &[String],
    spans: &[Vec<(usize, usize)>],
    start: usize,
    options: &[OptionDeclaration],
) -> Result<Vec<bool>, String> {
    struct Occurrence<'a> {
        name: &'a str,
        declaration: Option<usize>,
        start: usize,
        end: usize,
        attached: bool,
        selected: bool,
    }
    let end = (start..argv.len())
        .find(|&i| argv[i] == "--")
        .unwrap_or(argv.len());
    let mut remove: Vec<bool> = spans.iter().map(|parts| !parts.is_empty()).collect();
    for i in start..argv.len() {
        if spans[i].is_empty() {
            continue;
        }
        let bare = spans[i].len() == 1 && spans[i][0] == (0, argv[i].len());
        let attached = i < end
            && declared_word(options, &argv[i]).is_some_and(|(item, name)| {
                name.starts_with("--")
                    && valid_attachment(item.arity, true)
                    && spans[i].len() == 1
                    && spans[i][0] == (name.len() + 1, argv[i].len())
            });
        let touches_declared = i < end
            && options
                .iter()
                .flat_map(|item| &item.names)
                .any(|name| touches_declared(&argv[i], name));
        if touches_declared && !bare && !attached {
            return Err(ambiguous(&argv[i]));
        }
    }
    let mut owned = vec![false; argv.len()];
    let mut occurrences = Vec::new();
    let mut i = start;
    while i < end {
        let word = &argv[i];
        if !option(word) {
            i += 1;
            continue;
        }
        let declared = declared_word(options, word);
        if declared.is_none()
            && options
                .iter()
                .flat_map(|item| &item.names)
                .any(|name| touches_declared(word, name) && word != name)
        {
            return Err(ambiguous(word));
        }
        let (name, declaration, attached) = if let Some((item, name)) = declared {
            if !valid_attachment(item.arity, word != name) {
                return Err(ambiguous(word));
            }
            let index = options
                .iter()
                .position(|candidate| std::ptr::eq(candidate, item))
                .unwrap();
            (name, Some(index), word != name)
        } else if let Some(&(first, _)) = spans[i].first() {
            let name = legacy_carrier(word, first).unwrap_or(word);
            (name, None, name != word)
        } else {
            (word.as_str(), None, word.contains('='))
        };
        let first = i;
        i += 1;
        match declaration.map(|index| options[index].arity) {
            Some(Arity::One) if !attached && i < end => i += 1,
            Some(Arity::Many) => {
                while i < end && !option(&argv[i]) {
                    i += 1;
                }
            }
            None if !attached
                && i < end
                && spans[i].len() == 1
                && spans[i][0] == (0, argv[i].len()) =>
            {
                i += 1
            }
            _ => {}
        }
        for used in &mut owned[first..i] {
            *used = true;
        }
        let selected = spans[first..i].iter().any(|parts| !parts.is_empty());
        occurrences.push(Occurrence {
            name,
            declaration,
            start: first,
            end: i,
            attached,
            selected,
        });
    }
    for at in start..end {
        if spans[at].len() != 1 || spans[at][0] != (0, argv[at].len()) || owned[at] {
            continue;
        }
        if let Some(occurrence) = occurrences
            .iter()
            .rev()
            .find(|item| item.start < at && item.end <= at && !item.selected)
        {
            if occurrence.declaration.is_none() && !argv[occurrence.start].contains('=') {
                return Err(ambiguous(occurrence.name));
            }
        }
    }
    for occurrence in &occurrences {
        let selected = occurrences.iter().find(|other| {
            other.selected
                && match (occurrence.declaration, other.declaration) {
                    (Some(a), Some(b)) => a == b,
                    (None, None) => legacy_same_option(&argv[occurrence.start], other.name),
                    _ => false,
                }
        });
        let Some(selected) = selected else { continue };
        if occurrence.declaration.is_none()
            && !occurrence.selected
            && !selected.name.starts_with("--")
            && argv[occurrence.start] != selected.name
            && !argv[occurrence.start].starts_with(&format!("{}=", selected.name))
        {
            return Err(ambiguous(selected.name));
        }
        for used in &mut remove[occurrence.start..occurrence.end] {
            *used = true;
        }
        if occurrence.declaration.is_none()
            && !occurrence.attached
            && occurrence.end == occurrence.start + 1
        {
            let value = occurrence.end;
            if value < end && !option(&argv[value]) && !remove[value] {
                if value + 1 < end && !option(&argv[value + 1]) && !remove[value + 1] {
                    return Err(ambiguous(occurrence.name));
                }
                remove[value] = true;
            }
        }
    }
    if let Some(i) = (1..argv.len()).rev().find(|&i| !remove[i]) {
        if argv[i] == "--" {
            remove[i] = true;
        }
    }
    Ok(remove)
}

impl ParsedHook {
    /// Match an erased shell shape before option arities are known.
    pub(crate) fn expanded_matches(&self, exact: &[OsString]) -> bool {
        expanded_matches_parts(&self.argv, &self.spans, exact)
    }

    pub(crate) fn finish(
        self,
        exact: &[OsString],
        options: &[OptionDeclaration],
        has_default_universe: bool,
    ) -> Result<Hook, String> {
        let Self {
            argv,
            spans: all,
            placeholders,
            environment_placeholders,
            placeholder,
            start,
        } = self;
        let mut inline = None;
        for filter in placeholders
            .iter()
            .flatten()
            .chain(&environment_placeholders)
            .filter_map(|p| p.filter.as_ref())
        {
            if inline.is_some_and(|prior| prior != filter) {
                return Err("two different unit filters in one command".into());
            }
            inline = Some(filter);
        }
        if inline.is_some_and(Filter::exclusion_only) && !has_default_universe {
            return Err("an exclusion-only filter needs a default unit universe".into());
        }
        let remove = removals(&argv, &all, start, options)?;
        let mut exec = Vec::with_capacity(exact.len());
        let mut removed = Vec::new();
        for (i, word) in exact.iter().enumerate() {
            if remove[i] {
                removed.push(word.clone());
            } else {
                exec.push(word.clone());
            }
        }
        Ok(Hook {
            original: exact.to_vec(),
            argv: exec,
            removed,
            spans: all,
            placeholders,
            environment_placeholders,
            placeholder,
        })
    }
}

/// Normalize aliases and environment spellings while preserving every modifier and filter.
pub(crate) fn normalize(word: &str) -> Result<String, String> {
    let parts = spans(word)?;
    let mut result = String::with_capacity(word.len());
    let mut cursor = 0;
    for (start, end, _) in parts {
        result.push_str(&word[cursor..start]);
        let token = &word[start..end];
        let mut normalized = None;
        for &(name, env) in CHANGED {
            let primary = if name == "units" { "changed" } else { name };
            let brace = format!("{{{name}");
            if let Some(suffix) = token.strip_prefix(&brace) {
                normalized = Some(format!("{{{primary}{suffix}"));
                break;
            }
            if let Some(env) = env {
                let braced = format!("${{{env}");
                let plain = format!("${env}");
                if let Some(suffix) = token.strip_prefix(&braced) {
                    normalized = Some(format!("{{{primary}{suffix}"));
                    break;
                }
                if token == plain {
                    normalized = Some(format!("{{{primary}}}"));
                    break;
                }
            }
        }
        result.push_str(normalized.as_deref().unwrap_or(token));
        cursor = end;
    }
    result.push_str(&word[cursor..]);
    Ok(result)
}

#[cfg(all(test, unix))]
fn expanded_matches(hook: &Hook, exact: &[OsString]) -> bool {
    parse(&hook.original)
        .ok()
        .flatten()
        .is_some_and(|parsed| parsed.expanded_matches(exact))
}

/// Does this argv equal a shell-expanded form of the recorded hook?
fn expanded_matches_parts(
    original: &[String],
    all: &[Vec<(usize, usize)>],
    exact: &[OsString],
) -> bool {
    let incoming = shadows(exact);
    let n = original.len();
    let m = incoming.len();
    if !all.iter().any(|s| !s.is_empty()) || n > 128 || m > 2048 {
        return false;
    }
    let mut reachable = vec![false; (n + 1) * (m + 1)];
    let stride = m + 1;
    reachable[0] = true;
    for i in 0..n {
        let word = &original[i];
        let spans = &all[i];
        let mut erased = String::new();
        let mut cursor = 0;
        for &(start, end) in spans {
            erased.push_str(&word[cursor..start]);
            cursor = end;
        }
        erased.push_str(&word[cursor..]);
        let brace_chars = if spans.len() == 1 {
            let (a, b) = spans[0];
            let inner = &word[a..b];
            if matches!(
                inner,
                "{changed}" | "{units}" | "{unit}" | "{changed-inputs}"
            ) {
                let mut chars = inner.as_bytes()[1..inner.len() - 1].to_vec();
                chars.sort_unstable();
                chars.dedup();
                Some(
                    chars
                        .into_iter()
                        .map(|c| format!("{}{}{}", &word[..a], c as char, &word[b..]))
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            }
        } else {
            None
        };
        for j in 0..=m {
            if !reachable[i * stride + j] {
                continue;
            }
            if spans.is_empty() {
                if j < m && incoming[j] == *word {
                    reachable[(i + 1) * stride + j + 1] = true;
                }
                if i + 1 < n && j < m && option(word) {
                    let next = &all[i + 1];
                    if next.len() == 1
                        && next[0] == (0, original[i + 1].len())
                        && incoming[j] == format!("{word}=")
                    {
                        reachable[(i + 2) * stride + j + 1] = true;
                    }
                }
            } else {
                if erased.is_empty() {
                    reachable[(i + 1) * stride + j] = true;
                }
                if j < m && incoming[j] == erased {
                    reachable[(i + 1) * stride + j + 1] = true;
                }
                if let Some(chars) = &brace_chars {
                    if j + chars.len() <= m && incoming[j..j + chars.len()] == **chars {
                        reachable[(i + 1) * stride + j + chars.len()] = true;
                    }
                }
            }
        }
    }
    reachable[n * stride + m]
}

/// Argv text made safe to print on one line of stoop's output. Control characters become
/// `\u{..}` text; then the plan CLI's escape neutralises `::` and `##[` (GitHub workflow
/// commands), `%`, and bidirectional formatting characters.
pub(crate) fn safe(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            shown.push_str(&format!("\\u{{{:x}}}", ch as u32));
        } else {
            shown.push(ch);
        }
    }
    crate::plan::output::escape(&shown)
}

/// One argv word in single quotes, as refusals and cut-off messages show it.
fn quote_word(text: &str) -> String {
    format!("'{}'", safe(text).replace('\'', "'\\''"))
}

/// Removed words as a list, `["--files", "{changed}"]`, for the run line.
pub(crate) fn show(words: &[OsString]) -> String {
    let items: Vec<String> = words
        .iter()
        .map(|item| format!("\"{}\"", safe(&item.to_string_lossy()).replace('"', "\\\"")))
        .collect();
    format!("[{}]", items.join(", "))
}

/// Words as a shell would type them, for explain output.
pub(crate) fn render(words: &[OsString]) -> String {
    words
        .iter()
        .map(|item| {
            let item = item.to_string_lossy();
            let bare = !item.is_empty()
                && item
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./=:,@+%".contains(&b));
            if bare {
                safe(&item)
            } else {
                quote_word(&item)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The option a removed placeholder was removed with: `--files` for `--files={changed}`.
fn option_name(word: &str) -> &str {
    word.find(['=', '{']).map_or(word, |at| &word[..at])
}

/// The option that carried a removed placeholder, if one did.
fn dropped_option(hook: &Hook) -> Option<String> {
    hook.removed
        .iter()
        .map(|item| shadow(item))
        .find(|item| option(item))
        .map(|item| lossy_shadow(option_name(&item)))
}

/// The line a run prints when the shell removed a recorded placeholder.
pub(crate) fn expanded_line(hook: &Hook) -> String {
    let placeholder = render(&[OsString::from(hook.placeholder.clone())]);
    match dropped_option(hook) {
        Some(name) => {
            let name = safe(&name);
            format!(
                "stoop: the shell expanded {placeholder} after {name}; running the full command, which drops {name}; quote it"
            )
        }
        None => format!(
            "stoop: the shell expanded {placeholder} as an argument; running the full command; quote it"
        ),
    }
}

/// The explain line for a placeholder the shell removed from a recorded hook.
pub(crate) fn expanded_explain(hook: &Hook) -> String {
    format!(
        "stoop: would run full: the shell expanded the recorded hook {}; it would run {}",
        render(&hook.original),
        render(&hook.argv)
    )
}

/// The 2a diagnostic for an unconfigured argv matching different full commands.
pub(crate) fn ambiguous_line(argv: &[OsString], matches: usize, explain: bool) -> String {
    let typed = render(argv);
    if explain {
        format!(
            "stoop: would run as typed: {typed} matches {matches} recorded hooks with different full commands; quote the placeholder or use --literal"
        )
    } else {
        format!(
            "stoop: {typed} matches {matches} recorded hooks with different full commands; running it as typed; quote the placeholder or use --literal"
        )
    }
}

/// The option or argument that holds the first empty value, made safe to print.
fn empty_label(argv: &[OsString]) -> Option<String> {
    let words = shadows(argv);
    for (i, item) in words.iter().enumerate().skip(1) {
        if item.is_empty() {
            let label = words
                .get(i - 1)
                .filter(|s| option(s))
                .map_or("argument", String::as_str);
            return Some(safe(&lossy_shadow(label)));
        }
        if option(item) && item.ends_with('=') {
            return Some(safe(&lossy_shadow(item.trim_end_matches('='))));
        }
    }
    None
}

/// The line for an empty value that no recorded hook explains, on a run or in explain.
pub(crate) fn empty_value_line(argv: &[OsString], explain: bool) -> Option<String> {
    let label = empty_label(argv)?;
    Some(if explain {
        format!("stoop: would run as typed: no hook recorded with a placeholder at {label}")
    } else {
        format!("stoop: {label} has an empty value; if a shell expanded a placeholder there, quote it: '{{changed}}'")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_neutralises_control_bidi_and_workflow_text() {
        assert_eq!(safe("a\nb\u{1b}c"), "a\\u{a}b\\u{1b}c");
        assert_eq!(safe("x\u{202E}y"), "x\\u{202e}y");
        assert_eq!(safe("##[error]z::w"), "#%23[error]z%3A%3Aw");
    }

    #[test]
    fn shell_environment_placeholders_stay_separate_from_argument_spans() {
        let argv: Vec<OsString> = [
            "sh",
            "-c",
            "echo ${STOOP_CHANGED:*.t}",
            "sh",
            "--files",
            "{changed:*.t}",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let hook = parse(&argv)
            .unwrap()
            .unwrap()
            .finish(&argv, &[], false)
            .unwrap();
        assert_eq!(hook.spans.len(), hook.placeholders.len());
        for (spans, placeholders) in hook.spans.iter().zip(&hook.placeholders) {
            assert_eq!(spans.len(), placeholders.len());
        }
        assert_eq!(hook.environment_placeholders.len(), 1);
        assert_eq!(
            hook.environment_placeholders[0]
                .filter
                .as_ref()
                .unwrap()
                .text(),
            "*.t"
        );
        assert_eq!(hook.argv, argv[..4]);
    }
}

#[cfg(all(test, unix))]
mod non_utf8_words {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    fn raw(bytes: &[u8]) -> OsString {
        OsString::from_vec(bytes.to_vec())
    }

    #[test]
    fn a_non_utf8_word_is_an_ordinary_word_even_when_lossy_text_would_be_a_placeholder() {
        // Converted lossily this is a placeholder; as bytes it is an ordinary word.
        let argv = [OsString::from("./t"), raw(b"{changed:*.rs\xff}")];
        assert!(matches!(prepare(&argv), Ok(None)));
    }

    #[test]
    fn a_placeholder_next_to_a_non_utf8_word_still_expands() {
        let argv = [
            OsString::from("./t"),
            raw(b"\xff"),
            OsString::from("{changed}"),
        ];
        assert!(matches!(prepare(&argv), Ok(Some(_))));
    }

    #[test]
    fn distinct_words_have_distinct_shadows() {
        let fe = shadow(OsStr::from_bytes(b"\xfe"));
        assert_ne!(fe, shadow(OsStr::from_bytes(b"\xff")));
        assert_ne!(fe, shadow(OsStr::new("\u{fffd}")));
        assert_eq!(shadow(OsStr::new("{changed}")), "{changed}");
    }
}

#[cfg(all(test, unix))]
mod incoming_words_tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn a_non_utf8_incoming_word_never_matches_a_recorded_replacement_character() {
        let recorded = [
            OsString::from("./t"),
            OsString::from("\u{fffd}"),
            OsString::from("--files"),
            OsString::from("{changed}"),
        ];
        let hook = prepare(&recorded).unwrap().unwrap();
        let typed = [
            OsString::from("./t"),
            OsString::from_vec(b"\xff".to_vec()),
            OsString::from("--files"),
        ];
        assert!(!expanded_matches(&hook, &typed));
        let utf8 = [
            OsString::from("./t"),
            OsString::from("\u{fffd}"),
            OsString::from("--files"),
        ];
        assert!(expanded_matches(&hook, &utf8));
    }
}
