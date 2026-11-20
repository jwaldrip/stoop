//! Explicit changed-unit hooks. Slice 2a executes only their full-command form.

use std::ffi::{OsStr, OsString};
use std::path::Path;

#[derive(Clone, Debug)]
pub(crate) struct Hook {
    pub original: Vec<OsString>,
    pub argv: Vec<OsString>,
    pub removed: Vec<OsString>,
    pub spans: Vec<Vec<(usize, usize)>>,
    pub placeholder: String,
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

fn segments(suffix: &str, inputs: bool) -> Result<(), String> {
    if suffix.is_empty() {
        return Ok(());
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
            continue;
        }
        if inputs {
            return Err("a changed-inputs placeholder cannot have a filter".into());
        }
        if filter {
            return Err("a placeholder can have only one filter".into());
        }
        filter = true;
        let mut pattern_start = 0;
        let mut slash_escape = false;
        let mut in_class = false;
        let mut positive = false;
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
                    positive |= !pattern.starts_with('!');
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
        positive |= !pattern.starts_with('!');
        if !positive {
            return Err("an exclusion-only filter needs a default unit universe".into());
        }
    }
    Ok(())
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

fn spans(word: &str) -> Result<Vec<(usize, usize)>, String> {
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
                    segments(&word[j..end - 1], name == "changed-inputs")?;
                    found = Some(end);
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
                    segments(&word[j..end - 1], name == "changed-inputs")?;
                    found = Some(end);
                    break;
                }
            }
            let env_plain = format!("${env}");
            if rest.starts_with(&env_plain) {
                let end = i + env_plain.len();
                if is_boundary(word.as_bytes().get(end).copied()) {
                    found = Some(end);
                    break;
                }
            }
        }
        if let Some(end) = found {
            out.push((i, end));
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

fn carrier(word: &str, first: usize) -> Option<String> {
    if word.starts_with("--") {
        return word[..first]
            .split_once('=')
            .map(|(name, _)| name.to_string());
    }
    if word.starts_with('-') && word.len() > 2 && first >= 2 {
        return word.get(..2).map(str::to_string);
    }
    None
}

fn same_option(word: &str, name: &str) -> bool {
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

fn declaration<'a>(options: &'a [OptionDeclaration], name: &str) -> Option<&'a OptionDeclaration> {
    options
        .iter()
        .find(|item| item.names.iter().any(|alias| alias == name))
}

fn declared_word<'a>(
    options: &'a [OptionDeclaration],
    word: &str,
) -> Option<(&'a OptionDeclaration, &'a str)> {
    options
        .iter()
        .flat_map(|item| item.names.iter().map(move |name| (item, name.as_str())))
        .filter(|(_, name)| same_option(word, name))
        .max_by_key(|(_, name)| name.len())
}

fn ambiguous(name: &str) -> String {
    let name = safe(&lossy_shadow(name));
    format!("cannot tell where the values for {name} end; attach the placeholder with =, put it right after {name} or after --, or declare the option in .stoop.toml")
}

pub(crate) struct ParsedHook {
    argv: Vec<String>,
    spans: Vec<Vec<(usize, usize)>>,
    placeholder: String,
    start: usize,
}

pub(crate) fn parse(exact: &[OsString]) -> Result<Option<ParsedHook>, String> {
    let argv = shadows(exact);
    let shell = shell_code(&argv);
    let mut all = Vec::with_capacity(argv.len());
    let mut found = false;
    let mut env_code = false;
    let mut placeholder = String::new();
    for (idx, word) in argv.iter().enumerate() {
        if exact[idx].to_str().is_some() && mangled(word) {
            return Err(MANGLED.to_string());
        }
        let parts = spans(word)?;
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
    }
    if !found && !env_code {
        return Ok(None);
    }
    let start = shell.and_then(|(_, zero)| zero).map_or(1, |zero| zero + 1);
    Ok(Some(ParsedHook {
        argv,
        spans: all,
        placeholder,
        start,
    }))
}

pub(crate) fn prepare(exact: &[OsString]) -> Result<Option<Hook>, String> {
    parse(exact)?
        .map(|parsed| parsed.finish(exact, &[]))
        .transpose()
}

impl ParsedHook {
    pub(crate) fn finish(
        self,
        exact: &[OsString],
        options: &[OptionDeclaration],
    ) -> Result<Hook, String> {
        let Self {
            argv,
            spans: all,
            placeholder,
            start,
        } = self;
        let mut remove = vec![false; argv.len()];
        let mut carriers = Vec::new();
        for (i, parts) in all.iter().enumerate().skip(1) {
            if parts.is_empty() {
                continue;
            }
            remove[i] = true;
            let whole = parts.len() == 1 && parts[0] == (0, argv[i].len());
            if !whole {
                if let Some(name) = carrier(&argv[i], parts[0].0) {
                    carriers.push(name);
                }
            } else if i > start && option(&argv[i - 1]) && !remove[i - 1] {
                match declared_word(options, &argv[i - 1]) {
                    Some((item, name)) if item.arity == Arity::Many => {
                        carriers.push(name.to_string());
                    }
                    Some((item, name)) if item.arity == Arity::One && argv[i - 1] == name => {
                        remove[i - 1] = true;
                        carriers.push(name.to_string());
                    }
                    Some(_) => {}
                    None if !argv[i - 1].contains('=') => {
                        remove[i - 1] = true;
                        carriers.push(argv[i - 1].clone());
                    }
                    None => {}
                }
            } else if i > start && argv[i - 1] != "--" {
                for j in (start..i).rev() {
                    if argv[j] == "--" {
                        break;
                    }
                    if option(&argv[j]) && !remove[j] {
                        match declared_word(options, &argv[j]) {
                            Some((item, name)) if item.arity == Arity::Many => {
                                carriers.push(name.to_string());
                            }
                            Some(_) => {}
                            None if !argv[j].contains('=') => return Err(ambiguous(&argv[j])),
                            None => {}
                        }
                        break;
                    }
                }
            }
        }
        for name in &carriers {
            let declared = declaration(options, name);
            let mut i = start;
            while i < argv.len() {
                let matches = declared.map_or_else(
                    || same_option(&argv[i], name),
                    |item| item.names.iter().any(|alias| same_option(&argv[i], alias)),
                );
                if matches && all[i].is_empty() && (!remove[i] || declared.is_some()) {
                    let exact_option = declared.map_or_else(
                        || argv[i] == *name,
                        |item| item.names.iter().any(|alias| argv[i] == *alias),
                    );
                    if declared.is_some_and(|item| item.arity == Arity::Many) {
                        remove[i] = true;
                        i += 1;
                        while i < argv.len() && argv[i] != "--" && !option(&argv[i]) {
                            remove[i] = true;
                            i += 1;
                        }
                        continue;
                    }
                    if exact_option {
                        remove[i] = true;
                        if declared.is_none_or(|item| item.arity == Arity::One)
                            && i + 1 < argv.len()
                            && !remove[i + 1]
                            && argv[i + 1] != "--"
                            && !option(&argv[i + 1])
                        {
                            if declared.is_none()
                                && i + 2 < argv.len()
                                && !remove[i + 2]
                                && argv[i + 2] != "--"
                                && !option(&argv[i + 2])
                            {
                                return Err(ambiguous(name));
                            }
                            remove[i + 1] = true;
                            i += 1;
                        }
                    } else if declared.is_none()
                        && !name.starts_with("--")
                        && !argv[i].starts_with(&format!("{name}="))
                    {
                        return Err(ambiguous(name));
                    } else {
                        remove[i] = true;
                    }
                }
                i += 1;
            }
        }
        if let Some(i) = (1..argv.len()).rev().find(|&i| !remove[i]) {
            if argv[i] == "--" {
                remove[i] = true;
            }
        }
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
            placeholder,
        })
    }
}

/// Normalize aliases and environment spellings while preserving every modifier and filter.
pub(crate) fn normalize(word: &str) -> Result<String, String> {
    let parts = spans(word)?;
    let mut result = String::with_capacity(word.len());
    let mut cursor = 0;
    for (start, end) in parts {
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

/// Does this argv equal a shell-expanded form of the recorded hook?
pub(crate) fn expanded_matches(hook: &Hook, exact: &[OsString]) -> bool {
    let original = shadows(&hook.original);
    let incoming = shadows(exact);
    let n = original.len();
    let m = incoming.len();
    if !hook.spans.iter().any(|s| !s.is_empty()) || n > 128 || m > 2048 {
        return false;
    }
    let mut reachable = vec![false; (n + 1) * (m + 1)];
    let stride = m + 1;
    reachable[0] = true;
    for i in 0..n {
        let word = &original[i];
        let spans = &hook.spans[i];
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
                    let next = &hook.spans[i + 1];
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

/// The line for placeholder-free argv that matches more than one recorded full command.
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
    use super::safe;

    #[test]
    fn safe_neutralises_control_bidi_and_workflow_text() {
        assert_eq!(safe("a\nb\u{1b}c"), "a\\u{a}b\\u{1b}c");
        assert_eq!(safe("x\u{202E}y"), "x\\u{202e}y");
        assert_eq!(safe("##[error]z::w"), "#%23[error]z%3A%3Aw");
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
