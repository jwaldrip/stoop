//! Explicit changed-unit hooks. Slice 2a executes only their full-command form.

use std::path::Path;

#[derive(Clone, Debug)]
pub(crate) struct Hook {
    pub original: Vec<String>,
    pub argv: Vec<String>,
    pub removed: Vec<String>,
    pub spans: Vec<Vec<(usize, usize)>>,
    pub placeholder: String,
}

const HINT: &str = "quote it: '{changed:*.test.ts|*.spec.ts}'";
const CHANGED: &[(&str, &str)] = &[
    ("changed-inputs", "STOOP_CHANGED_INPUTS"),
    ("changed", "STOOP_CHANGED"),
    ("units", "STOOP_UNITS"),
    ("unit", "STOOP_UNIT"),
];

fn option(word: &str) -> bool {
    word.starts_with('-') && word.len() > 1 && word != "--"
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
        for (name, env) in CHANGED {
            let primary = format!("{{{name}");
            let env_braced = format!("${{{env}");
            let env_plain = format!("${env}");
            if rest.starts_with(&primary) {
                let j = i + primary.len();
                if matches!(word.as_bytes().get(j), Some(b':') | Some(b'}') | None) {
                    let end = end_of(word, j).ok_or_else(|| {
                        format!(
                            "{word:?} is cut off; the shell split it at |, ; or a space; {HINT}"
                        )
                    })?;
                    segments(&word[j..end - 1], *name == "changed-inputs")?;
                    found = Some(end);
                    break;
                }
            }
            if rest.starts_with(&env_braced) {
                let j = i + env_braced.len();
                if matches!(word.as_bytes().get(j), Some(b':') | Some(b'}') | None) {
                    let end =
                        end_of(word, j).ok_or_else(|| format!("{word:?} is cut off; {HINT}"))?;
                    segments(&word[j..end - 1], *name == "changed-inputs")?;
                    found = Some(end);
                    break;
                }
            }
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
    CHANGED.iter().any(|(name, _)| {
        let fragment = format!("{name}:");
        word.starts_with(&fragment)
            || word
                .split_once('=')
                .is_some_and(|(_, value)| value.starts_with(&fragment))
            || (word.starts_with('-')
                && !word.starts_with("--")
                && word.get(2..).is_some_and(|s| s.starts_with(&fragment)))
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

fn ambiguous(name: &str) -> String {
    format!("cannot tell where values for {name} end; use a single-value {name}=VALUE form or run the full command without the hook; option arity configuration will be supported later")
}

pub(crate) fn prepare(argv: &[String]) -> Result<Option<Hook>, String> {
    let shell = shell_code(argv);
    let mut all = Vec::with_capacity(argv.len());
    let mut found = false;
    let mut env_code = false;
    let mut placeholder = String::new();
    for (idx, word) in argv.iter().enumerate() {
        if mangled(word) {
            return Err(format!("the shell expanded a placeholder into separate words; put | between patterns and {HINT}"));
        }
        let parts = spans(word)?;
        if let Some((code, zero)) = shell {
            if idx == code {
                if parts.iter().any(|&(a, _)| word.as_bytes()[a] == b'{') {
                    return Err("a brace placeholder cannot be substituted into shell code; pass it as a separate argument".into());
                }
                env_code = CHANGED.iter().any(|(_, env)| {
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
        } else if i > start && option(&argv[i - 1]) && !argv[i - 1].contains('=') && !remove[i - 1]
        {
            remove[i - 1] = true;
            carriers.push(argv[i - 1].clone());
        } else if i > start && argv[i - 1] != "--" {
            for j in (start..i).rev() {
                if argv[j] == "--" {
                    break;
                }
                if option(&argv[j]) && !remove[j] {
                    if !argv[j].contains('=') {
                        return Err(ambiguous(&argv[j]));
                    }
                    break;
                }
            }
        }
    }
    for name in &carriers {
        let mut i = start;
        while i < argv.len() {
            if !remove[i] && same_option(&argv[i], name) {
                if argv[i] == *name {
                    remove[i] = true;
                    if i + 1 < argv.len()
                        && !remove[i + 1]
                        && argv[i + 1] != "--"
                        && !option(&argv[i + 1])
                    {
                        if i + 2 < argv.len()
                            && !remove[i + 2]
                            && argv[i + 2] != "--"
                            && !option(&argv[i + 2])
                        {
                            return Err(ambiguous(name));
                        }
                        remove[i + 1] = true;
                        i += 1;
                    }
                } else if !name.starts_with("--") && !argv[i].starts_with(&format!("{name}=")) {
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
    let mut exec = Vec::with_capacity(argv.len());
    let mut removed = Vec::new();
    for (i, word) in argv.iter().enumerate() {
        if remove[i] {
            removed.push(word.clone());
        } else {
            exec.push(word.clone());
        }
    }
    Ok(Some(Hook {
        original: argv.to_vec(),
        argv: exec,
        removed,
        spans: all,
        placeholder,
    }))
}

/// Does this argv equal a shell-expanded form of the recorded hook?
pub(crate) fn expanded_matches(hook: &Hook, incoming: &[String]) -> bool {
    let n = hook.original.len();
    let m = incoming.len();
    if !hook.spans.iter().any(|s| !s.is_empty()) || n > 128 || m > 2048 {
        return false;
    }
    let mut reachable = vec![false; (n + 1) * (m + 1)];
    let stride = m + 1;
    reachable[0] = true;
    for i in 0..n {
        let word = &hook.original[i];
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
                        && next[0] == (0, hook.original[i + 1].len())
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

pub(crate) fn empty_hint(argv: &[String]) -> Option<String> {
    for (i, word) in argv.iter().enumerate().skip(1) {
        if word.is_empty() {
            let label = argv
                .get(i.wrapping_sub(1))
                .filter(|s| option(s))
                .map_or("argument", String::as_str);
            return Some(format!("{label} has an empty value; if a shell expanded a placeholder there, quote it: '{{changed}}'"));
        }
        if option(word) && word.ends_with('=') {
            let label = word.trim_end_matches('=');
            return Some(format!("{label} has an empty value; if a shell expanded a placeholder there, quote it: '{{changed}}'"));
        }
    }
    None
}
