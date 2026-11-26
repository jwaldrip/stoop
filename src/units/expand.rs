//! One unit's launch: the hook's argv with each placeholder replaced by that unit (spec 3.2), and
//! each list form replaced by the path of the list file that holds the unit (spec 4.12).
//!
//! `{changed-inputs}` and a joined list form name more than one unit's worth of state, so a hook that
//! uses one runs its first-run form, and `supported` refuses it before any launch. Shell environment
//! code needs no placeholder: its words stay as written, and the variables are exported for each unit.

use super::hook::{Base, FileMode, Hook, Join, Placeholder, PlaceholderName};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

/// One unit's launch: its argv, and the value `STOOP_CHANGED` and `STOOP_UNITS` hold for it.
pub(crate) struct Launch {
    pub argv: Vec<OsString>,
    pub value: OsString,
}

/// Whether every placeholder of `hook` can stand for one unit. `{changed-inputs}` names changed inputs
/// that no one unit has, so a hook that reads them takes the first-run form, in its placeholder spelling
/// and in shell code alike (spec 4.11). A list has no join, so a joined list runs the first-run form too
/// (spec 4.12). Other shell environment code needs no placeholder: its variables are exported for each
/// unit (spec 4.7).
pub(crate) fn supported(hook: &Hook) -> bool {
    let reads_changed_inputs = hook.shell_env_code
        && hook
            .original
            .iter()
            .any(|word| has_bytes(word.as_encoded_bytes(), b"STOOP_CHANGED_INPUTS"));
    !reads_changed_inputs
        && hook.placeholders.iter().flatten().all(|placeholder| {
            placeholder.name != PlaceholderName::ChangedInputs
                && (placeholder.file.is_none() || placeholder.join.is_none())
        })
}

/// Whether `needle` occurs in `haystack`. It also finds `STOOP_CHANGED_INPUTS_FILE`, which holds it.
fn has_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The list forms a launch of `hook` reads, each once, in placeholder order (spec 4.12).
pub(crate) fn list_forms(hook: &Hook) -> Vec<(FileMode, Base)> {
    let mut forms: Vec<(FileMode, Base)> = Vec::new();
    for placeholder in hook.placeholders.iter().flatten() {
        if let Some(mode) = placeholder.file {
            let form = (mode, placeholder.base);
            if !forms.contains(&form) {
                forms.push(form);
            }
        }
    }
    forms
}

/// The name a list form is written under in a launch's directory. `changed` is the newline list of
/// the unit's cwd-relative path, the one `STOOP_CHANGED_FILE` names.
pub(crate) fn list_name(mode: FileMode, base: Base) -> &'static str {
    match (mode, base) {
        (FileMode::File, Base::Cwd) => "changed",
        (FileMode::File, Base::Root) => "changed-root",
        (FileMode::File, Base::Abs) => "changed-abs",
        (FileMode::Nul, Base::Cwd) => "nul",
        (FileMode::Nul, Base::Root) => "nul-root",
        (FileMode::Nul, Base::Abs) => "nul-abs",
    }
}

/// One unit's list in a form: the unit's text as its argument shows it, then the form's terminator, a
/// newline or a NUL (spec 4.12). A unit never holds a newline or a NUL (plan 3.3), so each entry is one
/// line or one NUL-terminated record.
pub(crate) fn list_bytes(
    root: &Path,
    cwd: &Path,
    unit: &str,
    mode: FileMode,
    base: Base,
) -> Vec<u8> {
    let mut bytes = entry(root, cwd, unit, base).as_encoded_bytes().to_vec();
    bytes.push(match mode {
        FileMode::File => b'\n',
        FileMode::Nul => 0,
    });
    bytes
}

/// `to` as seen from `from`, both absolute: a `..` for each component of `from` below their
/// common ancestor, then the rest of `to`.
fn relative(from: &Path, to: &Path) -> PathBuf {
    let from: Vec<Component<'_>> = from.components().collect();
    let to: Vec<Component<'_>> = to.components().collect();
    let shared = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut out = PathBuf::new();
    for _ in shared..from.len() {
        out.push("..");
    }
    for part in &to[shared..] {
        out.push(part.as_os_str());
    }
    out
}

/// A unit's path as a placeholder with `base` shows it. The root is absolute, so `cwd` and the
/// root's join stay comparable.
pub(crate) fn render(root: &Path, cwd: &Path, unit: &str, base: Base) -> OsString {
    match base {
        Base::Cwd => relative(cwd, &root.join(unit)).into_os_string(),
        Base::Root => OsString::from(unit),
        Base::Abs => root.join(unit).into_os_string(),
    }
}

/// The text a unit shows in an argument or a list. A relative result that begins with `-` gets `./`, so
/// the runner reads it as a path and not as an option.
fn entry(root: &Path, cwd: &Path, unit: &str, base: Base) -> OsString {
    let text = render(root, cwd, unit, base);
    if base != Base::Abs && text.as_encoded_bytes().first() == Some(&b'-') {
        let mut dotted = OsString::from("./");
        dotted.push(&text);
        return dotted;
    }
    text
}

/// The argument one placeholder becomes for one unit. A list form is the path `lists` names for it,
/// because the unit lives in that file. A joined placeholder is refused when its unit's text holds the
/// separator it joins with, because one unit's text would then read as several.
fn argument(
    root: &Path,
    cwd: &Path,
    unit: &str,
    placeholder: &Placeholder,
    lists: &dyn Fn(FileMode, Base) -> Option<OsString>,
) -> Option<OsString> {
    if let Some(mode) = placeholder.file {
        // A list has no join: its entries are one per line or one per NUL, so a joined list is refused.
        if placeholder.join.is_some() {
            return None;
        }
        return lists(mode, placeholder.base);
    }
    let text = entry(root, cwd, unit, placeholder.base);
    if let Some(join) = placeholder.join {
        let separator = match join {
            Join::Comma => b',',
            Join::Space => b' ',
            Join::Newline => b'\n',
        };
        if text.as_encoded_bytes().contains(&separator) {
            return None;
        }
    }
    Some(text)
}

/// The argv for one unit: each word with every placeholder replaced by its text for that unit, and each
/// list form by the path `lists` names for it. The words come from `hook.original`, so an option that the
/// full form removes stays in place. None when a placeholder cannot take the unit.
pub(crate) fn argv_with(
    hook: &Hook,
    unit: &str,
    root: &Path,
    cwd: &Path,
    lists: &dyn Fn(FileMode, Base) -> Option<OsString>,
) -> Option<Vec<OsString>> {
    hook.original
        .iter()
        .enumerate()
        .map(|(index, word)| {
            let spans = hook.spans.get(index)?;
            if spans.is_empty() {
                return Some(word.clone());
            }
            let placeholders = hook.placeholders.get(index)?;
            if placeholders.len() != spans.len() {
                return None;
            }
            let text = word.to_str()?;
            let mut out = OsString::new();
            let mut at = 0;
            for (&(start, end), placeholder) in spans.iter().zip(placeholders) {
                out.push(text.get(at..start)?);
                out.push(argument(root, cwd, unit, placeholder, lists)?);
                at = end;
            }
            out.push(text.get(at..)?);
            Some(out)
        })
        .collect()
}

/// `argv_with` for a hook without list paths: the argv the expansion tests pin for one unit.
#[cfg(all(test, unix))]
pub(crate) fn argv(hook: &Hook, unit: &str, root: &Path, cwd: &Path) -> Option<Vec<OsString>> {
    argv_with(hook, unit, root, cwd, &|_, _| None)
}

/// One unit's launch: its argv with each list form named by `lists`, and the value `STOOP_CHANGED` and
/// `STOOP_UNITS` hold for it. None when a placeholder cannot take the unit.
pub(crate) fn launch(
    hook: &Hook,
    unit: &str,
    root: &Path,
    cwd: &Path,
    lists: &dyn Fn(FileMode, Base) -> Option<OsString>,
) -> Option<Launch> {
    Some(Launch {
        argv: argv_with(hook, unit, root, cwd, lists)?,
        value: render(root, cwd, unit, Base::Cwd),
    })
}

/// Whether every unit of the roster expands (spec 3.1, check 7). The list files of a launch do not exist
/// until the launch makes them, and the check reads no list's text, so any path stands in for them.
pub(crate) fn expands(hook: &Hook, units: &[String], root: &Path, cwd: &Path) -> bool {
    let stand_in = |_: FileMode, _: Base| Some(OsString::from("list"));
    units
        .iter()
        .all(|unit| argv_with(hook, unit, root, cwd, &stand_in).is_some())
}

/// Whether every unit of the roster fits the newline lists of the hook: no unit's entry holds a newline.
/// Only an absolute entry can, because the root's own path can hold one. A newline list has one entry per
/// line, so it cannot name such a unit and the run keeps the full form (spec 4.12). A NUL list has no such
/// limit: its entries end at NUL.
pub(crate) fn lines_fit(hook: &Hook, units: &[String], root: &Path, cwd: &Path) -> bool {
    units.iter().all(|unit| {
        hook.placeholders.iter().flatten().all(|placeholder| {
            placeholder.file != Some(FileMode::File)
                || !entry(root, cwd, unit, placeholder.base)
                    .as_encoded_bytes()
                    .contains(&b'\n')
        })
    })
}

/// The launch for every unit of the roster, in roster order, for a hook without list forms.
#[cfg(all(test, unix))]
pub(crate) fn launches(
    hook: &Hook,
    units: &[String],
    root: &Path,
    cwd: &Path,
) -> Option<Vec<Launch>> {
    units
        .iter()
        .map(|unit| launch(hook, unit, root, cwd, &|_, _| None))
        .collect()
}

/// The most bytes that a list variable carries whole (spec 5.3), and that `STOOP_CHANGED_INPUTS` carries whole (spec
/// 3.11). Above it the variable is unset, and the list file holds the list.
pub(crate) const ENV_LIST_MAX: usize = 64 * 1024;

/// The most bytes that one argument word may hold (spec 6).
pub(crate) const WORD_MAX: usize = 64 * 1024;

/// Whether a list of `len` bytes is exported whole in its variable (spec 5.3).
pub(crate) fn listed(len: usize) -> bool {
    len <= ENV_LIST_MAX
}

/// The system's argument limit (spec 6): `sysconf(_SC_ARG_MAX)`, or 131,072 when that is not a positive number.
pub(crate) fn arg_max() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: `sysconf` reads no pointers.
        let value = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
        if let Ok(value) = usize::try_from(value) {
            if value > 0 {
                return value;
            }
        }
    }
    131_072
}

/// The bytes one launch needs on the command line (spec 6): each word and each `name=value` pair with its terminator,
/// and eight bytes of pointer for every word and variable and for the two terminating pointers.
pub(crate) fn launch_bytes(argv: &[OsString], env: &[(OsString, OsString)]) -> usize {
    let words: usize = argv.iter().map(|word| word.len() + 1).sum();
    let vars: usize = env
        .iter()
        .map(|(name, value)| name.len() + 1 + value.len() + 1)
        .sum();
    words + vars + 8 * (argv.len() + env.len() + 2)
}

/// Whether a launch fits the command line (spec 6): no word over `WORD_MAX`, and its bytes within half of `arg_max`.
pub(crate) fn fits(argv: &[OsString], env: &[(OsString, OsString)], arg_max: usize) -> bool {
    argv.iter().all(|word| word.len() <= WORD_MAX) && launch_bytes(argv, env) <= arg_max / 2
}

/// Whether the hook takes the grouped form (spec 5.1). It is not shell environment code, no placeholder names one unit
/// or the changed inputs, no `each` combines with a join or a file mode, and a word with more than one placeholder
/// holds only plain ones.
pub(crate) fn groups(hook: &Hook) -> bool {
    !hook.shell_env_code
        && hook.placeholders.iter().all(|placeholders| {
            let plain = placeholders
                .iter()
                .all(|placeholder| placeholder.join.is_none() && placeholder.file.is_none());
            placeholders.iter().all(|placeholder| {
                placeholder.name != PlaceholderName::Unit
                    && placeholder.name != PlaceholderName::ChangedInputs
                    && !(placeholder.each
                        && (placeholder.join.is_some() || placeholder.file.is_some()))
            }) && (placeholders.len() <= 1 || plain)
        })
}

/// The argv and the unit value of one grouped launch (spec 4.12, 5.2, 5.3).
pub(crate) struct Many {
    pub argv: Vec<OsString>,
    pub value: OsString,
}

/// The grouped launch for `units`, in roster order (spec 4.12, 4.13, 5.2). None when a unit's entry holds the separator
/// of a join. The roster screen refuses that before any launch (C8), so this is a guard for a later change.
pub(crate) fn launch_many(
    hook: &Hook,
    units: &[String],
    root: &Path,
    cwd: &Path,
    lists: &dyn Fn(FileMode, Base) -> Option<OsString>,
) -> Option<Many> {
    if units.is_empty() {
        return None;
    }
    let mut argv = Vec::new();
    for (index, word) in hook.original.iter().enumerate() {
        expand_word(hook, index, word, units, root, cwd, lists, &mut argv)?;
    }
    let mut value = OsString::new();
    for (index, unit) in units.iter().enumerate() {
        if index > 0 {
            value.push("\n");
        }
        value.push(render(root, cwd, unit, Base::Cwd));
    }
    Some(Many { argv, value })
}

/// Pushes the words that one word of the hook becomes for `units` (spec 4.12, 4.13). A word that is exactly one plain
/// placeholder becomes one word per unit. An `each` placeholder that follows an option word repeats the option. A join
/// or a list makes one word. Any other word is copied once per unit, with each placeholder bound to that unit.
#[allow(clippy::too_many_arguments)]
fn expand_word(
    hook: &Hook,
    index: usize,
    word: &OsString,
    units: &[String],
    root: &Path,
    cwd: &Path,
    lists: &dyn Fn(FileMode, Base) -> Option<OsString>,
    out: &mut Vec<OsString>,
) -> Option<()> {
    let spans = hook.spans.get(index)?;
    if spans.is_empty() {
        out.push(word.clone());
        return Some(());
    }
    let placeholders = hook.placeholders.get(index)?;
    if placeholders.len() != spans.len() {
        return None;
    }
    let text = word.to_str()?;
    if let [placeholder] = placeholders.as_slice() {
        if let Some(mode) = placeholder.file {
            let list = lists(mode, placeholder.base)?;
            out.push(filled(text, spans, placeholders, &|_| Some(list.clone()))?);
            return Some(());
        }
        if let Some(join) = placeholder.join {
            let joined = joined(units, root, cwd, placeholder.base, join)?;
            out.push(filled(text, spans, placeholders, &|_| {
                Some(joined.clone())
            })?);
            return Some(());
        }
        if spans[0] == (0, text.len()) {
            if placeholder.each {
                if let Some(option) = option_before(hook, index) {
                    out.push(entry(root, cwd, &units[0], placeholder.base));
                    for unit in &units[1..] {
                        out.push(option.clone());
                        out.push(entry(root, cwd, unit, placeholder.base));
                    }
                    return Some(());
                }
            }
            out.extend(
                units
                    .iter()
                    .map(|unit| entry(root, cwd, unit, placeholder.base)),
            );
            return Some(());
        }
    } else if placeholders
        .iter()
        .any(|placeholder| placeholder.file.is_some() || placeholder.join.is_some())
    {
        return None;
    }
    for unit in units {
        out.push(filled(text, spans, placeholders, &|placeholder| {
            Some(entry(root, cwd, unit, placeholder.base))
        })?);
    }
    Some(())
}

/// The entries of `units` joined by `join` into one word (spec 4.13). None when one entry holds the separator.
fn joined(units: &[String], root: &Path, cwd: &Path, base: Base, join: Join) -> Option<OsString> {
    let (separator, byte) = match join {
        Join::Comma => (",", b','),
        Join::Space => (" ", b' '),
        Join::Newline => ("\n", b'\n'),
    };
    let mut out = OsString::new();
    for (index, unit) in units.iter().enumerate() {
        let text = entry(root, cwd, unit, base);
        if text.as_encoded_bytes().contains(&byte) {
            return None;
        }
        if index > 0 {
            out.push(separator);
        }
        out.push(text);
    }
    Some(out)
}

/// `text` with the span of each placeholder replaced by what `value` gives for that placeholder (spec 4.12).
fn filled(
    text: &str,
    spans: &[(usize, usize)],
    placeholders: &[Placeholder],
    value: &dyn Fn(&Placeholder) -> Option<OsString>,
) -> Option<OsString> {
    let mut out = OsString::new();
    let mut at = 0;
    for (&(start, end), placeholder) in spans.iter().zip(placeholders) {
        out.push(text.get(at..start)?);
        out.push(value(placeholder)?);
        at = end;
    }
    out.push(text.get(at..)?);
    Some(out)
}

/// The option word before the word at `index`, when that word has no placeholder and is an option token: it starts with
/// `-`, is longer than one character, and is not `--` (spec 4.13).
fn option_before(hook: &Hook, index: usize) -> Option<OsString> {
    let before = index.checked_sub(1)?;
    let word = hook.original.get(before)?;
    let plain = hook.spans.get(before)?.is_empty();
    let option = word
        .to_str()
        .is_some_and(|text| text.starts_with('-') && text.len() > 1 && text != "--");
    (plain && option).then(|| word.clone())
}

/// The changed inputs of a launch as `STOOP_CHANGED_INPUTS` holds them (spec 3.11): the cwd-relative path of each key
/// inside the root, sorted, without repeats, one per line.
pub(crate) fn inputs_text<'a>(
    root: &Path,
    cwd: &Path,
    keys: impl Iterator<Item = &'a String>,
) -> OsString {
    let mut paths: Vec<OsString> = keys
        .filter(|key| !key.starts_with('/'))
        .map(|key| {
            let path = render(root, cwd, key, Base::Cwd);
            if path.is_empty() {
                OsString::from(".")
            } else {
                path
            }
        })
        .collect();
    paths.sort();
    paths.dedup();
    let mut text = OsString::new();
    for (index, path) in paths.iter().enumerate() {
        if index > 0 {
            text.push("\n");
        }
        text.push(path);
    }
    text
}

/// The variables that one launch sets for its units (spec 5.3), with each list path at `stand_in` bytes, as the fit
/// check counts them. The run sets the same names, and the same values where they are listed, with the real paths.
pub(crate) fn exports(value: &OsStr, inputs: &OsStr, stand_in: usize) -> Vec<(OsString, OsString)> {
    let list = OsString::from("x".repeat(stand_in));
    let mut env = vec![
        (OsString::from("STOOP_CHANGED_FILE"), list.clone()),
        (OsString::from("STOOP_CHANGED_INPUTS_FILE"), list),
    ];
    if listed(value.len()) {
        env.push((OsString::from("STOOP_CHANGED"), value.to_os_string()));
        env.push((OsString::from("STOOP_UNITS"), value.to_os_string()));
    }
    if listed(inputs.len()) {
        env.push((
            OsString::from("STOOP_CHANGED_INPUTS"),
            inputs.to_os_string(),
        ));
    }
    env
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::run::units::hook::prepare;

    fn hook(words: &[&str]) -> Hook {
        let exact: Vec<OsString> = words.iter().map(OsString::from).collect();
        prepare(&exact).unwrap().expect("a placeholder")
    }

    fn one(words: &[&str], unit: &str, root: &str, cwd: &str) -> Vec<String> {
        argv(&hook(words), unit, Path::new(root), Path::new(cwd))
            .expect("the unit expands")
            .iter()
            .map(|word| word.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn every_placeholder_spelling_becomes_the_unit_path_from_the_root() {
        for word in [
            "{changed}",
            "{units}",
            "{unit}",
            "$STOOP_CHANGED",
            "{changed:cwd}",
        ] {
            assert_eq!(
                one(&["t", word], "tests/a.t", "/r", "/r"),
                ["t", "tests/a.t"],
                "{word}"
            );
        }
    }

    #[test]
    fn value_forms_expand_to_the_unit_for_one_unit() {
        assert_eq!(
            one(&["t", "-f", "{changed:each}"], "tests/a.t", "/r", "/r"),
            ["t", "-f", "tests/a.t"]
        );
        assert_eq!(
            one(&["t", "--files={changed}"], "tests/a.t", "/r", "/r"),
            ["t", "--files=tests/a.t"]
        );
        assert_eq!(
            one(&["t", "-f{changed}"], "tests/a.t", "/r", "/r"),
            ["t", "-ftests/a.t"]
        );
        assert_eq!(
            one(
                &["t", "--files=base,{changed:comma}"],
                "tests/a.t",
                "/r",
                "/r"
            ),
            ["t", "--files=base,tests/a.t"]
        );
        assert_eq!(
            one(&["t", "--files={changed:space}"], "tests/a.t", "/r", "/r"),
            ["t", "--files=tests/a.t"]
        );
    }

    #[test]
    fn the_base_of_the_placeholder_decides_the_path_text() {
        assert_eq!(
            one(&["t", "{changed}"], "tests/a.t", "/r", "/r/tests"),
            ["t", "a.t"]
        );
        assert_eq!(
            one(&["t", "{changed}"], "tests/a.t", "/r", "/r/sub"),
            ["t", "../tests/a.t"]
        );
        assert_eq!(
            one(&["t", "{changed:root}"], "tests/a.t", "/r", "/r/sub"),
            ["t", "tests/a.t"]
        );
        assert_eq!(
            one(&["t", "{changed:abs}"], "tests/a.t", "/r", "/r/sub"),
            ["t", "/r/tests/a.t"]
        );
    }

    #[test]
    fn a_relative_result_that_starts_with_a_dash_becomes_a_path() {
        assert_eq!(
            one(&["t", "{changed}"], "-x.t", "/r", "/r"),
            ["t", "./-x.t"]
        );
        assert_eq!(
            one(&["t", "{changed:root}"], "-x.t", "/r", "/r/sub"),
            ["t", "./-x.t"]
        );
        assert_eq!(
            one(&["t", "{changed:abs}"], "-x.t", "/r", "/r"),
            ["t", "/r/-x.t"]
        );
    }

    #[test]
    fn a_shell_wrapper_keeps_its_code_and_expands_the_argument() {
        assert_eq!(
            one(
                &["sh", "-c", "cmd \"$@\"", "sh", "--files", "{changed}"],
                "tests/a.t",
                "/r",
                "/r"
            ),
            ["sh", "-c", "cmd \"$@\"", "sh", "--files", "tests/a.t"]
        );
    }

    #[test]
    fn the_first_run_form_is_kept_for_the_shapes_one_unit_cannot_stand_for() {
        assert!(supported(&hook(&["t", "@{changed:file}"])));
        assert!(supported(&hook(&["t", "{changed:nul}"])));
        assert!(!supported(&hook(&["t", "{changed-inputs}"])));
        assert!(!supported(&hook(&["t", "{changed:file:comma}"])));
        assert!(supported(&hook(&["sh", "-c", "echo $STOOP_CHANGED", "sh"])));
        assert!(supported(&hook(&["t", "{changed:each}"])));
    }

    #[test]
    fn a_unit_containing_the_join_separator_is_refused() {
        let comma = hook(&["t", "--files={changed:comma}"]);
        assert!(argv(&comma, "a,b.t", Path::new("/r"), Path::new("/r")).is_none());
        assert!(argv(&comma, "a.t", Path::new("/r"), Path::new("/r")).is_some());
        let space = hook(&["t", "{changed:space}"]);
        assert!(argv(&space, "a b.t", Path::new("/r"), Path::new("/r")).is_none());
        // The separator in the root refuses an absolute join too.
        let abs = hook(&["t", "{changed:abs:space}"]);
        assert!(argv(&abs, "a.t", Path::new("/r s"), Path::new("/r s")).is_none());
        let units = vec!["a.t".to_string(), "b,c.t".to_string()];
        assert!(launches(&comma, &units, Path::new("/r"), Path::new("/r")).is_none());
    }

    #[test]
    fn launches_follow_the_roster_and_export_the_cwd_value() {
        let hook = hook(&["t", "{changed}"]);
        let units = vec!["tests/a.t".to_string(), "tests/b.t".to_string()];
        let launches = launches(&hook, &units, Path::new("/r"), Path::new("/r/tests")).unwrap();
        assert_eq!(launches.len(), 2);
        assert_eq!(launches[0].value, OsString::from("a.t"));
        assert_eq!(launches[1].argv[0], "t");
        assert_eq!(launches[1].value, OsString::from("b.t"));
        assert_eq!(
            launches[1].argv,
            [OsString::from("t"), OsString::from("b.t")]
        );
    }

    #[test]
    fn a_list_holds_each_unit_as_its_argument_shows_it_with_its_terminator() {
        let root = Path::new("/r");
        assert_eq!(
            list_bytes(root, root, "tests/a.t", FileMode::File, Base::Cwd),
            b"tests/a.t\n"
        );
        assert_eq!(
            list_bytes(root, root, "tests/a.t", FileMode::Nul, Base::Cwd),
            b"tests/a.t\0"
        );
        assert_eq!(
            list_bytes(root, root, "-x.t", FileMode::File, Base::Cwd),
            b"./-x.t\n"
        );
        assert_eq!(
            list_bytes(
                root,
                Path::new("/r/sub"),
                "tests/a.t",
                FileMode::File,
                Base::Cwd
            ),
            b"../tests/a.t\n"
        );
        assert_eq!(
            list_bytes(root, root, "tests/a.t", FileMode::File, Base::Abs),
            b"/r/tests/a.t\n"
        );
    }

    #[test]
    fn each_list_form_is_named_once_in_placeholder_order() {
        let forms = list_forms(&hook(&[
            "t",
            "{changed:file}",
            "{changed:nul:root}",
            "--files={changed:file}",
        ]));
        assert_eq!(
            forms,
            [(FileMode::File, Base::Cwd), (FileMode::Nul, Base::Root)]
        );
    }

    #[test]
    fn shell_code_that_reads_the_changed_inputs_is_not_supported() {
        assert!(!supported(&hook(&[
            "sh",
            "-c",
            "run.sh $STOOP_CHANGED_INPUTS; exit $?",
            "sh"
        ])));
        assert!(!supported(&hook(&[
            "sh",
            "-c",
            "run.sh \"${STOOP_CHANGED_INPUTS_FILE}\"; exit $?",
            "sh"
        ])));
        assert!(supported(&hook(&[
            "sh",
            "-c",
            "run.sh \"$STOOP_CHANGED\"; exit $?",
            "sh"
        ])));
    }

    #[test]
    fn a_newline_list_cannot_name_an_absolute_path_that_holds_a_newline() {
        let root = Path::new("/r\nx");
        let units = ["tests/a.t".to_string()];
        assert!(!lines_fit(
            &hook(&["t", "{changed:file:abs}"]),
            &units,
            root,
            root
        ));
        assert!(lines_fit(
            &hook(&["t", "{changed:file}"]),
            &units,
            root,
            root
        ));
        assert!(lines_fit(
            &hook(&["t", "{changed:nul:abs}"]),
            &units,
            root,
            root
        ));
        assert_eq!(
            list_bytes(root, root, "tests/a.t", FileMode::Nul, Base::Abs),
            b"/r\nx/tests/a.t\0"
        );
    }

    fn many(words: &[&str], units: &[&str]) -> Option<Vec<String>> {
        let units: Vec<String> = units.iter().map(|unit| unit.to_string()).collect();
        let lists = |_: FileMode, _: Base| Some(OsString::from("<list>"));
        launch_many(
            &hook(words),
            &units,
            Path::new("/r"),
            Path::new("/r"),
            &lists,
        )
        .map(|many| {
            many.argv
                .iter()
                .map(|word| word.to_string_lossy().into_owned())
                .collect()
        })
    }

    #[test]
    fn launch_many_gives_the_4_13_rows() {
        let units = ["tests/a.t", "tests/b.t"];
        let rows: [(&[&str], &[&str]); 11] = [
            (
                &["t", "--files", "{changed}"],
                &["t", "--files", "tests/a.t", "tests/b.t"],
            ),
            (
                &["t", "--files={changed}"],
                &["t", "--files=tests/a.t", "--files=tests/b.t"],
            ),
            (&["t", "-f{changed}"], &["t", "-ftests/a.t", "-ftests/b.t"]),
            (
                &["t", "-f", "{changed:each}"],
                &["t", "-f", "tests/a.t", "-f", "tests/b.t"],
            ),
            (
                &["t", "--files={changed:comma}"],
                &["t", "--files=tests/a.t,tests/b.t"],
            ),
            (
                &["t", "--files=base,{changed:comma}"],
                &["t", "--files=base,tests/a.t,tests/b.t"],
            ),
            (
                &["t", "--files", "base", "--files", "{changed}"],
                &["t", "--files", "base", "--files", "tests/a.t", "tests/b.t"],
            ),
            (
                &["t", "-v", "--", "{changed}"],
                &["t", "-v", "--", "tests/a.t", "tests/b.t"],
            ),
            (&["t", "{changed:space}"], &["t", "tests/a.t tests/b.t"]),
            (&["t", "$STOOP_CHANGED"], &["t", "tests/a.t", "tests/b.t"]),
            (&["t", "@{changed:file}"], &["t", "@<list>"]),
        ];
        for (words, expected) in rows {
            let expected: Vec<String> = expected.iter().map(|word| word.to_string()).collect();
            assert_eq!(many(words, &units), Some(expected), "{words:?}");
        }
    }

    #[test]
    fn one_unit_as_a_group_is_the_same_launch_as_one_unit() {
        let forms: [&[&str]; 9] = [
            &["t", "--files", "{changed}"],
            &["t", "--files={changed}"],
            &["t", "-f{changed}"],
            &["t", "-f", "{changed:each}"],
            &["t", "--files={changed:comma}"],
            &["t", "--files=base,{changed:comma}"],
            &["t", "{changed:space}"],
            &["t", "$STOOP_CHANGED"],
            &["t", "{changed}"],
        ];
        for words in forms {
            let single = one(words, "tests/a.t", "/r", "/r");
            assert_eq!(many(words, &["tests/a.t"]), Some(single), "{words:?}");
        }
    }

    #[test]
    fn a_group_refuses_a_member_whose_entry_holds_the_join_separator() {
        let lists = |_: FileMode, _: Base| None;
        let units = vec!["a,b.t".to_string(), "c.t".to_string()];
        let hook = hook(&["t", "--files={changed:comma}"]);
        assert!(launch_many(&hook, &units, Path::new("/r"), Path::new("/r"), &lists).is_none());
        assert!(launch_many(&hook, &[], Path::new("/r"), Path::new("/r"), &lists).is_none());
    }

    #[test]
    fn groups_takes_the_plain_forms_and_refuses_the_rest() {
        assert!(groups(&hook(&["t", "--files={changed}"])));
        assert!(groups(&hook(&["t", "-f", "{changed:each}"])));
        assert!(groups(&hook(&["t", "@{changed:file}"])));
        assert!(!groups(&hook(&["t", "{unit}"])));
        assert!(!groups(&hook(&["t", "{changed-inputs}"])));
        assert!(!groups(&hook(&["t", "{changed:each:comma}"])));
        assert!(!groups(&hook(&["sh", "-c", "t \"$STOOP_CHANGED\"", "sh"])));
    }

    #[test]
    fn fits_bounds_each_word_and_the_total_at_their_limits() {
        assert!(fits(
            &[OsString::from("x".repeat(WORD_MAX))],
            &[],
            usize::MAX
        ));
        assert!(!fits(
            &[OsString::from("x".repeat(WORD_MAX + 1))],
            &[],
            usize::MAX
        ));
        let argv = [OsString::from("t")];
        let bytes = launch_bytes(&argv, &[]);
        assert!(fits(&argv, &[], 2 * bytes));
        assert!(!fits(&argv, &[], 2 * bytes - 1));
        assert!(arg_max() > 0);
    }

    #[test]
    fn exports_list_a_long_value_only_through_its_file() {
        let long = OsString::from("x".repeat(ENV_LIST_MAX + 1));
        let names: Vec<OsString> = exports(&long, OsStr::new("a"), 9)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert!(!names.iter().any(|name| name == "STOOP_CHANGED"));
        assert!(!names.iter().any(|name| name == "STOOP_UNITS"));
        assert!(names.iter().any(|name| name == "STOOP_CHANGED_FILE"));
        assert!(names.iter().any(|name| name == "STOOP_CHANGED_INPUTS"));
    }
}
