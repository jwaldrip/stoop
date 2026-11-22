//! One unit's launch: the hook's argv with each placeholder replaced by that unit (spec 3.2), and
//! each list form replaced by the path of the list file that holds the unit (spec 4.12).
//!
//! `{changed-inputs}` and a joined list form name more than one unit's worth of state, so a hook that
//! uses one runs its first-run form, and `supported` refuses it before any launch. Shell environment
//! code needs no placeholder: its words stay as written, and the variables are exported for each unit.

use super::hook::{Base, FileMode, Hook, Join, Placeholder, PlaceholderName};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// One unit's launch: its argv, and the value `STOOP_CHANGED` and `STOOP_UNITS` hold for it.
pub(crate) struct Launch {
    pub unit: String,
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
fn render(root: &Path, cwd: &Path, unit: &str, base: Base) -> OsString {
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
        unit: unit.to_owned(),
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
        assert_eq!(launches[0].unit, "tests/a.t");
        assert_eq!(launches[0].value, OsString::from("a.t"));
        assert_eq!(launches[1].unit, "tests/b.t");
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
}
