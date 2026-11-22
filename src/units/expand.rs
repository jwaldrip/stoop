//! One unit's launch: the hook's argv with each placeholder replaced by that unit (spec 3.2).
//!
//! Only a single unit is expanded. A hook whose placeholders need more than one unit's worth of
//! state (a list file, the changed-inputs variable, shell environment code) runs its first-run
//! form instead, and `supported` refuses it before any launch.

use super::hook::{Base, Hook, Join, Placeholder, PlaceholderName};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// One unit's launch: its argv, and the value `STOOP_CHANGED` and `STOOP_UNITS` hold for it.
pub(crate) struct Launch {
    pub unit: String,
    pub argv: Vec<OsString>,
    pub value: OsString,
}

/// Whether every placeholder of `hook` reduces to one unit's text.
pub(crate) fn supported(hook: &Hook) -> bool {
    !hook.shell_env_code
        && hook.placeholders.iter().flatten().all(|placeholder| {
            placeholder.file.is_none() && placeholder.name != PlaceholderName::ChangedInputs
        })
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

/// The text a placeholder becomes in an argument. A relative result that begins with `-` gets
/// `./`, so the runner reads it as a path and not as an option. None when the text holds the
/// separator the placeholder joins with, because one unit's text would then read as several.
fn argument(root: &Path, cwd: &Path, unit: &str, placeholder: &Placeholder) -> Option<OsString> {
    let text = render(root, cwd, unit, placeholder.base);
    let bytes = text.as_encoded_bytes();
    if let Some(join) = placeholder.join {
        let separator = match join {
            Join::Comma => b',',
            Join::Space => b' ',
            Join::Newline => b'\n',
        };
        if bytes.contains(&separator) {
            return None;
        }
    }
    if placeholder.base != Base::Abs && bytes.first() == Some(&b'-') {
        let mut dotted = OsString::from("./");
        dotted.push(&text);
        return Some(dotted);
    }
    Some(text)
}

/// The argv for one unit: each word with every placeholder replaced by its text for that unit.
/// The words come from `hook.original`, so an option that the full form removes stays in place.
/// None when a placeholder cannot take the unit.
pub(crate) fn argv(hook: &Hook, unit: &str, root: &Path, cwd: &Path) -> Option<Vec<OsString>> {
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
                out.push(argument(root, cwd, unit, placeholder)?);
                at = end;
            }
            out.push(text.get(at..)?);
            Some(out)
        })
        .collect()
}

/// The launch for every unit of the roster, in roster order. None when any unit cannot be
/// expanded, and then the whole command runs its first-run form.
pub(crate) fn launches(
    hook: &Hook,
    units: &[String],
    root: &Path,
    cwd: &Path,
) -> Option<Vec<Launch>> {
    units
        .iter()
        .map(|unit| {
            Some(Launch {
                unit: unit.clone(),
                argv: argv(hook, unit, root, cwd)?,
                value: render(root, cwd, unit, Base::Cwd),
            })
        })
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
        assert!(!supported(&hook(&["t", "@{changed:file}"])));
        assert!(!supported(&hook(&["t", "{changed:nul}"])));
        assert!(!supported(&hook(&["t", "{changed-inputs}"])));
        assert!(!supported(&hook(&[
            "sh",
            "-c",
            "echo $STOOP_CHANGED",
            "sh"
        ])));
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
}
