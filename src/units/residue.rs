//! The residue of a suite (spec 3.8): the paths the whole command reads that no unit's own run reads. A unit's run is
//! judged by its own proof, so the residue is the work that only the whole command does. It is compared by path, and it
//! is stored provisional, because a path comparison cannot confirm it (C4, C5). W7 refuses a skip while the residue is
//! unknown or not empty; `stoop explain` names it.

use super::hook::safe;
use crate::input::Input;
use std::collections::BTreeSet;

/// How many residue paths a bundle stores: the first in sorted order. Its count still holds every path.
pub(crate) const STORED: usize = 32;

/// How many residue paths the explain line names.
const NAMED: usize = 5;

/// The residue of a whole proof: how many of its input paths no unit covers, and the first `STORED` of them in sorted
/// order. A path is covered when this run's catalog walk listed it (`listings`) or a unit's proof reads it (`covered`).
/// A path outside the root is compared by its absolute text, which is how the proof records it.
pub(crate) fn uncovered(
    whole: &[Input],
    listings: &[String],
    covered: &BTreeSet<&str>,
) -> (usize, Vec<String>) {
    let listed: BTreeSet<&str> = listings.iter().map(String::as_str).collect();
    let rest: BTreeSet<&str> = whole
        .iter()
        .map(|input| input.path.as_str())
        .filter(|path| !listed.contains(path) && !covered.contains(path))
        .collect();
    let paths = rest
        .iter()
        .take(STORED)
        .map(|path| (*path).to_owned())
        .collect();
    (rest.len(), paths)
}

/// The line `stoop explain` prints for a known, non-empty residue: its count, then the first paths it names.
pub(crate) fn line(count: usize, paths: &[String]) -> String {
    let noun = if count == 1 { "file" } else { "files" };
    let named: Vec<String> = paths.iter().take(NAMED).map(|path| safe(path)).collect();
    format!(
        "stoop: the full command reads {count} {noun} no unit's own run reads, such as {}; widen the filter or narrow the command",
        named.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(path: &str) -> Input {
        Input {
            path: path.into(),
            id: "f:00".into(),
            oid: None,
            oid_basis: None,
        }
    }

    #[test]
    fn a_listing_and_a_unit_input_are_covered_and_the_rest_is_residue() {
        let whole = [
            input("."),
            input("tests"),
            input("src/shared.src"),
            input("lint"),
            input("/usr/bin/od"),
        ];
        let listings = [".".to_owned(), "tests".to_owned()];
        let covered = BTreeSet::from(["src/shared.src"]);
        let (count, paths) = uncovered(&whole, &listings, &covered);
        assert_eq!(count, 2);
        assert_eq!(paths, ["/usr/bin/od", "lint"]);
    }

    #[test]
    fn the_stored_paths_are_the_first_in_sorted_order_and_the_count_holds_them_all() {
        let whole: Vec<Input> = (0..40).rev().map(|n| input(&format!("f/{n:02}"))).collect();
        let (count, paths) = uncovered(&whole, &[], &BTreeSet::new());
        assert_eq!(count, 40);
        assert_eq!(paths.len(), STORED);
        assert_eq!(paths.first().map(String::as_str), Some("f/00"));
        assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn the_line_names_at_most_five_paths_and_counts_every_one() {
        let paths: Vec<String> = ["a", "b", "c", "d", "e", "f"].map(String::from).to_vec();
        assert_eq!(
            line(6, &paths),
            "stoop: the full command reads 6 files no unit's own run reads, such as a, b, c, d, e; widen the filter or narrow the command"
        );
        assert_eq!(
            line(1, &paths[..1]),
            "stoop: the full command reads 1 file no unit's own run reads, such as a; widen the filter or narrow the command"
        );
    }

    #[test]
    fn the_line_shows_control_characters_as_text() {
        let text = line(1, &["a\nb".to_owned()]);
        assert!(text.contains("such as a\\u{a}b;"), "{text}");
    }
}
