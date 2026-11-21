//! Root-relative unit filters. Matching uses UTF-8 bytes on every platform.

/// Maximum filter text and pattern count accepted for catalog discovery.
pub(crate) const MAX_FILTER_BYTES: usize = 32 * 1024;
pub(crate) const MAX_FILTER_PATTERNS: usize = 1024;
/// Maximum matcher state updates across one catalog scan.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const MATCH_WORK_BUDGET: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Filter {
    text: String,
    patterns: Vec<Pattern>,
    problem: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pattern {
    exclude: bool,
    anchored: bool,
    directory: bool,
    tokens: Vec<Token>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Byte(u8),
    Any,
    Star,
    GlobStar,
    GlobStarSlash,
    Class {
        negated: bool,
        ranges: Vec<(u8, u8)>,
    },
}

impl Filter {
    /// The hook parser has already checked separators, escaping and brackets.
    pub(crate) fn inline(text: &str) -> Self {
        if text.len() > MAX_FILTER_BYTES {
            return Self {
                text: text.to_owned(),
                patterns: Vec::new(),
                problem: Some("unit filter exceeds the size limit"),
            };
        }
        let mut parts = Vec::new();
        let mut start = 0;
        let mut escaped = false;
        let mut bracket = false;
        for (index, byte) in text.bytes().enumerate() {
            if escaped {
                escaped = false;
            } else {
                match byte {
                    b'\\' => escaped = true,
                    b'[' => bracket = true,
                    b']' => bracket = false,
                    b'|' if !bracket => {
                        parts.push(&text[start..index]);
                        if parts.len() >= MAX_FILTER_PATTERNS {
                            return Self {
                                text: text.to_owned(),
                                patterns: Vec::new(),
                                problem: Some("unit filter has too many patterns"),
                            };
                        }
                        start = index + 1;
                    }
                    _ => {}
                }
            }
        }
        parts.push(&text[start..]);
        if parts.len() > MAX_FILTER_PATTERNS {
            return Self {
                text: text.to_owned(),
                patterns: Vec::new(),
                problem: Some("unit filter has too many patterns"),
            };
        }
        Self::new(text.to_owned(), parts.into_iter())
    }

    /// Configuration already validated each array element as a pattern.
    pub(crate) fn configured(patterns: &[String]) -> Self {
        let size = patterns
            .iter()
            .try_fold(0usize, |sum, p| sum.checked_add(p.len()))
            .and_then(|sum| sum.checked_add(patterns.len().saturating_sub(1)));
        if patterns.len() > MAX_FILTER_PATTERNS || size.is_none_or(|n| n > MAX_FILTER_BYTES) {
            return Self {
                text: String::new(),
                patterns: Vec::new(),
                problem: Some("configured unit filter exceeds its size or pattern limit"),
            };
        }
        Self::new(patterns.join("|"), patterns.iter().map(String::as_str))
    }

    fn new<'a>(text: String, patterns: impl Iterator<Item = &'a str>) -> Self {
        let patterns: Vec<Pattern> = patterns.map(Pattern::compile).collect();
        let problem = patterns
            .iter()
            .flat_map(|pattern| &pattern.tokens)
            .any(|token| matches!(token, Token::Class { ranges, .. } if ranges.is_empty()))
            .then_some("unit filter has an empty character class");
        Self {
            text,
            patterns,
            problem,
        }
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn exclusion_only(&self) -> bool {
        if self.problem.is_none() {
            return !self.patterns.is_empty()
                && self.patterns.iter().all(|pattern| pattern.exclude);
        }
        let bytes = self.text.as_bytes();
        let mut start = 0;
        let mut escaped = false;
        let mut class = false;
        for (index, &byte) in bytes.iter().enumerate() {
            if escaped {
                escaped = false;
            } else {
                match byte {
                    b'\\' => escaped = true,
                    b'[' => class = true,
                    b']' => class = false,
                    b'|' if !class => {
                        if bytes.get(start) != Some(&b'!') {
                            return false;
                        }
                        start = index + 1;
                    }
                    _ => {}
                }
            }
        }
        bytes.get(start) == Some(&b'!')
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn starts_with_exclusion(&self) -> bool {
        self.patterns.first().is_some_and(|pattern| pattern.exclude)
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        self.problem.map_or(Ok(()), Err)
    }

    pub(crate) fn matches(&self, path: &str, is_dir: bool) -> bool {
        self.matches_with_default(path, is_dir, true)
    }

    /// A leading exclusion starts with the supplied default universe.
    pub(crate) fn matches_with_default(&self, path: &str, is_dir: bool, default: bool) -> bool {
        let mut budget = usize::MAX;
        self.matches_counted(path, is_dir, default, &mut budget)
            .unwrap_or(false)
    }

    pub(crate) fn matches_counted(
        &self,
        path: &str,
        is_dir: bool,
        default: bool,
        budget: &mut usize,
    ) -> Result<bool, &'static str> {
        self.validate()?;
        let path = if is_dir {
            path.trim_end_matches('/')
        } else {
            path
        };
        if path.len() > 4096 {
            return Ok(false);
        }
        let mut states = [false; 4097];
        let mut included = self.patterns.first().is_some_and(|p| p.exclude) && default;
        for pattern in &self.patterns {
            if pattern.matches(path.as_bytes(), is_dir, &mut states, budget)? {
                included = !pattern.exclude;
            }
        }
        Ok(included)
    }
}

impl Pattern {
    fn compile(text: &str) -> Self {
        let (exclude, text) = match text.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let bytes = text.as_bytes();
        let backslashes = bytes[..bytes.len().saturating_sub(1)]
            .iter()
            .rev()
            .take_while(|&&byte| byte == b'\\')
            .count();
        let directory = text.ends_with('/') && backslashes % 2 == 0;
        let text = if directory {
            &text[..text.len() - 1]
        } else {
            text
        };
        let anchored = text.contains('/');
        let text = text.strip_prefix('/').unwrap_or(text);
        let bytes = text.as_bytes();
        let mut tokens = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'\\' if index + 1 < bytes.len() => {
                    tokens.push(Token::Byte(bytes[index + 1]));
                    index += 2;
                }
                b'?' => {
                    tokens.push(Token::Any);
                    index += 1;
                }
                b'*' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    if bytes.get(index) == Some(&b'/')
                        && (tokens.is_empty() || matches!(tokens.last(), Some(Token::Byte(b'/'))))
                    {
                        tokens.push(Token::GlobStarSlash);
                        index += 1;
                    } else {
                        tokens.push(Token::GlobStar);
                    }
                }
                b'*' => {
                    tokens.push(Token::Star);
                    index += 1;
                }
                b'[' => {
                    let (token, next) = Self::class(bytes, index + 1);
                    tokens.push(token);
                    index = next;
                }
                byte => {
                    tokens.push(Token::Byte(byte));
                    index += 1;
                }
            }
        }
        Self {
            exclude,
            anchored,
            directory,
            tokens,
        }
    }

    fn class(bytes: &[u8], mut index: usize) -> (Token, usize) {
        let negated = matches!(bytes.get(index), Some(b'!' | b'^'));
        if negated {
            index += 1;
        }
        let mut chars = Vec::new();
        while index < bytes.len() && bytes[index] != b']' {
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                chars.push((bytes[index + 1], true));
                index += 2;
            } else {
                chars.push((bytes[index], false));
                index += 1;
            }
        }
        let mut ranges = Vec::new();
        let mut at = 0;
        while at < chars.len() {
            if at + 2 < chars.len() && chars[at + 1] == (b'-', false) {
                ranges.push((chars[at].0, chars[at + 2].0));
                at += 3;
            } else {
                ranges.push((chars[at].0, chars[at].0));
                at += 1;
            }
        }
        (
            Token::Class { negated, ranges },
            (index + 1).min(bytes.len()),
        )
    }

    fn matches(
        &self,
        path: &[u8],
        is_dir: bool,
        states: &mut [bool; 4097],
        budget: &mut usize,
    ) -> Result<bool, &'static str> {
        if self.directory && !is_dir {
            return Ok(false);
        }
        let path = if self.anchored {
            path
        } else {
            path.rsplit(|byte| *byte == b'/').next().unwrap_or(path)
        };
        let n = path.len();
        states[..=n].fill(false);
        states[0] = true;
        for token in &self.tokens {
            let factor = match token {
                Token::Class { ranges, .. } => ranges.len().max(1),
                _ => 1,
            };
            let cost = (n + 1)
                .checked_mul(factor)
                .ok_or("unit filter work budget exceeded")?;
            *budget = budget
                .checked_sub(cost)
                .ok_or("unit filter work budget exceeded")?;
            if !states[..=n].iter().any(|state| *state) {
                return Ok(false);
            }
            match token {
                Token::Star | Token::GlobStar => {
                    for i in 1..=n {
                        states[i] |= states[i - 1]
                            && (matches!(token, Token::GlobStar) || path[i - 1] != b'/');
                    }
                }
                Token::GlobStarSlash => {
                    let mut seen = false;
                    for i in 0..n {
                        seen |= states[i];
                        if seen && path[i] == b'/' {
                            states[i + 1] = true;
                        }
                    }
                }
                other => {
                    for i in (1..=n).rev() {
                        let byte = path[i - 1];
                        let accepts = match other {
                            Token::Byte(expected) => byte == *expected,
                            Token::Any => byte != b'/',
                            Token::Class { negated, ranges } => {
                                byte != b'/'
                                    && (ranges.iter().any(|&(a, b)| a <= byte && byte <= b)
                                        != *negated)
                            }
                            _ => unreachable!(),
                        };
                        states[i] = states[i - 1] && accepts;
                    }
                    states[0] = false;
                }
            }
        }
        Ok(states[n])
    }
}

#[cfg(test)]
mod tests {
    use super::Filter;

    #[test]
    fn stars_never_let_a_single_star_cross_a_slash() {
        let f = Filter::inline("tests/*.t");
        assert!(f.matches("tests/a.t", false));
        assert!(!f.matches("tests/sub/a.t", false));
    }

    #[test]
    fn question_mark_matches_one_byte_but_not_a_slash() {
        let f = Filter::inline("a/tests?x.t");
        assert!(f.matches("a/testsXx.t", false));
        assert!(!f.matches("a/tests/x.t", false));
    }

    #[test]
    fn slash_anchors_at_root_but_basename_patterns_match_any_depth() {
        assert!(!Filter::inline("tests/*.t").matches("sub/tests/a.t", false));
        assert!(Filter::inline("*.t").matches("sub/tests/a.t", false));
        assert!(Filter::inline("/tests/*.t").matches("tests/a.t", false));
    }

    #[test]
    fn matches_are_case_sensitive_and_byte_wise() {
        assert!(!Filter::inline("*.t").matches("A.T", false));
        assert!(!Filter::inline("?.t").matches("é.t", false));
        assert!(Filter::inline("??.t").matches("é.t", false));
    }

    #[test]
    fn the_last_matching_pattern_wins() {
        let f = Filter::inline("**/*.t|!tests/**|tests/a.t");
        assert!(f.matches("tests/a.t", false));
        assert!(!f.matches("tests/b.t", false));
        assert!(f.matches("other/c.t", false));
        assert!(!Filter::inline("!tests/**").matches("tests/a.t", false));
        assert!(Filter::inline("!tests/**").matches("other/a.t", false));
    }

    #[test]
    fn escapes_and_classes_are_matched_literally() {
        assert!(Filter::inline(r"**/literal\*.t").matches("sub/literal*.t", false));
        assert!(!Filter::inline(r"**/literal\*.t").matches("sub/literalX.t", false));
        assert!(Filter::inline("tests/[a-c]?.t").matches("tests/b1.t", false));
        assert!(!Filter::inline("tests/[!a-c]?.t").matches("tests/b1.t", false));
        assert!(Filter::inline(r"\!literal.t").matches("!literal.t", false));
    }

    #[test]
    fn double_star_slash_matches_zero_or_more_directories() {
        let f = Filter::inline("**/*.t");
        assert!(f.matches("a.t", false));
        assert!(f.matches("sub/a.t", false));
        let f = Filter::inline("tests/**/a.t");
        assert!(f.matches("tests/a.t", false));
        assert!(f.matches("tests/sub/a.t", false));
        assert!(Filter::inline("tests/**").matches("tests/sub/a.t", false));
    }

    #[test]
    fn trailing_slash_matches_directories_only() {
        let f = Filter::inline("tests/");
        assert!(f.matches("tests/", true));
        assert!(!f.matches("tests", false));
        assert!(!f.matches("tests/a.t", false));
    }

    #[test]
    fn trailing_separator_obeys_backslash_escape_parity() {
        let even = Filter::inline(r"dir\\/");
        assert!(even.matches("dir\\/", true));
        assert!(!even.matches("dir\\", false));
        let odd = Filter::inline(r"dir\/");
        assert!(!odd.matches("dir/", true));
    }
}
