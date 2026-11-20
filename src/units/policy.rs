//! Full verification is a one-way decision; branch data never authorizes publication.

use super::{config::Config, hook};
use serde::Deserialize;
use std::path::Path;

const MAX_EVENT_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) fn valid_branch(name: &str) -> bool {
    !name.is_empty()
        && name != "@"
        && !name.chars().any(char::is_control)
        && !name.starts_with('/')
        && !name.ends_with(['/', '.'])
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("@{")
        && !name
            .split('/')
            .any(|part| part.starts_with('.') || part.ends_with(".lock"))
        && !name
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || b"~^:?*[\\".contains(&byte))
}

struct Field<T> {
    present: bool,
    value: Option<T>,
}

impl<T> Default for Field<T> {
    fn default() -> Self {
        Self {
            present: false,
            value: None,
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            present: true,
            value: Option::<T>::deserialize(deserializer)?,
        })
    }
}

#[derive(Deserialize)]
struct EventPolicy {
    repository: EventRepository,
    #[serde(rename = "ref", default)]
    reference: Field<String>,
    #[serde(default)]
    number: Field<u64>,
    #[serde(default)]
    pull_request: Field<EventPullRequest>,
}

#[derive(Deserialize)]
struct EventRepository {
    default_branch: String,
}

#[derive(Deserialize)]
struct EventPullRequest {
    number: Option<u64>,
    head: Option<EventRef>,
    base: Option<EventRef>,
}

#[derive(Deserialize)]
struct EventRef {
    #[serde(rename = "ref")]
    name: String,
}

fn event_context() -> Option<EventPolicy> {
    let path = std::env::var_os("GITHUB_EVENT_PATH")?;
    let bytes = super::config::read_regular_bounded(Path::new(&path), MAX_EVENT_BYTES).ok()?;
    let event: EventPolicy = serde_json::from_slice(&bytes).ok()?;
    valid_branch(&event.repository.default_branch).then_some(event)
}

fn positive(text: &str) -> Option<u64> {
    text.parse::<u64>().ok().filter(|number| *number > 0)
}

fn is_default_branch(branch: &str, default: &str) -> bool {
    branch == default
}

fn agrees_if_present(name: &str, expected: &str) -> bool {
    std::env::var_os(name).is_none_or(|value| value == expected)
}

fn empty_if_present(name: &str) -> bool {
    std::env::var_os(name).is_none_or(|value| value.is_empty())
}

fn pull_ref(reference: &str) -> bool {
    let Some((number, kind)) = reference
        .strip_prefix("refs/pull/")
        .and_then(|tail| tail.split_once('/'))
    else {
        return false;
    };
    positive(number).is_some() && matches!(kind, "head" | "merge")
}

fn configured_default(config: &Config) -> Result<Option<String>, ()> {
    match std::env::var_os("STOOP_DEFAULT_BRANCH") {
        Some(value) => {
            let value = value.into_string().map_err(|_| ())?;
            if !valid_branch(&value) {
                return Err(());
            }
            Ok(Some(value))
        }
        None => Ok(config.default_branch.clone()),
    }
}

fn remote_name(sync: Option<&str>) -> Option<&str> {
    match sync {
        None | Some("git") | Some("git:") => Some("origin"),
        Some(value) => value.strip_prefix("git:"),
    }
}

fn context_branch(name: &str) -> Result<Option<String>, ()> {
    match std::env::var_os(name) {
        Some(value) => {
            let value = value.into_string().map_err(|_| ())?;
            if valid_branch(&value) {
                Ok(Some(value))
            } else {
                Err(())
            }
        }
        None => Ok(None),
    }
}

fn consistent_context(names: &[&str]) -> Result<Option<String>, ()> {
    let mut found = None;
    for name in names {
        if let Some(value) = context_branch(name)? {
            if found.as_ref().is_some_and(|previous| previous != &value) {
                return Err(());
            }
            found = Some(value);
        }
    }
    Ok(found)
}

/// Return why a hooked run must ignore a matching whole-command proof, if any.
pub(crate) fn forced_reason(
    root: &Path,
    config: &Config,
    sync: Option<&str>,
    sync_write: bool,
) -> Option<String> {
    if sync_write {
        return Some("sync writer".into());
    }
    if let Some(every) = config.verify_every {
        let ordinal = match std::env::var_os("STOOP_RUN_NUMBER") {
            Some(value) => value.to_str().and_then(positive),
            None if std::env::var_os("GITHUB_ACTIONS").is_some() => {
                std::env::var("GITHUB_RUN_NUMBER")
                    .ok()
                    .as_deref()
                    .and_then(positive)
            }
            None => None,
        };
        match ordinal {
            Some(number) if number % every == 0 => {
                return Some(format!("verify_every {every}: run {number}"));
            }
            Some(_) => {}
            None => return Some("no run number for verify_every".into()),
        }
    }
    let ci = std::env::var_os("CI").is_some();
    let github = std::env::var_os("GITHUB_ACTIONS").is_some();
    let configured = match configured_default(config) {
        Ok(value) => value,
        Err(()) => return Some("unknown default branch".into()),
    };
    let remote_default = if root.join(".git").exists() {
        remote_name(sync).and_then(|remote| crate::gitprobe::remote_head_branch(root, remote))
    } else {
        None
    };
    if github {
        let Some(EventPolicy {
            repository: EventRepository {
                default_branch: default,
            },
            reference: payload_ref,
            number: payload_number,
            pull_request: pull,
        }) = event_context()
        else {
            return Some("unknown GitHub branch context".into());
        };
        if configured.as_ref().is_some_and(|branch| branch != &default)
            || (ci
                && remote_default
                    .as_ref()
                    .is_some_and(|branch| branch != &default))
            || (ci
                && std::env::var("STOOP_DEFAULT_BRANCH")
                    .ok()
                    .zip(config.default_branch.as_ref())
                    .is_some_and(|(a, b)| a != *b))
        {
            return Some("conflicting default branch context".into());
        }
        let event = std::env::var("GITHUB_EVENT_NAME").ok();
        let reference = std::env::var("GITHUB_REF").ok();
        if payload_ref.present && payload_ref.value.as_deref() != reference.as_deref() {
            return Some("conflicting GitHub branch context".into());
        }
        match (event.as_deref(), reference.as_deref()) {
            (Some("push"), Some(reference)) => {
                if payload_number.present || pull.present {
                    return Some("conflicting GitHub event kind".into());
                }
                let Some(branch) = reference
                    .strip_prefix("refs/heads/")
                    .filter(|name| valid_branch(name))
                else {
                    return Some("unknown GitHub branch context".into());
                };
                if !agrees_if_present("GITHUB_REF_NAME", branch)
                    || !agrees_if_present("GITHUB_REF_TYPE", "branch")
                    || !empty_if_present("GITHUB_HEAD_REF")
                    || !empty_if_present("GITHUB_BASE_REF")
                {
                    return Some("conflicting GitHub branch context".into());
                }
                return is_default_branch(branch, &default)
                    .then(|| format!("default branch {}", hook::safe(&default)));
            }
            (Some("pull_request" | "pull_request_target"), Some(reference))
                if pull_ref(reference) =>
            {
                let name = reference.strip_prefix("refs/pull/").unwrap_or_default();
                let number = name
                    .split_once('/')
                    .and_then(|(number, _)| positive(number));
                if pull.present && pull.value.is_none() {
                    return Some("conflicting GitHub pull request context".into());
                }
                let pull = pull.value.as_ref();
                if (payload_number.present && payload_number.value != number)
                    || pull
                        .and_then(|p| p.number)
                        .is_some_and(|value| Some(value) != number)
                    || (std::env::var_os("GITHUB_HEAD_REF").is_some()
                        && pull.and_then(|p| p.head.as_ref()).is_none())
                    || (std::env::var_os("GITHUB_BASE_REF").is_some()
                        && pull.and_then(|p| p.base.as_ref()).is_none())
                    || pull.is_some_and(|p| {
                        if p.number.is_none() || p.head.is_none() || p.base.is_none() {
                            return true;
                        }
                        p.head.as_ref().is_some_and(|head| {
                            !valid_branch(&head.name)
                                || !agrees_if_present("GITHUB_HEAD_REF", &head.name)
                        }) || p.base.as_ref().is_some_and(|base| {
                            !valid_branch(&base.name)
                                || !agrees_if_present("GITHUB_BASE_REF", &base.name)
                        })
                    })
                {
                    return Some("conflicting GitHub pull request context".into());
                }
                if !agrees_if_present("GITHUB_REF_NAME", name)
                    || !agrees_if_present("GITHUB_REF_TYPE", "branch")
                {
                    return Some("conflicting GitHub branch context".into());
                }
                return None;
            }
            _ => return Some("unknown GitHub branch context".into()),
        }
    }
    if !root.join(".git").exists() {
        return ci.then(|| "unknown CI branch context".into());
    }
    let local = crate::gitprobe::head_branch(root);
    let (provider_branch, provider_default) = if ci {
        let current =
            consistent_context(&["CI_COMMIT_BRANCH", "BUILDKITE_BRANCH", "CIRCLE_BRANCH"]);
        let default =
            consistent_context(&["CI_DEFAULT_BRANCH", "BUILDKITE_PIPELINE_DEFAULT_BRANCH"]);
        match (current, default) {
            (Ok(Some(current)), Ok(default))
                if local.as_ref().is_none_or(|head| head == &current) =>
            {
                (Some(current), default)
            }
            _ => return Some("unknown or conflicting CI branch context".into()),
        }
    } else {
        (None, None)
    };
    let defaults = [
        configured.as_deref(),
        config.default_branch.as_deref(),
        provider_default.as_deref(),
        remote_default.as_deref(),
    ];
    if ci {
        let mut seen = None;
        for default in defaults.into_iter().flatten() {
            if seen.is_some_and(|previous| previous != default) {
                return Some("conflicting default branch context".into());
            }
            seen = Some(default);
        }
    }
    let Some(branch) = provider_branch.or(local) else {
        return Some("unknown branch context".into());
    };
    let mut known = false;
    for default in defaults.into_iter().flatten() {
        known = true;
        if is_default_branch(&branch, default) {
            return Some(format!("default branch {}", hook::safe(default)));
        }
    }
    (!known).then(|| "unknown branch context".into())
}
