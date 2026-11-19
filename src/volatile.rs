//! Environment variables that change on every run are not inputs.
//!
//! The environment counts as an input because a variable read never shows up in a file trace.
//! Some variables change on every run or on every commit and say nothing about what a command
//! produces. Two sources exclude them, and the command text overrules both:
//!
//! - the curated table below, for variables that a shell, a terminal, a multiplexer or a CI
//!   provider documents as per run, per session or per commit;
//! - the learner, which excludes a variable from one proof key once its opaque value has changed
//!   on each of the last recorded runs of that key, and never repeated within the window.
//!
//! A name the command text mentions always counts, and so does a name given with `--env`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// One reason and the names it covers. `names` match exactly; `prefixes` match by their start.
pub struct Group {
    pub why: &'static str,
    /// Where the names were read, or why none could be.
    pub source: &'static str,
    pub names: &'static [&'static str],
    pub prefixes: &'static [&'static str],
}

// Each group names one kind of per-run, per-session or per-commit value. A name is here only if
// its meaning is documented as such, or if the group's source line says that none could be read.
// Branch and tag names are not here: a script may branch on them, and they do not change per commit.
pub const GROUPS: &[Group] = &[
    Group {
        why: "shell clock or counter",
        source: "bash: https://tiswww.case.edu/php/chet/bash/bashref.html ; zsh: https://zsh.sourceforge.io/Doc/Release/Parameters.html and https://zsh.sourceforge.io/Doc/Release/Zsh-Modules.html ; fish: https://fishshell.com/docs/current/language.html",
        names: &[
            "RANDOM",
            "SRANDOM",
            "SECONDS",
            "EPOCHSECONDS",
            "EPOCHREALTIME",
            "BASHPID",
            "PPID",
            "COLUMNS",
            "LINES",
            "CMD_DURATION",
        ],
        prefixes: &[],
    },
    Group {
        why: "terminal or multiplexer session",
        source: "tmux TMUX and TMUX_PANE: https://man.openbsd.org/tmux ; GNU screen STY: https://www.gnu.org/software/screen/manual/screen.html ; xterm WINDOWID: https://invisible-island.net/xterm/manpage/xterm.html ; kitty KITTY_WINDOW_ID: https://sw.kovidgoyal.net/kitty/remote-control/ ; zellij ZELLIJ_SESSION_NAME: https://zellij.dev/documentation/integration",
        names: &[
            "TMUX",
            "TMUX_PANE",
            "STY",
            "WINDOWID",
            "KITTY_WINDOW_ID",
            "ZELLIJ_SESSION_NAME",
        ],
        prefixes: &[],
    },
    Group {
        why: "terminal session",
        source: "named as per session by the owner (2026-11-18); no public reference was readable for these",
        names: &[
            "ZELLIJ_PANE_ID",
            "TERM_SESSION_ID",
            "ITERM_SESSION_ID",
            "WT_SESSION",
            "WEZTERM_PANE",
            "ALACRITTY_SOCKET",
            "ALACRITTY_LOG",
            "GNOME_TERMINAL_SCREEN",
            "KONSOLE_DBUS_SESSION",
            "KONSOLE_DBUS_WINDOW",
        ],
        prefixes: &[],
    },
    Group {
        why: "login or SSH session",
        source: "XDG_SESSION_ID, XDG_VTNR: https://www.freedesktop.org/software/systemd/man/latest/pam_systemd.html ; SSH_AGENT_PID: https://man.openbsd.org/ssh-agent ; DBUS_SESSION_BUS_ADDRESS: https://dbus.freedesktop.org/doc/dbus-specification.html ; SSH_CONNECTION, SSH_CLIENT, SSH_TTY, GPG_AGENT_INFO: named as per session by the owner; no public reference was readable",
        names: &[
            "XDG_SESSION_ID",
            "XDG_VTNR",
            "SSH_AGENT_PID",
            "DBUS_SESSION_BUS_ADDRESS",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "SSH_TTY",
            "GPG_AGENT_INFO",
        ],
        prefixes: &[],
    },
    Group {
        why: "editor window socket",
        source: "named as per window by the owner (2026-11-18); no public reference was readable",
        names: &["VSCODE_IPC_HOOK_CLI", "VSCODE_GIT_IPC_HANDLE"],
        prefixes: &[],
    },
    Group {
        why: "macOS login session or launch",
        source: "named by the owner (2026-11-18); Apple publishes no reference for these names",
        names: &[
            "SECURITYSESSIONID",
            "Apple_PubSub_Socket_Render",
            "LaunchInstanceID",
            "XPC_SERVICE_NAME",
        ],
        prefixes: &[],
    },
    Group {
        why: "GitLab per-job or per-pipeline value",
        source: "https://docs.gitlab.com/ci/variables/predefined_variables/",
        names: &[
            "CI_JOB_ID",
            "CI_JOB_URL",
            "CI_JOB_STARTED_AT",
            "CI_JOB_STARTED_AT_SLUG",
            "CI_CONCURRENT_ID",
            "CI_CONCURRENT_PROJECT_ID",
            "CI_BUILD_NETWORK_NAME",
            "CI_PIPELINE_ID",
            "CI_PIPELINE_IID",
            "CI_PIPELINE_URL",
            "CI_PIPELINE_CREATED_AT",
        ],
        prefixes: &[],
    },
    Group {
        why: "GitLab runner identity",
        source: "https://docs.gitlab.com/ci/variables/predefined_variables/",
        names: &["CI_RUNNER_ID", "CI_RUNNER_DESCRIPTION", "CI_RUNNER_SHORT_TOKEN"],
        prefixes: &[],
    },
    Group {
        why: "GitLab per-commit value",
        source: "https://docs.gitlab.com/ci/variables/predefined_variables/",
        names: &[
            "CI_COMMIT_SHA",
            "CI_COMMIT_SHORT_SHA",
            "CI_COMMIT_BEFORE_SHA",
            "CI_COMMIT_TIMESTAMP",
            "CI_COMMIT_MESSAGE",
            "CI_COMMIT_MESSAGE_IS_TRUNCATED",
            "CI_COMMIT_TITLE",
            "CI_COMMIT_DESCRIPTION",
            "CI_COMMIT_AUTHOR",
            "CI_COMMIT_USER_LOGIN",
            "CI_COMMIT_DEFAULT_BRANCH_BASE_SHA",
            "CI_MERGE_REQUEST_DIFF_BASE_SHA",
            "CI_MERGE_REQUEST_PIPELINE_BASE_SHA",
            "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA",
            "CI_MERGE_REQUEST_TARGET_BRANCH_SHA",
            "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA",
            "CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_SHA",
        ],
        prefixes: &[],
    },
    Group {
        why: "rotating CI job credential",
        source: "GitLab CI_JOB_TOKEN (valid while the job runs), CI_REGISTRY_PASSWORD (equal to CI_JOB_TOKEN), CI_REPOSITORY_URL (embeds CI_JOB_TOKEN): https://docs.gitlab.com/ci/variables/predefined_variables/ ; CircleCI OIDC tokens: https://circleci.com/docs/variables/ ; Bitbucket step OIDC token: https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/ ; Azure SYSTEM_ACCESSTOKEN: https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables",
        names: &[
            "CI_JOB_TOKEN",
            "CI_REGISTRY_PASSWORD",
            "CI_REPOSITORY_URL",
            "CIRCLE_OIDC_TOKEN",
            "CIRCLE_OIDC_TOKEN_V2",
            "CIRCLE_OIDC_TOKEN_V3",
            "BITBUCKET_STEP_OIDC_TOKEN",
            "SYSTEM_ACCESSTOKEN",
        ],
        prefixes: &[],
    },
    Group {
        why: "AWS session credential",
        source: "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html",
        names: &["AWS_SESSION_TOKEN"],
        prefixes: &[],
    },
    Group {
        why: "Buildkite per-build, per-job or per-agent value",
        source: "https://buildkite.com/docs/pipelines/environment-variables",
        names: &[
            "BUILDKITE_BUILD_ID",
            "BUILDKITE_BUILD_NUMBER",
            "BUILDKITE_BUILD_URL",
            "BUILDKITE_BUILD_AUTHOR",
            "BUILDKITE_BUILD_AUTHOR_EMAIL",
            "BUILDKITE_BUILD_CREATOR",
            "BUILDKITE_BUILD_CREATOR_EMAIL",
            "BUILDKITE_COMMIT",
            "BUILDKITE_COMMIT_RESOLVED",
            "BUILDKITE_MESSAGE",
            "BUILDKITE_MERGE_QUEUE_BASE_COMMIT",
            "BUILDKITE_JOB_ID",
            "BUILDKITE_JOB_LOG_TMPFILE",
            "BUILDKITE_GROUP_ID",
            "BUILDKITE_REBUILT_FROM_BUILD_ID",
            "BUILDKITE_REBUILT_FROM_BUILD_NUMBER",
            "BUILDKITE_TRIGGERED_FROM_BUILD_ID",
            "BUILDKITE_TRIGGERED_FROM_BUILD_NUMBER",
            "BUILDKITE_GITHUB_DEPLOYMENT_ID",
            "BUILDKITE_GITHUB_COMMENT_ID",
            "BUILDKITE_GITHUB_REVIEW_ID",
            "BUILDKITE_ORIGIN_REVIEW_ID",
            "BUILDKITE_AGENT_ID",
            "BUILDKITE_AGENT_NAME",
            "BUILDKITE_AGENT_PID",
        ],
        prefixes: &[],
    },
    Group {
        why: "CircleCI per-job, per-pipeline or per-workflow value",
        source: "https://circleci.com/docs/variables/",
        names: &[
            "CIRCLE_BUILD_NUM",
            "CIRCLE_BUILD_URL",
            "CIRCLE_COMPARE_URL",
            "CIRCLE_PIPELINE_ID",
            "CIRCLE_SHA1",
            "CIRCLE_USERNAME",
            "CIRCLE_WORKFLOW_ID",
            "CIRCLE_WORKFLOW_JOB_ID",
            "CIRCLE_WORKFLOW_WORKSPACE_ID",
        ],
        prefixes: &[],
    },
    Group {
        why: "Travis per-build or per-job value",
        source: "https://docs.travis-ci.com/user/environment-variables/",
        names: &[
            "TRAVIS_BUILD_ID",
            "TRAVIS_BUILD_NUMBER",
            "TRAVIS_BUILD_WEB_URL",
            "TRAVIS_COMMIT",
            "TRAVIS_COMMIT_MESSAGE",
            "TRAVIS_COMMIT_RANGE",
            "TRAVIS_PULL_REQUEST_SHA",
            "TRAVIS_JOB_ID",
            "TRAVIS_JOB_NUMBER",
            "TRAVIS_JOB_WEB_URL",
            "TRAVIS_JOB_RESTARTED_BY",
        ],
        prefixes: &[],
    },
    Group {
        why: "Jenkins or TeamCity per-build value",
        source: "Jenkins: https://www.jenkins.io/doc/book/pipeline/jenkinsfile/ ; TeamCity: https://www.jetbrains.com/help/teamcity/predefined-build-parameters.html",
        names: &["BUILD_ID", "BUILD_NUMBER", "BUILD_TAG", "BUILD_URL"],
        prefixes: &[],
    },
    Group {
        why: "Jenkins executor identity",
        source: "https://www.jenkins.io/doc/book/pipeline/jenkinsfile/",
        names: &["EXECUTOR_NUMBER", "NODE_NAME"],
        prefixes: &[],
    },
    Group {
        why: "Azure Pipelines per-build, per-job or per-agent value",
        source: "https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables",
        names: &[
            "BUILD_BUILDID",
            "BUILD_BUILDNUMBER",
            "BUILD_SOURCEVERSION",
            "BUILD_SOURCEVERSIONMESSAGE",
            "BUILD_REQUESTEDFOR",
            "BUILD_REQUESTEDFOREMAIL",
            "BUILD_REQUESTEDFORID",
            "BUILD_QUEUEDBY",
            "SYSTEM_JOBID",
            "SYSTEM_PULLREQUEST_SOURCECOMMITID",
            "AGENT_ID",
            "AGENT_NAME",
            "AGENT_MACHINENAME",
        ],
        prefixes: &[],
    },
    Group {
        why: "Drone per-build, per-stage or per-commit value",
        source: "https://docs.drone.io/pipeline/environment/reference/",
        names: &[
            "DRONE_BUILD_NUMBER",
            "DRONE_BUILD_CREATED",
            "DRONE_BUILD_STARTED",
            "DRONE_BUILD_FINISHED",
            "DRONE_BUILD_LINK",
            "DRONE_BUILD_PARENT",
            "DRONE_STAGE_STARTED",
            "DRONE_STAGE_FINISHED",
            "DRONE_COMMIT",
            "DRONE_COMMIT_SHA",
            "DRONE_COMMIT_BEFORE",
            "DRONE_COMMIT_AFTER",
            "DRONE_COMMIT_AUTHOR",
            "DRONE_COMMIT_AUTHOR_AVATAR",
            "DRONE_COMMIT_AUTHOR_EMAIL",
            "DRONE_COMMIT_AUTHOR_NAME",
            "DRONE_COMMIT_LINK",
            "DRONE_COMMIT_MESSAGE",
        ],
        prefixes: &[],
    },
    Group {
        why: "Bitbucket per-run or per-step value",
        source: "https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/",
        names: &[
            "BITBUCKET_BUILD_NUMBER",
            "BITBUCKET_COMMIT",
            "BITBUCKET_PR_DESTINATION_COMMIT",
            "BITBUCKET_PIPELINE_UUID",
            "BITBUCKET_STEP_UUID",
            "BITBUCKET_STEP_RUN_NUMBER",
            "BITBUCKET_STEP_TRIGGERER_UUID",
            "BITBUCKET_MERGE_QUEUE_PR_IDS",
            "BITBUCKET_TRIGGER_PIPELINE_RUN_UUID",
            "BITBUCKET_TRIGGER_PIPELINE_UUID",
            "BITBUCKET_TRIGGER_STEP_UUID",
            "BITBUCKET_TRIGGER_DEPLOYMENT_UUID",
            "BITBUCKET_TRIGGER_TEST_CASE_UUID",
        ],
        prefixes: &[],
    },
    Group {
        why: "AWS CodeBuild per-build or per-commit value",
        source: "https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html",
        names: &[
            "CODEBUILD_BUILD_ID",
            "CODEBUILD_BUILD_ARN",
            "CODEBUILD_BUILD_NUMBER",
            "CODEBUILD_BUILD_URL",
            "CODEBUILD_PUBLIC_BUILD_URL",
            "CODEBUILD_BATCH_BUILD_IDENTIFIER",
            "CODEBUILD_INITIATOR",
            "CODEBUILD_START_TIME",
            "CODEBUILD_SOURCE_VERSION",
            "CODEBUILD_RESOLVED_SOURCE_VERSION",
            "CODEBUILD_WEBHOOK_PREV_COMMIT",
        ],
        prefixes: &[],
    },
    Group {
        why: "Semaphore per-workflow, per-pipeline, per-job or per-commit value",
        source: "https://docs.semaphore.io/ci-cd-environment/environment-variables",
        names: &[
            "SEMAPHORE_WORKFLOW_ID",
            "SEMAPHORE_WORKFLOW_NUMBER",
            "SEMAPHORE_PIPELINE_ID",
            "SEMAPHORE_JOB_ID",
            "SEMAPHORE_GIT_SHA",
            "SEMAPHORE_GIT_COMMIT_RANGE",
            "SEMAPHORE_GIT_COMMITTER",
            "SEMAPHORE_GIT_COMMIT_AUTHOR",
            "SEMAPHORE_GIT_PR_SHA",
        ],
        prefixes: &[],
    },
    Group {
        why: "AppVeyor per-build, per-job or per-commit value",
        source: "https://www.appveyor.com/docs/environment-variables/",
        names: &[
            "APPVEYOR_BUILD_ID",
            "APPVEYOR_BUILD_NUMBER",
            "APPVEYOR_BUILD_VERSION",
            "APPVEYOR_JOB_ID",
            "APPVEYOR_JOB_NUMBER",
            "APPVEYOR_REPO_COMMIT",
            "APPVEYOR_REPO_COMMIT_AUTHOR",
            "APPVEYOR_REPO_COMMIT_AUTHOR_EMAIL",
            "APPVEYOR_REPO_COMMIT_MESSAGE",
            "APPVEYOR_REPO_COMMIT_MESSAGE_EXTENDED",
            "APPVEYOR_REPO_COMMIT_TIMESTAMP",
            "APPVEYOR_PULL_REQUEST_HEAD_COMMIT",
        ],
        prefixes: &[],
    },
    Group {
        why: "GoCD per-run counter, label or revision",
        source: "https://docs.gocd.org/current/faq/dev_use_current_revision_in_build.html",
        names: &[
            "GO_PIPELINE_COUNTER",
            "GO_PIPELINE_LABEL",
            "GO_STAGE_COUNTER",
            "GO_REVISION",
            "GO_FROM_REVISION",
            "GO_TO_REVISION",
            "GO_TRIGGER_USER",
        ],
        prefixes: &[
            "GO_REVISION_",
            "GO_FROM_REVISION_",
            "GO_TO_REVISION_",
            "GO_DEPENDENCY_LABEL_",
        ],
    },
];

/// The curated reason a name is excluded, or `None` when it is not a curated name. A name that is
/// not UTF-8 can match none of them, because every curated name is ASCII.
pub fn curated_reason(name: &str) -> Option<&'static str> {
    GROUPS
        .iter()
        .find(|group| {
            group.names.contains(&name) || group.prefixes.iter().any(|p| name.starts_with(p))
        })
        .map(|group| group.why)
}

/// A name the command text mentions always counts, matched by its text in the command.
pub fn mentioned(name: &OsStr, mention: &str) -> bool {
    let name = name.to_string_lossy();
    !name.is_empty() && mention.contains(name.as_ref())
}

/// Names the learner never excludes. They are behavioural or path-like settings that a command
/// can depend on, even when a value looks opaque. The list is conservative on purpose: a miss only
/// costs a re-run.
pub fn never_learn(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TZ", "CI", "DEBUG", "CC", "CXX", "AR",
        "LD", "PWD", "OLDPWD", "EDITOR", "VISUAL", "PAGER", "IFS", "MAKEFLAGS", "MAKELEVEL",
        "SHELLOPTS", "BASHOPTS", "PS1", "PS2", "PS4", "PYTHONPATH", "PYTHONHASHSEED",
        "NODE_OPTIONS", "JAVA_HOME", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "RUSTFLAGS",
        "RUSTDOCFLAGS", "CPATH", "PKG_CONFIG_PATH", "GOFLAGS", "GOOS", "GOARCH", "GOROOT", "GOPATH",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    ];
    const PREFIX: &[&str] = &[
        "LC_", "CARGO", "RUST", "NODE_", "PYTHON", "JAVA_", "GO", "NPM_", "npm_", "PIP_", "BUNDLE",
        "GEM_", "NO_", "FORCE_", "DYLD_", "LD_", "MAKE", "CMAKE_", "PKG_", "XDG_", "HOMEBREW_",
        "GIT_", "SSL_", "CURL_", "STOOP_",
    ];
    const SUFFIX: &[&str] = &[
        "_ENV", "_FLAGS", "_OPTS", "_OPTIONS", "_ARGS", "_MODE", "_PROFILE", "_LEVEL", "_CONFIG",
        "_PATH", "_HOME", "_ROOT", "_DIR", "_TARGET", "_ARCH", "_PLATFORM", "_OS", "_VERSION",
        "_SEED", "_FILE", "_LOCALE", "_LANG", "_TZ", "_SKIP", "_ONLY", "_DISABLE", "_ENABLE",
    ];
    const CONTAINS: &[&str] = &["DEBUG", "VERBOSE", "TRACE", "QUIET", "COLOR", "FORCE", "DRY_RUN"];
    EXACT.contains(&name)
        || PREFIX.iter().any(|p| name.starts_with(p))
        || SUFFIX.iter().any(|s| name.ends_with(s))
        || CONTAINS.iter().any(|c| name.contains(c))
}

/// Whether a value looks like an opaque identifier or a timestamp: a long token that is all hex
/// digits, or that mixes letters and digits, or a long all-digit value. A plain word, a short
/// version string or a boolean does not.
pub fn opaque(value: &str) -> bool {
    if value.len() >= 8 && value.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    value.split(|c: char| !c.is_ascii_alphanumeric()).any(|token| {
        token.len() >= 8
            && (token.bytes().all(|b| b.is_ascii_hexdigit())
                || (token.bytes().any(|b| b.is_ascii_digit())
                    && token.bytes().any(|b| b.is_ascii_alphabetic())))
    })
}

/// The digest the learner remembers for one observed value, or `None` when the value cannot count
/// as an identifier: a value that is not UTF-8, or one that does not look opaque. The digest is
/// keyed with the proof salt when there is one, so the learner state reveals no more than proofs do.
pub fn digest(name: &str, value: &[u8], salt: Option<&[u8]>) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    if !opaque(text) {
        return None;
    }
    let full = crate::run::env_hash_bytes(name, value, salt);
    Some(full.trim_start_matches("s:").chars().take(16).collect())
}

/// Identifies the salt a learner state was built with, so that a changed salt starts learning again.
/// The salt itself is never stored.
pub fn salt_id(salt: Option<&[u8]>) -> String {
    match salt {
        None => String::new(),
        Some(salt) => blake3::derive_key("stoop volatile salt id v1", salt)
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

/// What the volatile policy decided for one run's candidate names.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Names the fingerprint counts, sorted.
    pub counted: Vec<String>,
    /// Names the policy excludes, sorted by name, with the reason each one is excluded.
    pub excluded: Vec<(String, String)>,
}

/// Split candidate names (environment keys) into those counted and those excluded. A name the
/// command mentions and a name forced with `--env` always count. A curated name is excluded for its
/// group's reason. A learned name is excluded for the learned reason.
pub fn plan(
    candidates: &[String],
    mention: &str,
    forced: &[String],
    learned: &BTreeMap<String, u64>,
) -> Plan {
    let mut out = Plan::default();
    for key in candidates {
        let name = crate::run::env_name(key);
        if forced.contains(key) || mentioned(&name, mention) {
            out.counted.push(key.clone());
            continue;
        }
        if let Some(why) = curated_reason(key) {
            out.excluded.push((key.clone(), why.to_string()));
        } else if let Some(runs) = learned.get(key) {
            out.excluded.push((
                key.clone(),
                format!("changes on every run (learned after {runs} runs)"),
            ));
        } else {
            out.counted.push(key.clone());
        }
    }
    out.counted.sort();
    out.excluded.sort();
    out
}

/// Recorded runs in a row that must each show a new opaque value before a name is learned.
pub const MIN_RUNS: usize = 4;
/// The most recent recorded runs the learner keeps for one name. A repeat inside this window stops
/// learning until the repeated value leaves it.
pub const WINDOW: usize = 8;
const MAX_KEYS: usize = 64;
const MAX_NAMES: usize = 64;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const FILE: &str = "volatile-v1.json";
const LOCK: &str = "volatile-v1.lock";
static NEXT: AtomicU64 = AtomicU64::new(0);

/// The names one proof key has learned, with the runs each was learned after, and a warning when
/// the stored state was damaged or from another stoop version.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Learned {
    pub names: BTreeMap<String, u64>,
    pub warning: Option<String>,
}

#[derive(Default, Deserialize, Serialize)]
struct Catalog {
    version: u8,
    #[serde(default)]
    keys: BTreeMap<String, KeyState>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct KeyState {
    /// Recorded runs observed for this key.
    #[serde(default)]
    runs: u64,
    /// Identity of the salt the digests were keyed with; empty when unsalted.
    #[serde(default)]
    salt: String,
    /// Unix time of the last update, which orders eviction.
    #[serde(default)]
    updated: u64,
    #[serde(default)]
    names: BTreeMap<String, NameState>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct NameState {
    /// Digests of the last recorded runs in a row, oldest first, at most `WINDOW`.
    #[serde(default)]
    window: Vec<String>,
    /// Runs in the window when the name was learned. Absent until it is learned, and then sticky.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    learned: Option<u64>,
    /// The run count at which this name was last observed.
    #[serde(default)]
    last: u64,
}

/// What a damaged state file means for this run.
enum Damage {
    /// Corrupt, oversized or malformed: safe to replace with a fresh state.
    Replace(String),
    /// Written by another stoop version, or unreadable: never overwritten.
    Keep(String),
}

fn path(store: &Path) -> PathBuf {
    store.join(FILE)
}

fn read_catalog(store: &Path) -> Result<Catalog, Damage> {
    let file = match File::open(path(store)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Catalog {
                version: 1,
                keys: BTreeMap::new(),
            });
        }
        Err(error) => return Err(Damage::Keep(format!("it cannot be read ({error})"))),
    };
    let mut bytes = Vec::new();
    if let Err(error) = file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes) {
        return Err(Damage::Keep(format!("it cannot be read ({error})")));
    }
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(Damage::Replace("it is larger than the size limit".into()));
    }
    let catalog: Catalog = match serde_json::from_slice(&bytes) {
        Ok(catalog) => catalog,
        Err(error) => return Err(Damage::Replace(format!("it is not valid ({error})"))),
    };
    if catalog.version != 1 {
        return Err(Damage::Keep(format!(
            "it was written by another stoop version (state version {})",
            catalog.version
        )));
    }
    Ok(catalog)
}

fn lock(store: &Path) -> io::Result<File> {
    fs::create_dir_all(store)?;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(store.join(".gitignore"))
    {
        Ok(mut file) => file.write_all(b"*\n")?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(store.join(LOCK))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn write_bytes(store: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = store.join(format!(
        ".volatile-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path(store))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

/// Text from a damaged file, escaped for stoop's output. A workflow command must not be
/// smuggled through a warning.
fn safe(text: &str) -> String {
    crate::plan::output::escape(text)
}

/// The names learned for `key`, read without writing. Damage yields no names and one warning, so
/// a damaged state costs only the exclusions it would have made.
pub fn load(store: &Path, key: &str, salt_id: &str) -> Learned {
    match read_catalog(store) {
        Ok(catalog) => Learned {
            names: learned_of(catalog.keys.get(key), salt_id),
            warning: None,
        },
        Err(Damage::Replace(why) | Damage::Keep(why)) => Learned {
            names: BTreeMap::new(),
            warning: Some(format!(
                "stoop: volatile env records are unavailable ({}); counting every variable",
                safe(&why)
            )),
        },
    }
}

fn learned_of(state: Option<&KeyState>, salt_id: &str) -> BTreeMap<String, u64> {
    let Some(state) = state.filter(|state| state.salt == salt_id) else {
        return BTreeMap::new();
    };
    state
        .names
        .iter()
        .filter_map(|(name, learned)| learned.learned.map(|runs| (name.clone(), runs)))
        .collect()
}

fn all_distinct(window: &[String]) -> bool {
    window
        .iter()
        .enumerate()
        .all(|(i, digest)| !window[..i].contains(digest))
}

/// Record one recorded run of `key`. `observed` maps each candidate name to its digest, or to `None`
/// when the name is absent or its value does not look opaque. A name that is missing from
/// `observed` breaks its streak. A damaged state is replaced with a warning. Returns the
/// repair note, if any.
pub fn observe(
    store: &Path,
    key: &str,
    salt_id: &str,
    observed: &BTreeMap<String, Option<String>>,
    now: u64,
) -> Result<Option<String>, String> {
    let _lock = lock(store).map_err(|error| {
        format!("stoop: cannot lock volatile env records ({error}); counting every variable")
    })?;
    let (mut catalog, repaired) = match read_catalog(store) {
        Ok(catalog) => (catalog, None),
        Err(Damage::Replace(why)) => (
            Catalog {
                version: 1,
                keys: BTreeMap::new(),
            },
            Some(format!(
                "stoop: volatile env records were replaced because {}",
                safe(&why)
            )),
        ),
        Err(Damage::Keep(why)) => {
            return Err(format!(
                "stoop: volatile env records are kept as they are ({}); counting every variable",
                safe(&why)
            ));
        }
    };
    let state = catalog.keys.entry(key.to_string()).or_default();
    if state.salt != salt_id {
        *state = KeyState {
            salt: salt_id.to_string(),
            ..KeyState::default()
        };
    }
    state.runs += 1;
    state.updated = now;
    let run = state.runs;
    for (name, digest) in observed {
        let entry = state.names.entry(name.clone()).or_default();
        if entry.learned.is_some() {
            continue;
        }
        match digest {
            Some(digest) => {
                entry.window.push(digest.clone());
                if entry.window.len() > WINDOW {
                    entry.window.remove(0);
                }
                entry.last = run;
                if entry.window.len() >= MIN_RUNS && all_distinct(&entry.window) {
                    entry.learned = Some(entry.window.len() as u64);
                }
            }
            None => entry.window.clear(),
        }
    }
    for (name, entry) in state.names.iter_mut() {
        if entry.learned.is_none() && !observed.contains_key(name) {
            entry.window.clear();
        }
    }
    state
        .names
        .retain(|_, entry| entry.learned.is_some() || !entry.window.is_empty());
    while state.names.len() > MAX_NAMES {
        let oldest = state
            .names
            .iter()
            .filter(|(_, entry)| entry.learned.is_none())
            .min_by_key(|(_, entry)| entry.last)
            .map(|(name, _)| name.clone());
        match oldest {
            Some(name) => {
                state.names.remove(&name);
            }
            None => break,
        }
    }
    while catalog.keys.len() > MAX_KEYS {
        let stale = catalog
            .keys
            .iter()
            .filter(|(name, _)| name.as_str() != key)
            .min_by_key(|(_, state)| state.updated)
            .map(|(name, _)| name.clone());
        match stale {
            Some(name) => {
                catalog.keys.remove(&name);
            }
            None => break,
        }
    }
    loop {
        let bytes = serde_json::to_vec(&catalog).map_err(|error| {
            format!("stoop: cannot save volatile env records ({error}); counting every variable")
        })?;
        if bytes.len() as u64 <= MAX_FILE_BYTES {
            write_bytes(store, &bytes).map_err(|error| {
                format!("stoop: cannot save volatile env records ({error}); counting every variable")
            })?;
            return Ok(repaired);
        }
        let stale = catalog
            .keys
            .iter()
            .filter(|(name, _)| name.as_str() != key)
            .min_by_key(|(_, state)| state.updated)
            .map(|(name, _)| name.clone());
        match stale {
            Some(name) => {
                catalog.keys.remove(&name);
            }
            None => {
                return Err(
                    "stoop: volatile env records exceed the size limit; counting every variable"
                        .into(),
                );
            }
        }
    }
}

/// Forget what was learned for `key`. Returns whether anything was stored under it.
pub fn forget(store: &Path, key: &str) -> Result<bool, String> {
    if !path(store).exists() {
        return Ok(false);
    }
    let _lock = lock(store)
        .map_err(|error| format!("stoop: cannot lock volatile env records ({error})"))?;
    let mut catalog = match read_catalog(store) {
        Ok(catalog) => catalog,
        Err(Damage::Replace(why) | Damage::Keep(why)) => {
            return Err(format!(
                "stoop: volatile env records are unavailable ({})",
                safe(&why)
            ));
        }
    };
    if catalog.keys.remove(key).is_none() {
        return Ok(false);
    }
    let bytes = serde_json::to_vec(&catalog).map_err(|error| error.to_string())?;
    write_bytes(store, &bytes)
        .map_err(|error| format!("stoop: cannot save volatile env records ({error})"))?;
    Ok(true)
}

/// Every key with learned names, with each name and the runs it was learned after, sorted by key.
pub fn list(store: &Path) -> Result<Vec<(String, Vec<(String, u64)>)>, String> {
    let catalog = read_catalog(store).map_err(|damage| match damage {
        Damage::Replace(why) | Damage::Keep(why) => format!(
            "stoop: volatile env records are unavailable ({})",
            safe(&why)
        ),
    })?;
    Ok(catalog
        .keys
        .iter()
        .filter_map(|(key, state)| {
            let learned: Vec<(String, u64)> = learned_of(Some(state), &state.salt)
                .into_iter()
                .collect();
            (!learned.is_empty()).then(|| (key.clone(), learned))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "stoop-volatile-unit-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// Opaque values, each different from the others.
    const V: [&str; 6] = [
        "3f9a2c1d", "7b20e4a8", "c5d61f09", "0a8e77b2", "9d4c3e11", "e2f0b7c4",
    ];

    fn seen(store: &Path, key: &str, name: &str, value: Option<&str>) {
        let mut observed = BTreeMap::new();
        observed.insert(
            name.to_string(),
            value.and_then(|v| digest(name, v.as_bytes(), None)),
        );
        observe(store, key, "", &observed, 1).unwrap();
    }

    fn learned(store: &Path, key: &str, name: &str) -> Option<u64> {
        load(store, key, "").names.get(name).copied()
    }

    #[test]
    fn every_group_names_a_reason_and_a_source() {
        for group in GROUPS {
            assert!(!group.why.is_empty());
            assert!(!group.source.is_empty());
            assert!(!group.names.is_empty() || !group.prefixes.is_empty());
        }
    }

    #[test]
    fn each_group_is_reachable_through_its_own_first_name() {
        for group in GROUPS {
            let name = group.names.first().copied().unwrap_or_else(|| {
                group.prefixes.first().copied().unwrap()
            });
            let probe = format!("{name}X");
            assert!(
                curated_reason(name).is_some() || curated_reason(&probe).is_some(),
                "{name}"
            );
        }
    }

    #[test]
    fn per_run_names_are_curated_and_behavioural_names_are_not() {
        for name in [
            "RANDOM", "SRANDOM", "SECONDS", "EPOCHREALTIME", "BASHPID", "PPID", "TMUX_PANE",
            "STY", "XDG_SESSION_ID", "CI_JOB_ID", "CI_JOB_TOKEN", "CI_COMMIT_SHA",
            "CI_COMMIT_MESSAGE", "BUILDKITE_BUILD_NUMBER", "CIRCLE_BUILD_NUM", "TRAVIS_JOB_ID",
            "SECURITYSESSIONID", "VSCODE_IPC_HOOK_CLI", "AWS_SESSION_TOKEN", "GO_PIPELINE_COUNTER",
        ] {
            assert!(curated_reason(name).is_some(), "{name} should be curated");
        }
        for name in [
            "NODE_ENV", "CI", "DEBUG", "RUSTFLAGS", "CC", "PATH", "HOME", "LANG", "FOO",
            "CI_COMMIT_REF_NAME", "CI_COMMIT_BRANCH", "CI_JOB_NAME", "CI_PIPELINE_SOURCE",
            "CI_DEFAULT_BRANCH", "BUILDKITE_BRANCH", "CIRCLE_BRANCH", "TRAVIS_BRANCH",
            "SEMAPHORE_GIT_BRANCH", "AWS_REGION", "TMPDIR", "__CFBundleIdentifier",
            "TERM_PROGRAM_VERSION", "WT_PROFILE_ID", "ITERM_PROFILE", "VTE_VERSION",
            "BUILDKITE_BUILD_CHECKOUT_PATH", "BUILDKITE_AGENT_ACCESS_TOKEN",
            "SEMAPHORE_API_TOKEN",
        ] {
            assert!(curated_reason(name).is_none(), "{name} must stay counted");
        }
    }

    #[test]
    fn prefixes_match_only_the_families_they_name() {
        assert!(curated_reason("GO_REVISION_CODE").is_some());
        assert!(curated_reason("GO_REVISION").is_some());
        assert!(curated_reason("GO_REVISIONS").is_none());
        assert!(curated_reason("GO_REVISIO").is_none());
        assert!(curated_reason("CI_COMMIT_SOMETHING_NEW").is_none());
        assert!(curated_reason("CI_").is_none());
    }

    #[test]
    fn a_name_that_is_not_utf8_is_never_curated() {
        assert!(curated_reason("\u{0}ff").is_none());
        assert!(curated_reason("\u{0}52414e444f4d").is_none());
    }

    #[test]
    fn a_mention_counts_a_name_the_command_text_names() {
        assert!(mentioned(OsStr::new("RANDOM"), "echo $RANDOM"));
        assert!(!mentioned(OsStr::new("RANDOM"), "echo hi"));
        assert!(!mentioned(OsStr::new(""), "anything"));
    }

    #[test]
    fn the_plan_counts_mentioned_and_forced_names_and_excludes_the_rest_of_the_volatile_ones() {
        let candidates: Vec<String> = ["CI_JOB_ID", "RANDOM", "FOO", "TMUX_PANE", "NODE_ENV"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let learned = BTreeMap::from([("FOO".to_string(), 4)]);
        let plan = plan(
            &candidates,
            "echo $RANDOM",
            &["TMUX_PANE".to_string()],
            &learned,
        );
        assert_eq!(
            plan.counted,
            vec!["NODE_ENV".to_string(), "RANDOM".to_string(), "TMUX_PANE".to_string()]
        );
        assert_eq!(
            plan.excluded,
            vec![
                ("CI_JOB_ID".to_string(), "GitLab per-job or per-pipeline value".to_string()),
                (
                    "FOO".to_string(),
                    "changes on every run (learned after 4 runs)".to_string()
                ),
            ]
        );
    }

    #[test]
    fn a_name_the_learner_never_learns_is_refused() {
        for name in [
            "PATH", "HOME", "LANG", "LC_ALL", "CC", "CARGO_TARGET_DIR", "RUSTFLAGS", "RUSTC_WRAPPER",
            "NODE_ENV", "NODE_OPTIONS", "GOFLAGS", "DEBUG", "TZ", "MY_TOOL_VERBOSE", "DATABASE_DIR",
            "BUILD_SEED", "CI_CONFIG_PATH", "PYTHONHASHSEED", "STOOP_LEARN_VOLATILE", "NO_COLOR",
            "RAILS_ENV", "SOMETHING_OPTS", "SOMETHING_MODE",
        ] {
            assert!(never_learn(name), "{name} must not be learned");
        }
        for name in ["FOO", "SESSION_MARK", "RUN_TOKEN", "TOOL_SHARD_ID"] {
            assert!(!never_learn(name), "{name} may be learned");
        }
    }

    #[test]
    fn opaque_values_are_identifiers_and_timestamps() {
        for value in [
            "3f9a2c1d",
            "1700000000",
            "20241231235959",
            "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/",
            "550e8400-e29b-41d4-a716-446655440000",
            "a1b2c3d4e5f6",
        ] {
            assert!(opaque(value), "{value} should look opaque");
        }
        for value in [
            "", "18", "1.2.3", "production", "true", "x86_64-unknown-linux-gnu", "/home/me/project",
            "node-18.17.1", "ubuntu-latest",
        ] {
            assert!(!opaque(value), "{value:?} should not look opaque");
        }
    }

    #[test]
    fn a_digest_is_absent_for_a_value_that_is_not_opaque_or_not_utf8() {
        assert!(digest("FOO", b"production", None).is_none());
        assert!(digest("FOO", b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8", None).is_none());
        assert_eq!(digest("FOO", b"3f9a2c1d", None).map(|d| d.len()), Some(16));
    }

    #[test]
    fn the_salt_id_is_empty_when_unsalted_and_hides_the_salt() {
        assert_eq!(salt_id(None), "");
        let id = salt_id(Some(b"secret"));
        assert_eq!(id.len(), 16);
        assert!(!id.contains("secret"));
        assert_ne!(id, salt_id(Some(b"other")));
    }

    #[test]
    fn four_distinct_runs_in_a_row_learn_a_changing_name() {
        let s = store("four");
        for value in &V[..3] {
            seen(&s, "k", "SESSION_MARK", Some(value));
        }
        assert_eq!(learned(&s, "k", "SESSION_MARK"), None, "three runs learn nothing");
        seen(&s, "k", "SESSION_MARK", Some(V[3]));
        assert_eq!(learned(&s, "k", "SESSION_MARK"), Some(4));
    }

    #[test]
    fn a_constant_value_is_never_learned() {
        let s = store("constant");
        for _ in 0..10 {
            seen(&s, "k", "SESSION_MARK", Some(V[0]));
        }
        assert_eq!(learned(&s, "k", "SESSION_MARK"), None);
    }

    #[test]
    fn alternating_values_are_never_learned() {
        let s = store("alternating");
        for i in 0..12 {
            seen(&s, "k", "SESSION_MARK", Some(V[i % 2]));
        }
        assert_eq!(learned(&s, "k", "SESSION_MARK"), None);
    }

    #[test]
    fn a_repeated_value_blocks_learning_until_it_leaves_the_window() {
        let s = store("repeat");
        seen(&s, "k", "SESSION_MARK", Some(V[0]));
        seen(&s, "k", "SESSION_MARK", Some(V[1]));
        seen(&s, "k", "SESSION_MARK", Some(V[2]));
        seen(&s, "k", "SESSION_MARK", Some(V[0]));
        seen(&s, "k", "SESSION_MARK", Some(V[3]));
        seen(&s, "k", "SESSION_MARK", Some(V[4]));
        seen(&s, "k", "SESSION_MARK", Some(V[5]));
        assert_eq!(
            learned(&s, "k", "SESSION_MARK"),
            None,
            "the repeat of V[0] is still in the window"
        );
        seen(&s, "k", "SESSION_MARK", Some("0c0c0c0c"));
        assert_eq!(learned(&s, "k", "SESSION_MARK"), Some(8));
    }

    #[test]
    fn a_run_without_the_name_breaks_the_streak() {
        let s = store("gap");
        seen(&s, "k", "SESSION_MARK", Some(V[0]));
        seen(&s, "k", "SESSION_MARK", Some(V[1]));
        seen(&s, "k", "SESSION_MARK", None);
        seen(&s, "k", "SESSION_MARK", Some(V[2]));
        seen(&s, "k", "SESSION_MARK", Some(V[3]));
        seen(&s, "k", "SESSION_MARK", Some(V[4]));
        assert_eq!(learned(&s, "k", "SESSION_MARK"), None);
        seen(&s, "k", "SESSION_MARK", Some(V[5]));
        assert_eq!(learned(&s, "k", "SESSION_MARK"), Some(4));
    }

    #[test]
    fn a_value_that_does_not_look_opaque_breaks_the_streak() {
        let s = store("plain");
        seen(&s, "k", "SESSION_MARK", Some(V[0]));
        seen(&s, "k", "SESSION_MARK", Some(V[1]));
        seen(&s, "k", "SESSION_MARK", Some("plain"));
        seen(&s, "k", "SESSION_MARK", Some(V[2]));
        seen(&s, "k", "SESSION_MARK", Some(V[3]));
        seen(&s, "k", "SESSION_MARK", Some(V[4]));
        assert_eq!(learned(&s, "k", "SESSION_MARK"), None);
    }

    #[test]
    fn a_learned_name_stays_learned_and_is_not_observed_again() {
        let s = store("sticky");
        for value in &V[..4] {
            seen(&s, "k", "SESSION_MARK", Some(value));
        }
        for _ in 0..3 {
            seen(&s, "k", "SESSION_MARK", Some(V[0]));
        }
        assert_eq!(learned(&s, "k", "SESSION_MARK"), Some(4));
    }

    #[test]
    fn learning_is_per_key() {
        let s = store("per-key");
        for value in &V[..4] {
            seen(&s, "a", "SESSION_MARK", Some(value));
        }
        assert_eq!(learned(&s, "a", "SESSION_MARK"), Some(4));
        assert_eq!(learned(&s, "b", "SESSION_MARK"), None);
    }

    #[test]
    fn a_changed_salt_starts_learning_again() {
        let s = store("salt");
        let mut observed = BTreeMap::new();
        for value in &V[..4] {
            observed.clear();
            observed.insert(
                "SESSION_MARK".to_string(),
                digest("SESSION_MARK", value.as_bytes(), Some(b"one")),
            );
            observe(&s, "k", &salt_id(Some(b"one")), &observed, 1).unwrap();
        }
        assert_eq!(load(&s, "k", &salt_id(Some(b"one"))).names.len(), 1);
        assert!(load(&s, "k", &salt_id(Some(b"two"))).names.is_empty());
        observed.clear();
        observed.insert(
            "SESSION_MARK".to_string(),
            digest("SESSION_MARK", V[4].as_bytes(), Some(b"two")),
        );
        observe(&s, "k", &salt_id(Some(b"two")), &observed, 1).unwrap();
        assert!(load(&s, "k", &salt_id(Some(b"two"))).names.is_empty());
    }

    #[test]
    fn a_damaged_state_file_warns_and_is_replaced_on_the_next_write() {
        let s = store("damaged");
        fs::write(path(&s), b"{not json").unwrap();
        let loaded = load(&s, "k", "");
        assert!(loaded.names.is_empty());
        let warning = loaded.warning.unwrap();
        assert!(warning.contains("counting every variable"), "{warning}");
        let note = observe(&s, "k", "", &BTreeMap::new(), 1).unwrap().unwrap();
        assert!(note.contains("replaced"), "{note}");
        assert!(load(&s, "k", "").warning.is_none());
    }

    #[test]
    fn an_oversized_state_file_is_treated_as_damaged() {
        let s = store("oversize");
        fs::write(path(&s), vec![b' '; (MAX_FILE_BYTES + 1) as usize]).unwrap();
        assert!(load(&s, "k", "").warning.unwrap().contains("size limit"));
    }

    #[test]
    fn a_state_from_another_version_is_kept_and_never_overwritten() {
        let s = store("newer");
        let bytes = br#"{"version":2,"keys":{}}"#;
        fs::write(path(&s), bytes).unwrap();
        assert!(observe(&s, "k", "", &BTreeMap::new(), 1)
            .unwrap_err()
            .contains("kept as they are"));
        assert_eq!(fs::read(path(&s)).unwrap(), bytes);
    }

    #[test]
    fn a_damage_warning_cannot_carry_workflow_commands_from_the_file() {
        let s = store("poisoned");
        fs::write(path(&s), br#"{"version":"##[error]poisoned"}"#).unwrap();
        let warning = load(&s, "k", "").warning.unwrap();
        assert!(!warning.contains("##["), "{warning}");
    }

    #[test]
    fn concurrent_observers_lose_no_runs() {
        let s = store("concurrent");
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let s = &s;
                scope.spawn(move || {
                    for _ in 0..5 {
                        observe(s, "k", "", &BTreeMap::new(), 1).unwrap();
                    }
                });
            }
        });
        let catalog = read_catalog(&s).ok().unwrap();
        assert_eq!(catalog.keys["k"].runs, 40);
    }

    #[test]
    fn forget_resets_the_key_and_leaves_other_keys_alone() {
        let s = store("forget");
        for value in &V[..4] {
            seen(&s, "a", "SESSION_MARK", Some(value));
            seen(&s, "b", "SESSION_MARK", Some(value));
        }
        assert_eq!(forget(&s, "a"), Ok(true));
        assert_eq!(forget(&s, "a"), Ok(false));
        assert_eq!(learned(&s, "a", "SESSION_MARK"), None);
        assert_eq!(learned(&s, "b", "SESSION_MARK"), Some(4));
    }

    #[test]
    fn list_reports_only_keys_with_learned_names() {
        let s = store("list");
        for value in &V[..4] {
            seen(&s, "learned", "SESSION_MARK", Some(value));
        }
        seen(&s, "quiet", "SESSION_MARK", Some(V[0]));
        assert_eq!(
            list(&s).unwrap(),
            vec![("learned".to_string(), vec![("SESSION_MARK".to_string(), 4)])]
        );
    }

    #[test]
    fn the_key_count_is_bounded_and_the_stalest_key_goes() {
        let s = store("keys");
        for i in 0..(MAX_KEYS + 3) {
            observe(&s, &format!("k{i}"), "", &BTreeMap::new(), i as u64).unwrap();
        }
        let catalog = read_catalog(&s).ok().unwrap();
        assert_eq!(catalog.keys.len(), MAX_KEYS);
        assert!(!catalog.keys.contains_key("k0"));
        assert!(catalog.keys.contains_key(&format!("k{}", MAX_KEYS + 2)));
    }

    #[test]
    fn the_name_count_per_key_is_bounded() {
        let s = store("names");
        for i in 0..(MAX_NAMES + 5) {
            let mut observed = BTreeMap::new();
            observed.insert(format!("N{i}"), Some(format!("{i:016x}")));
            observe(&s, "k", "", &observed, 1).unwrap();
        }
        assert!(read_catalog(&s).ok().unwrap().keys["k"].names.len() <= MAX_NAMES);
    }
}
