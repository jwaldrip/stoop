//! Environment variables that change on every run are not inputs.
//!
//! The environment counts as an input because a variable read never shows up in a file trace.
//! Some variables are bookkeeping: they change on every run, every commit or every terminal, and
//! say nothing about what a command produces. Two sources exclude them. The command text overrules
//! both: a name the text mentions, and a name forced with `--env`, always count. The command text
//! is the argv words and the `stoop sh` step body, never the files the command runs.
//!
//! - The curated table below. Each name is one a tool documents as per run, per session or per
//!   commit, and each group cites the page or source it was read from. A name that could not be
//!   sourced is not here. A group that names a provider counts only where that provider's marker
//!   variable is set.
//! - The learner. A name whose opaque value is new on each of the last few runs of the same proof
//!   key is excluded for that key, and only while its value is still an identifier. A value that
//!   returns is evidence the name is not bookkeeping: it is counted again, and never learned again
//!   for that key. A learned name holding a plain value is counted again, and may be learned later.
//!
//! Every invocation that reaches the decision is an observation, skips included. A skipped run's
//! value equals an earlier proof's value, so counting only recorded runs would miss a repeat.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// One reason and the names it covers. `names` match exactly; `prefixes` match the start of a name.
/// Families are listed by name, not by prefix: a family such as `BUILDKITE_` also holds behavioural
/// settings (`BUILDKITE_CLEAN_CHECKOUT`, `BUILDKITE_BRANCH`) that change what a command does.
pub struct Group {
    pub why: &'static str,
    /// The page or source each name was read from, with the section where it is named. The table
    /// test reads it; no run does.
    #[cfg_attr(not(test), allow(dead_code))]
    pub source: &'static str,
    pub names: &'static [&'static str],
    pub prefixes: &'static [&'static str],
    /// Marker variables a provider sets. The group counts only where one of them is set. Empty
    /// means the group always counts.
    pub requires: &'static [&'static str],
}

pub const GROUPS: &[Group] = &[
    Group {
        why: "shell clock or counter",
        source: "bash: https://tiswww.case.edu/php/chet/bash/bashref.html (Bash Variables); zsh: https://zsh.sourceforge.io/Doc/Release/Parameters.html (RANDOM, SECONDS) and https://zsh.sourceforge.io/Doc/Release/Zsh-Modules.html (EPOCHSECONDS, EPOCHREALTIME)",
        names: &["RANDOM", "SRANDOM", "SECONDS", "EPOCHSECONDS", "EPOCHREALTIME"],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "shell process id",
        source: "bash: https://tiswww.case.edu/php/chet/bash/bashref.html (Bash Variables: BASHPID, PPID)",
        names: &["BASHPID", "PPID"],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "terminal size",
        source: "bash: https://tiswww.case.edu/php/chet/bash/bashref.html (COLUMNS, LINES); zsh: https://zsh.sourceforge.io/Doc/Release/Parameters.html (COLUMNS, LINES)",
        names: &["COLUMNS", "LINES"],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "terminal multiplexer or window id",
        source: "tmux TMUX, TMUX_PANE: https://man.openbsd.org/tmux (ENVIRONMENT) ; GNU screen STY: http://www.gnu.org/software/screen/manual/screen.html ; xterm WINDOWID: https://invisible-island.net/xterm/manpage/xterm.html ; kitty KITTY_WINDOW_ID and KITTY_LISTEN_ON: https://sw.kovidgoyal.net/kitty/remote-control/ ; zellij ZELLIJ_SESSION_NAME: https://zellij.dev/documentation/integration",
        names: &[
            "TMUX",
            "TMUX_PANE",
            "STY",
            "WINDOWID",
            "KITTY_WINDOW_ID",
            "KITTY_LISTEN_ON",
            "ZELLIJ_SESSION_NAME",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "GNU screen window number",
        source: "GNU screen: http://www.gnu.org/software/screen/manual/screen.html (environment variable WINDOW, set in each window)",
        names: &["WINDOW"],
        prefixes: &[],
        requires: &["STY"],
    },
    Group {
        why: "terminal emulator instance or pane",
        source: "WezTerm WEZTERM_PANE: https://github.com/wezterm/wezterm/blob/main/docs/cli/cli/index.markdown ; WEZTERM_UNIX_SOCKET: https://github.com/wezterm/wezterm/blob/main/wezterm-gui/src/main.rs ; Windows Terminal WT_SESSION: https://github.com/microsoft/terminal/blob/main/src/cascadia/TerminalConnection/ConptyConnection.cpp ; Alacritty ALACRITTY_SOCKET: https://github.com/alacritty/alacritty/blob/master/alacritty/src/polling/ipc.rs ; Alacritty ALACRITTY_WINDOW_ID: https://github.com/alacritty/alacritty/blob/master/alacritty_terminal/src/tty/unix.rs ; GNOME Terminal GNOME_TERMINAL_SCREEN and GNOME_TERMINAL_SERVICE: https://github.com/GNOME/gnome-terminal/blob/master/src/terminal-defines.hh ; iTerm2 ITERM_SESSION_ID: https://github.com/gnachman/iterm2/blob/master/sources/PTYSession/PTYSession.h ; iTerm2 TERM_SESSION_ID: https://iterm2.com/documentation-variables.html ; Konsole KONSOLE_DBUS_SESSION: https://github.com/KDE/konsole/blob/master/src/session/Session.cpp",
        names: &[
            "WEZTERM_PANE",
            "WEZTERM_UNIX_SOCKET",
            "WT_SESSION",
            "ALACRITTY_SOCKET",
            "ALACRITTY_WINDOW_ID",
            "GNOME_TERMINAL_SCREEN",
            "GNOME_TERMINAL_SERVICE",
            "ITERM_SESSION_ID",
            "TERM_SESSION_ID",
            "KONSOLE_DBUS_SESSION",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "login session or SSH connection",
        source: "systemd-logind XDG_SESSION_ID, XDG_VTNR: https://www.freedesktop.org/software/systemd/man/latest/pam_systemd.html ; D-Bus DBUS_SESSION_BUS_ADDRESS: https://dbus.freedesktop.org/doc/dbus-specification.html ; sshd SSH_CONNECTION, SSH_CLIENT, SSH_TTY: https://github.com/openssh/openssh-portable/blob/master/session.c ; ssh-agent SSH_AGENT_PID: https://man.openbsd.org/ssh-agent",
        names: &[
            "XDG_SESSION_ID",
            "XDG_VTNR",
            "DBUS_SESSION_BUS_ADDRESS",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "SSH_TTY",
            "SSH_AGENT_PID",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "editor window socket",
        source: "VS Code VSCODE_IPC_HOOK_CLI: https://github.com/microsoft/vscode/blob/main/src/vs/server/node/server.cli.ts ; VS Code VSCODE_GIT_IPC_HANDLE: https://github.com/microsoft/vscode/blob/main/extensions/git/src/ipc/ipcServer.ts",
        names: &["VSCODE_IPC_HOOK_CLI", "VSCODE_GIT_IPC_HANDLE"],
        prefixes: &[],
        requires: &[],
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
            "CI_RUNNER_ID",
        ],
        prefixes: &[],
        requires: &[],
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
        requires: &[],
    },
    Group {
        why: "Buildkite per-build, per-job or per-agent value",
        source: "https://buildkite.com/docs/pipelines/environment-variables",
        names: &[
            "BUILDKITE_BUILD_ID",
            "BUILDKITE_BUILD_NUMBER",
            "BUILDKITE_BUILD_URL",
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
            "BUILDKITE_AGENT_PID",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Buildkite per-commit value",
        source: "https://buildkite.com/docs/pipelines/environment-variables",
        names: &[
            "BUILDKITE_COMMIT",
            "BUILDKITE_MESSAGE",
            "BUILDKITE_BUILD_AUTHOR",
            "BUILDKITE_BUILD_AUTHOR_EMAIL",
            "BUILDKITE_MERGE_QUEUE_BASE_COMMIT",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "CircleCI per-job or per-workflow value",
        source: "https://circleci.com/docs/variables/",
        names: &[
            "CIRCLE_BUILD_NUM",
            "CIRCLE_BUILD_URL",
            "CIRCLE_PIPELINE_ID",
            "CIRCLE_WORKFLOW_ID",
            "CIRCLE_WORKFLOW_JOB_ID",
            "CIRCLE_WORKFLOW_WORKSPACE_ID",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "CircleCI per-commit value",
        source: "https://circleci.com/docs/variables/",
        names: &["CIRCLE_SHA1", "CIRCLE_COMPARE_URL"],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Travis per-build or per-job value",
        source: "https://docs.travis-ci.com/user/environment-variables/",
        names: &[
            "TRAVIS_BUILD_ID",
            "TRAVIS_BUILD_NUMBER",
            "TRAVIS_BUILD_WEB_URL",
            "TRAVIS_JOB_ID",
            "TRAVIS_JOB_NUMBER",
            "TRAVIS_JOB_WEB_URL",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Travis per-commit value",
        source: "https://docs.travis-ci.com/user/environment-variables/",
        names: &[
            "TRAVIS_COMMIT",
            "TRAVIS_COMMIT_MESSAGE",
            "TRAVIS_COMMIT_RANGE",
            "TRAVIS_PULL_REQUEST_SHA",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Jenkins or TeamCity per-build value",
        source: "Jenkins: https://www.jenkins.io/doc/book/pipeline/jenkinsfile/ (BUILD_ID, BUILD_NUMBER, BUILD_TAG, BUILD_URL) ; TeamCity: https://www.jetbrains.com/help/teamcity/predefined-build-parameters.html (env.BUILD_NUMBER, env.BUILD_URL, env.TEAMCITY_BUILD_PROPERTIES_FILE)",
        names: &[
            "BUILD_ID",
            "BUILD_NUMBER",
            "BUILD_TAG",
            "BUILD_URL",
            "TEAMCITY_BUILD_PROPERTIES_FILE",
        ],
        prefixes: &[],
        requires: &["JENKINS_URL", "TEAMCITY_VERSION"],
    },
    Group {
        why: "Jenkins per-executor slot",
        source: "https://www.jenkins.io/doc/book/pipeline/jenkinsfile/ (EXECUTOR_NUMBER)",
        names: &["EXECUTOR_NUMBER"],
        prefixes: &[],
        requires: &["JENKINS_URL"],
    },
    Group {
        why: "Jenkins per-commit value",
        source: "Git plugin: https://plugins.jenkins.io/git/ (GIT_COMMIT, GIT_PREVIOUS_COMMIT, GIT_PREVIOUS_SUCCESSFUL_COMMIT)",
        names: &["GIT_COMMIT", "GIT_PREVIOUS_COMMIT", "GIT_PREVIOUS_SUCCESSFUL_COMMIT"],
        prefixes: &[],
        requires: &["JENKINS_URL"],
    },
    Group {
        why: "TeamCity per-commit value",
        source: "https://www.jetbrains.com/help/teamcity/predefined-build-parameters.html (env.BUILD_VCS_NUMBER_<VCS_root_ID>)",
        names: &[],
        prefixes: &["BUILD_VCS_NUMBER_"],
        requires: &["TEAMCITY_VERSION"],
    },
    Group {
        why: "Azure Pipelines per-build, per-job or per-agent value",
        source: "https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables (Build.BuildId, Build.BuildNumber, System.JobId, Agent.Id; a variable's environment name is its dotted name in capitals with underscores, as its example shows: Build.ArtifactStagingDirectory becomes BUILD_ARTIFACTSTAGINGDIRECTORY)",
        names: &[
            "BUILD_BUILDID",
            "BUILD_BUILDNUMBER",
            "SYSTEM_JOBID",
            "AGENT_ID",
        ],
        prefixes: &[],
        requires: &["TF_BUILD"],
    },
    Group {
        why: "Azure Pipelines per-commit value",
        source: "https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables (Build.SourceVersion, Build.SourceVersionMessage, System.PullRequest.SourceCommitId)",
        names: &[
            "BUILD_SOURCEVERSION",
            "BUILD_SOURCEVERSIONMESSAGE",
            "SYSTEM_PULLREQUEST_SOURCECOMMITID",
        ],
        prefixes: &[],
        requires: &["TF_BUILD"],
    },
    Group {
        why: "Bitbucket per-run value",
        source: "https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/",
        names: &[
            "BITBUCKET_BUILD_NUMBER",
            "BITBUCKET_PIPELINE_UUID",
            "BITBUCKET_STEP_UUID",
            "BITBUCKET_STEP_RUN_NUMBER",
            "BITBUCKET_TRIGGER_PIPELINE_RUN_UUID",
            "BITBUCKET_TRIGGER_STEP_UUID",
            "BITBUCKET_MERGE_QUEUE_PR_IDS",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Bitbucket per-commit value",
        source: "https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/",
        names: &["BITBUCKET_COMMIT", "BITBUCKET_PR_DESTINATION_COMMIT"],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Drone per-build or per-stage value",
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
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Drone per-commit value",
        source: "https://docs.drone.io/pipeline/environment/reference/",
        names: &[
            "DRONE_COMMIT",
            "DRONE_COMMIT_SHA",
            "DRONE_COMMIT_BEFORE",
            "DRONE_COMMIT_AFTER",
            "DRONE_COMMIT_AUTHOR",
            "DRONE_COMMIT_AUTHOR_EMAIL",
            "DRONE_COMMIT_AUTHOR_NAME",
            "DRONE_COMMIT_LINK",
            "DRONE_COMMIT_MESSAGE",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "AWS CodeBuild per-build value",
        source: "https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html",
        names: &[
            "CODEBUILD_BUILD_ID",
            "CODEBUILD_BUILD_ARN",
            "CODEBUILD_BUILD_NUMBER",
            "CODEBUILD_BUILD_URL",
            "CODEBUILD_PUBLIC_BUILD_URL",
            "CODEBUILD_START_TIME",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "AWS CodeBuild per-commit value",
        source: "https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html",
        names: &[
            "CODEBUILD_SOURCE_VERSION",
            "CODEBUILD_RESOLVED_SOURCE_VERSION",
            "CODEBUILD_WEBHOOK_PREV_COMMIT",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Semaphore per-workflow, per-pipeline or per-job value",
        source: "https://docs.semaphore.io/ci-cd-environment/environment-variables",
        names: &[
            "SEMAPHORE_WORKFLOW_ID",
            "SEMAPHORE_WORKFLOW_NUMBER",
            "SEMAPHORE_PIPELINE_ID",
            "SEMAPHORE_JOB_ID",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "Semaphore per-commit value",
        source: "https://docs.semaphore.io/ci-cd-environment/environment-variables",
        names: &[
            "SEMAPHORE_GIT_SHA",
            "SEMAPHORE_GIT_COMMIT_RANGE",
            "SEMAPHORE_GIT_COMMITTER",
            "SEMAPHORE_GIT_COMMIT_AUTHOR",
            "SEMAPHORE_GIT_PR_SHA",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "AppVeyor per-build or per-job value",
        source: "https://www.appveyor.com/docs/environment-variables/",
        names: &[
            "APPVEYOR_BUILD_ID",
            "APPVEYOR_BUILD_NUMBER",
            "APPVEYOR_BUILD_VERSION",
            "APPVEYOR_JOB_ID",
            "APPVEYOR_JOB_NUMBER",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "AppVeyor per-commit value",
        source: "https://www.appveyor.com/docs/environment-variables/",
        names: &[
            "APPVEYOR_REPO_COMMIT",
            "APPVEYOR_REPO_COMMIT_AUTHOR",
            "APPVEYOR_REPO_COMMIT_AUTHOR_EMAIL",
            "APPVEYOR_REPO_COMMIT_MESSAGE",
            "APPVEYOR_REPO_COMMIT_MESSAGE_EXTENDED",
            "APPVEYOR_REPO_COMMIT_TIMESTAMP",
            "APPVEYOR_PULL_REQUEST_HEAD_COMMIT",
        ],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "GoCD per-pipeline or per-stage counter and label",
        source: "https://docs.gocd.org/current/faq/dev_use_current_revision_in_build.html",
        names: &["GO_PIPELINE_COUNTER", "GO_PIPELINE_LABEL", "GO_STAGE_COUNTER"],
        prefixes: &[],
        requires: &[],
    },
    Group {
        why: "GoCD per-commit revision",
        source: "https://docs.gocd.org/current/faq/dev_use_current_revision_in_build.html",
        names: &["GO_REVISION", "GO_FROM_REVISION", "GO_TO_REVISION"],
        prefixes: &[
            "GO_REVISION_",
            "GO_FROM_REVISION_",
            "GO_TO_REVISION_",
            "GO_DEPENDENCY_LABEL_",
        ],
        requires: &[],
    },
    Group {
        why: "rotating credential issued per job or per session",
        source: "GitLab CI_JOB_TOKEN (valid while the job runs), CI_REGISTRY_PASSWORD (the job token), CI_REPOSITORY_URL (embeds it): https://docs.gitlab.com/ci/variables/predefined_variables/ ; CircleCI CIRCLE_OIDC_TOKEN and versions: https://circleci.com/docs/variables/ ; Bitbucket BITBUCKET_STEP_OIDC_TOKEN: https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/ ; Azure SYSTEM_ACCESSTOKEN (the security token of the running build): https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables ; AWS CLI AWS_SESSION_TOKEN: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html",
        names: &[
            "CI_JOB_TOKEN",
            "CI_REGISTRY_PASSWORD",
            "CI_REPOSITORY_URL",
            "CIRCLE_OIDC_TOKEN",
            "CIRCLE_OIDC_TOKEN_V2",
            "CIRCLE_OIDC_TOKEN_V3",
            "BITBUCKET_STEP_OIDC_TOKEN",
            "SYSTEM_ACCESSTOKEN",
            "AWS_SESSION_TOKEN",
        ],
        prefixes: &[],
        requires: &[],
    },
];

/// The marker variables the environment sets, out of every marker a group names.
fn markers_set() -> BTreeSet<String> {
    all_markers()
        .into_iter()
        .filter(|marker| std::env::var_os(marker).is_some())
        .collect()
}

/// Every marker variable a group names in its `requires`.
pub fn all_markers() -> BTreeSet<String> {
    GROUPS
        .iter()
        .flat_map(|group| group.requires.iter())
        .map(|marker| marker.to_string())
        .collect()
}

/// The curated reason a name is excluded, or `None` when it is not curated. A group with `requires`
/// counts only when one of those markers is in `markers`. Every curated name is ASCII, so a name
/// that is not UTF-8 never matches.
pub fn curated_reason(name: &str, markers: &BTreeSet<String>) -> Option<&'static str> {
    GROUPS
        .iter()
        .find(|group| {
            (group.names.contains(&name) || group.prefixes.iter().any(|p| name.starts_with(p)))
                && (group.requires.is_empty()
                    || group
                        .requires
                        .iter()
                        .any(|marker| markers.contains(*marker)))
        })
        .map(|group| group.why)
}

/// Whether the command text names the variable. A name it names always counts.
pub fn mentioned(name: &str, mention: &str) -> bool {
    !name.is_empty() && mention.contains(name)
}

/// Names the learner never learns. They are behavioural or path-like settings that a command can
/// depend on even when a value looks opaque. The list is conservative on purpose: a miss only costs
/// one extra run.
pub fn never_learn(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TZ",
        "CI",
        "DEBUG",
        "CC",
        "CXX",
        "AR",
        "LD",
        "PWD",
        "OLDPWD",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "IFS",
        "MAKEFLAGS",
        "MAKELEVEL",
        "SHELLOPTS",
        "BASHOPTS",
        "PS1",
        "PS2",
        "PS4",
        "PYTHONPATH",
        "PYTHONHASHSEED",
        "NODE_OPTIONS",
        "JAVA_HOME",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CPATH",
        "PKG_CONFIG_PATH",
        "GOFLAGS",
        "GOOS",
        "GOARCH",
        "GOROOT",
        "GOPATH",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "SOURCE_DATE_EPOCH",
        "IMAGE_TAG",
    ];
    const PREFIX: &[&str] = &[
        "LC_",
        "CARGO",
        "RUST",
        "NODE_",
        "PYTHON",
        "JAVA_",
        "GO",
        "NPM_",
        "npm_",
        "PIP_",
        "BUNDLE",
        "GEM_",
        "NO_",
        "FORCE_",
        "DYLD_",
        "LD_",
        "MAKE",
        "CMAKE_",
        "PKG_",
        "XDG_",
        "HOMEBREW_",
        "GIT_",
        "SSL_",
        "CURL_",
        "STOOP_",
    ];
    const SUFFIX: &[&str] = &[
        "_ENV",
        "_FLAGS",
        "_OPTS",
        "_OPTIONS",
        "_ARGS",
        "_MODE",
        "_PROFILE",
        "_LEVEL",
        "_CONFIG",
        "_PATH",
        "_HOME",
        "_ROOT",
        "_DIR",
        "_TARGET",
        "_ARCH",
        "_PLATFORM",
        "_OS",
        "_VERSION",
        "_SEED",
        "_FILE",
        "_LOCALE",
        "_LANG",
        "_TZ",
        "_SKIP",
        "_ONLY",
        "_DISABLE",
        "_ENABLE",
        "_TAG",
        "_SHA",
        "_DIGEST",
        "_EPOCH",
    ];
    const CONTAINS: &[&str] = &[
        "DEBUG", "VERBOSE", "TRACE", "QUIET", "COLOR", "FORCE", "DRY_RUN",
    ];
    EXACT.contains(&name)
        || PREFIX.iter().any(|p| name.starts_with(p))
        || SUFFIX.iter().any(|s| name.ends_with(s))
        || CONTAINS.iter().any(|c| name.contains(c))
}

/// Whether a value looks like an opaque identifier or a timestamp.
///
/// - a token of eight or more characters that mixes letters and digits, or is hexadecimal with a
///   letter in it (`3f9a2c1d`, `550e8400`, a random suffix in a path);
/// - a run of ten or more digits (epoch seconds and milliseconds, a compact date with a time);
/// - a date with a time of day (`2024-12-31T23:59:59Z`).
///
/// A plain date, a short number, a version, a word or a path of words does not count. A date
/// changes once a day, not on every run, so it is not treated as a per-run identifier.
pub fn opaque(value: &str) -> bool {
    if has_time_of_day_date(value) {
        return true;
    }
    value
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| {
            let len = token.len();
            let digits = token.bytes().filter(u8::is_ascii_digit).count();
            let letters = token.bytes().filter(u8::is_ascii_alphabetic).count();
            if digits == len {
                return len >= 10;
            }
            len >= 8
                && ((digits > 0 && letters > 0)
                    || (token.bytes().all(|b| b.is_ascii_hexdigit())
                        && token
                            .bytes()
                            .any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F'))))
        })
}

/// `YYYY-MM-DD` followed by a time of day, with `T` or a space between them.
fn has_time_of_day_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(16).any(|w| {
        w[0..4].iter().all(u8::is_ascii_digit)
            && w[4] == b'-'
            && w[5..7].iter().all(u8::is_ascii_digit)
            && w[7] == b'-'
            && w[8..10].iter().all(u8::is_ascii_digit)
            && (w[10] == b'T' || w[10] == b' ')
            && w[11..13].iter().all(u8::is_ascii_digit)
            && w[13] == b':'
            && w[14..16].iter().all(u8::is_ascii_digit)
    })
}

/// The digest the learner remembers for one value, or `None` when the value cannot count as an
/// identifier: it is not UTF-8, or it does not look opaque. The digest is keyed with the proof salt
/// when there is one, so the learner state reveals no more than proofs already do.
pub fn digest(name: &str, value: &[u8], salt: Option<&[u8]>) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    if !opaque(text) {
        return None;
    }
    let full = crate::run::env_hash_bytes(name, value, salt);
    Some(full.trim_start_matches("s:").chars().take(16).collect())
}

/// Identifies the salt a learner state was built with, so a changed salt starts learning again.
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

/// What the policy decided for one run's candidate names. Both lists are sorted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Names the fingerprint counts.
    pub counted: Vec<String>,
    /// Names the policy excludes, each with the reason it is excluded.
    pub excluded: Vec<(String, String)>,
}

/// Split candidate environment keys into counted and excluded names. A name the command text
/// mentions and a name forced with `--env` always count. A curated name is excluded for its
/// group's reason when one of the group's markers is in `markers`. A learned name is excluded only
/// while it is in `active`: learned, and holding an identifier now.
pub fn plan(
    candidates: &[String],
    mention: &str,
    forced: &[String],
    active: &BTreeMap<String, u32>,
    markers: &BTreeSet<String>,
) -> Plan {
    let mut out = Plan::default();
    for key in candidates {
        let name = crate::run::env_name(key);
        if forced.contains(key) || mentioned(&name.to_string_lossy(), mention) {
            out.counted.push(key.clone());
        } else if let Some(why) = curated_reason(key, markers) {
            out.excluded.push((key.clone(), why.to_string()));
        } else if let Some(runs) = active.get(key) {
            out.excluded.push((
                key.clone(),
                format!("changes on every run (learned after {runs} runs)"),
            ));
        } else {
            out.counted.push(key.clone());
        }
    }
    out.counted.sort();
    out.counted.dedup();
    out.excluded.sort();
    out.excluded.dedup_by(|a, b| a.0 == b.0);
    out
}

/// Consecutive observations, each with a value the name has not had before, that learn a name.
pub const MIN_RUNS: u32 = 4;
/// The most distinct values kept per name. A value that has left this history can repeat unseen.
const SEEN_MAX: usize = 16;
/// Names kept per key. The least recently observed go first.
const MAX_NAMES: usize = 64;
/// Keys kept in the store. The least recently updated go first.
const MAX_KEYS: usize = 512;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const FILE: &str = "volatile-v1.json";
const LOCK: &str = "volatile-v1.lock";
static NEXT: AtomicU64 = AtomicU64::new(0);

/// One run's input to the policy.
pub struct Request<'a> {
    pub store: &'a Path,
    /// The proof key the run belongs to. Learning is per key.
    pub key: &'a str,
    /// Every environment key the fingerprint could count, before the policy.
    pub candidates: &'a [String],
    pub mention: &'a str,
    /// Names forced to count with `--env`.
    pub forced: &'a [String],
    /// Names the user exempted with `--ignore-env`. A learned name among them is not counted back in.
    pub ignore: &'a [String],
    pub salt: Option<&'a [u8]>,
    /// False turns learning off: nothing is observed and no learned name is excluded.
    pub learn: bool,
    /// True when this run may write the learner state: a trusted run that records. Otherwise the
    /// observation is applied in memory only, so a run cannot exclude a name that a trusted run
    /// would have counted.
    pub persist: bool,
    pub now: u64,
}

/// The policy's decision for one run, with what a run should say about it.
#[derive(Debug, Default)]
pub struct Outcome {
    pub plan: Plan,
    /// Lines for names learned or counted again on this run. Empty unless the state was written.
    pub changes: Vec<String>,
    /// A damaged or unwritable state: the run counts every variable it would have counted.
    pub warning: Option<String>,
}

pub fn decide(req: &Request) -> Outcome {
    let mut candidates: Vec<String> = req.candidates.iter().chain(req.forced).cloned().collect();
    candidates.sort();
    candidates.dedup();
    let markers = markers_set();
    let mut outcome = Outcome::default();
    let mut universe = candidates.clone();
    let mut active: BTreeMap<String, u32> = BTreeMap::new();
    if req.learn {
        let observed = observations(&candidates, req.mention, req.forced, req.salt, &markers);
        let plain = plain_now(&candidates);
        let salt_id = salt_id(req.salt);
        let step = if req.persist {
            persist(req.store, req.key, &salt_id, &observed, &plain, req.now)
        } else {
            in_memory(req.store, req.key, &salt_id, &observed, &plain, req.now)
        };
        outcome.changes = step.changes;
        outcome.warning = step.warning;
        // A learned name joins the universe even when it is unset, so its absence is counted. An
        // ignored name never comes back.
        universe.extend(
            step.learned
                .keys()
                .filter(|name| !req.ignore.contains(*name))
                .cloned(),
        );
        // Excluded only while it holds an identifier now: the state records that it was learned,
        // not what it holds.
        active = step
            .learned
            .into_iter()
            .filter(|(name, _)| observed.contains_key(name) && !never_learn(name))
            .collect();
    }
    universe.sort();
    universe.dedup();
    outcome.plan = plan(&universe, req.mention, req.forced, &active, &markers);
    outcome
}

/// Candidate names that hold a value which is not an identifier now.
fn plain_now(candidates: &[String]) -> BTreeSet<String> {
    candidates
        .iter()
        .filter(|key| {
            std::env::var_os(crate::run::env_name(key.as_str()))
                .is_some_and(|value| !identifier(&value))
        })
        .cloned()
        .collect()
}

/// Whether a value looks like an identifier: UTF-8 that `opaque` accepts, as `digest` requires.
fn identifier(value: &std::ffi::OsStr) -> bool {
    value.to_str().is_some_and(opaque)
}

/// The digest of each name this run could learn: present, opaque, and neither curated, never
/// learned, mentioned nor forced. A name absent from the map breaks any streak it was on.
fn observations(
    candidates: &[String],
    mention: &str,
    forced: &[String],
    salt: Option<&[u8]>,
    markers: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for key in candidates {
        if forced.contains(key) || curated_reason(key, markers).is_some() || never_learn(key) {
            continue;
        }
        let name = crate::run::env_name(key);
        if mentioned(&name.to_string_lossy(), mention) {
            continue;
        }
        let Some(value) = std::env::var_os(&name) else {
            continue;
        };
        if let Some(digest) = digest(key, value.as_encoded_bytes(), salt) {
            out.insert(key.clone(), digest);
        }
    }
    out
}

#[derive(Default, Deserialize, Serialize)]
struct Catalog {
    version: u8,
    #[serde(default)]
    keys: BTreeMap<String, KeyState>,
}

impl Catalog {
    fn fresh() -> Self {
        Catalog {
            version: 1,
            keys: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct KeyState {
    /// Identity of the salt the digests were keyed with. A different salt starts again.
    #[serde(default)]
    salt: String,
    /// Invocations of this key that reached the decision.
    #[serde(default)]
    runs: u64,
    #[serde(default)]
    updated: u64,
    #[serde(default)]
    names: BTreeMap<String, NameState>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct NameState {
    /// Consecutive observations that each brought a new value. Reset by a gap or a repeat.
    #[serde(default)]
    streak: u32,
    /// The most recent distinct digests, oldest first.
    #[serde(default)]
    seen: Vec<String>,
    /// The run count at which the name was learned. Absent until then, and cleared by a repeat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    learned: Option<u32>,
    /// Once a learned name repeats, it is never learned again for this key.
    #[serde(default)]
    refused: bool,
    /// The key's run count when the name was last observed.
    #[serde(default)]
    last: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Change {
    Learned(String),
    Revoked(String),
    Stopped(String),
}

/// What one run of the policy produced: the learned names and what changed.
struct Step {
    learned: BTreeMap<String, u32>,
    changes: Vec<String>,
    warning: Option<String>,
}

impl Step {
    fn refused(warning: String) -> Step {
        Step {
            learned: BTreeMap::new(),
            changes: Vec::new(),
            warning: Some(warning),
        }
    }
}

/// Apply one invocation's observations to a key's state. A repeat resets the streak, and revokes a
/// learned name for good. A new value extends the streak, and learns the name after `MIN_RUNS`.
/// A name absent from `observed` breaks its streak but keeps what it has learned. A learned name in
/// `plain` loses its learning without being refused.
fn advance(
    state: &mut KeyState,
    observed: &BTreeMap<String, String>,
    plain: &BTreeSet<String>,
    now: u64,
) -> Vec<Change> {
    state.runs += 1;
    state.updated = now;
    let run = state.runs;
    let mut changes = Vec::new();
    // A learned name holding a plain value is no longer excluded. Its learning goes, but it is not
    // refused: if it holds identifiers again, it can be learned again.
    for name in plain {
        let Some(entry) = state.names.get_mut(name) else {
            continue;
        };
        if entry.learned.take().is_some() {
            entry.streak = 0;
            changes.push(Change::Stopped(name.clone()));
        }
    }
    for (name, digest) in observed {
        let entry = state.names.entry(name.clone()).or_default();
        entry.last = run;
        if entry.seen.contains(digest) {
            entry.streak = 0;
            if entry.learned.is_some() {
                entry.learned = None;
                entry.refused = true;
                changes.push(Change::Revoked(name.clone()));
            }
            continue;
        }
        entry.seen.push(digest.clone());
        if entry.seen.len() > SEEN_MAX {
            entry.seen.remove(0);
        }
        if entry.learned.is_none() && !entry.refused {
            entry.streak += 1;
            if entry.streak >= MIN_RUNS {
                entry.learned = Some(MIN_RUNS);
                changes.push(Change::Learned(name.clone()));
            }
        }
    }
    for (name, entry) in state.names.iter_mut() {
        if entry.learned.is_none() && !observed.contains_key(name) {
            entry.streak = 0;
        }
    }
    prune(state);
    changes
}

fn prune(state: &mut KeyState) {
    if state.names.len() <= MAX_NAMES {
        return;
    }
    let mut order: Vec<(u64, String)> = state
        .names
        .iter()
        .map(|(name, entry)| (entry.last, name.clone()))
        .collect();
    order.sort();
    let excess = state.names.len() - MAX_NAMES;
    for (_, name) in order.into_iter().take(excess) {
        state.names.remove(&name);
    }
}

fn learned_of(state: &KeyState) -> BTreeMap<String, u32> {
    state
        .names
        .iter()
        .filter_map(|(name, entry)| entry.learned.map(|runs| (name.clone(), runs)))
        .collect()
}

/// The key's state under the current salt. A state from another salt is not reused.
fn take_key(catalog: &mut Catalog, key: &str, salt_id: &str) -> KeyState {
    match catalog.keys.remove(key) {
        Some(state) if state.salt == salt_id => state,
        _ => KeyState {
            salt: salt_id.to_string(),
            ..KeyState::default()
        },
    }
}

fn render(change: &Change) -> String {
    match change {
        Change::Learned(name) => format!(
            "ignoring env {}: changes on every run (learned after {MIN_RUNS} runs)",
            safe(name)
        ),
        Change::Revoked(name) => format!(
            "counting env {} again: it returned to an earlier value, so it is not ignored for this key any more",
            safe(name)
        ),
        Change::Stopped(name) => format!(
            "counting env {} again: its value is no longer an identifier, so it is not ignored for this key any more",
            safe(name)
        ),
    }
}

/// Text from a damaged file or an environment name, escaped for stoop's output. A workflow command
/// must not be smuggled through a warning. Mirrors the escaping of hook records.
pub fn safe(text: &str) -> String {
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

/// What a damaged state file means for this run.
enum Damage {
    /// Missing parts, corrupt or oversized: safe to replace with a fresh state.
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
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Catalog::fresh()),
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

/// An exclusive lock on the store, held for one read-modify-write. The store is created if absent.
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

/// The key that goes first when space is needed: the least recently updated, never `keep`.
fn stalest(catalog: &Catalog, keep: &str) -> Option<String> {
    catalog
        .keys
        .iter()
        .filter(|(name, _)| name.as_str() != keep)
        .min_by_key(|(_, state)| state.updated)
        .map(|(name, _)| name.clone())
}

/// Serialise the catalog within the key and size limits, dropping the stalest keys to fit.
fn fit(catalog: &mut Catalog, keep: &str) -> Result<Vec<u8>, String> {
    while catalog.keys.len() > MAX_KEYS {
        match stalest(catalog, keep) {
            Some(name) => {
                catalog.keys.remove(&name);
            }
            None => break,
        }
    }
    loop {
        let bytes = serde_json::to_vec(catalog).map_err(|error| {
            format!("stoop: cannot save volatile env records ({error}); counting every variable")
        })?;
        if bytes.len() as u64 <= MAX_FILE_BYTES {
            return Ok(bytes);
        }
        match stalest(catalog, keep) {
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

/// A trusted run: observe under the store's lock, and write the new state before deciding.
fn persist(
    store: &Path,
    key: &str,
    salt_id: &str,
    observed: &BTreeMap<String, String>,
    plain: &BTreeSet<String>,
    now: u64,
) -> Step {
    let _guard = match lock(store) {
        Ok(guard) => guard,
        Err(error) => {
            return Step::refused(format!(
                "stoop: cannot lock volatile env records ({error}); counting every variable"
            ));
        }
    };
    let (mut catalog, warning) = match read_catalog(store) {
        Ok(catalog) => (catalog, None),
        Err(Damage::Replace(why)) => (
            Catalog::fresh(),
            Some(format!(
                "stoop: volatile env records were replaced because {}",
                safe(&why)
            )),
        ),
        Err(Damage::Keep(why)) => {
            return Step::refused(format!(
                "stoop: volatile env records are kept as they are ({}); counting every variable",
                safe(&why)
            ));
        }
    };
    let mut state = take_key(&mut catalog, key, salt_id);
    let changes = advance(&mut state, observed, plain, now);
    let learned = learned_of(&state);
    catalog.keys.insert(key.to_string(), state);
    let bytes = match fit(&mut catalog, key) {
        Ok(bytes) => bytes,
        Err(message) => return Step::refused(message),
    };
    if let Err(error) = write_bytes(store, &bytes) {
        return Step::refused(format!(
            "stoop: cannot save volatile env records ({error}); counting every variable"
        ));
    }
    Step {
        learned,
        changes: changes.iter().map(render).collect(),
        warning,
    }
}

/// A run that may not write: observe in memory only, so the decision matches a trusted run's.
fn in_memory(
    store: &Path,
    key: &str,
    salt_id: &str,
    observed: &BTreeMap<String, String>,
    plain: &BTreeSet<String>,
    now: u64,
) -> Step {
    let mut catalog = match read_catalog(store) {
        Ok(catalog) => catalog,
        Err(Damage::Replace(why) | Damage::Keep(why)) => {
            return Step::refused(format!(
                "stoop: volatile env records are unavailable ({}); counting every variable",
                safe(&why)
            ));
        }
    };
    let mut state = take_key(&mut catalog, key, salt_id);
    advance(&mut state, observed, plain, now);
    Step {
        learned: learned_of(&state),
        changes: Vec::new(),
        warning: None,
    }
}

/// Forget what was learned for `key`. Returns whether anything was stored under it.
pub fn forget(store: &Path, key: &str) -> Result<bool, String> {
    if !path(store).exists() {
        return Ok(false);
    }
    let _guard = lock(store)
        .map_err(|error| format!("stoop: cannot lock volatile env records ({error})"))?;
    let mut catalog = match read_catalog(store) {
        Ok(catalog) => catalog,
        Err(Damage::Replace(_)) => Catalog::fresh(),
        Err(Damage::Keep(why)) => {
            return Err(format!(
                "stoop: volatile env records are unavailable ({})",
                safe(&why)
            ));
        }
    };
    let removed = catalog.keys.remove(key).is_some();
    let bytes = serde_json::to_vec(&catalog).map_err(|error| error.to_string())?;
    write_bytes(store, &bytes)
        .map_err(|error| format!("stoop: cannot save volatile env records ({error})"))?;
    Ok(removed)
}

/// The learned names of each key: the key, then each name and the runs it was learned after.
pub type Listing = Vec<(String, Vec<(String, u32)>)>;

/// Every key with names learned under `salt_id`, with each name and the runs it was learned after.
pub fn list(store: &Path, salt_id: &str) -> Result<Listing, String> {
    if !path(store).exists() {
        return Ok(Vec::new());
    }
    let catalog = read_catalog(store).map_err(|damage| match damage {
        Damage::Replace(why) | Damage::Keep(why) => format!(
            "stoop: volatile env records are unavailable ({})",
            safe(&why)
        ),
    })?;
    Ok(catalog
        .keys
        .iter()
        .filter(|(_, state)| state.salt == salt_id)
        .filter_map(|(key, state)| {
            let learned: Vec<(String, u32)> = learned_of(state).into_iter().collect();
            (!learned.is_empty()).then(|| (key.clone(), learned))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("stoop-volatile-unit-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// Opaque values, each different from the others.
    const V: [&str; 8] = [
        "3f9a2c1d", "7b20e4a8", "c5d61f09", "0a8e77b2", "9d4c3e11", "e2f0b7c4", "4a1b9d6e",
        "b8c2f3a0",
    ];

    /// Set `name` to `value` (or unset it), then decide for one trusted run of `key`.
    fn observe(store: &Path, key: &str, name: &str, value: Option<&str>) -> Outcome {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
        let names = vec![name.to_string()];
        decide(&Request {
            store,
            key,
            candidates: &names,
            mention: "",
            forced: &[],
            ignore: &[],
            salt: None,
            learn: true,
            persist: true,
            now: 1,
        })
    }

    fn learned_names(outcome: &Outcome) -> Vec<String> {
        outcome
            .plan
            .excluded
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }

    #[test]
    fn every_group_names_a_reason_and_a_source_and_no_dash() {
        for group in GROUPS {
            assert!(!group.why.is_empty());
            assert!(!group.source.is_empty());
            assert!(
                !group.names.is_empty() || !group.prefixes.is_empty(),
                "{}",
                group.why
            );
            for text in [group.why, group.source] {
                assert!(
                    !text.contains('\u{2014}') && !text.contains('\u{2013}'),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn no_curated_name_is_listed_twice() {
        let mut seen = std::collections::BTreeSet::new();
        for group in GROUPS {
            for name in group.names {
                assert!(seen.insert(*name), "{name} appears in two groups");
            }
        }
    }

    #[test]
    fn per_run_names_are_curated() {
        for name in [
            "RANDOM",
            "SRANDOM",
            "SECONDS",
            "EPOCHREALTIME",
            "BASHPID",
            "PPID",
            "COLUMNS",
            "TMUX_PANE",
            "STY",
            "WINDOWID",
            "KITTY_WINDOW_ID",
            "ZELLIJ_SESSION_NAME",
            "WEZTERM_PANE",
            "WT_SESSION",
            "ALACRITTY_SOCKET",
            "GNOME_TERMINAL_SCREEN",
            "ITERM_SESSION_ID",
            "TERM_SESSION_ID",
            "KONSOLE_DBUS_SESSION",
            "XDG_SESSION_ID",
            "XDG_VTNR",
            "DBUS_SESSION_BUS_ADDRESS",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "SSH_TTY",
            "SSH_AGENT_PID",
            "VSCODE_IPC_HOOK_CLI",
            "VSCODE_GIT_IPC_HANDLE",
            "CI_JOB_ID",
            "CI_JOB_URL",
            "CI_COMMIT_SHA",
            "CI_COMMIT_MESSAGE",
            "CI_PIPELINE_ID",
            "CI_PIPELINE_URL",
            "CI_JOB_TOKEN",
            "BUILDKITE_BUILD_NUMBER",
            "BUILDKITE_JOB_ID",
            "BUILDKITE_COMMIT",
            "BUILDKITE_AGENT_PID",
            "CIRCLE_BUILD_NUM",
            "CIRCLE_SHA1",
            "CIRCLE_WORKFLOW_JOB_ID",
            "CIRCLE_OIDC_TOKEN",
            "TRAVIS_BUILD_NUMBER",
            "TRAVIS_COMMIT",
            "TRAVIS_JOB_ID",
            "BUILD_NUMBER",
            "BUILD_URL",
            "GIT_COMMIT",
            "EXECUTOR_NUMBER",
            "BUILD_VCS_NUMBER_1",
            "BUILD_BUILDID",
            "BUILD_SOURCEVERSION",
            "SYSTEM_JOBID",
            "SYSTEM_ACCESSTOKEN",
            "AGENT_ID",
            "BITBUCKET_BUILD_NUMBER",
            "BITBUCKET_COMMIT",
            "BITBUCKET_STEP_OIDC_TOKEN",
            "DRONE_BUILD_NUMBER",
            "DRONE_COMMIT_SHA",
            "CODEBUILD_BUILD_ARN",
            "CODEBUILD_RESOLVED_SOURCE_VERSION",
            "SEMAPHORE_WORKFLOW_ID",
            "SEMAPHORE_JOB_ID",
            "SEMAPHORE_GIT_SHA",
            "APPVEYOR_BUILD_ID",
            "APPVEYOR_REPO_COMMIT",
            "GO_PIPELINE_COUNTER",
            "GO_REVISION",
            "GO_REVISION_CODE",
            "GO_DEPENDENCY_LABEL_pipeline",
            "AWS_SESSION_TOKEN",
        ] {
            assert!(
                curated_reason(name, &all_markers()).is_some(),
                "{name} should be curated"
            );
        }
    }

    #[test]
    fn behavioural_and_branch_and_trigger_names_stay_counted() {
        for name in [
            "NODE_ENV",
            "CI",
            "DEBUG",
            "RUSTFLAGS",
            "CC",
            "PATH",
            "HOME",
            "LANG",
            "FOO",
            "TERM_PROGRAM_VERSION",
            "VTE_VERSION",
            "WT_PROFILE_ID",
            "ITERM_PROFILE",
            "DISPLAY",
            "TMPDIR",
            "CI_COMMIT_REF_NAME",
            "CI_COMMIT_BRANCH",
            "CI_JOB_NAME",
            "CI_PIPELINE_SOURCE",
            "CI_DEFAULT_BRANCH",
            "CI_NODE_INDEX",
            "CI_RUNNER_DESCRIPTION",
            "BUILDKITE_BRANCH",
            "BUILDKITE_CLEAN_CHECKOUT",
            "BUILDKITE_PARALLEL_JOB",
            "BUILDKITE_AGENT_NAME",
            "BUILDKITE_PIPELINE_SLUG",
            "CIRCLE_BRANCH",
            "CIRCLE_NODE_INDEX",
            "CIRCLE_USERNAME",
            "TRAVIS_BRANCH",
            "TRAVIS_JOB_RESTARTED_BY",
            "NODE_NAME",
            "SEMAPHORE_API_TOKEN",
            "AGENT_NAME",
            "AGENT_MACHINENAME",
            "BUILD_REQUESTEDFOR",
            "CODEBUILD_INITIATOR",
            "GO_TRIGGER_USER",
            "GO_MATERIAL_HAS_CHANGED",
            "VSCODE_INJECTION",
            "VSCODE_GIT_ASKPASS_NODE",
            "GPG_AGENT_INFO",
            "ALACRITTY_LOG",
            "KONSOLE_DBUS_WINDOW",
            "JOB_URL",
            "BUILDKITE_BUILD_CHECKOUT_PATH",
            "SECURITYSESSIONID",
        ] {
            assert!(
                curated_reason(name, &all_markers()).is_none(),
                "{name} must stay counted"
            );
        }
    }

    #[test]
    fn prefixes_match_only_the_families_they_name() {
        assert!(curated_reason("GO_REVISION_CODE", &all_markers()).is_some());
        assert!(curated_reason("GO_DEPENDENCY_LABEL_x", &all_markers()).is_some());
        assert!(curated_reason("BUILD_VCS_NUMBER_2", &all_markers()).is_some());
        assert!(curated_reason("GO_REVISIONS", &all_markers()).is_none());
        assert!(curated_reason("GO_REVISIO", &all_markers()).is_none());
        assert!(curated_reason("BUILD_VCS_NUMBER", &all_markers()).is_none());
        assert!(curated_reason("CI_", &all_markers()).is_none());
    }

    #[test]
    fn a_name_that_is_not_utf8_is_never_curated() {
        assert!(curated_reason("\u{0}ff", &all_markers()).is_none());
        assert!(curated_reason("\u{0}52414e444f4d", &all_markers()).is_none());
    }

    #[test]
    fn a_mention_counts_a_name_the_command_text_names() {
        assert!(mentioned("RANDOM", "echo $RANDOM"));
        assert!(!mentioned("RANDOM", "echo hi"));
        assert!(!mentioned("", "anything"));
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
            &BTreeSet::new(),
        );
        assert_eq!(
            plan.counted,
            vec![
                "NODE_ENV".to_string(),
                "RANDOM".to_string(),
                "TMUX_PANE".to_string()
            ]
        );
        assert_eq!(
            plan.excluded,
            vec![
                (
                    "CI_JOB_ID".to_string(),
                    "GitLab per-job or per-pipeline value".to_string()
                ),
                (
                    "FOO".to_string(),
                    "changes on every run (learned after 4 runs)".to_string()
                ),
            ]
        );
    }

    #[test]
    fn a_learned_name_that_the_command_mentions_still_counts() {
        let candidates = vec!["FOO".to_string()];
        let learned = BTreeMap::from([("FOO".to_string(), 4)]);
        let plan = plan(&candidates, "echo FOO", &[], &learned, &BTreeSet::new());
        assert_eq!(plan.counted, vec!["FOO".to_string()]);
        assert!(plan.excluded.is_empty());
    }

    #[test]
    fn a_name_the_learner_never_learns_is_refused() {
        for name in [
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "CC",
            "CARGO_TARGET_DIR",
            "RUSTFLAGS",
            "RUSTC_WRAPPER",
            "NODE_ENV",
            "NODE_OPTIONS",
            "GOFLAGS",
            "DEBUG",
            "TZ",
            "MY_TOOL_VERBOSE",
            "DATABASE_DIR",
            "BUILD_SEED",
            "CI_CONFIG_PATH",
            "PYTHONHASHSEED",
            "STOOP_LEARN_VOLATILE",
            "NO_COLOR",
            "RAILS_ENV",
            "SOMETHING_OPTS",
            "SOMETHING_MODE",
            "TRACEPARENT_TRACE",
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
            "1700000000123",
            "20241231235959",
            "2024-12-31T23:59:59Z",
            "2024-12-31 23:59",
            "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/",
            "550e8400-e29b-41d4-a716-446655440000",
            "a1b2c3d4e5f6",
        ] {
            assert!(opaque(value), "{value} should look opaque");
        }
        for value in [
            "",
            "18",
            "1.2.3",
            "production",
            "true",
            "x86_64-unknown-linux-gnu",
            "/home/me/project",
            "node-18.17.1",
            "ubuntu-latest",
            "20241231",
            "2024-12-31",
            "Python3.11.4",
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
    fn four_fresh_values_in_a_row_learn_the_name_and_exclude_it_on_that_run() {
        let s = dir("four");
        let name = "VOLATILE_TEST_FOUR";
        for value in &V[..3] {
            let out = observe(&s, "k", name, Some(value));
            assert!(out.plan.excluded.is_empty(), "{:?}", out.plan);
        }
        let out = observe(&s, "k", name, Some(V[3]));
        assert_eq!(learned_names(&out), vec![name.to_string()]);
        assert_eq!(
            out.plan.excluded[0].1,
            "changes on every run (learned after 4 runs)"
        );
        assert_eq!(
            out.changes,
            vec![format!(
                "ignoring env {name}: changes on every run (learned after 4 runs)"
            )]
        );
    }

    #[test]
    fn a_constant_value_is_never_learned() {
        let s = dir("constant");
        for _ in 0..10 {
            let out = observe(&s, "k", "VOLATILE_TEST_CONST", Some(V[0]));
            assert!(out.plan.excluded.is_empty());
        }
    }

    #[test]
    fn alternating_values_are_never_learned() {
        let s = dir("alternating");
        for i in 0..12 {
            let out = observe(&s, "k", "VOLATILE_TEST_ALT", Some(V[i % 2]));
            assert!(out.plan.excluded.is_empty(), "run {i}");
        }
    }

    #[test]
    fn a_value_repeated_on_a_skipped_run_blocks_learning() {
        // A run that skips reaches the decision with an earlier proof's value. Counting only
        // recorded runs would see a, b, c, d and learn; the repeat of a must be seen.
        let s = dir("skipped-repeat");
        let name = "VOLATILE_TEST_SKIP";
        for value in [V[0], V[1], V[0], V[2], V[3]] {
            let out = observe(&s, "k", name, Some(value));
            assert!(out.plan.excluded.is_empty(), "learned too early at {value}");
        }
    }

    #[test]
    fn a_repeat_resets_the_streak_and_learning_resumes_after_it() {
        let s = dir("reset");
        let name = "VOLATILE_TEST_RESET";
        for value in [V[0], V[1], V[2], V[0], V[3], V[4], V[5]] {
            observe(&s, "k", name, Some(value));
        }
        let out = observe(&s, "k", name, Some(V[6]));
        assert_eq!(learned_names(&out), vec![name.to_string()]);
    }

    #[test]
    fn a_gap_breaks_the_streak() {
        let s = dir("gap");
        let name = "VOLATILE_TEST_GAP";
        for value in [V[0], V[1], V[2]] {
            observe(&s, "k", name, Some(value));
        }
        assert!(observe(&s, "k", name, None).plan.excluded.is_empty());
        for value in [V[3], V[4], V[5]] {
            assert!(observe(&s, "k", name, Some(value)).plan.excluded.is_empty());
        }
        assert_eq!(
            learned_names(&observe(&s, "k", name, Some(V[6]))),
            vec![name.to_string()]
        );
    }

    #[test]
    fn a_value_that_does_not_look_opaque_breaks_the_streak() {
        let s = dir("plain");
        let name = "VOLATILE_TEST_PLAIN";
        for value in [V[0], V[1], V[2]] {
            observe(&s, "k", name, Some(value));
        }
        assert!(observe(&s, "k", name, Some("production"))
            .plan
            .excluded
            .is_empty());
        for value in [V[3], V[4], V[5]] {
            assert!(observe(&s, "k", name, Some(value)).plan.excluded.is_empty());
        }
    }

    #[test]
    fn a_learned_name_that_returns_to_an_earlier_value_is_counted_again_and_never_learned_for_the_key(
    ) {
        let s = dir("revoke");
        let name = "VOLATILE_TEST_REVOKE";
        for value in [V[0], V[1], V[2], V[3]] {
            observe(&s, "k", name, Some(value));
        }
        let back = observe(&s, "k", name, Some(V[0]));
        assert!(
            back.plan.excluded.is_empty(),
            "the repeat must count on its own run"
        );
        assert_eq!(
            back.changes,
            vec![format!(
                "counting env {name} again: it returned to an earlier value, so it is not ignored for this key any more"
            )]
        );
        for value in [V[4], V[5], V[6], V[7]] {
            assert!(observe(&s, "k", name, Some(value)).plan.excluded.is_empty());
        }
    }

    #[test]
    fn learning_is_per_key() {
        let s = dir("per-key");
        let name = "VOLATILE_TEST_KEYS";
        for value in [V[0], V[1], V[2], V[3]] {
            observe(&s, "a", name, Some(value));
        }
        assert_eq!(
            learned_names(&observe(&s, "a", name, Some(V[4]))),
            vec![name.to_string()]
        );
        assert!(observe(&s, "b", name, Some(V[5])).plan.excluded.is_empty());
    }

    #[test]
    fn a_changed_salt_starts_learning_again() {
        let s = dir("salt");
        let name = "VOLATILE_TEST_SALT";
        std::env::set_var(name, "x");
        let names = vec![name.to_string()];
        let run = |salt: &[u8], value: &str| {
            std::env::set_var(name, value);
            decide(&Request {
                store: &s,
                key: "k",
                candidates: &names,
                mention: "",
                forced: &[],
                ignore: &[],
                salt: Some(salt),
                learn: true,
                persist: true,
                now: 1,
            })
        };
        for value in &V[..4] {
            run(b"one", value);
        }
        let other = run(b"two", V[4]);
        assert!(
            other.plan.excluded.is_empty(),
            "a new salt starts from nothing"
        );
        assert_eq!(learned_names(&run(b"two", V[5])), Vec::<String>::new());
        assert!(
            learned_names(&run(b"one", V[6])).is_empty(),
            "switching back starts from nothing: one key holds one salt's state"
        );
        std::env::remove_var(name);
    }

    #[test]
    fn the_mention_rule_counts_a_learned_name_again() {
        let s = dir("mention");
        let name = "VOLATILE_TEST_MENTION";
        for value in [V[0], V[1], V[2], V[3]] {
            observe(&s, "k", name, Some(value));
        }
        std::env::set_var(name, V[4]);
        let names = vec![name.to_string()];
        let out = decide(&Request {
            store: &s,
            key: "k",
            candidates: &names,
            mention: &format!("echo ${name}"),
            forced: &[],
            ignore: &[],
            salt: None,
            learn: true,
            persist: true,
            now: 1,
        });
        assert_eq!(out.plan.counted, vec![name.to_string()]);
        assert!(out.plan.excluded.is_empty());
        std::env::remove_var(name);
    }

    #[test]
    fn a_forced_name_counts_even_when_learned() {
        let s = dir("forced");
        let name = "VOLATILE_TEST_FORCED";
        for value in [V[0], V[1], V[2], V[3]] {
            observe(&s, "k", name, Some(value));
        }
        std::env::set_var(name, V[4]);
        let names = vec![name.to_string()];
        let forced = vec![name.to_string()];
        let out = decide(&Request {
            store: &s,
            key: "k",
            candidates: &names,
            mention: "",
            forced: &forced,
            ignore: &[],
            salt: None,
            learn: true,
            persist: true,
            now: 1,
        });
        assert_eq!(out.plan.counted, vec![name.to_string()]);
        std::env::remove_var(name);
    }

    #[test]
    fn learning_off_applies_no_learned_exclusion_and_observes_nothing() {
        let s = dir("off");
        let name = "VOLATILE_TEST_OFF";
        for value in [V[0], V[1], V[2], V[3]] {
            observe(&s, "k", name, Some(value));
        }
        let before = fs::read(path(&s)).unwrap();
        std::env::set_var(name, V[4]);
        let names = vec![name.to_string()];
        let out = decide(&Request {
            store: &s,
            key: "k",
            candidates: &names,
            mention: "",
            forced: &[],
            ignore: &[],
            salt: None,
            learn: false,
            persist: true,
            now: 1,
        });
        assert!(out.plan.excluded.is_empty());
        assert_eq!(fs::read(path(&s)).unwrap(), before);
        std::env::remove_var(name);
    }

    #[test]
    fn an_untrusted_run_applies_its_observation_but_never_writes_it() {
        let s = dir("in-memory");
        let name = "VOLATILE_TEST_MEMORY";
        for value in [V[0], V[1], V[2]] {
            observe(&s, "k", name, Some(value));
        }
        let before = fs::read(path(&s)).unwrap();
        std::env::set_var(name, V[3]);
        let names = vec![name.to_string()];
        let out = decide(&Request {
            store: &s,
            key: "k",
            candidates: &names,
            mention: "",
            forced: &[],
            ignore: &[],
            salt: None,
            learn: true,
            persist: false,
            now: 1,
        });
        assert_eq!(
            learned_names(&out),
            vec![name.to_string()],
            "the observation applies"
        );
        assert!(
            out.changes.is_empty(),
            "nothing was written, so nothing is announced"
        );
        assert_eq!(fs::read(path(&s)).unwrap(), before, "nothing was written");
        std::env::remove_var(name);
    }

    #[test]
    fn a_damaged_state_file_warns_counts_everything_and_is_replaced_by_the_next_write() {
        let s = dir("damaged");
        fs::write(path(&s), b"{not json").unwrap();
        let out = observe(&s, "k", "VOLATILE_TEST_DAMAGED", Some(V[0]));
        assert!(out.plan.excluded.is_empty());
        let warning = out.warning.unwrap();
        assert!(warning.contains("replaced"), "{warning}");
        assert!(observe(&s, "k", "VOLATILE_TEST_DAMAGED", Some(V[1]))
            .warning
            .is_none());
    }

    #[test]
    fn an_oversized_state_file_is_treated_as_damaged() {
        let s = dir("oversize");
        fs::write(path(&s), vec![b' '; (MAX_FILE_BYTES + 1) as usize]).unwrap();
        let out = observe(&s, "k", "VOLATILE_TEST_OVERSIZE", Some(V[0]));
        assert!(out.warning.unwrap().contains("size limit"));
    }

    #[test]
    fn a_state_from_another_version_is_kept_and_never_overwritten() {
        let s = dir("newer");
        let bytes = br#"{"version":2,"keys":{}}"#;
        fs::write(path(&s), bytes).unwrap();
        let out = observe(&s, "k", "VOLATILE_TEST_NEWER", Some(V[0]));
        assert!(out.warning.unwrap().contains("kept as they are"));
        assert_eq!(fs::read(path(&s)).unwrap(), bytes);
    }

    #[test]
    fn a_damage_warning_cannot_carry_workflow_commands_from_the_file() {
        let s = dir("poisoned");
        fs::write(path(&s), b"{\"version\":\"##[error]poisoned\"}").unwrap();
        let out = observe(&s, "k", "VOLATILE_TEST_POISON", Some(V[0]));
        let warning = out.warning.unwrap();
        assert!(!warning.contains("##["), "{warning}");
    }

    #[test]
    fn concurrent_observers_lose_no_runs() {
        let s = dir("concurrent");
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let s = &s;
                scope.spawn(move || {
                    for _ in 0..5 {
                        decide(&Request {
                            store: s,
                            key: "k",
                            candidates: &[],
                            mention: "",
                            forced: &[],
                            ignore: &[],
                            salt: None,
                            learn: true,
                            persist: true,
                            now: 1,
                        });
                    }
                });
            }
        });
        let catalog = read_catalog(&s).ok().unwrap();
        assert_eq!(catalog.keys["k"].runs, 40);
    }

    #[test]
    fn forget_resets_one_key_and_leaves_the_others() {
        let s = dir("forget");
        let name = "VOLATILE_TEST_FORGET";
        for value in [V[0], V[1], V[2], V[3]] {
            observe(&s, "a", name, Some(value));
            observe(&s, "b", name, Some(value));
        }
        assert_eq!(forget(&s, "a"), Ok(true));
        assert_eq!(forget(&s, "a"), Ok(false));
        assert!(observe(&s, "a", name, Some(V[4])).plan.excluded.is_empty());
        assert_eq!(
            learned_names(&observe(&s, "b", name, Some(V[5]))),
            vec![name.to_string()]
        );
    }

    #[test]
    fn list_reports_only_keys_with_names_learned_under_the_current_salt() {
        let s = dir("list");
        let name = "VOLATILE_TEST_LIST";
        for value in [V[0], V[1], V[2], V[3]] {
            observe(&s, "learned", name, Some(value));
        }
        observe(&s, "quiet", name, Some(V[0]));
        assert_eq!(
            list(&s, "").unwrap(),
            vec![("learned".to_string(), vec![(name.to_string(), 4)])]
        );
        assert!(list(&s, "another-salt").unwrap().is_empty());
    }

    #[test]
    fn the_key_count_is_bounded_and_the_stalest_key_goes() {
        let s = dir("keys");
        for i in 0..(MAX_KEYS + 3) {
            decide(&Request {
                store: &s,
                key: &format!("k{i}"),
                candidates: &[],
                mention: "",
                forced: &[],
                ignore: &[],
                salt: None,
                learn: true,
                persist: true,
                now: i as u64 + 1,
            });
        }
        let catalog = read_catalog(&s).ok().unwrap();
        assert_eq!(catalog.keys.len(), MAX_KEYS);
        assert!(!catalog.keys.contains_key("k0"));
        assert!(catalog.keys.contains_key(&format!("k{}", MAX_KEYS + 2)));
    }

    #[test]
    fn the_name_count_per_key_is_bounded() {
        let s = dir("names");
        let names: Vec<String> = (0..(MAX_NAMES + 5))
            .map(|i| format!("VOLATILE_TEST_N{i}"))
            .collect();
        for name in &names {
            std::env::set_var(name, V[0]);
        }
        decide(&Request {
            store: &s,
            key: "k",
            candidates: &names,
            mention: "",
            forced: &[],
            ignore: &[],
            salt: None,
            learn: true,
            persist: true,
            now: 1,
        });
        for name in &names {
            std::env::remove_var(name);
        }
        let catalog = read_catalog(&s).ok().unwrap();
        assert!(catalog.keys["k"].names.len() <= MAX_NAMES);
    }

    #[test]
    fn a_name_that_is_not_utf8_can_be_learned_by_its_exact_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let s = dir("non-utf8");
        let name = OsString::from_vec(b"VOLATILE_TEST_\xff".to_vec());
        let key = crate::run::env_key(&name);
        let names = vec![key.clone()];
        for value in [V[0], V[1], V[2], V[3]] {
            std::env::set_var(&name, value);
            decide(&Request {
                store: &s,
                key: "k",
                candidates: &names,
                mention: "",
                forced: &[],
                ignore: &[],
                salt: None,
                learn: true,
                persist: true,
                now: 1,
            });
        }
        std::env::set_var(&name, V[4]);
        let out = decide(&Request {
            store: &s,
            key: "k",
            candidates: &names,
            mention: "",
            forced: &[],
            ignore: &[],
            salt: None,
            learn: true,
            persist: true,
            now: 1,
        });
        std::env::remove_var(&name);
        assert_eq!(learned_names(&out), vec![key]);
    }
}

#[cfg(test)]
mod review_tests {
    //! Tests for the review of b6b33ad: a learned name is excluded only while it holds an
    //! identifier, an unset learned name counts, provider gates count only under their marker, the
    //! CodeBuild batch identifier is not curated, and the reviewed behavioural names are never learned.
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("stoop-volatile-red-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    const V: [&str; 4] = ["3f9a2c1d", "7b20e4a8", "c5d61f09", "0a8e77b2"];

    fn observe(store: &Path, name: &str, value: Option<&str>) -> Outcome {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
        let names = vec![name.to_string()];
        decide(&Request {
            store,
            key: "k",
            candidates: &names,
            mention: "",
            forced: &[],
            ignore: &[],
            salt: None,
            learn: true,
            persist: true,
            now: 1,
        })
    }

    #[test]
    fn a_learned_name_whose_value_is_no_longer_an_identifier_counts() {
        let s = dir("plain-after-learning");
        let name = "VOLATILE_RED_PLAIN_AFTER";
        for value in V {
            observe(&s, name, Some(value));
        }
        let plain = observe(&s, name, Some("production"));
        assert!(plain.plan.excluded.is_empty(), "{:?}", plain.plan);
        assert!(
            plain.plan.counted.contains(&name.to_string()),
            "{:?}",
            plain.plan
        );
        let staging = observe(&s, name, Some("staging"));
        assert!(staging.plan.excluded.is_empty(), "{:?}", staging.plan);
        // Revoked, not refused: one new identifier does not learn the name again.
        let once = observe(&s, name, Some("d1e2f3a4"));
        assert!(once.plan.excluded.is_empty(), "{:?}", once.plan);
        std::env::remove_var(name);
    }

    #[test]
    fn an_unset_learned_name_counts() {
        let s = dir("unset-after-learning");
        let name = "VOLATILE_RED_UNSET_AFTER";
        for value in V {
            observe(&s, name, Some(value));
        }
        // A run's candidates come from the environment, so an unset name is not among them.
        let unset = decide(&Request {
            store: &s,
            key: "k",
            candidates: &[],
            mention: "",
            forced: &[],
            salt: None,
            learn: true,
            persist: true,
            now: 1,
            ignore: &[],
        });
        assert!(unset.plan.excluded.is_empty(), "{:?}", unset.plan);
        assert!(
            unset.plan.counted.contains(&name.to_string()),
            "{:?}",
            unset.plan
        );
    }

    #[test]
    fn codebuild_batch_build_identifier_is_not_curated() {
        assert!(curated_reason("CODEBUILD_BATCH_BUILD_IDENTIFIER", &all_markers()).is_none());
    }

    #[test]
    fn the_reviewed_behavioural_names_are_never_learned() {
        for name in [
            "SOURCE_DATE_EPOCH",
            "IMAGE_TAG",
            "FEATURE_FLAGS_SHA",
            "MY_APP_TAG",
            "MY_APP_DIGEST",
            "BUILD_EPOCH",
        ] {
            assert!(never_learn(name), "{name} must not be learned");
        }
    }

    #[test]
    fn jenkins_names_count_when_their_provider_marker_is_absent() {
        let names = vec!["BUILD_NUMBER".to_string()];
        let plan = plan(&names, "", &[], &BTreeMap::new(), &BTreeSet::new());
        assert!(
            plan.counted.contains(&"BUILD_NUMBER".to_string()),
            "{plan:?}"
        );
    }

    #[test]
    fn a_provider_gated_name_is_curated_only_where_its_marker_is_set() {
        let none = BTreeSet::new();
        let jenkins = BTreeSet::from(["JENKINS_URL".to_string()]);
        let azure = BTreeSet::from(["TF_BUILD".to_string()]);
        let screen = BTreeSet::from(["STY".to_string()]);
        assert!(curated_reason("BUILD_NUMBER", &none).is_none());
        assert!(curated_reason("BUILD_NUMBER", &jenkins).is_some());
        assert!(curated_reason("GIT_COMMIT", &none).is_none());
        assert!(curated_reason("GIT_COMMIT", &jenkins).is_some());
        assert!(curated_reason("AGENT_ID", &jenkins).is_none());
        assert!(curated_reason("AGENT_ID", &azure).is_some());
        assert!(curated_reason("WINDOW", &none).is_none());
        assert!(curated_reason("WINDOW", &screen).is_some());
        // Terminal size is curated everywhere: its one real effect is on help-text snapshots.
        assert!(curated_reason("COLUMNS", &none).is_some());
    }

    #[test]
    fn an_ignored_learned_name_stays_out_of_the_plan() {
        let s = dir("ignored-learned");
        let name = "VOLATILE_RED_IGNORED";
        for value in V {
            observe(&s, name, Some(value));
        }
        let ignore = vec![name.to_string()];
        let out = decide(&Request {
            store: &s,
            key: "k",
            candidates: &[],
            mention: "",
            forced: &[],
            salt: None,
            learn: true,
            persist: true,
            now: 1,
            ignore: &ignore,
        });
        std::env::remove_var(name);
        assert!(
            out.plan.counted.iter().all(|key| key != name)
                && out.plan.excluded.iter().all(|(key, _)| key != name),
            "{:?}",
            out.plan
        );
    }
}
