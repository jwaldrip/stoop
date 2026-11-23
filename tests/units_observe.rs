#![cfg(unix)]
//! Exercise diagnostic observations against real traced processes, without runner installs.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {

    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "stoop-observe-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("bin")).unwrap();
            Self { root }
        }

        fn write(&self, path: &str, contents: &str, executable: bool) {
            let path = self.root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
            if executable {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }

        fn command(&self) -> Command {
            let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
            command
                .current_dir(&self.root)
                .env_clear()
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
                )
                .env("HOME", &self.root)
                .env("LOG", self.root.join("launches"))
                .env("STOOP_STORE", self.root.join(".stoop"));
            command
        }

        fn run(&self, args: &[&str]) -> Output {
            self.command().args(args).output().unwrap()
        }

        fn log(&self) -> String {
            fs::read_to_string(self.root.join("launches")).unwrap_or_default()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    fn one_observation(output: &Output, expected: &str) {
        let stderr = stderr(output);
        assert!(output.status.success(), "{stderr}");
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.contains("stoop: observed "))
                .count(),
            1,
            "{stderr}"
        );
        assert!(stderr.lines().any(|line| line == expected), "{stderr}");
    }

    #[test]
    fn npm_shell_and_jest_run_once_then_warm_skip_and_explain_do_not_launch() {
        let f = Fixture::new();
        f.write(
            "bin/npm",
            "#!/bin/sh\nprintf 'npm\\n' >> \"$LOG\"\nexec /bin/sh -c 'exec jest'\n",
            true,
        );
        f.write(
            "bin/jest",
            "#!/bin/sh\nprintf 'jest\\n' >> \"$LOG\"\n",
            true,
        );
        let args = ["run", "--root", ".", "--", "npm", "test"];
        let cold = f.run(&args);
        one_observation(&cold, "stoop: observed jest via npm (diagnostic only)");
        assert_eq!(f.log(), "npm\njest\n");
        assert!(stderr(&cold).contains("recorded"), "{}", stderr(&cold));
        let proof_path = fs::read_dir(f.root.join(".stoop/proofs"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let proof: serde_json::Value =
            serde_json::from_slice(&fs::read(proof_path).unwrap()).unwrap();
        assert!(proof["proofs"][0].get("execs").is_none());
        assert!(proof["proofs"][0].get("effective_argv").is_none());

        let explain = f.run(&["explain", "--root", ".", "--", "npm", "test"]);
        assert!(explain.status.success(), "{}", stderr(&explain));
        assert!(!stderr(&explain).contains("stoop: observed "));
        assert_eq!(f.log(), "npm\njest\n");

        let warm = f.run(&args);
        assert!(warm.status.success(), "{}", stderr(&warm));
        assert!(stderr(&warm).contains("stoop: skip"), "{}", stderr(&warm));
        assert!(!stderr(&warm).contains("stoop: observed "));
        assert_eq!(f.log(), "npm\njest\n");
    }

    #[test]
    fn make_nested_shell_and_shebang_keep_the_switched_working_directory() {
        let f = Fixture::new();
        f.write(
            "Makefile",
            "test:\n\tcd nested && /bin/sh -c 'exec pytest'\n",
            false,
        );
        f.write("nested/.keep", "", false);
        f.write("bin/pytest", "#!/bin/sh\npwd >> \"$LOG\"\n", true);
        let output = f.run(&["run", "--root", ".", "--", "make", "test"]);
        one_observation(
            &output,
            "stoop: observed pytest via make > sh (diagnostic only)",
        );
        let cwd = fs::canonicalize(f.root.join("nested")).unwrap();
        assert_eq!(f.log(), format!("{}\n", cwd.display()));
    }

    #[test]
    fn parallel_spawn_observes_children_without_changing_their_count() {
        let f = Fixture::new();
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        let script = r#"python3 -c 'import os; ps=[os.posix_spawnp("pytest", ["pytest"], os.environ) for _ in range(8)]; [os.waitpid(p, 0) for p in ps]'; true"#;
        for run in 0..12 {
            let output = f
                .command()
                .env("STOOP_STORE", f.root.join(format!(".stoop-{run}")))
                .args(["run", "--root", ".", "--", "sh", "-c", script])
                .output()
                .unwrap();
            one_observation(&output, "stoop: observed pytest via sh (diagnostic only)");
        }
        assert_eq!(f.log().lines().count(), 12 * 8);
    }

    #[test]
    fn shell_wrapper_uses_actual_command_flag_grammar() {
        let f = Fixture::new();
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        f.write("script.sh", "pytest\n", false);
        let script = f.run(&["run", "--root", ".", "--", "bash", "--norc", "script.sh"]);
        one_observation(&script, "stoop: observed pytest (diagnostic only)");
        let command = f.run(&[
            "run",
            "--root",
            ".",
            "--",
            "bash",
            "-o",
            "pipefail",
            "-c",
            "exec pytest",
        ]);
        one_observation(&command, "stoop: observed pytest via sh (diagnostic only)");
        for flag in ["-O", "+O"] {
            let output = f.run(&[
                "run",
                "--root",
                ".",
                "--",
                "bash",
                flag,
                "extglob",
                "-c",
                "exec pytest",
            ]);
            one_observation(&output, "stoop: observed pytest via sh (diagnostic only)");
        }
        assert_eq!(f.log(), "pytest\npytest\npytest\npytest\n");
    }

    #[test]
    fn failed_exec_attempt_is_not_reported_as_a_runner() {
        let f = Fixture::new();
        f.write(
            "bad/jest",
            "#!/bin/sh\nprintf 'wrong\\n' >> \"$LOG\"\n",
            false,
        );
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        let output = f.run(&[
            "run",
            "--root",
            ".",
            "--",
            "sh",
            "-c",
            "./bad/jest >/dev/null 2>&1; exec pytest",
        ]);
        one_observation(&output, "stoop: observed pytest via sh (diagnostic only)");
        assert!(!stderr(&output).contains("jest"));
        assert_eq!(f.log(), "pytest\n");
    }

    #[test]
    fn multiple_runners_are_named_in_one_diagnostic_without_reexecution() {
        let f = Fixture::new();
        f.write(
            "bin/jest",
            "#!/bin/sh\nprintf 'jest\\n' >> \"$LOG\"\n",
            true,
        );
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        let output = f.run(&["run", "--root", ".", "--", "sh", "-c", "jest; pytest"]);

        one_observation(
            &output,
            "stoop: observed jest via sh, pytest via sh (diagnostic only)",
        );
        assert_eq!(f.log(), "jest\npytest\n");
    }
    fn compile(f: &Fixture, source: &str, name: &str, flags: &[&str]) -> PathBuf {
        let input = format!("{name}.c");
        f.write(&input, source, false);
        let output = f.root.join(name);
        let compiled = Command::new("cc")
            .arg(f.root.join(input))
            .args(flags)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{}", stderr(&compiled));
        output
    }

    #[test]
    fn execveat_and_nonleader_thread_exec_preserve_successful_ancestry() {
        let f = Fixture::new();
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        let at = compile(
            &f,
            r#"
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
extern char **environ;
int main(void) {
    char *args[] = { "pytest", 0 };
    execveat(AT_FDCWD, "bin/pytest", args, environ, 0);
    return 1;
}
"#,
            "exec-at",
            &[],
        );
        let thread = compile(
            &f,
            r#"
#include <pthread.h>
#include <unistd.h>
void *run(void *unused) {
    (void)unused;
    char *args[] = { "pytest", 0 };
    execv("bin/pytest", args);
    return 0;
}
int main(void) {
    pthread_t worker;
    if (pthread_create(&worker, 0, run, 0)) return 1;
    return pthread_join(worker, 0);
}
"#,
            "thread-exec",
            &["-pthread"],
        );
        for program in [&at, &thread] {
            let output = f.run(&["run", "--root", ".", "--", program.to_str().unwrap()]);
            one_observation(&output, "stoop: observed pytest (diagnostic only)");
        }
        assert_eq!(f.log(), "pytest\npytest\n");
    }

    #[test]
    fn execveat_with_an_empty_path_observes_the_executed_file() {
        let f = Fixture::new();
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        let helper = compile(
            &f,
            r#"
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
extern char **environ;
int main(void) {
    int fd = open("bin/pytest", O_RDONLY);
    if (fd < 0) return 1;
    char *args[] = { "pytest", 0 };
    execveat(fd, "", args, environ, AT_EMPTY_PATH);
    return 1;
}
"#,
            "exec-fd",
            &[],
        );
        let output = f.run(&["run", "--root", ".", "--", helper.to_str().unwrap()]);
        one_observation(&output, "stoop: observed pytest (diagnostic only)");
        assert_eq!(f.log(), "pytest\n");
    }

    #[test]
    fn oversized_arguments_discard_only_the_diagnostic() {
        let f = Fixture::new();
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        let helper = compile(
            &f,
            r#"
#include <string.h>
#include <unistd.h>
int main(void) {
    static char long_arg[20000];
    memset(long_arg, 'a', sizeof(long_arg) - 1);
    char *args[] = { "pytest", long_arg, 0 };
    execv("bin/pytest", args);
    return 1;
}
"#,
            "large-argv",
            &[],
        );
        let output = f.run(&["run", "--root", ".", "--", helper.to_str().unwrap()]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(!stderr(&output).contains("stoop: observed "));
        assert_eq!(f.log(), "pytest\n");
    }

    #[test]
    fn oversized_argument_count_keeps_previously_observed_runners() {
        let f = Fixture::new();
        f.write(
            "bin/jest",
            "#!/bin/sh\nprintf 'jest\\n' >> \"$LOG\"\n",
            true,
        );
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        compile(
            &f,
            r#"
#include <unistd.h>
int main(void) {
    char *args[132];
    args[0] = "pytest";
    for (int i = 1; i < 131; i++) args[i] = "x";
    args[131] = 0;
    execv("bin/pytest", args);
    return 1;
}
"#,
            "large-argc",
            &[],
        );
        let output = f.run(&[
            "run",
            "--root",
            ".",
            "--",
            "sh",
            "-c",
            "jest; exec ./large-argc",
        ]);
        one_observation(&output, "stoop: observed jest via sh (diagnostic only)");
        assert_eq!(f.log(), "jest\npytest\n");
    }

    #[test]
    fn quiet_no_record_and_shell_mode_do_not_collect_or_announce() {
        for mode in ["--quiet", "--no-record"] {
            let f = Fixture::new();
            f.write(
                "bin/pytest",
                "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
                true,
            );
            let output = f.run(&["run", "--root", ".", mode, "--", "pytest"]);
            assert!(output.status.success(), "{}", stderr(&output));
            assert!(!stderr(&output).contains("stoop: observed "));
            assert_eq!(f.log(), "pytest\n");
        }
        let f = Fixture::new();
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        f.write("step.sh", "pytest\n", false);
        let output = f.run(&["sh", "step.sh"]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(!stderr(&output).contains("stoop: observed "));
        assert_eq!(f.log(), "pytest\n");
    }

    // The shim delivers the child's stop before its parent's fork event on every run,
    // whichever order the kernel reports them in. The lineage must survive that order.
    #[test]
    fn child_stop_before_fork_event_keeps_lineage() {
        let f = Fixture::new();
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n",
            true,
        );
        let source = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// The kernel may report the child's initial stop before or after its parent's fork
// event. This shim always returns the child's stop first: it holds the parent's fork
// event, waits for the child's own stop, and returns the held event on the next wait.
static pid_t held;
static int held_status, phase;

static void __attribute__((noreturn)) fail(const char *message) {
    (void)!write(2, message, strlen(message));
    _exit(97);
}

static void record(const char *order) {
    const char *path = getenv("ORDER_LOG");
    int fd = path ? open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600) : -1;
    if (fd >= 0) {
        (void)!write(fd, order, strlen(order));
        close(fd);
    }
}

pid_t waitpid(pid_t pid, int *status, int options) {
    static pid_t (*real_waitpid)(pid_t, int *, int);
    if (!real_waitpid) real_waitpid = dlsym(RTLD_NEXT, "waitpid");
    if (pid == -1 && phase == 1) {
        phase = 2;
        *status = held_status;
        return held;
    }
    pid_t result = real_waitpid(pid, status, options);
    if (pid != -1 || phase != 0 || result <= 0 || !WIFSTOPPED(*status)) return result;
    int event = (*status >> 16) & 255;
    if (event == 0 && WSTOPSIG(*status) == SIGSTOP) {
        record("child-stop-first");
        phase = 2;
        return result;
    }
    if (event != PTRACE_EVENT_FORK && event != PTRACE_EVENT_VFORK && event != PTRACE_EVENT_CLONE) {
        return result;
    }
    held = result;
    held_status = *status;
    unsigned long message = 0;
    if (ptrace(PTRACE_GETEVENTMSG, held, (void *)0, &message) < 0) fail("order shim: no child pid\n");
    pid_t child = (pid_t)message;
    for (int i = 0; i < 5000; i++) {
        int child_status = 0;
        pid_t got = real_waitpid(child, &child_status, __WALL | WNOHANG);
        if (got == child) {
            if (!WIFSTOPPED(child_status) || WSTOPSIG(child_status) != SIGSTOP) {
                fail("order shim: the child did not stop with SIGSTOP\n");
            }
            *status = child_status;
            record("child-stop-first");
            phase = 1;
            return child;
        }
        if (got < 0 && errno != EINTR) fail("order shim: waiting for the child failed\n");
        usleep(1000);
    }
    record("child-stop-timeout");
    fail("order shim: the child's stop never arrived\n");
}
"#;
        let lib = compile(&f, source, "order-lib", &["-shared", "-fPIC", "-ldl"]);
        let output = f
            .command()
            .env("LD_PRELOAD", &lib)
            .env("ORDER_LOG", f.root.join("order-log"))
            .args(["run", "--root", ".", "--", "sh", "-c", "pytest; true"])
            .output()
            .unwrap();
        one_observation(&output, "stoop: observed pytest via sh (diagnostic only)");
        assert_eq!(
            fs::read_to_string(f.root.join("order-log")).unwrap_or_default(),
            "child-stop-first",
            "the child's stop must reach the tracer before its parent's fork event",
        );
        assert_eq!(f.log(), "pytest\n");
    }

    #[test]
    fn missing_parent_event_releases_child_without_rerunning() {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let f = Fixture::new();
        compile(
            &f,
            r#"
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int fd = open(getenv("LOG"), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return 1;
    if (write(fd, "pytest\n", 7) != 7) return 2;
    pid_t child = fork();
    if (child < 0) return 3;
    if (child == 0) {
        usleep(200000);
        if (write(fd, "child\n", 6) != 6) _exit(4);
        _exit(0);
    }
    waitpid(child, 0, 0);
    write(fd, "parent-survived\n", 16);
    return 0;
}
"#,
            "bin/pytest",
            &[],
        );
        let interposer = compile(
            &f,
            r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
pid_t waitpid(pid_t pid, int *status, int options) {
    static pid_t (*real_waitpid)(pid_t, int *, int);
    static pid_t root;
    static int injected;
    if (!real_waitpid) real_waitpid = dlsym(RTLD_NEXT, "waitpid");
    if ((options & __WALL) && pid > 0 && !root) root = pid;
    pid_t result = real_waitpid(pid, status, options);
    if ((options & __WALL) && pid == -1 && result == root && !injected
        && WIFSTOPPED(*status)) {
        int event = (*status >> 16) & 255;
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
            injected = 1;
            kill(root, SIGKILL);
            const char *path = getenv("DROP_LOG");
            int fd = path ? open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600) : -1;
            if (fd >= 0) { write(fd, "x", 1); close(fd); }
            return real_waitpid(pid, status, options);
        }
    }
    return result;
}
"#,
            "drop-fork",
            &["-shared", "-fPIC", "-ldl"],
        );
        let mut child = f
            .command()
            .env("LD_PRELOAD", &interposer)
            .env("DROP_LOG", f.root.join("drop-log"))
            .args(["run", "--root", ".", "--", "pytest"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!("held child never released: {}", stderr(&output));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let err = stderr(&output);
        assert_eq!(output.status.code(), Some(137), "{err}");
        assert_eq!(fs::read_to_string(f.root.join("drop-log")).unwrap(), "x");
        assert_eq!(f.log(), "pytest\nchild\n");
        assert!(!err.contains("stoop: observed "), "{err}");
        assert!(!err.contains("not traced"), "{err}");
    }

    #[test]
    fn tracer_wait_fault_does_not_announce_or_restart_the_command() {
        let f = Fixture::new();
        f.write(
            "bin/pytest",
            "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\nsleep 1\n",
            true,
        );
        f.write(
            "wait.c",
            r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

pid_t waitpid(pid_t pid, int *status, int options) {
    static pid_t (*real_waitpid)(pid_t, int *, int);
    static int injected;
    if (!real_waitpid) real_waitpid = dlsym(RTLD_NEXT, "waitpid");
    const char *marker = getenv("LOG");
    struct stat st;
    if (pid == -1 && !injected && marker && stat(marker, &st) == 0 && st.st_size > 0) {
        injected = 1;
        errno = EIO;
        return -1;
    }
    return real_waitpid(pid, status, options);
}
"#,
            false,
        );
        let lib = f.root.join("wait.so");
        let compiled = Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&lib)
            .arg(f.root.join("wait.c"))
            .arg("-ldl")
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{}", stderr(&compiled));
        let output = f
            .command()
            .env("LD_PRELOAD", &lib)
            .args(["run", "--root", ".", "--", "pytest"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stderr(&output).contains("wait"), "{}", stderr(&output));
        assert!(!stderr(&output).contains("stoop: observed "));
        assert_eq!(f.log(), "pytest\n");
        assert!(!Path::new(&f.root).join(".stoop/proofs").exists());
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn unsupported_platform_runs_without_observation_or_skips() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let root = std::env::temp_dir().join(format!("stoop-untraced-observe-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("pytest");
    fs::write(&script, "#!/bin/sh\nprintf 'pytest\\n' >> \"$LOG\"\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_stoop"))
            .current_dir(&root)
            .env_clear()
            .env("LOG", root.join("launches"))
            .env("STOOP_STORE", root.join(".stoop"))
            .args(["run", "--", script.to_str().unwrap()])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains("not traced"), "{stderr}");
        assert!(!stderr.contains("stoop: observed "), "{stderr}");
    }
    assert_eq!(
        fs::read_to_string(root.join("launches")).unwrap(),
        "pytest\npytest\n"
    );
    assert!(!root.join(".stoop/proofs").exists());
    fs::remove_dir_all(root).unwrap();
}
