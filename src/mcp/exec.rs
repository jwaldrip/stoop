//! Run the stoop binary as a child: bounded output, a deadline, and cancellation.
//!
//! The child's stdin is closed (it must never read the protocol stream) and its output is
//! captured, so none of it reaches stdout. The child leads its own process group, so a timeout
//! or a cancellation takes its whole tree with it.

use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How much of one output stream to keep, and which end of it.
pub struct Keep {
    pub cap: usize,
    /// Keep the last `cap` bytes (a run's output) rather than the first (a plan's JSON).
    pub tail: bool,
}

pub struct Limits {
    pub timeout: Duration,
    pub stdout: Keep,
    pub stderr: Keep,
}

/// Bytes kept from one stream, and the true total they came from.
#[derive(Debug, Clone)]
pub struct Stream {
    pub text: String,
    pub bytes: u64,
    pub truncated: bool,
}

pub struct Finished {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Stream,
    pub stderr: Stream,
    pub timed_out: bool,
    pub cancelled: bool,
}

struct Tail {
    keep: Keep,
    total: u64,
    buf: Vec<u8>,
}

impl Tail {
    fn new(keep: Keep) -> Tail {
        Tail {
            keep,
            total: 0,
            buf: Vec::new(),
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.total += chunk.len() as u64;
        if self.keep.tail {
            self.buf.extend_from_slice(chunk);
            // Trim in batches so a long stream is not shifted on every read.
            if self.buf.len() > 2 * self.keep.cap {
                let cut = self.buf.len() - self.keep.cap;
                self.buf.drain(..cut);
            }
        } else if self.buf.len() < self.keep.cap {
            let room = self.keep.cap - self.buf.len();
            self.buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
    }

    fn finish(&self) -> Stream {
        let kept = if self.keep.tail && self.buf.len() > self.keep.cap {
            &self.buf[self.buf.len() - self.keep.cap..]
        } else {
            &self.buf[..]
        };
        Stream {
            text: String::from_utf8_lossy(kept).into_owned(),
            bytes: self.total,
            truncated: self.total > kept.len() as u64,
        }
    }
}

fn spawn_reader<R: Read + Send + 'static>(mut source: R, sink: Arc<Mutex<Tail>>, done: Sender<()>) {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        while let Ok(n) = source.read(&mut chunk) {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().push(&chunk[..n]);
        }
        let _ = done.send(());
    });
}

/// SIGKILL the child's process group. Only called while the child is still unreaped, so its
/// process group id cannot have been reused.
fn kill_group(pid: i32) {
    // SAFETY: killpg only sends a signal; a failure (the group is already gone) is harmless.
    unsafe {
        libc::killpg(pid, libc::SIGKILL);
    }
}

/// Run `exe` with `args` in `cwd`. `cancelled` is polled while it runs; returning true stops it.
pub fn run(
    exe: &Path,
    args: &[String],
    cwd: &Path,
    limits: Limits,
    cancelled: &mut dyn FnMut() -> bool,
) -> io::Result<Finished> {
    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let pid = child.id() as i32;
    let out = Arc::new(Mutex::new(Tail::new(limits.stdout)));
    let err = Arc::new(Mutex::new(Tail::new(limits.stderr)));
    let (done_tx, done_rx) = channel();
    spawn_reader(
        child.stdout.take().expect("piped"),
        Arc::clone(&out),
        done_tx.clone(),
    );
    spawn_reader(
        child.stderr.take().expect("piped"),
        Arc::clone(&err),
        done_tx,
    );

    let started = Instant::now();
    let mut timed_out = false;
    let mut was_cancelled = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if started.elapsed() >= limits.timeout {
            timed_out = true;
            kill_group(pid);
            break child.wait().ok();
        }
        if cancelled() {
            was_cancelled = true;
            kill_group(pid);
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // A grandchild may hold a pipe open. Wait briefly for the readers, then take what is there.
    let deadline = Instant::now() + Duration::from_millis(500);
    for _ in 0..2 {
        let left = deadline.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
    }
    let stdout = out.lock().unwrap().finish();
    let stderr = err.lock().unwrap().finish();
    Ok(Finished {
        code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()),
        stdout,
        stderr,
        timed_out,
        cancelled: was_cancelled,
    })
}
