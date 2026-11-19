//! Small platform helpers that behave the same on Unix and Windows.

use std::fs::OpenOptions;
use std::process::ExitStatus;

/// Files stoop creates for its own use are private to the user where the platform has modes.
pub trait Private {
    /// Owner read and write only on Unix. Windows has no mode bits, so nothing changes there.
    fn private(&mut self) -> &mut Self;
}

impl Private for OpenOptions {
    fn private(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600)
        }
        #[cfg(windows)]
        {
            self
        }
    }
}

/// The exit code stoop reports for a finished command: its own code, or 128 plus the signal
/// that killed it. Windows has no signals; a process that dies with an NTSTATUS such as
/// `0xC0000005` already carries it as its exit code.
pub fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(0)
    }
    #[cfg(not(unix))]
    {
        1
    }
}
