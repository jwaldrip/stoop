//! Operating-system primitives whose Unix and Windows forms differ. Each item has one name and
//! one meaning on both platforms, so callers never branch on the operating system themselves.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

/// Owner-only permissions for the files stoop creates: mode 0600 on Unix. A Windows file takes
/// the access rules of its directory, so nothing is set there.
pub trait OwnerOnly {
    fn owner_only(&mut self) -> &mut Self;
}

impl OwnerOnly for OpenOptions {
    fn owner_only(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600);
        }
        self
    }
}

/// Blocks until this process holds the exclusive lock on `file`. The lock lasts until the file
/// is closed. Use it only on a lock file that is never read as data: a Windows byte-range lock
/// is mandatory, so other handles could not read a locked range.
#[cfg(unix)]
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: flock only reads the descriptor, which the file owns.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Blocks until this process holds the exclusive lock on `file`. See the Unix form.
#[cfg(windows)]
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: the handle belongs to `file`, and the zeroed OVERLAPPED is the synchronous form
    // LockFileEx takes when no event or offset is needed.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if locked == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What an open file is: its device and its index on that device, which together name one file
/// for as long as it exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    pub device: u64,
    pub index: u64,
}

/// The identity of an open file.
#[cfg(unix)]
pub fn file_id(file: &File) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(FileId {
        device: metadata.dev(),
        index: metadata.ino(),
    })
}

/// The identity of an open file.
#[cfg(windows)]
pub fn file_id(file: &File) -> io::Result<FileId> {
    let info = handle_information(file)?;
    Ok(FileId {
        device: u64::from(info.dwVolumeSerialNumber),
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

/// The number of hard links that name an open file.
#[cfg(windows)]
pub fn hard_links(file: &File) -> io::Result<u64> {
    Ok(u64::from(handle_information(file)?.nNumberOfLinks))
}

#[cfg(windows)]
fn handle_information(
    file: &File,
) -> io::Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: the handle is open, and the output is a valid structure of the size it expects.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// Whether `metadata` describes a reparse point (a symbolic link, junction or other redirection)
/// whose target must not be read in its place. Unix opens refuse links with `O_NOFOLLOW`.
#[cfg(windows)]
pub fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Whether `metadata` describes a reparse point. Unix has none; links are refused at open.
#[cfg(not(windows))]
pub fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

/// A process tree: the root process and every process it starts, killed as one unit.
///
/// On Windows the tree is a Job object. The root starts suspended, joins the job, and only then
/// runs, so nothing it starts can escape. The job kills its processes when the last handle to it
/// closes, so a stoop that dies takes its command's processes with it. `release` turns that off
/// for a normal finish, where background processes keep running as they do on Unix.
#[cfg(windows)]
pub mod tree {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenThread, ResumeThread, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
    };

    /// Spawns `command` with its root suspended. Pass the child to [`Tree::contain`] before it
    /// runs anything.
    pub fn spawn_suspended(command: &mut Command) -> io::Result<Child> {
        command.creation_flags(CREATE_SUSPENDED);
        command.spawn()
    }

    /// An owned job object. Dropping it kills its processes unless `release` was called first.
    pub struct Tree {
        job: HANDLE,
    }

    impl Tree {
        /// Places the suspended root in a new job object and resumes it. On failure the root is
        /// killed, so the command never runs outside a tree.
        pub fn contain(child: &mut Child) -> io::Result<Tree> {
            let joined = Tree::join(child);
            if joined.is_err() {
                let _ = child.kill();
                let _ = child.wait();
            }
            joined
        }

        fn join(child: &Child) -> io::Result<Tree> {
            // SAFETY: both arguments are null, which asks for an unnamed job with default security.
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job == 0 {
                return Err(io::Error::last_os_error());
            }
            let tree = Tree { job };
            tree.set_kill_on_close(true)?;
            // SAFETY: the process handle belongs to the child, which the caller still owns.
            if unsafe { AssignProcessToJobObject(tree.job, child.as_raw_handle() as _) } == 0 {
                return Err(io::Error::last_os_error());
            }
            resume_threads(child.id())?;
            Ok(tree)
        }

        fn set_kill_on_close(&self, on: bool) -> io::Result<()> {
            // SAFETY: a zeroed limit structure is a valid "no limits" value.
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            if on {
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            }
            // SAFETY: the buffer is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the stated size.
            let set = unsafe {
                SetInformationJobObject(
                    self.job,
                    JobObjectExtendedLimitInformation,
                    (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if set == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Kills every process in the tree.
        pub fn kill(&self) -> io::Result<()> {
            // SAFETY: the job handle is owned by this value.
            if unsafe { TerminateJobObject(self.job, 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Ends the tree's hold on its processes after a normal finish. Whatever is still running
        /// keeps running, as it does on Unix.
        pub fn release(self) -> io::Result<()> {
            self.set_kill_on_close(false)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            // SAFETY: the handle is owned by this value and is closed exactly once.
            unsafe { CloseHandle(self.job) };
        }
    }

    /// Resumes the one thread a suspended, newly created process has. Threads of other processes
    /// are left alone.
    fn resume_threads(pid: u32) -> io::Result<()> {
        // SAFETY: a snapshot of the threads of every process; closed below.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let result = resume_listed(snapshot, pid);
        // SAFETY: the snapshot handle is owned here and closed exactly once.
        unsafe { CloseHandle(snapshot) };
        result
    }

    fn resume_listed(snapshot: HANDLE, pid: u32) -> io::Result<()> {
        // SAFETY: a zeroed THREADENTRY32 with its size set is the documented starting state.
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut resumed = 0usize;
        // SAFETY: the snapshot is open and the entry is correctly sized.
        let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                // SAFETY: opens a thread of the child for resuming only; closed below.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread == 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: the thread handle is open and owned here.
                let previous = unsafe { ResumeThread(thread) };
                // SAFETY: closes the handle opened above, exactly once.
                unsafe { CloseHandle(thread) };
                if previous == u32::MAX {
                    return Err(io::Error::last_os_error());
                }
                resumed += 1;
            }
            // SAFETY: as for Thread32First.
            more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        if resumed == 0 {
            return Err(io::Error::other(
                "the suspended process has no thread to resume",
            ));
        }
        Ok(())
    }
}

/// Whether the execute bit is set. Windows has no such bit, so its files are never executable.
#[cfg(unix)]
pub fn executable(metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o111 != 0
}

/// Whether the execute bit is set. Windows has no such bit, so its files are never executable.
#[cfg(windows)]
pub fn executable(_metadata: &Metadata) -> bool {
    false
}

/// The number of hard links that name `path`, without following a link at its final name.
#[cfg(unix)]
pub fn hard_links_at(path: &Path) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::symlink_metadata(path)?.nlink())
}

/// The number of hard links that name `path`, without following a link at its final name.
#[cfg(windows)]
pub fn hard_links_at(path: &Path) -> io::Result<u64> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    hard_links(&file)
}

/// Refuses to follow a link at the final name: `O_NOFOLLOW` on Unix. On Windows the link itself is
/// opened, so the caller refuses a reparse point with `is_reparse_point`.
pub trait NoFollow {
    fn no_follow(&mut self) -> &mut Self;
}

impl NoFollow for OpenOptions {
    fn no_follow(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            self.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        self
    }
}

/// The identity and hard-link count of the file a path names, without following a final link.
pub fn identity_at(path: &Path) -> io::Result<(FileId, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path)?;
        Ok((
            FileId {
                device: metadata.dev(),
                index: metadata.ino(),
            },
            metadata.nlink(),
        ))
    }
    #[cfg(windows)]
    {
        let file = OpenOptions::new().read(true).no_follow().open(path)?;
        Ok((file_id(&file)?, hard_links(&file)?))
    }
}

#[cfg(all(test, windows))]
mod tree_tests {
    use super::tree::{spawn_suspended, Tree};
    use std::process::Command;

    #[test]
    fn a_contained_command_reports_its_own_exit_code() {
        let mut child = spawn_suspended(Command::new("cmd").args(["/c", "exit 5"])).unwrap();
        let tree = Tree::contain(&mut child).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(5));
        tree.release().unwrap();
    }

    #[test]
    fn killing_the_tree_ends_its_grandchildren() {
        let mut child =
            spawn_suspended(Command::new("cmd").args(["/c", "ping -n 60 127.0.0.1 > nul"]))
                .unwrap();
        let tree = Tree::contain(&mut child).unwrap();
        tree.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    }
}
