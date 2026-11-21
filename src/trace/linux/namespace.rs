use std::io;
use std::path::PathBuf;

/// The initial PID namespace inode, from Linux `include/linux/proc_ns.h`.
pub(super) const PROC_PID_INIT_INO: u64 = 0xEFFF_FFFC;

pub(super) fn is_initial_pid_namespace(link: io::Result<PathBuf>) -> bool {
    let Ok(link) = link else {
        return false;
    };
    link.to_str()
        .and_then(|name| name.strip_prefix("pid:["))
        .and_then(|name| name.strip_suffix(']'))
        .filter(|number| number.len() == 10)
        .and_then(|number| number.parse::<u64>().ok())
        == Some(PROC_PID_INIT_INO)
}
