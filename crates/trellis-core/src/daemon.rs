//! Host-side daemon plumbing shared by trellisd and the conformance suite:
//! the single-owner lock and host capability probe. Nothing here grants or
//! denies egress — those decisions live in the reducer.

use crate::types::{ApiErr, Code};
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Take the exclusive owner lock for the data root. A second live daemon
/// gets BUSY (spec §6.2). The file persists; the flock does not.
pub fn owner_lock(path: &Path) -> Result<File, ApiErr> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|_| ApiErr::new(Code::InvalidInput))?;
    let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(ApiErr::new(Code::Busy));
        }
        return Err(ApiErr::new(Code::InvalidInput));
    }
    Ok(f)
}
