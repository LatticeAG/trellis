//! Agent fd-3 channel (spec §4.3): a SOCK_SEQPACKET socketpair between the
//! agent's inherited fd 3 and the daemon. The channel MUST NOT carry
//! ancillary data — any SCM_RIGHTS/SCM_CREDENTIALS control message is a
//! protocol violation: the receiver fails the request and the run is denied
//! egress (TV-T--47). One request = one packet, bounded by REQ_MAX.

use crate::frame::REQ_MAX;
use crate::types::{ApiErr, Code};
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Receive one request packet from an agent channel socket. Rejects packets
/// with any control messages attached and packets over the request bound.
pub fn agent_recv(sock: &UnixStream) -> Result<Vec<u8>, ApiErr> {
    let fd = sock.as_raw_fd();
    let mut buf = vec![0u8; REQ_MAX + 1];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut cbuf = [0u8; 256];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cbuf.len();
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(ApiErr::new(Code::InvalidInput));
    }
    if n == 0 {
        // orderly shutdown: agent closed fd 3
        return Err(ApiErr::new(Code::Stopped));
    }
    // Any ancillary data at all is a violation; MSG_CTRUNC also trips.
    if msg.msg_controllen > 0 || msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(ApiErr::new(Code::InvalidInput));
    }
    if n as usize > REQ_MAX {
        return Err(ApiErr::new(Code::InvalidInput));
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// Send one packet. Plain data only — the guard never passes descriptors.
pub fn agent_send(sock: &UnixStream, bytes: &[u8]) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: bytes.len(),
    };
    let msg: libc::msghdr = unsafe {
        let mut m: libc::msghdr = std::mem::zeroed();
        m.msg_iov = &mut iov;
        m.msg_iovlen = 1;
        m
    };
    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Test/harness helper: send a packet carrying `fd` via SCM_RIGHTS. Used to
/// prove the receiver rejects descriptor passing.
pub fn send_with_fd(sock: &UnixStream, bytes: &[u8], fd: i32) -> io::Result<()> {
    let sfd = sock.as_raw_fd();
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut _,
        iov_len: bytes.len(),
    };
    let mut cbuf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
        let p = libc::CMSG_DATA(cmsg) as *mut i32;
        std::ptr::write_unaligned(p, fd);
    }
    let n = unsafe { libc::sendmsg(sfd, &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
