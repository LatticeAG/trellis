//! trellis-guard — the independent guard process.
//!
//! Spawned by trellisd with an inherited SOCK_SEQPACKET socket on fd 3.
//! It speaks the closed guard RPC (guard.register/renew/stop/release),
//! drives the §5.4 automaton against the kernel gate, and acknowledges every
//! well-formed call so the daemon can detect a frozen guard via ack age.
//!
//!   trellis-guard --fd 3
//!
//! On hosts without the certified enforcement profile the guard still runs:
//! containment ops fail closed (register denies rather than lease).

use std::cell::RefCell;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::Instant;

use trellis_core::chan::{agent_recv, agent_send};
use trellis_core::guard::GuardModel;
use trellis_core::json;
use trellis_core::os::{LinuxOs, Os};
use trellis_core::wire::{guard_request, GuardRequest};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut fd: Option<i32> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--fd" if fd.is_none() && i + 1 < args.len() => {
                fd = args[i + 1].parse().ok();
                i += 2;
            }
            _ => i += 1,
        }
    }
    let Some(fd) = fd else {
        eprintln!("usage: trellis-guard --fd N");
        std::process::exit(64);
    };
    std::process::exit(run(fd));
}

fn run(fd: i32) -> i32 {
    let sock = unsafe { UnixStream::from_raw_fd(fd) };
    sock.set_nonblocking(false).ok();
    let os: Rc<RefCell<dyn Os>> = Rc::new(RefCell::new(LinuxOs::new()));
    let mut guard = GuardModel::new(os);
    let mono0 = Instant::now();
    loop {
        let now = mono0.elapsed().as_nanos() as u64;
        guard.poll(now);
        let bytes = match agent_recv(&sock) {
            Ok(b) => b,
            Err(_) => return 0, // EOF or protocol violation: channel ends
        };
        let v = match json::parse(&bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let (id, req) = match guard_request(&v) {
            Ok(x) => x,
            Err(e) => {
                let resp = trellis_core::wire::err_response("trq_000000000000000000000", e.code);
                let _ = agent_send(&sock, &resp.canonical());
                continue;
            }
        };
        let (result, err) = match req {
            GuardRequest::Register {
                run_id,
                boot_id,
                cgroup_inode,
                startup_deadline_ns,
                durable_head,
            } => match guard.register(
                now,
                &run_id,
                &boot_id,
                cgroup_inode,
                startup_deadline_ns,
                durable_head,
            ) {
                Ok(r) => (Some(r.wire()), None),
                Err(c) => (None, Some(c)),
            },
            GuardRequest::Renew {
                run_id,
                generation,
                beat_seq,
                agent_deadline_ns,
                durable_head,
            } => match guard.renew(
                now,
                &run_id,
                generation,
                beat_seq,
                agent_deadline_ns,
                durable_head,
            ) {
                Ok(r) => (Some(r.wire()), None),
                Err(rsn) => (None, Some(reason_code(rsn))),
            },
            GuardRequest::Stop {
                run_id,
                generation,
                reason,
            } => match guard.stop(now, &run_id, generation, reason) {
                Ok(r) => (Some(r.wire()), None),
                Err(rsn) => (None, Some(reason_code(rsn))),
            },
            GuardRequest::Release {
                run_id,
                generation,
                terminal_head,
            } => match guard.release(now, &run_id, generation, terminal_head) {
                Ok(_) => (
                    Some(trellis_core::json::Value::obj(vec![(
                        "released",
                        trellis_core::json::Value::Bool(true),
                    )])),
                    None,
                ),
                Err(c) => (None, Some(c)),
            },
        };
        let resp = match (result, err) {
            (Some(r), None) => trellis_core::wire::ok_response(&id, r),
            (_, Some(c)) => trellis_core::wire::err_response(&id, c),
            _ => continue,
        };
        let _ = agent_send(&sock, &resp.canonical());
    }
}

/// Guard-internal reason -> wire code (the daemon maps back to the Reason).
fn reason_code(_r: trellis_core::types::Reason) -> trellis_core::types::Code {
    trellis_core::types::Code::InvalidInput
}
