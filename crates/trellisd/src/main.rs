//! trellisd — the Trellis watchdog daemon.
//!
//!   trellisd --config PATH [--json]
//!
//! Single-writer reducer behind a root-only unix socket. A run is admitted
//! only when host preflight passes; otherwise the daemon stays LOCKED and
//! reports honestly via doctor/host.get. Signals drain: SIGTERM/SIGINT latch
//! every live run HOST_SHUTDOWN, then the process exits.

use std::cell::RefCell;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use trellis_core::crypto::Keypair;
use trellis_core::daemon::owner_lock;
use trellis_core::engine::{Engine, RandomIds, Surface};
use trellis_core::frame::{read_frame, write_frame, RESP_MAX};
use trellis_core::guard::GuardModel;
use trellis_core::json::{self, Value};
use trellis_core::os::{LinuxOs, Os};
use trellis_core::schema::host_config;
use trellis_core::store::Store;

static DRAIN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: i32) {
    DRAIN.store(true, Ordering::SeqCst);
}

fn diag(json_mode: bool, code: &str, msg: &str) {
    if json_mode {
        let v = Value::obj(vec![
            ("level", Value::str("error")),
            ("code", Value::str(code)),
            ("msg", Value::str(msg)),
        ]);
        let mut e = std::io::stderr();
        let _ = e.write_all(&v.canonical());
        let _ = e.write_all(b"\n");
    } else {
        eprintln!("trellisd: {}: {}", code, msg);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config: Option<PathBuf> = None;
    let mut json_mode = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" if config.is_none() && i + 1 < args.len() => {
                config = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--json" => {
                json_mode = true;
                i += 1;
            }
            _ => {
                eprintln!("usage: trellisd --config PATH [--json]");
                std::process::exit(64);
            }
        }
    }
    let Some(config_path) = config else {
        eprintln!("usage: trellisd --config PATH [--json]");
        std::process::exit(64);
    };
    std::process::exit(run(&config_path, json_mode));
}

fn run(config_path: &Path, json_mode: bool) -> i32 {
    // 1. host config
    let cfg_bytes = match std::fs::read(config_path) {
        Ok(b) => b,
        Err(_) => {
            diag(json_mode, "INVALID_INPUT", "config unreadable");
            return 64;
        }
    };
    let cfg_v = match json::parse(&cfg_bytes) {
        Ok(v) => v,
        Err(_) => {
            diag(json_mode, "INVALID_INPUT", "config not strict JSON");
            return 64;
        }
    };
    let cfg = match host_config(&cfg_v) {
        Ok(c) => c,
        Err(e) => {
            diag(json_mode, e.code.as_str(), "config schema invalid");
            return 64;
        }
    };

    // 2. data root + owner lock + key
    if let Err(e) = std::fs::create_dir_all(&cfg.data_root) {
        diag(json_mode, "INVALID_INPUT", &format!("data_root: {}", e));
        return 74;
    }
    let lock_path = Path::new(&cfg.data_root).join("owner.lock");
    let _owner = match owner_lock(&lock_path) {
        Ok(f) => f,
        Err(e) => {
            diag(
                json_mode,
                e.code.as_str(),
                "another daemon owns this data root",
            );
            return 75;
        }
    };
    let keys_dir = Path::new(&cfg.data_root).join("keys");
    let seed_path = keys_dir.join(format!("{}.seed", cfg.log_key_id));
    let log_key = match std::fs::read(&seed_path) {
        Ok(s) if s.len() == 32 => Keypair::from_seed(&s.try_into().unwrap()),
        _ => {
            diag(json_mode, "INVALID_INPUT", "log key seed missing/short");
            return 74;
        }
    };

    // 3. durable store
    let store = match Store::open(&Path::new(&cfg.data_root).join("store.db")) {
        Ok(s) => s,
        Err(_) => {
            diag(json_mode, "AUDIT_FAULT", "store open failed");
            return 74;
        }
    };

    // 4. engine over real OS + in-process guard automaton. The independent
    //    trellis-guard process binary is spawned per-run by launch on the
    //    certified profile; on this host preflight will lock before that.
    let kernel_boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let os: Rc<RefCell<dyn Os>> = Rc::new(RefCell::new(LinuxOs::new()));
    let guard = Rc::new(RefCell::new(GuardModel::new(os.clone())));
    let mut eng = Engine::new(
        cfg.clone(),
        store,
        os,
        guard,
        Box::new(RandomIds),
        log_key,
        kernel_boot,
    );
    eng.startup();

    // 5. control socket
    let sock_path = Path::new(&cfg.control_socket);
    if let Some(d) = sock_path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::remove_file(sock_path);
    let listener = match UnixListener::bind(sock_path) {
        Ok(l) => l,
        Err(e) => {
            diag(
                json_mode,
                "INVALID_INPUT",
                &format!("bind {}: {}", cfg.control_socket, e),
            );
            return 69;
        }
    };
    let _ = std::fs::set_permissions(
        sock_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    );
    listener.set_nonblocking(true).ok();

    // 6. signals
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as usize);
        libc::signal(libc::SIGINT, on_signal as *const () as usize);
    }

    let mono0 = Instant::now();
    let mut conns: Vec<UnixStream> = Vec::new();
    while !DRAIN.load(Ordering::SeqCst) {
        eng.now = mono0.elapsed().as_nanos() as u64;
        eng.wall = trellis_core::clock::wall_utc_now();
        eng.boundary();
        // accept
        loop {
            match listener.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).ok();
                    conns.push(s);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        // service each connection: one framed request → one framed response
        let i = 0;
        while i < conns.len() {
            let mut s = conns.remove(i);
            let peer_uid = peer_uid(&s).unwrap_or(u64::MAX);
            let resp = match read_frame(&mut s, trellis_core::frame::REQ_MAX) {
                Ok(Some(raw)) => eng.call(Surface::Control, peer_uid, raw),
                Ok(None) => Value::Null,
                Err(e) => trellis_core::wire::err_response("trq_000000000000000000000", e.code),
            };
            if resp != Value::Null {
                let _ = write_frame(&mut s, &resp, RESP_MAX);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    eng.drain();
    eng.boundary();
    let _ = std::fs::remove_file(sock_path);
    0
}

/// SO_PEERCRED: the connecting process's real uid.
fn peer_uid(s: &UnixStream) -> Option<u64> {
    let fd = s.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as u32;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len,
        )
    };
    if r == 0 && len as usize >= std::mem::size_of::<libc::ucred>() {
        Some(cred.uid as u64)
    } else {
        None
    }
}
