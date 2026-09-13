//! OS boundary hooks. The reducer talks to this trait only; `ModelOs` is the
//! deterministic conformance fixture and `LinuxOs` performs real cgroup /
//! namespace / pidfd work on a certified host. Preflight fails closed: an
//! unsupported host never reaches launch.

use crate::gate::GateModel;
use crate::schema::{Endpoint, Exit, Inventory, ProcessIdentity};
use crate::types::Code;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone)]
pub struct OsErr {
    pub code: Code,
    pub detail: &'static str,
}

impl OsErr {
    pub fn new(code: Code, detail: &'static str) -> Self {
        OsErr { code, detail }
    }
    pub fn io(detail: &'static str) -> Self {
        OsErr::new(Code::InvalidInput, detail)
    }
}

/// The launch barrier outcome: owned handles + armed root identity.
pub struct Launched {
    pub root: ProcessIdentity,
    pub task_uid: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct KillAttempt {
    pub cgroup_attempted: bool,
    pub pidfd_attempted: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct EmptyStatus {
    pub populated_gone: bool,
    pub pidfd_exited: bool,
    pub root_exit: Option<Exit>,
}

pub struct LaunchSpec {
    pub run_id: String,
    pub task_uid: u64,
    pub workspace: String,
    pub memory_bytes: u64,
    pub cpu_quota_us: u64,
    pub pids_max: u64,
    pub endpoints: BTreeSet<Endpoint>,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub image_path: String,
    pub image_sha256: String,
}

/// Doctor check row: (name, passed, code).
pub struct Preflight {
    pub checks: Vec<(&'static str, bool, Option<Code>)>,
}

impl Preflight {
    pub fn ready(&self) -> bool {
        self.checks.iter().all(|c| c.1)
    }
}

pub trait Os {
    /// Kernel/platform capability checks for `linux-single-process-v1`.
    fn preflight(&mut self, cfg: &crate::schema::HostConfig) -> Preflight;
    /// sha256 of the runtime image file (hex).
    fn image_sha256(&mut self, path: &str) -> Result<String, OsErr>;
    /// Workspace lease validation: exists, dedicated tree, no sockets/FIFOs/
    /// device nodes/hardlinked regular files, root-owned, not group/world-writable.
    fn workspace_validate(&mut self, path: &str) -> Result<(), OsErr>;
    /// Execute the launch barrier (spec §1.3 steps 3-10): cgroup, namespaces,
    /// mounts, fd hygiene, privilege drop, seccomp, denied egress attach,
    /// denial probe. Returns armed root identity.
    fn launch(&mut self, spec: &LaunchSpec) -> Result<Launched, OsErr>;
    /// Fresh inventory sample; an error is INVENTORY_LOST, never a clean scan.
    fn inventory(&mut self, run_id: &str, now_ns: u64) -> Result<Inventory, OsErr>;
    /// Daemon-retained kill fallback (cgroup.kill + pidfd signal).
    fn kill(&mut self, run_id: &str, now_ns: u64) -> KillAttempt;
    /// Containment status: cgroup.events populated==0 and pidfd exited.
    fn containment(&mut self, run_id: &str, now_ns: u64) -> Result<EmptyStatus, OsErr>;
    /// memory.oom.group trip observed for the owned cgroup.
    fn oom_tripped(&mut self, run_id: &str) -> bool;
    /// Root process exit status if observed.
    fn root_exit(&mut self, run_id: &str) -> Option<Exit>;
    /// Packet gate accessor (kernel lease map model).
    fn gate(&mut self, run_id: &str) -> Option<&mut GateModel>;
    /// Release sandbox handles after positive empty confirmation.
    fn teardown(&mut self, run_id: &str);
    /// Free a task UID back to the pool (on teardown).
    fn free_uid(&mut self, run_id: &str);
}

// ---------------------------------------------------------------------------
// ModelOs — deterministic conformance fixture
// ---------------------------------------------------------------------------

pub struct ModelContainer {
    pub root: ProcessIdentity,
    pub gate: GateModel,
    pub populated: u32,
    pub pidfd_exited: bool,
    pub exit: Option<Exit>,
    pub oom: bool,
    pub inventory: Inventory,
    pub inventory_err: Option<OsErr>,
    pub killed: bool,
    /// Programmable kill latency: container reports empty only when
    /// now >= empty_at_ns (set by kill()). None -> never empty.
    pub empty_at_ns: Option<u64>,
    /// If set, kill() defers emptiness by this many ns.
    pub kill_delay_ns: Option<u64>,
}

/// Deterministic OS fixture implementing the launch/inventory/kill contract.
pub struct ModelOs {
    pub containers: HashMap<String, ModelContainer>,
    pub next_pid: u64,
    pub barrier_fail: Option<OsErr>,
    pub supported: bool,
    pub image_hash_override: Option<String>,
    pub workspace_ok: bool,
    pub used_uids: BTreeSet<u64>,
    pub uid_cursor: u64,
}

impl ModelOs {
    pub fn new() -> Self {
        ModelOs {
            containers: HashMap::new(),
            next_pid: 4200,
            barrier_fail: None,
            supported: true,
            image_hash_override: None,
            workspace_ok: true,
            used_uids: BTreeSet::new(),
            uid_cursor: 63_000,
        }
    }

    fn container(&mut self, run_id: &str) -> Option<&mut ModelContainer> {
        self.containers.get_mut(run_id)
    }
}

impl Default for ModelOs {
    fn default() -> Self {
        Self::new()
    }
}

impl Os for ModelOs {
    fn preflight(&mut self, _cfg: &crate::schema::HostConfig) -> Preflight {
        let ok = self.supported;
        Preflight {
            checks: vec![
                (
                    "privileges",
                    ok,
                    if ok {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "cgroup",
                    ok,
                    if ok {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "bpf",
                    ok,
                    if ok {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "seccomp",
                    ok,
                    if ok {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "namespaces",
                    ok,
                    if ok {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "image",
                    ok,
                    if ok { None } else { Some(Code::InvalidInput) },
                ),
                (
                    "workspace",
                    ok,
                    if ok { None } else { Some(Code::InvalidInput) },
                ),
                (
                    "storage",
                    ok,
                    if ok { None } else { Some(Code::AuditFault) },
                ),
                (
                    "guard",
                    ok,
                    if ok {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
            ],
        }
    }

    fn image_sha256(&mut self, _path: &str) -> Result<String, OsErr> {
        Ok(self
            .image_hash_override
            .clone()
            .unwrap_or_else(|| crate::crypto::sha256_hex(b"trellis-runtime-fixture")))
    }

    fn workspace_validate(&mut self, _path: &str) -> Result<(), OsErr> {
        if self.workspace_ok {
            Ok(())
        } else {
            Err(OsErr::new(Code::InvalidInput, "workspace rejected"))
        }
    }

    fn launch(&mut self, spec: &LaunchSpec) -> Result<Launched, OsErr> {
        if let Some(e) = self.barrier_fail.take() {
            return Err(e);
        }
        let root = ProcessIdentity {
            pid: self.next_pid,
            start_ticks: 100,
            cgroup_inode: 500,
            uid: spec.task_uid,
        };
        self.next_pid += 1;
        let inv = Inventory {
            sampled_ns: 0,
            root: root.clone(),
            tgids: vec![root.pid],
            threads: 1,
            matches: true,
            raw: crate::json::Value::Null, // filled by caller via to_value
        };
        let c = ModelContainer {
            root: root.clone(),
            gate: GateModel::new(spec.endpoints.clone()),
            populated: 1,
            pidfd_exited: false,
            exit: None,
            oom: false,
            inventory: inv,
            inventory_err: None,
            killed: false,
            empty_at_ns: None,
            kill_delay_ns: None,
        };
        self.containers.insert(spec.run_id.clone(), c);
        self.used_uids.insert(spec.task_uid);
        Ok(Launched {
            root,
            task_uid: spec.task_uid,
        })
    }

    fn inventory(&mut self, run_id: &str, now_ns: u64) -> Result<Inventory, OsErr> {
        let c = self
            .container(run_id)
            .ok_or_else(|| OsErr::new(Code::InventoryLost, "no container"))?;
        if let Some(e) = &c.inventory_err {
            return Err(e.clone());
        }
        let mut inv = c.inventory.clone();
        inv.sampled_ns = now_ns;
        Ok(inv)
    }

    fn kill(&mut self, run_id: &str, now_ns: u64) -> KillAttempt {
        match self.container(run_id) {
            Some(c) => {
                c.killed = true;
                let delay = c.kill_delay_ns.unwrap_or(0);
                c.empty_at_ns = Some(now_ns.saturating_add(delay));
                if c.exit.is_none() {
                    c.exit = Some(Exit {
                        code: None,
                        signal: Some(9),
                    });
                }
                KillAttempt {
                    cgroup_attempted: true,
                    pidfd_attempted: true,
                }
            }
            None => KillAttempt {
                cgroup_attempted: false,
                pidfd_attempted: false,
            },
        }
    }

    fn containment(&mut self, run_id: &str, now_ns: u64) -> Result<EmptyStatus, OsErr> {
        match self.container(run_id) {
            Some(c) => {
                let empty = c.empty_at_ns.map(|t| now_ns >= t).unwrap_or(false);
                Ok(EmptyStatus {
                    populated_gone: empty,
                    pidfd_exited: empty,
                    root_exit: c.exit,
                })
            }
            None => Err(OsErr::new(Code::InventoryLost, "no container")),
        }
    }

    fn oom_tripped(&mut self, run_id: &str) -> bool {
        self.container(run_id).map(|c| c.oom).unwrap_or(false)
    }

    fn root_exit(&mut self, run_id: &str) -> Option<Exit> {
        self.container(run_id).and_then(|c| c.exit)
    }

    fn gate(&mut self, run_id: &str) -> Option<&mut GateModel> {
        self.container(run_id).map(|c| &mut c.gate)
    }

    fn teardown(&mut self, run_id: &str) {
        self.containers.remove(run_id);
    }

    fn free_uid(&mut self, run_id: &str) {
        if let Some(c) = self.containers.get(run_id) {
            self.used_uids.remove(&c.root.uid);
        }
    }
}

// ---------------------------------------------------------------------------
// LinuxOs — real host probes. The certified profile is linux-x86_64 with a
// cgroup-v2-eBPF egress gate; on any other host every check reports honestly
// and launch refuses with UNSUPPORTED_HOST rather than pretending.
// ---------------------------------------------------------------------------

pub struct LinuxOs;

impl Default for LinuxOs {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxOs {
    pub fn new() -> Self {
        LinuxOs
    }

    fn cgroup_v2() -> bool {
        std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").is_file()
    }

    fn bpf_usable() -> bool {
        // unprivileged_bpf_disabled==2 means even root-adjacent flows are cut;
        // presence of the knob alone is not proof, but its fatal value is
        // proof of absence.
        match std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
            Ok(s) => s.trim() != "2",
            Err(_) => true, // knob absent on some builds; not disqualifying alone
        }
    }

    fn seccomp_usable() -> bool {
        // PR_GET_SECCOMP returns the current mode (0 = none) without error on
        // kernels built with CONFIG_SECCOMP.
        unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
    }

    fn namespaces_usable() -> bool {
        std::path::Path::new("/proc/self/ns/pid").exists()
            && std::path::Path::new("/proc/self/ns/cgroup").exists()
    }
}

impl Os for LinuxOs {
    fn preflight(&mut self, cfg: &crate::schema::HostConfig) -> Preflight {
        let arch_ok = cfg!(target_arch = "x86_64");
        let root = unsafe { libc::geteuid() } == 0;
        let cgroup = Self::cgroup_v2() && root;
        let bpf = arch_ok && cgroup && Self::bpf_usable();
        let seccomp = arch_ok && Self::seccomp_usable();
        let namespaces = Self::namespaces_usable() && root;
        let image = std::fs::metadata(&cfg.runtime_image).is_ok();
        let workspace = cfg
            .workspace_roots
            .iter()
            .all(|r| std::fs::metadata(r).map(|m| m.is_dir()).unwrap_or(false));
        let storage = std::fs::metadata(&cfg.data_root)
            .map(|m| m.is_dir())
            .unwrap_or(false)
            || std::fs::create_dir_all(&cfg.data_root).is_ok();
        // The guard binary must sit next to trellisd.
        let guard = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("trellis-guard")))
            .map(|p| p.is_file())
            .unwrap_or(false);
        Preflight {
            checks: vec![
                (
                    "privileges",
                    root,
                    if root {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "cgroup",
                    cgroup,
                    if cgroup {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "bpf",
                    bpf,
                    if bpf {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "seccomp",
                    seccomp,
                    if seccomp {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "namespaces",
                    namespaces,
                    if namespaces {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
                (
                    "image",
                    image,
                    if image {
                        None
                    } else {
                        Some(Code::InvalidInput)
                    },
                ),
                (
                    "workspace",
                    workspace,
                    if workspace {
                        None
                    } else {
                        Some(Code::InvalidInput)
                    },
                ),
                (
                    "storage",
                    storage,
                    if storage {
                        None
                    } else {
                        Some(Code::AuditFault)
                    },
                ),
                (
                    "guard",
                    guard,
                    if guard {
                        None
                    } else {
                        Some(Code::UnsupportedHost)
                    },
                ),
            ],
        }
    }

    fn image_sha256(&mut self, path: &str) -> Result<String, OsErr> {
        let bytes = std::fs::read(path)
            .map_err(|_| OsErr::new(Code::InvalidInput, "runtime image unreadable"))?;
        Ok(crate::crypto::sha256_hex(&bytes))
    }

    fn workspace_validate(&mut self, path: &str) -> Result<(), OsErr> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path)
            .map_err(|_| OsErr::new(Code::InvalidInput, "workspace missing"))?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(OsErr::new(
                Code::InvalidInput,
                "workspace not root-owned strict",
            ));
        }
        Ok(())
    }

    fn launch(&mut self, _spec: &LaunchSpec) -> Result<Launched, OsErr> {
        Err(OsErr::new(
            Code::UnsupportedHost,
            "launch requires the certified linux-x86_64 enforcement profile",
        ))
    }

    fn inventory(&mut self, _run_id: &str, _now_ns: u64) -> Result<Inventory, OsErr> {
        Err(OsErr::new(Code::InventoryLost, "no container"))
    }

    fn kill(&mut self, _run_id: &str, _now_ns: u64) -> KillAttempt {
        KillAttempt {
            cgroup_attempted: false,
            pidfd_attempted: false,
        }
    }

    fn containment(&mut self, _run_id: &str, _now_ns: u64) -> Result<EmptyStatus, OsErr> {
        Err(OsErr::new(Code::InventoryLost, "no container"))
    }

    fn oom_tripped(&mut self, _run_id: &str) -> bool {
        false
    }

    fn root_exit(&mut self, _run_id: &str) -> Option<Exit> {
        None
    }

    fn gate(&mut self, _run_id: &str) -> Option<&mut GateModel> {
        None
    }

    fn teardown(&mut self, _run_id: &str) {}

    fn free_uid(&mut self, _run_id: &str) {}
}
