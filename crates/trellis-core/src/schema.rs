//! Closed-schema validators for every wire/config object (spec §2.1-§2.4, §5).
//!
//! Every object is closed: unknown properties are rejected (UNKNOWN_FIELD),
//! required nullable members must appear, absent differs from null.

use crate::json::Value;
use crate::scalars::*;
use crate::types::{ApiErr, Code};
use std::collections::BTreeMap;

pub type Res<T> = Result<T, ApiErr>;

fn err<T>(c: Code) -> Res<T> {
    Err(ApiErr::new(c))
}

pub fn obj(v: &Value) -> Res<&BTreeMap<String, Value>> {
    v.as_obj().ok_or_else(|| ApiErr::new(Code::InvalidInput))
}

/// Reject any property outside `allowed`.
pub fn closed(m: &BTreeMap<String, Value>, allowed: &[&str]) -> Res<()> {
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) {
            return err(Code::UnknownField);
        }
    }
    Ok(())
}

/// Required member must be present (present null is a valid presence).
pub fn get<'a>(m: &'a BTreeMap<String, Value>, name: &str) -> Res<&'a Value> {
    m.get(name).ok_or_else(|| ApiErr::new(Code::InvalidInput))
}

pub fn f_bool(v: &Value) -> Res<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => err(Code::InvalidInput),
    }
}

pub fn f_int(v: &Value) -> Res<u64> {
    v.as_int().ok_or_else(|| ApiErr::new(Code::InvalidInput))
}

pub fn f_int_range(v: &Value, lo: u64, hi: u64) -> Res<u64> {
    let n = f_int(v)?;
    if n < lo || n > hi {
        return err(Code::InvalidInput);
    }
    Ok(n)
}

pub fn f_str(v: &Value) -> Res<&str> {
    v.as_str().ok_or_else(|| ApiErr::new(Code::InvalidInput))
}

pub fn f_u(v: &Value) -> Res<u64> {
    let s = f_str(v)?;
    parse_u(s).ok_or_else(|| ApiErr::new(Code::InvalidInput))
}

pub fn f_u_str(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_u(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_hash(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_hash(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_sig(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_sig(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_pub(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_pub(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_nonce(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_nonce(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_text(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_text(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_path(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_path(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_utc(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_utc(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_uuid(v: &Value) -> Res<&str> {
    let s = f_str(v)?;
    if !is_uuid(s) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

pub fn f_id<'a>(v: &'a Value, prefix: &str) -> Res<&'a str> {
    let s = f_str(v)?;
    if !is_id(s, prefix) {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

/// v must be integer 1 -> UNSUPPORTED_VERSION for anything else.
pub fn f_v1(m: &BTreeMap<String, Value>) -> Res<()> {
    match m.get("v") {
        Some(Value::Int(1)) => Ok(()),
        Some(Value::Int(_)) => err(Code::UnsupportedVersion),
        Some(_) => err(Code::InvalidInput),
        None => err(Code::InvalidInput),
    }
}

fn f_lit<'a>(v: &'a Value, lit: &str) -> Res<&'a str> {
    let s = f_str(v)?;
    if s != lit {
        return err(Code::InvalidInput);
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Identifiers, pins, endpoints, exec
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub key_id: String,
    pub public_key: String,
}

pub fn pin(v: &Value) -> Res<Pin> {
    let m = obj(v)?;
    closed(m, &["key_id", "public_key"])?;
    Ok(Pin {
        key_id: f_id(get(m, "key_id")?, "trk")?.to_string(),
        public_key: f_pub(get(m, "public_key")?)?.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    pub ipv4: u32,
    pub port: u16,
}

/// Canonical IPv4: four octets, no leading zeros.
pub fn parse_ipv4(s: &str) -> Option<u32> {
    let mut parts = [0u32; 4];
    let split: Vec<&str> = s.split('.').collect();
    if split.len() != 4 {
        return None;
    }
    for (i, p) in split.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        parts[i] = n;
    }
    Some(parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3])
}

pub fn fmt_ipv4(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        ip >> 24,
        (ip >> 16) & 255,
        (ip >> 8) & 255,
        ip & 255
    )
}

/// Hard-denied IPv4 ranges (spec §2.2).
pub const HARD_DENY: &[(u32, u8)] = &[
    (0x00000000, 8),  // 0/8
    (0x0A000000, 8),  // 10/8
    (0x64400000, 10), // 100.64/10
    (0x7F000000, 8),  // 127/8
    (0xA9FE0000, 16), // 169.254/16
    (0xAC100000, 12), // 172.16/12
    (0xC0000000, 24), // 192.0.0/24
    (0xC0000200, 24), // 192.0.2/24
    (0xC0A80000, 16), // 192.168/16
    (0xC6120000, 15), // 198.18/15
    (0xC6336400, 24), // 198.51.100/24
    (0xCB007100, 24), // 203.0.113/24
    (0xE0000000, 4),  // 224/4
    (0xF0000000, 4),  // 240/4
];

pub fn in_deny_ranges(ip: u32, extra: &[(u32, u8)]) -> bool {
    HARD_DENY
        .iter()
        .chain(extra.iter())
        .any(|&(base, pfx)| (ip >> (32 - pfx)) == (base >> (32 - pfx)))
}

pub fn endpoint(v: &Value, extra_deny: &[(u32, u8)]) -> Res<Endpoint> {
    let m = obj(v)?;
    closed(m, &["ipv4", "port"])?;
    let ip_s = f_str(get(m, "ipv4")?)?;
    let ip = parse_ipv4(ip_s).ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
    if in_deny_ranges(ip, extra_deny) {
        return err(Code::InvalidInput);
    }
    let port = f_int_range(get(m, "port")?, 1, 65535)? as u16;
    Ok(Endpoint { ipv4: ip, port })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exec {
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
}

pub fn exec(v: &Value) -> Res<Exec> {
    let m = obj(v)?;
    closed(m, &["argv", "cwd", "env"])?;
    let argv_v = get(m, "argv")?
        .as_arr()
        .ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
    if argv_v.is_empty() || argv_v.len() > 64 {
        return err(Code::InvalidInput);
    }
    let mut argv = Vec::with_capacity(argv_v.len());
    let mut total = 0usize;
    for a in argv_v {
        let s = f_str(a)?;
        if s.is_empty() || s.len() > 4096 || s.contains('\0') {
            return err(Code::InvalidInput);
        }
        total += s.len();
        argv.push(s.to_string());
    }
    if total > 16384 {
        return err(Code::InvalidInput);
    }
    if !argv[0].starts_with('/') {
        return err(Code::InvalidInput);
    }
    let cwd = f_path(get(m, "cwd")?)?.to_string();
    let env_v = obj(get(m, "env")?)?;
    if env_v.len() > 32 {
        return err(Code::InvalidInput);
    }
    let mut env = BTreeMap::new();
    let mut etotal = 0usize;
    for (k, val) in env_v {
        let kb = k.as_bytes();
        if kb.is_empty()
            || kb.len() > 64
            || !matches!(kb[0], b'A'..=b'Z' | b'_')
            || !kb[1..]
                .iter()
                .all(|c| matches!(c, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
        {
            return err(Code::InvalidInput);
        }
        let s = f_str(val)?;
        if s.len() > 4096 || s.contains('\0') {
            return err(Code::InvalidInput);
        }
        etotal += k.len() + s.len();
        env.insert(k.clone(), s.to_string());
    }
    if etotal > 8192 {
        return err(Code::InvalidInput);
    }
    Ok(Exec { argv, cwd, env })
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapMode {
    None,
    Lexwatt { config_hash: String },
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub policy_id: String,
    pub revision: u64,
    pub agent_id: String,
    pub image_sha256: String,
    pub exec_hash: String,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub startup_ms: u64,
    pub max_threads: u64,
    pub scan_ms: u64,
    pub allow: Vec<Endpoint>,
    pub memory_bytes: u64,
    pub cpu_quota_us: u64,
    pub cap: CapMode,
    pub operator_ref: String,
    /// Canonical validated body value (what gets hashed/signed).
    pub body: Value,
}

/// Validate a PolicyBody Value with bound rules. `extra_deny` holds
/// host-owned/local prefixes that additionally cannot appear in allow.
pub fn policy_body(v: &Value, extra_deny: &[(u32, u8)]) -> Res<Policy> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "kind",
            "policy_id",
            "revision",
            "agent_id",
            "image_sha256",
            "exec_hash",
            "heartbeat",
            "replication",
            "egress",
            "resources",
            "cap",
            "operator_ref",
        ],
    )?;
    f_v1(m)?;
    f_lit(get(m, "kind")?, "trellis-policy")?;
    let policy_id = f_id(get(m, "policy_id")?, "trp")?.to_string();
    let revision = f_u(get(m, "revision")?)?;
    if revision < 1 {
        return err(Code::InvalidInput);
    }
    let agent_id = f_id(get(m, "agent_id")?, "tra")?.to_string();
    let image_sha256 = f_hash(get(m, "image_sha256")?)?.to_string();
    let exec_hash = f_hash(get(m, "exec_hash")?)?.to_string();

    let hb = obj(get(m, "heartbeat")?)?;
    closed(hb, &["interval_ms", "timeout_ms", "startup_ms"])?;
    let interval_ms = f_int_range(get(hb, "interval_ms")?, 100, 10_000)?;
    let timeout_ms = f_int_range(get(hb, "timeout_ms")?, 3 * interval_ms, 60_000)?;
    let startup_ms = f_int_range(get(hb, "startup_ms")?, timeout_ms, 60_000)?;

    let rp = obj(get(m, "replication")?)?;
    closed(rp, &["profile", "max_threads", "scan_ms"])?;
    f_lit(get(rp, "profile")?, "single-process")?;
    let max_threads = f_int_range(get(rp, "max_threads")?, 1, 256)?;
    let scan_ms = f_int_range(get(rp, "scan_ms")?, 50, 1000)?;
    if scan_ms > interval_ms {
        return err(Code::InvalidInput);
    }

    let eg = obj(get(m, "egress")?)?;
    closed(eg, &["profile", "allow"])?;
    f_lit(get(eg, "profile")?, "ipv4-tcp-static")?;
    let allow_v = get(eg, "allow")?
        .as_arr()
        .ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
    if allow_v.len() > 32 {
        return err(Code::InvalidInput);
    }
    let mut allow = Vec::with_capacity(allow_v.len());
    for e in allow_v {
        allow.push(endpoint(e, extra_deny)?);
    }
    // must be sorted by numeric address then port, no duplicates
    for w in allow.windows(2) {
        if w[0] >= w[1] {
            return err(Code::InvalidInput);
        }
    }

    let rs = obj(get(m, "resources")?)?;
    closed(rs, &["memory_bytes", "cpu_quota_us", "cpu_period_us"])?;
    let memory_bytes = f_u(get(rs, "memory_bytes")?)?;
    if !(67_108_864..=17_179_869_184).contains(&memory_bytes) {
        return err(Code::InvalidInput);
    }
    let cpu_quota_us = f_int_range(get(rs, "cpu_quota_us")?, 1000, 100_000)?;
    if f_int(get(rs, "cpu_period_us")?)? != 100_000 {
        return err(Code::InvalidInput);
    }

    let cap_m = obj(get(m, "cap")?)?;
    let cap = match f_str(get(cap_m, "mode")?)? {
        "none" => {
            closed(cap_m, &["mode"])?;
            CapMode::None
        }
        "lexwatt" => {
            closed(cap_m, &["mode", "config_hash", "required"])?;
            let config_hash = f_hash(get(cap_m, "config_hash")?)?.to_string();
            if !f_bool(get(cap_m, "required")?)? {
                return err(Code::InvalidInput);
            }
            CapMode::Lexwatt { config_hash }
        }
        _ => return err(Code::InvalidInput),
    };

    let operator_ref = f_text(get(m, "operator_ref")?)?.to_string();

    Ok(Policy {
        policy_id,
        revision,
        agent_id,
        image_sha256,
        exec_hash,
        interval_ms,
        timeout_ms,
        startup_ms,
        max_threads,
        scan_ms,
        allow,
        memory_bytes,
        cpu_quota_us,
        cap,
        operator_ref,
        body: v.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct SignedPolicy {
    pub policy: Policy,
    pub key_id: String,
    pub sig: String,
    pub raw: Value,
}

pub fn signed_policy(v: &Value, extra_deny: &[(u32, u8)]) -> Res<SignedPolicy> {
    let m = obj(v)?;
    closed(m, &["body", "key_id", "sig"])?;
    let policy = policy_body(get(m, "body")?, extra_deny)?;
    Ok(SignedPolicy {
        policy,
        key_id: f_id(get(m, "key_id")?, "trk")?.to_string(),
        sig: f_sig(get(m, "sig")?)?.to_string(),
        raw: v.clone(),
    })
}

// ---------------------------------------------------------------------------
// HostConfig, KeyFile, StartInput
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HostConfig {
    pub host_id: String,
    pub control_socket: String,
    pub data_root: String,
    pub runtime_image: String,
    pub workspace_roots: Vec<String>,
    pub task_uid_min: u64,
    pub task_uid_max: u64,
    pub max_runs: u64,
    pub policy_pins: Vec<Pin>,
    pub log_key_id: String,
    pub renew_ms: u64,
    pub lease_ms: u64,
    pub stop_wait_ms: u64,
    pub audit_max_bytes: u64,
    pub audit_reserve_bytes: u64,
    pub retention_days: u64,
    pub cap_adapter: String,
    pub raw: Value,
}

pub fn host_config(v: &Value) -> Res<HostConfig> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "host_id",
            "control_socket",
            "data_root",
            "runtime_image",
            "workspace_roots",
            "task_uid_min",
            "task_uid_max",
            "max_runs",
            "policy_pins",
            "log_key_id",
            "guard",
            "audit",
            "cap_adapter",
        ],
    )?;
    f_v1(m)?;
    let host_id = f_id(get(m, "host_id")?, "trh")?.to_string();
    let control_socket = f_path(get(m, "control_socket")?)?.to_string();
    let data_root = f_path(get(m, "data_root")?)?.to_string();
    let runtime_image = f_path(get(m, "runtime_image")?)?.to_string();

    let roots_v = get(m, "workspace_roots")?
        .as_arr()
        .ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
    if roots_v.is_empty() || roots_v.len() > 32 {
        return err(Code::InvalidInput);
    }
    let mut workspace_roots = Vec::new();
    for r in roots_v {
        workspace_roots.push(f_path(r)?.to_string());
    }
    {
        let mut dedup = workspace_roots.clone();
        dedup.sort();
        dedup.dedup();
        if dedup.len() != workspace_roots.len() {
            return err(Code::InvalidInput); // aliasing roots
        }
    }

    let task_uid_min = f_int_range(get(m, "task_uid_min")?, 1000, 2_147_483_647)?;
    let task_uid_max = f_int_range(get(m, "task_uid_max")?, 1000, 2_147_483_647)?;
    if task_uid_max < task_uid_min {
        return err(Code::InvalidInput);
    }
    let pool = task_uid_max - task_uid_min + 1;
    let max_runs = f_int_range(get(m, "max_runs")?, 1, 32)?;
    if max_runs > pool {
        return err(Code::InvalidInput);
    }

    let pins_v = get(m, "policy_pins")?
        .as_arr()
        .ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
    if pins_v.is_empty() || pins_v.len() > 256 {
        return err(Code::InvalidInput);
    }
    let mut policy_pins = Vec::new();
    for p in pins_v {
        policy_pins.push(pin(p)?);
    }
    {
        let mut ids: Vec<&str> = policy_pins.iter().map(|p| p.key_id.as_str()).collect();
        ids.sort();
        ids.dedup();
        let mut pubs: Vec<&str> = policy_pins.iter().map(|p| p.public_key.as_str()).collect();
        pubs.sort();
        pubs.dedup();
        if ids.len() != policy_pins.len() || pubs.len() != policy_pins.len() {
            return err(Code::InvalidInput);
        }
    }

    let log_key_id = f_id(get(m, "log_key_id")?, "trk")?.to_string();

    let g = obj(get(m, "guard")?)?;
    closed(g, &["renew_ms", "lease_ms", "stop_wait_ms"])?;
    // v1 fixes these constants (literal schema members).
    let renew_ms = f_int(get(g, "renew_ms")?)?;
    let lease_ms = f_int(get(g, "lease_ms")?)?;
    let stop_wait_ms = f_int(get(g, "stop_wait_ms")?)?;
    if renew_ms != 250 || lease_ms != 750 || stop_wait_ms != 2000 {
        return err(Code::InvalidInput);
    }

    let a = obj(get(m, "audit")?)?;
    closed(a, &["max_bytes_per_run", "reserve_bytes", "retention_days"])?;
    let audit_max_bytes = f_u(get(a, "max_bytes_per_run")?)?;
    if !(67_108_864..=10_737_418_240).contains(&audit_max_bytes) {
        return err(Code::InvalidInput);
    }
    let audit_reserve_bytes = f_u(get(a, "reserve_bytes")?)?;
    if audit_reserve_bytes != 1_048_576 {
        return err(Code::InvalidInput);
    }
    let retention_days = f_int_range(get(a, "retention_days")?, 180, 3650)?;

    let cap_adapter = match f_str(get(m, "cap_adapter")?)? {
        "disabled" => "disabled".to_string(),
        "lexwatt-contained-v1" => "lexwatt-contained-v1".to_string(),
        _ => return err(Code::InvalidInput),
    };

    Ok(HostConfig {
        host_id,
        control_socket,
        data_root,
        runtime_image,
        workspace_roots,
        task_uid_min,
        task_uid_max,
        max_runs,
        policy_pins,
        log_key_id,
        renew_ms,
        lease_ms,
        stop_wait_ms,
        audit_max_bytes,
        audit_reserve_bytes,
        retention_days,
        cap_adapter,
        raw: v.clone(),
    })
}

pub fn key_file(v: &Value) -> Res<Pin> {
    let m = obj(v)?;
    closed(m, &["v", "key_id", "public_key"])?;
    f_v1(m)?;
    Ok(Pin {
        key_id: f_id(get(m, "key_id")?, "trk")?.to_string(),
        public_key: f_pub(get(m, "public_key")?)?.to_string(),
    })
}

#[derive(Debug, Clone)]
pub struct StartInput {
    pub policy: SignedPolicy,
    pub exec: Exec,
    pub workspace_root: String,
    pub task_ref: Option<String>,
    pub expected_host_epoch: u64,
    pub raw: Value,
}

pub fn start_input(v: &Value, extra_deny: &[(u32, u8)]) -> Res<StartInput> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "policy",
            "exec",
            "workspace_root",
            "task_ref",
            "expected_host_epoch",
        ],
    )?;
    let policy = signed_policy(get(m, "policy")?, extra_deny)?;
    let exec = exec(get(m, "exec")?)?;
    let workspace_root = f_path(get(m, "workspace_root")?)?.to_string();
    let task_ref = match get(m, "task_ref")? {
        Value::Null => None,
        t => Some(f_text(t)?.to_string()),
    };
    let expected_host_epoch = f_u(get(m, "expected_host_epoch")?)?;
    Ok(StartInput {
        policy,
        exec,
        workspace_root,
        task_ref,
        expected_host_epoch,
        raw: v.clone(),
    })
}

// ---------------------------------------------------------------------------
// Live protocol objects (spec §2.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u64,
    pub start_ticks: u64,
    pub cgroup_inode: u64,
    pub uid: u64,
}

pub fn process_identity(v: &Value) -> Res<ProcessIdentity> {
    let m = obj(v)?;
    closed(m, &["pid", "start_ticks", "cgroup_inode", "uid"])?;
    Ok(ProcessIdentity {
        pid: f_int_range(get(m, "pid")?, 1, 2_147_483_647)?,
        start_ticks: f_u(get(m, "start_ticks")?)?,
        cgroup_inode: f_u(get(m, "cgroup_inode")?)?,
        uid: f_int(get(m, "uid")?)?,
    })
}

impl ProcessIdentity {
    pub fn to_value(&self) -> Value {
        Value::obj(vec![
            ("pid", Value::int(self.pid)),
            ("start_ticks", Value::str(self.start_ticks.to_string())),
            ("cgroup_inode", Value::str(self.cgroup_inode.to_string())),
            ("uid", Value::int(self.uid)),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub sampled_ns: u64,
    pub root: ProcessIdentity,
    pub tgids: Vec<u64>,
    pub threads: u64,
    pub matches: bool,
    pub raw: Value,
}

/// Shape validation only: any observed TGID set is representable evidence;
/// `matches` records the separately evaluated predicate and may be false.
pub fn inventory(v: &Value) -> Res<Inventory> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "sampled_ns",
            "root",
            "tgids",
            "threads",
            "matches",
            "coverage",
        ],
    )?;
    let sampled_ns = f_u(get(m, "sampled_ns")?)?;
    let root = process_identity(get(m, "root")?)?;
    let tgids_v = get(m, "tgids")?
        .as_arr()
        .ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
    let mut tgids = Vec::with_capacity(tgids_v.len());
    for t in tgids_v {
        tgids.push(f_int_range(t, 1, 2_147_483_647)?);
    }
    // sorted distinct list
    for w in tgids.windows(2) {
        if w[0] >= w[1] {
            return err(Code::InvalidInput);
        }
    }
    let threads = f_int(get(m, "threads")?)?;
    let matches = f_bool(get(m, "matches")?)?;
    f_lit(get(m, "coverage")?, "local-cgroup-single-process")?;
    Ok(Inventory {
        sampled_ns,
        root,
        tgids,
        threads,
        matches,
        raw: v.clone(),
    })
}

/// The match predicate: tgids == [root.pid], root identity equals the armed
/// identity, and 1 <= threads <= max_threads.
pub fn inventory_matches(inv: &Inventory, armed: &ProcessIdentity, max_threads: u64) -> bool {
    inv.tgids == [armed.pid]
        && inv.root.pid == armed.pid
        && inv.root.start_ticks == armed.start_ticks
        && inv.root.cgroup_inode == armed.cgroup_inode
        && inv.root.uid == armed.uid
        && inv.threads >= 1
        && inv.threads <= max_threads
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub run_id: String,
    pub boot_id: String,
    pub challenge_id: String,
    pub seq: u64,
    pub nonce: String,
    pub policy_hash: String,
    pub expires_ns: u64,
    pub raw: Value,
}

pub fn challenge(v: &Value) -> Res<Challenge> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "run_id",
            "boot_id",
            "challenge_id",
            "seq",
            "nonce",
            "policy_hash",
            "expires_ns",
        ],
    )?;
    Ok(Challenge {
        run_id: f_id(get(m, "run_id")?, "trr")?.to_string(),
        boot_id: f_id(get(m, "boot_id")?, "trb")?.to_string(),
        challenge_id: f_id(get(m, "challenge_id")?, "trc")?.to_string(),
        seq: f_u(get(m, "seq")?)?,
        nonce: f_nonce(get(m, "nonce")?)?.to_string(),
        policy_hash: f_hash(get(m, "policy_hash")?)?.to_string(),
        expires_ns: f_u(get(m, "expires_ns")?)?,
        raw: v.clone(),
    })
}

impl Challenge {
    pub fn to_value(&self) -> Value {
        self.raw.clone()
    }
}

#[derive(Debug, Clone)]
pub struct BeatInput {
    pub run_id: String,
    pub boot_id: String,
    pub challenge_id: String,
    pub seq: u64,
    pub nonce: String,
    pub policy_hash: String,
    pub scope_ok: bool,
    pub claimed_processes: u64,
    pub progress: u64,
    pub raw: Value,
}

pub fn beat_input(v: &Value) -> Res<BeatInput> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "run_id",
            "boot_id",
            "challenge_id",
            "seq",
            "nonce",
            "policy_hash",
            "scope_ok",
            "claimed_processes",
            "progress",
        ],
    )?;
    Ok(BeatInput {
        run_id: f_id(get(m, "run_id")?, "trr")?.to_string(),
        boot_id: f_id(get(m, "boot_id")?, "trb")?.to_string(),
        challenge_id: f_id(get(m, "challenge_id")?, "trc")?.to_string(),
        seq: f_u(get(m, "seq")?)?,
        nonce: f_nonce(get(m, "nonce")?)?.to_string(),
        policy_hash: f_hash(get(m, "policy_hash")?)?.to_string(),
        scope_ok: f_bool(get(m, "scope_ok")?)?,
        claimed_processes: f_int(get(m, "claimed_processes")?)?,
        progress: f_u(get(m, "progress")?)?,
        raw: v.clone(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit {
    pub code: Option<u64>,
    pub signal: Option<u64>,
}

/// Exit: exactly one non-null member; code 0..255 or signal 1..64.
pub fn exit(v: &Value) -> Res<Exit> {
    let m = obj(v)?;
    closed(m, &["code", "signal"])?;
    let code = match get(m, "code")? {
        Value::Null => None,
        c => Some(f_int_range(c, 0, 255)?),
    };
    let signal = match get(m, "signal")? {
        Value::Null => None,
        s => Some(f_int_range(s, 1, 64)?),
    };
    if code.is_some() == signal.is_some() {
        return err(Code::InvalidInput);
    }
    Ok(Exit { code, signal })
}

impl Exit {
    pub fn to_value(&self) -> Value {
        Value::obj(vec![
            ("code", self.code.map(Value::int).unwrap_or(Value::Null)),
            ("signal", self.signal.map(Value::int).unwrap_or(Value::Null)),
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    Operator,
    Agent,
    Daemon,
    Guard,
    Engine,
}

impl ActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Agent => "agent",
            Self::Daemon => "daemon",
            Self::Guard => "guard",
            Self::Engine => "engine",
        }
    }
}

pub fn actor(v: &Value) -> Res<(ActorKind, Option<u64>)> {
    let m = obj(v)?;
    closed(m, &["kind", "uid"])?;
    let kind = match f_str(get(m, "kind")?)? {
        "operator" => ActorKind::Operator,
        "agent" => ActorKind::Agent,
        "daemon" => ActorKind::Daemon,
        "guard" => ActorKind::Guard,
        "engine" => ActorKind::Engine,
        _ => return err(Code::InvalidInput),
    };
    let uid = match get(m, "uid")? {
        Value::Null => None,
        u => Some(f_int(u)?),
    };
    Ok((kind, uid))
}

/// Art: mandatory on every event; evidence literal.
pub fn art(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(m, &["operator_ref", "oversight", "evidence"])?;
    f_text(get(m, "operator_ref")?)?;
    match f_str(get(m, "oversight")?)? {
        "automatic" | "human_requested" => {}
        _ => return err(Code::InvalidInput),
    }
    f_lit(get(m, "evidence")?, "software_observation")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Events (spec §2.4)
// ---------------------------------------------------------------------------

pub const EVENT_KINDS: &[&str] = &[
    "RunCreated",
    "RunArmed",
    "RunRejected",
    "HeartbeatAccepted",
    "GateGranted",
    "InventoryObserved",
    "StopLatched",
    "GateClosed",
    "KillIssued",
    "StopUnconfirmed",
    "ContainmentEmpty",
    "RunStopped",
    "RequestDenied",
    "FaultObserved",
    "RecoveryObserved",
    "CapObserved",
];

pub fn head(v: &Value) -> Res<crate::types::Head> {
    let m = obj(v)?;
    closed(m, &["seq", "hash"])?;
    Ok(crate::types::Head {
        seq: f_u(get(m, "seq")?)?,
        hash: f_hash(get(m, "hash")?)?.to_string(),
    })
}

/// Validate EventData by kind.
pub fn event_data(kind: &str, v: &Value) -> Res<()> {
    let m = obj(v)?;
    match kind {
        "RunCreated" => {
            closed(
                m,
                &[
                    "agent_id",
                    "policy_hash",
                    "exec_hash",
                    "task_ref",
                    "host_epoch",
                ],
            )?;
            f_id(get(m, "agent_id")?, "tra")?;
            f_hash(get(m, "policy_hash")?)?;
            f_hash(get(m, "exec_hash")?)?;
            match get(m, "task_ref")? {
                Value::Null => {}
                t => {
                    f_text(t)?;
                }
            }
            f_u(get(m, "host_epoch")?)?;
        }
        "RunArmed" => {
            closed(m, &["root", "startup_deadline_ns"])?;
            process_identity(get(m, "root")?)?;
            f_u(get(m, "startup_deadline_ns")?)?;
        }
        "RunRejected" => {
            closed(m, &["code"])?;
            if Code::parse(f_str(get(m, "code")?)?).is_none() {
                return err(Code::InvalidInput);
            }
        }
        "HeartbeatAccepted" => {
            closed(m, &["beat_seq", "challenge_id", "deadline_ns", "progress"])?;
            f_u(get(m, "beat_seq")?)?;
            f_id(get(m, "challenge_id")?, "trc")?;
            f_u(get(m, "deadline_ns")?)?;
            f_u(get(m, "progress")?)?;
        }
        "GateGranted" => {
            closed(m, &["beat_seq", "deadline_ns", "guard_generation"])?;
            f_u(get(m, "beat_seq")?)?;
            f_u(get(m, "deadline_ns")?)?;
            f_u(get(m, "guard_generation")?)?;
        }
        "InventoryObserved" => {
            closed(m, &["inventory"])?;
            inventory(get(m, "inventory")?)?;
        }
        "StopLatched" => {
            closed(m, &["reason", "note_hash"])?;
            if crate::types::Reason::parse(f_str(get(m, "reason")?)?).is_none() {
                return err(Code::InvalidInput);
            }
            match get(m, "note_hash")? {
                Value::Null => {}
                h => {
                    f_hash(h)?;
                }
            }
        }
        "GateClosed" => {
            closed(m, &["guard_generation", "confirmed_ns"])?;
            f_u(get(m, "guard_generation")?)?;
            f_u(get(m, "confirmed_ns")?)?;
        }
        "KillIssued" => {
            closed(m, &["cgroup_attempted", "pidfd_attempted"])?;
            f_bool(get(m, "cgroup_attempted")?)?;
            f_bool(get(m, "pidfd_attempted")?)?;
        }
        "StopUnconfirmed" => {
            closed(m, &["gate_closed", "empty_observed"])?;
            f_bool(get(m, "gate_closed")?)?;
            f_bool(get(m, "empty_observed")?)?;
        }
        "ContainmentEmpty" => {
            closed(m, &["root_exit", "observed_ns"])?;
            match get(m, "root_exit")? {
                Value::Null => {}
                e => {
                    exit(e)?;
                }
            }
            f_u(get(m, "observed_ns")?)?;
        }
        "RunStopped" => {
            closed(
                m,
                &[
                    "first_reason",
                    "gate_closed",
                    "empty_observed",
                    "evidence_gap",
                ],
            )?;
            if crate::types::Reason::parse(f_str(get(m, "first_reason")?)?).is_none() {
                return err(Code::InvalidInput);
            }
            if !f_bool(get(m, "gate_closed")?)? {
                return err(Code::InvalidInput);
            }
            if !f_bool(get(m, "empty_observed")?)? {
                return err(Code::InvalidInput);
            }
            f_bool(get(m, "evidence_gap")?)?;
        }
        "RequestDenied" => {
            closed(m, &["request_id", "code"])?;
            f_id(get(m, "request_id")?, "trq")?;
            if Code::parse(f_str(get(m, "code")?)?).is_none() {
                return err(Code::InvalidInput);
            }
        }
        "FaultObserved" => {
            closed(m, &["reason"])?;
            if crate::types::Reason::parse(f_str(get(m, "reason")?)?).is_none() {
                return err(Code::InvalidInput);
            }
        }
        "RecoveryObserved" => {
            closed(m, &["previous_boot_id", "previous_head", "gap"])?;
            f_id(get(m, "previous_boot_id")?, "trb")?;
            head(get(m, "previous_head")?)?;
            f_bool(get(m, "gap")?)?;
        }
        "CapObserved" => {
            closed(
                m,
                &["engine_run_id", "engine_head", "state", "stop_required"],
            )?;
            let erid = f_str(get(m, "engine_run_id")?)?;
            if erid.len() != 25
                || !erid.starts_with("lwr_")
                || !erid[4..].bytes().all(|c| ID_ALPHABET.contains(&c))
            {
                return err(Code::InvalidInput);
            }
            head(get(m, "engine_head")?)?;
            f_str(get(m, "state")?)?;
            f_bool(get(m, "stop_required")?)?;
        }
        _ => return err(Code::InvalidInput),
    }
    Ok(())
}

/// Validate a complete EventBody (envelope + kind/data agreement).
pub fn event_body(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "host_id",
            "run_id",
            "boot_id",
            "event_id",
            "key_id",
            "seq",
            "prev_hash",
            "mono_ns",
            "wall_time",
            "policy_hash",
            "actor",
            "art",
            "kind",
            "data",
        ],
    )?;
    f_v1(m)?;
    f_id(get(m, "host_id")?, "trh")?;
    f_id(get(m, "run_id")?, "trr")?;
    f_id(get(m, "boot_id")?, "trb")?;
    f_id(get(m, "event_id")?, "tre")?;
    f_id(get(m, "key_id")?, "trk")?;
    let seq = f_u(get(m, "seq")?)?;
    if seq < 1 {
        return err(Code::InvalidInput);
    }
    f_hash(get(m, "prev_hash")?)?;
    f_u(get(m, "mono_ns")?)?;
    f_utc(get(m, "wall_time")?)?;
    f_hash(get(m, "policy_hash")?)?;
    actor(get(m, "actor")?)?;
    art(get(m, "art")?)?;
    let kind = f_str(get(m, "kind")?)?;
    if !EVENT_KINDS.contains(&kind) {
        return err(Code::InvalidInput);
    }
    event_data(kind, get(m, "data")?)?;
    Ok(())
}

/// Entry = { body, hash, sig }.
pub fn entry(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(m, &["body", "hash", "sig"])?;
    event_body(get(m, "body")?)?;
    f_hash(get(m, "hash")?)?;
    f_sig(get(m, "sig")?)?;
    Ok(())
}

pub fn checkpoint_body(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "checkpoint_id",
            "host_id",
            "run_id",
            "key_id",
            "head",
            "state",
            "audit",
            "wall_time",
        ],
    )?;
    f_v1(m)?;
    f_id(get(m, "checkpoint_id")?, "trn")?;
    f_id(get(m, "host_id")?, "trh")?;
    f_id(get(m, "run_id")?, "trr")?;
    f_id(get(m, "key_id")?, "trk")?;
    head(get(m, "head")?)?;
    if crate::types::RunState::parse(f_str(get(m, "state")?)?).is_none() {
        return err(Code::InvalidInput);
    }
    match f_str(get(m, "audit")?)? {
        "COMPLETE_PREFIX" | "GAP" => {}
        _ => return err(Code::InvalidInput),
    }
    f_utc(get(m, "wall_time")?)?;
    Ok(())
}

pub fn checkpoint(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(m, &["body", "hash", "sig"])?;
    checkpoint_body(get(m, "body")?)?;
    f_hash(get(m, "hash")?)?;
    f_sig(get(m, "sig")?)?;
    Ok(())
}

/// KillBody literals are normative: gate_closed/empty_observed=true and the
/// three evidence-limitation literals are closed (spec §2.4).
pub fn kill_body(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "host_id",
            "run_id",
            "key_id",
            "policy_hash",
            "stopped_event",
            "stop_reason",
            "gate_closed",
            "empty_observed",
            "evidence",
            "external_effects",
            "remote_replication",
        ],
    )?;
    f_v1(m)?;
    f_id(get(m, "host_id")?, "trh")?;
    f_id(get(m, "run_id")?, "trr")?;
    f_id(get(m, "key_id")?, "trk")?;
    f_hash(get(m, "policy_hash")?)?;
    head(get(m, "stopped_event")?)?;
    if crate::types::Reason::parse(f_str(get(m, "stop_reason")?)?).is_none() {
        return err(Code::InvalidInput);
    }
    if !f_bool(get(m, "gate_closed")?)? {
        return err(Code::InvalidInput);
    }
    if !f_bool(get(m, "empty_observed")?)? {
        return err(Code::InvalidInput);
    }
    f_lit(get(m, "evidence")?, "local-software-observation")?;
    f_lit(get(m, "external_effects")?, "NOT_REVERSED")?;
    f_lit(get(m, "remote_replication")?, "NOT_ATTESTED")?;
    Ok(())
}

pub fn kill_certificate(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(m, &["body", "hash", "sig"])?;
    kill_body(get(m, "body")?)?;
    f_hash(get(m, "hash")?)?;
    f_sig(get(m, "sig")?)?;
    Ok(())
}

/// Bundle (in-memory form, <= 256 entries).
pub fn bundle(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "format",
            "policy",
            "entries",
            "checkpoint",
            "certificate",
        ],
    )?;
    f_v1(m)?;
    f_lit(get(m, "format")?, "trellis-bundle/1")?;
    signed_policy(get(m, "policy")?, &[])?;
    let es = get(m, "entries")?
        .as_arr()
        .ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
    for e in es {
        entry(e)?;
    }
    checkpoint(get(m, "checkpoint")?)?;
    match get(m, "certificate")? {
        Value::Null => {}
        c => kill_certificate(c)?,
    }
    Ok(())
}

/// Emergency slot payload (spec §7.2).
pub fn emergency(v: &Value) -> Res<()> {
    let m = obj(v)?;
    closed(
        m,
        &[
            "v",
            "run_id",
            "boot_id",
            "last_head",
            "reason",
            "gate_closed",
            "kill_attempted",
            "empty_observed",
            "observed_ns",
        ],
    )?;
    f_v1(m)?;
    f_id(get(m, "run_id")?, "trr")?;
    f_id(get(m, "boot_id")?, "trb")?;
    head(get(m, "last_head")?)?;
    if crate::types::Reason::parse(f_str(get(m, "reason")?)?).is_none() {
        return err(Code::InvalidInput);
    }
    f_bool(get(m, "gate_closed")?)?;
    f_bool(get(m, "kill_attempted")?)?;
    f_bool(get(m, "empty_observed")?)?;
    f_u(get(m, "observed_ns")?)?;
    Ok(())
}

/// Recovery pin file `{v:1,host_id,heads:[{run_id,head}]}` sorted/unique.
pub fn recovery_pins(v: &Value) -> Res<Vec<(String, crate::types::Head)>> {
    let m = obj(v)?;
    closed(m, &["v", "host_id", "heads"])?;
    f_v1(m)?;
    f_id(get(m, "host_id")?, "trh")?;
    let hs = get(m, "heads")?
        .as_arr()
        .ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
    let mut out = Vec::new();
    for h in hs {
        let hm = obj(h)?;
        closed(hm, &["run_id", "head"])?;
        let run_id = f_id(get(hm, "run_id")?, "trr")?.to_string();
        let hd = head(get(hm, "head")?)?;
        out.push((run_id, hd));
    }
    for w in out.windows(2) {
        if w[0].0 >= w[1].0 {
            return err(Code::InvalidInput); // must be sorted, unique
        }
    }
    Ok(out)
}
