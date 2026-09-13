//! Offline receipt verification (spec §5.1 receipt.verify, §7.4, §8).
//! Pure: no syscalls, no clock, no randomness. Error precedence:
//! schema/version -> key resolution -> policy signature -> entry hash ->
//! entry signature -> continuity -> reducer transition ->
//! checkpoint/certificate agreement -> expected_head -> completeness.

use crate::crypto::*;
use crate::json::Value;
use crate::schema::*;
use crate::types::{ApiErr, Code, Head, Reason, RunState};

pub struct VerifyInput<'a> {
    pub bundle: &'a Value,
    pub log_pins: &'a [Pin],
    pub policy_pins: &'a [Pin],
    pub expected_head: Option<Head>,
    pub require_terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completeness {
    Terminal,
    Prefix,
    Gap,
}

pub struct VerifyResult {
    pub completeness: Completeness,
    pub head: Head,
    pub state: RunState,
}

impl VerifyResult {
    pub fn to_value(&self) -> Value {
        Value::obj(vec![
            ("integrity", Value::str("VALID")),
            (
                "completeness",
                Value::str(match self.completeness {
                    Completeness::Terminal => "TERMINAL",
                    Completeness::Prefix => "PREFIX",
                    Completeness::Gap => "GAP",
                }),
            ),
            ("head", self.head.to_value()),
            ("state", Value::str(self.state.as_str())),
            ("truth", Value::str("NOT_ATTESTED")),
        ])
    }
}

fn apierr<T>(c: Code) -> Result<T, ApiErr> {
    Err(ApiErr::new(c))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VState {
    Preparing,
    Waiting,
    Active,
    Stopping,
    Unconfirmed,
    Stopped,
    Rejected,
}

impl VState {
    fn run_state(self) -> RunState {
        match self {
            Self::Preparing => RunState::Preparing,
            Self::Waiting => RunState::Waiting,
            Self::Active => RunState::Active,
            Self::Stopping => RunState::Stopping,
            Self::Unconfirmed => RunState::Unconfirmed,
            Self::Stopped => RunState::Stopped,
            Self::Rejected => RunState::Rejected,
        }
    }
    fn live(self) -> bool {
        matches!(self, Self::Preparing | Self::Waiting | Self::Active)
    }
    fn terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Rejected)
    }
}

struct Replay {
    state: VState,
    boot_id: String,
    host_id: String,
    run_id: String,
    key_id: String,
    policy_hash: String,
    armed: Option<ProcessIdentity>,
    beat_seq: u64,
    deadline: u64, // current admission deadline (startup or last accepted)
    progress: u64,
    last_hb: Option<(u64, u64)>, // (beat_seq, deadline_ns)
    latched: Option<Reason>,
    gate_closed: bool,
    empty: bool,
    last_mono: u64,
    gap: bool,
    pending_fault: bool, // FaultObserved while live -> next lifecycle must latch
    pending_mismatch: bool, // InventoryObserved matches=false -> next lifecycle StopLatched(REPLICATION_MISMATCH)
    recovered: bool,        // RecoveryObserved seen -> next lifecycle must be StopLatched
    unconfirmed_emitted: bool,
    startup_deadline: u64,
}

/// Replay one event body through the reduced transition table.
/// All entries already passed hash/signature/continuity checks.
fn step(
    rp: &mut Replay,
    body: &Value,
    timeout_ms: u64,
    startup_ms: u64,
    max_threads: u64,
) -> Result<(), ApiErr> {
    let m = obj(body)?;
    let kind = f_str(get(m, "kind")?)?;
    let mono = f_u(get(m, "mono_ns")?)?;
    let seq = f_u(get(m, "seq")?)?;
    let data = get(m, "data")?;
    let bad = || ApiErr::new(Code::TransitionInvalid);

    // identity invariants
    if f_str(get(m, "run_id")?)? != rp.run_id
        || f_str(get(m, "host_id")?)? != rp.host_id
        || f_str(get(m, "key_id")?)? != rp.key_id
        || f_str(get(m, "policy_hash")?)? != rp.policy_hash
    {
        return Err(bad());
    }
    // boot continuity: boot_id changes only via RecoveryObserved
    let ev_boot = f_str(get(m, "boot_id")?)?;
    if ev_boot != rp.boot_id && kind != "RecoveryObserved" {
        return Err(bad());
    }
    if mono < rp.last_mono {
        return Err(bad());
    }

    // annotations legal in any nonterminal state
    if kind == "RequestDenied" {
        if rp.state.terminal() {
            return Err(bad());
        }
        rp.last_mono = mono;
        return Ok(());
    }
    if kind == "FaultObserved" {
        if rp.state.terminal() {
            return Err(bad());
        }
        if rp.state.live() {
            rp.pending_fault = true;
        }
        rp.last_mono = mono;
        return Ok(());
    }
    if kind == "CapObserved" {
        // no certified adapter exists in this edition; a linked run is impossible
        return Err(bad());
    }

    // deferred obligations
    if rp.pending_mismatch {
        let dm = obj(data)?;
        if kind != "StopLatched" || f_str(get(dm, "reason")?)? != "REPLICATION_MISMATCH" {
            return Err(bad());
        }
    }
    if rp.pending_fault && kind != "StopLatched" {
        return Err(bad());
    }
    if rp.recovered && kind != "StopLatched" && rp.state.live() {
        // recovery on a live run must latch RECOVERY next
        return Err(bad());
    }

    match kind {
        "RunCreated" => return Err(bad()), // only legal at seq 1 (handled by caller)
        "RunArmed" => {
            if rp.state != VState::Preparing {
                return Err(bad());
            }
            let dm = obj(data)?;
            let dl = f_u(get(dm, "startup_deadline_ns")?)?;
            if dl != mono + startup_ms * 1_000_000 {
                return Err(bad());
            }
            rp.armed = Some(process_identity(get(dm, "root")?)?);
            rp.deadline = dl;
            rp.startup_deadline = dl;
            rp.state = VState::Waiting;
        }
        "RunRejected" => {
            if rp.state != VState::Preparing {
                return Err(bad());
            }
            rp.state = VState::Rejected;
        }
        "HeartbeatAccepted" => {
            if !matches!(rp.state, VState::Waiting | VState::Active) {
                return Err(bad());
            }
            let dm = obj(data)?;
            let bs = f_u(get(dm, "beat_seq")?)?;
            let dl = f_u(get(dm, "deadline_ns")?)?;
            let prog = f_u(get(dm, "progress")?)?;
            if bs != rp.beat_seq + 1 {
                return Err(bad());
            }
            if dl != mono + timeout_ms * 1_000_000 {
                return Err(bad());
            }
            // the beat must have arrived before the prior deadline
            if mono >= rp.deadline {
                return Err(bad());
            }
            if prog < rp.progress {
                return Err(bad());
            }
            rp.beat_seq = bs;
            rp.last_hb = Some((bs, dl));
            rp.progress = prog;
            // accepted but not yet granted
        }
        "GateGranted" => {
            if !matches!(rp.state, VState::Waiting | VState::Active) {
                return Err(bad());
            }
            let dm = obj(data)?;
            let bs = f_u(get(dm, "beat_seq")?)?;
            let dl = f_u(get(dm, "deadline_ns")?)?;
            match rp.last_hb {
                Some((pbs, pdl)) if pbs == bs && pdl == dl => {}
                _ => return Err(bad()),
            }
            // grant precedes the prior admission deadline and the new deadline
            if mono >= rp.deadline || mono >= dl {
                return Err(bad());
            }
            rp.deadline = dl;
            rp.state = VState::Active;
            rp.last_hb = None;
        }
        "InventoryObserved" => {
            if !rp.state.live() {
                return Err(bad());
            }
            let inv = inventory(get(obj(data)?, "inventory")?)?;
            let armed = rp.armed.as_ref().ok_or_else(bad)?;
            let recomputed = inventory_matches(&inv, armed, max_threads);
            if inv.matches != recomputed {
                return Err(bad());
            }
            if !recomputed {
                rp.pending_mismatch = true;
            }
        }
        "StopLatched" => {
            if !rp.state.live() {
                return Err(bad());
            }
            let dm = obj(data)?;
            let reason = Reason::parse(f_str(get(dm, "reason")?)?).ok_or_else(bad)?;
            rp.latched = Some(reason);
            rp.state = VState::Stopping;
            rp.pending_fault = false;
            rp.pending_mismatch = false;
            rp.recovered = false;
        }
        "GateClosed" => {
            if !matches!(rp.state, VState::Stopping | VState::Unconfirmed) {
                return Err(bad());
            }
            let dm = obj(data)?;
            if f_u(get(dm, "confirmed_ns")?)? > mono {
                return Err(bad());
            }
            rp.gate_closed = true;
        }
        "KillIssued" => {
            if !matches!(rp.state, VState::Stopping | VState::Unconfirmed) {
                return Err(bad());
            }
        }
        "StopUnconfirmed" => {
            if rp.state != VState::Stopping || rp.unconfirmed_emitted {
                return Err(bad());
            }
            rp.unconfirmed_emitted = true;
            rp.state = VState::Unconfirmed;
        }
        "ContainmentEmpty" => {
            if !matches!(rp.state, VState::Stopping | VState::Unconfirmed) {
                return Err(bad());
            }
            let dm = obj(data)?;
            if f_u(get(dm, "observed_ns")?)? > mono {
                return Err(bad());
            }
            rp.empty = true;
        }
        "RunStopped" => {
            if !matches!(rp.state, VState::Stopping | VState::Unconfirmed) {
                return Err(bad());
            }
            if !rp.gate_closed || !rp.empty {
                return Err(bad());
            }
            let dm = obj(data)?;
            let fr = Reason::parse(f_str(get(dm, "first_reason")?)?).ok_or_else(bad)?;
            if Some(fr) != rp.latched {
                return Err(bad());
            }
            if f_bool(get(dm, "evidence_gap")?)? {
                rp.gap = true;
            }
            rp.state = VState::Stopped;
        }
        "RecoveryObserved" => {
            if rp.state.terminal() {
                return Err(bad());
            }
            if ev_boot == rp.boot_id {
                return Err(bad()); // must open a new boot
            }
            let dm = obj(data)?;
            if f_str(get(dm, "previous_boot_id")?)? != rp.boot_id {
                return Err(bad());
            }
            let ph = head(get(dm, "previous_head")?)?;
            // caller verified previous entry's seq/hash; ensure it equals the
            // reduced head *before* this entry: seq == seq-1 handled by chain.
            if ph.seq != seq - 1 {
                return Err(bad());
            }
            if f_bool(get(dm, "gap")?)? {
                rp.gap = true;
            }
            rp.boot_id = ev_boot.to_string();
            if rp.state.live() {
                rp.recovered = true;
            }
        }
        _ => return Err(bad()),
    }
    rp.last_mono = mono;
    Ok(())
}

fn pin_for<'a>(pins: &'a [Pin], key_id: &str) -> Result<&'a Pin, ApiErr> {
    pins.iter()
        .find(|p| p.key_id == key_id)
        .ok_or_else(|| ApiErr::new(Code::UntrustedKey))
}

/// Verify an in-memory bundle object.
pub fn verify(input: &VerifyInput) -> Result<VerifyResult, ApiErr> {
    // 1. strict schema/version (closed objects, literals)
    bundle(input.bundle)?;
    let bm = obj(input.bundle)?;
    let policy_v = get(bm, "policy")?;
    let sp = signed_policy(policy_v, &[])?;
    let entries_v = get(bm, "entries")?.as_arr().unwrap();
    if entries_v.is_empty() {
        return apierr(Code::Incomplete);
    }
    // 2. trusted key resolution (policy pin then log pin)
    let ppin = pin_for(input.policy_pins, &sp.key_id)?;
    let pm = obj(policy_v)?;
    let _ = pm;
    // 3. policy signature
    let ph = sp.policy.body_hash();
    if !verify_domain(D_POLICY_SIGN, &ph, &ppin.public_key, &sp.sig) {
        return apierr(Code::SignatureInvalid);
    }
    // entry envelopes
    let mut bodies: Vec<&Value> = Vec::with_capacity(entries_v.len());
    for e in entries_v {
        entry(e)?;
        let em = obj(e)?;
        bodies.push(get(em, "body")?);
    }
    // log pin resolved from first entry's key_id
    let first = obj(bodies[0])?;
    let key_id = f_id(get(first, "key_id")?, "trk")?;
    let lpin = pin_for(input.log_pins, key_id)?;
    // 4/5. entry hash + signature
    for (e, body) in entries_v.iter().zip(bodies.iter()) {
        let em = obj(e)?;
        let want = f_hash(get(em, "hash")?)?;
        let h = domain_hash(D_EVENT, body);
        if h != want {
            return apierr(Code::HashMismatch);
        }
        let sig = f_sig(get(em, "sig")?)?;
        if !verify_domain(D_EVENT_SIGN, &h, &lpin.public_key, sig) {
            return apierr(Code::SignatureInvalid);
        }
    }
    // 6. continuity: seq from 1, prev_hash chain, constant ids
    let mut prev_hash = crate::scalars::ZERO_HASH.to_string();
    let mut run_id: Option<String> = None;
    for (i, body) in bodies.iter().enumerate() {
        let m = obj(body)?;
        let seq = f_u(get(m, "seq")?)?;
        if seq != (i as u64) + 1 {
            return apierr(Code::ChainInvalid);
        }
        if f_str(get(m, "prev_hash")?)? != prev_hash {
            return apierr(Code::ChainInvalid);
        }
        if i == 0 && f_str(get(m, "kind")?)? != "RunCreated" {
            return apierr(Code::ChainInvalid);
        }
        if i == 0 {
            run_id = Some(f_id(get(m, "run_id")?, "trr")?.to_string());
        }
        prev_hash = domain_hash(D_EVENT, body);
    }
    // 7. reducer transition replay
    let first = obj(bodies[0])?;
    let dm = obj(get(first, "data")?)?;
    // RunCreated must match the supplied policy
    if f_id(get(dm, "agent_id")?, "tra")? != sp.policy.agent_id
        || f_str(get(dm, "policy_hash")?)? != ph
        || f_str(get(dm, "exec_hash")?)? != sp.policy.exec_hash
    {
        return apierr(Code::TransitionInvalid);
    }
    let mut rp = Replay {
        state: VState::Preparing,
        boot_id: f_id(get(first, "boot_id")?, "trb")?.to_string(),
        host_id: f_id(get(first, "host_id")?, "trh")?.to_string(),
        run_id: run_id.clone().unwrap(),
        key_id: key_id.to_string(),
        policy_hash: ph.clone(),
        armed: None,
        beat_seq: 0,
        deadline: u64::MAX,
        progress: 0,
        last_hb: None,
        latched: None,
        gate_closed: false,
        empty: false,
        last_mono: 0,
        gap: false,
        pending_fault: false,
        pending_mismatch: false,
        recovered: false,
        unconfirmed_emitted: false,
        startup_deadline: 0,
    };
    rp.last_mono = f_u(get(first, "mono_ns")?)?;
    for (i, body) in bodies.iter().enumerate() {
        if i == 0 {
            continue; // RunCreated validated above
        }
        step(
            &mut rp,
            body,
            sp.policy.timeout_ms,
            sp.policy.startup_ms,
            sp.policy.max_threads,
        )?;
    }
    // 8. checkpoint/certificate agreement
    let cpv = get(bm, "checkpoint")?;
    checkpoint(cpv)?;
    let cm = obj(cpv)?;
    let cbody = obj(get(cm, "body")?)?;
    let chash = f_hash(get(cm, "hash")?)?;
    if domain_hash(D_CHECKPOINT, &Value::Obj(cbody.clone())) != chash {
        return apierr(Code::HashMismatch);
    }
    let csig = f_sig(get(cm, "sig")?)?;
    if !verify_domain(D_CHECKPOINT_SIGN, chash, &lpin.public_key, csig) {
        return apierr(Code::SignatureInvalid);
    }
    if f_id(get(cbody, "key_id")?, "trk")? != rp.key_id
        || f_id(get(cbody, "run_id")?, "trr")? != rp.run_id
        || f_id(get(cbody, "host_id")?, "trh")? != rp.host_id
    {
        return apierr(Code::ChainInvalid);
    }
    let last_hash = domain_hash(D_EVENT, bodies.last().unwrap());
    let verified_head = Head {
        seq: bodies.len() as u64,
        hash: last_hash.clone(),
    };
    let cp_head = head(get(cbody, "head")?)?;
    if cp_head != verified_head {
        return apierr(Code::ChainInvalid);
    }
    if f_str(get(cbody, "state")?)? != rp.state.run_state().as_str() {
        return apierr(Code::ChainInvalid);
    }
    let audit_s = f_str(get(cbody, "audit")?)?;
    let derived_gap = rp.gap;
    if (audit_s == "GAP") != derived_gap {
        return apierr(Code::ChainInvalid);
    }
    match get(bm, "certificate")? {
        Value::Null => {}
        cert_v => {
            kill_certificate(cert_v)?;
            let km = obj(cert_v)?;
            let kb = obj(get(km, "body")?)?;
            let khash = f_hash(get(km, "hash")?)?;
            if domain_hash(D_KILL, &Value::Obj(kb.clone())) != khash {
                return apierr(Code::HashMismatch);
            }
            let ksig = f_sig(get(km, "sig")?)?;
            if !verify_domain(D_KILL_SIGN, khash, &lpin.public_key, ksig) {
                return apierr(Code::SignatureInvalid);
            }
            // exact reference to the terminal RunStopped event
            if !matches!(rp.state, VState::Stopped) {
                return apierr(Code::TransitionInvalid);
            }
            let se = head(get(kb, "stopped_event")?)?;
            if se != verified_head {
                return apierr(Code::ChainInvalid);
            }
            if f_id(get(kb, "key_id")?, "trk")? != rp.key_id
                || f_id(get(kb, "run_id")?, "trr")? != rp.run_id
                || f_id(get(kb, "host_id")?, "trh")? != rp.host_id
                || f_str(get(kb, "policy_hash")?)? != rp.policy_hash
            {
                return apierr(Code::ChainInvalid);
            }
            if Reason::parse(f_str(get(kb, "stop_reason")?)?) != rp.latched {
                return apierr(Code::ChainInvalid);
            }
        }
    }
    // 9. expected_head comparison
    if let Some(exp) = &input.expected_head {
        if exp.seq > verified_head.seq {
            return apierr(Code::Incomplete);
        }
        let at = domain_hash(D_EVENT, bodies[(exp.seq - 1) as usize]);
        if at != exp.hash {
            return apierr(Code::HashMismatch);
        }
        if exp.seq < verified_head.seq {
            return apierr(Code::Conflict);
        }
        // equal: exact match already established by hash check
    }
    // 10. completeness
    let completeness = if derived_gap {
        Completeness::Gap
    } else if rp.state.terminal() {
        Completeness::Terminal
    } else {
        Completeness::Prefix
    };
    if input.require_terminal && completeness != Completeness::Terminal {
        return apierr(Code::Incomplete);
    }
    Ok(VerifyResult {
        completeness,
        head: verified_head,
        state: rp.state.run_state(),
    })
}

// ---------------------------------------------------------------------------
// Streaming export verification (spec §7.4): header, entry records, trailer.
// ---------------------------------------------------------------------------

/// Verify a trellis-stream/1 byte stream. Lines are canonical JSON <= 65536
/// bytes; exactly one header, entries seq=1..head, one trailer, LF-terminated.
pub fn verify_stream(
    bytes: &[u8],
    log_pins: &[Pin],
    policy_pins: &[Pin],
    expected_head: Option<Head>,
    require_terminal: bool,
) -> Result<VerifyResult, ApiErr> {
    // split on LF; reject trailing bytes / missing LF
    if bytes.is_empty() || bytes[bytes.len() - 1] != b'\n' {
        return apierr(Code::Incomplete);
    }
    let lines: Vec<&[u8]> = bytes[..bytes.len() - 1].split(|c| *c == b'\n').collect();
    if lines.len() < 2 {
        return apierr(Code::Incomplete);
    }
    let mut entries: Vec<Value> = Vec::new();
    let mut header: Option<Value> = None;
    let mut trailer: Option<Value> = None;
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() || line.len() > crate::wire::EXPORT_LINE_MAX {
            return apierr(Code::InvalidInput);
        }
        let v = crate::json::parse(line).map_err(|_| ApiErr::new(Code::InvalidInput))?;
        // canonical byte check: the line must equal its canonical re-encoding
        if v.canonical() != *line {
            return apierr(Code::InvalidInput);
        }
        let m = obj(&v)?;
        let rec = f_str(get(m, "record")?)?;
        match rec {
            "header" => {
                if i != 0 || header.is_some() {
                    return apierr(Code::InvalidInput);
                }
                header = Some(v);
            }
            "entry" => {
                if header.is_none() || trailer.is_some() {
                    return apierr(Code::ChainInvalid);
                }
                let em = obj(get(m, "entry")?)?;
                let _ = em;
                entries.push(get(m, "entry")?.clone());
            }
            "trailer" => {
                if trailer.is_some() || i != lines.len() - 1 {
                    return apierr(Code::InvalidInput);
                }
                trailer = Some(v);
            }
            _ => return apierr(Code::InvalidInput),
        }
    }
    let trailer = trailer.ok_or_else(|| ApiErr::new(Code::Incomplete))?;
    let header = header.ok_or_else(|| ApiErr::new(Code::Incomplete))?;
    let tm = obj(&trailer)?;
    closed(tm, &["record", "count", "certificate"])?;
    let count = f_u(get(tm, "count")?)?;
    if count != entries.len() as u64 {
        return apierr(Code::ChainInvalid);
    }
    let hm = obj(&header)?;
    closed(hm, &["record", "v", "format", "policy", "checkpoint"])?;
    f_v1(hm)?;
    if f_str(get(hm, "format")?)? != crate::wire::EXPORT_FORMAT {
        return apierr(Code::InvalidInput);
    }
    let bundle = Value::obj(vec![
        ("v", Value::int(1)),
        ("format", Value::str("trellis-bundle/1")),
        ("policy", get(hm, "policy")?.clone()),
        ("entries", Value::Arr(entries)),
        ("checkpoint", get(hm, "checkpoint")?.clone()),
        ("certificate", get(tm, "certificate")?.clone()),
    ]);
    verify(&VerifyInput {
        bundle: &bundle,
        log_pins,
        policy_pins,
        expected_head,
        require_terminal,
    })
}
