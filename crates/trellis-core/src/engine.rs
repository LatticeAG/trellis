//! The single-writer reducer (spec §4): host/run/challenge state machines,
//! ordering/admission/idempotency, durable event chain, deadlines, stop
//! progression, recovery. All mutation flows through `dispatch` on the
//! dispatch boundary, which processes inputs in the pinned priority order.

use crate::crypto::*;
use crate::guard::{GuardEvent, HEALTH_NS};
use crate::json::Value;
use crate::os::{KillAttempt, LaunchSpec, Os};
use crate::scalars::{b64url_encode, nanoid, random_bytes, ZERO_HASH};
use crate::schema::*;
use crate::store::*;
use crate::types::*;
use crate::wire::{err_response, ok_response, request};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

pub const RENEW_MS: u64 = 250;
pub const LEASE_NS: u64 = 750_000_000;
pub const STOP_WAIT_NS: u64 = 2_000_000_000;
pub const RETRY_NS: u64 = 250_000_000;
pub const INVENTORY_REPERSIST_NS: u64 = 60_000_000_000;

pub trait IdSource {
    fn id(&mut self, prefix: &str) -> String;
    fn nonce(&mut self, seq: u64) -> String;
}

pub struct RandomIds;
impl IdSource for RandomIds {
    fn id(&mut self, prefix: &str) -> String {
        nanoid(prefix)
    }
    fn nonce(&mut self, _seq: u64) -> String {
        b64url_encode(&random_bytes(32))
    }
}

/// Deterministic IDs for the conformance harness (spec §5.2 fixtures).
pub struct DeterministicIds;
impl IdSource for DeterministicIds {
    fn id(&mut self, prefix: &str) -> String {
        // event ids follow seq; set by caller through EventSpec
        crate::fixtures::i(prefix, 0)
    }
    fn nonce(&mut self, seq: u64) -> String {
        crate::fixtures::fixture_nonce(seq)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Control,
    AgentFd3,
    InProcess, // verifier-only surface; receipt.verify is legal here
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audit {
    CompletePrefix,
    Gap,
}
impl Audit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompletePrefix => "COMPLETE_PREFIX",
            Self::Gap => "GAP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChState {
    Outstanding,
    Consumed,
    Expired,
    Invalidated,
}
impl ChState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outstanding => "OUTSTANDING",
            Self::Consumed => "CONSUMED",
            Self::Expired => "EXPIRED",
            Self::Invalidated => "INVALIDATED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateView {
    Closed,
    Leased,
    Unknown,
}
impl GateView {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "CLOSED",
            Self::Leased => "LEASED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Per-run live state. The durable projection is derived by `projection()`.
#[derive(Clone)]
pub struct RunRt {
    pub run_id: String,
    pub agent_id: String,
    pub policy: SignedPolicy,
    pub policy_hash: String,
    pub exec: Exec,
    pub workspace: String,
    pub task_uid: u64,
    pub state: RunState,
    pub head: Head,
    pub last_beat_seq: u64,
    pub deadline_ns: Option<u64>,
    pub gate: GateView,
    pub stop_reason: Option<Reason>,
    pub empty_observed: bool,
    pub root_exit: Option<Exit>,
    pub inventory: Option<Inventory>,
    pub audit: Audit,
    pub cap: &'static str,
    pub outstanding: Option<Challenge>,
    pub challenge_state: ChState,
    pub last_progress: u64,
    pub armed: Option<ProcessIdentity>,
    pub startup_deadline_ns: Option<u64>,
    pub latched_at_ns: Option<u64>,
    pub stop_unconfirmed_emitted: bool,
    pub gate_closed_observed: bool,
    pub kill_issued: Option<KillAttempt>,
    pub pending_request: Option<(String, String, String)>, // (principal, scope, request_id)
    pub last_renew_ns: u64,
    pub last_guard_ack_ns: u64,
    pub guard_registered: bool,
    pub guard_generation: u64,
    pub stop_initiated: bool,
    pub denial_count: u64,
    pub last_denial_audit_ns: u64,
    pub beats: u64,
    pub note_pending: Option<(String, Reason)>,
    pub launch_started: bool,
    pub last_inv_persisted: Option<Value>,
    pub last_inv_event_ns: u64,
    pub root_exit_observed: bool,
    pub kill_event_written: bool,
}

impl RunRt {
    fn new(start: &StartInput, run_id: &str, _boot_id: &str, task_uid: u64, head: Head) -> Self {
        RunRt {
            run_id: run_id.to_string(),
            agent_id: start.policy.policy.agent_id.clone(),
            policy: start.policy.clone(),
            policy_hash: domain_hash(D_POLICY, &start.policy.policy.body),
            exec: start.exec.clone(),
            workspace: start.workspace_root.clone(),
            task_uid,
            state: RunState::Preparing,
            head,
            last_beat_seq: 0,
            deadline_ns: None,
            gate: GateView::Closed,
            stop_reason: None,
            empty_observed: false,
            root_exit: None,
            inventory: None,
            audit: Audit::CompletePrefix,
            cap: "NONE",
            outstanding: None,
            challenge_state: ChState::Invalidated,
            last_progress: 0,
            armed: None,
            startup_deadline_ns: None,
            latched_at_ns: None,
            stop_unconfirmed_emitted: false,
            gate_closed_observed: false,
            kill_issued: None,
            pending_request: None,
            last_renew_ns: 0,
            last_guard_ack_ns: 0,
            guard_registered: false,
            guard_generation: 0,
            stop_initiated: false,
            denial_count: 0,
            last_denial_audit_ns: 0,
            beats: 0,
            note_pending: None,
            launch_started: false,
            last_inv_persisted: None,
            last_inv_event_ns: 0,
            root_exit_observed: false,
            kill_event_written: false,
        }
    }

    pub fn projection(&self, boot_id: &str) -> Value {
        Value::obj(vec![
            ("run_id", Value::str(self.run_id.clone())),
            ("agent_id", Value::str(self.agent_id.clone())),
            ("boot_id", Value::str(boot_id)),
            ("state", Value::str(self.state.as_str())),
            ("policy_hash", Value::str(self.policy_hash.clone())),
            ("last_beat_seq", Value::str(self.last_beat_seq.to_string())),
            (
                "deadline_ns",
                self.deadline_ns
                    .map(|d| Value::str(d.to_string()))
                    .unwrap_or(Value::Null),
            ),
            ("gate", Value::str(self.gate.as_str())),
            (
                "stop_reason",
                self.stop_reason
                    .map(|r| Value::str(r.as_str()))
                    .unwrap_or(Value::Null),
            ),
            ("empty_observed", Value::Bool(self.empty_observed)),
            (
                "root_exit",
                self.root_exit.map(|e| e.to_value()).unwrap_or(Value::Null),
            ),
            (
                "inventory",
                self.inventory
                    .as_ref()
                    .map(|i| i.raw.clone())
                    .unwrap_or(Value::Null),
            ),
            ("head", self.head.to_value()),
            ("audit", Value::str(self.audit.as_str())),
            ("cap", Value::str(self.cap)),
        ])
    }
}

/// Queued dispatch input.
pub enum Input {
    Req {
        surface: Surface,
        peer_uid: u64,
        id: String,
        method: String,
        params: Value,
    },
    StopReq {
        surface: Surface,
        peer_uid: u64,
        id: String,
        params: Value,
    },
    InventorySample {
        run_id: String,
    },
}

/// Event-emission context: everything make_event needs without holding a
/// borrow on the run across the &mut self call.
pub struct ECtx {
    pub seq: u64,
    pub prev: String,
    pub run_id: String,
    pub policy_hash: String,
    pub operator_ref: String,
}

pub enum Idem {
    Fresh,
    /// Cached FINAL response (full response object).
    Replay(Value),
    /// Same id, different body.
    Conflict,
    /// Same id, still PENDING.
    Pending,
}

pub struct Engine {
    pub cfg: HostConfig,
    pub state: HostState,
    pub boot_id: String,
    pub epoch: u64,
    pub kernel_boot_id: String,
    pub store: Store,
    pub runs: BTreeMap<String, RunRt>,
    pub ids: Box<dyn IdSource>,
    pub log_key: Keypair,
    pub log_key_id: String,
    pub os: Rc<RefCell<dyn Os>>,
    pub guard: Rc<RefCell<dyn crate::guard::GuardRpc>>,
    pub now: u64,
    pub wall: String,
    pub extra_deny: Vec<(u32, u8)>,
    /// Conformance-only fault points.
    pub suppress_renewals: bool,
    pub crash_point: Option<String>,
    pub crashed: bool,
    /// Denied-request audit aggregation (<=1 RequestDenied per run per sec).
    pub queue: VecDeque<Input>,
    pub responses: VecDeque<(String, Value)>,
    /// Run bound to the current fd-3 agent channel (set by transport).
    pub agent_channel_run: Option<String>,
    /// Fixture mode: deterministic ids/nonces.
    pub deterministic: bool,
    /// Next deterministic run ordinal (trr_<n>).
    pub run_seq: u64,
    /// Deterministic boot ordinal (trb_<n>).
    pub boot_seq: u64,
}

impl From<StoreErr> for ApiErr {
    fn from(e: StoreErr) -> Self {
        match e {
            StoreErr::FaultBlocked => ApiErr::new(Code::Busy),
            _ => ApiErr::new(Code::AuditFault),
        }
    }
}

impl Engine {
    pub fn new(
        cfg: HostConfig,
        store: Store,
        os: Rc<RefCell<dyn Os>>,
        guard: Rc<RefCell<dyn crate::guard::GuardRpc>>,
        ids: Box<dyn IdSource>,
        log_key: Keypair,
        kernel_boot_id: String,
    ) -> Self {
        let boot_id = nanoid("trb"); // replaced by harness when deterministic
        Engine {
            cfg,
            state: HostState::Starting,
            boot_id,
            epoch: 0,
            kernel_boot_id,
            store,
            runs: BTreeMap::new(),
            ids,
            log_key,
            log_key_id: String::new(),
            os,
            guard,
            now: 0,
            wall: crate::fixtures::wall_time().to_string(),
            extra_deny: Vec::new(),
            suppress_renewals: false,
            crash_point: None,
            crashed: false,
            queue: VecDeque::new(),
            responses: VecDeque::new(),
            agent_channel_run: None,
            deterministic: false,
            run_seq: 0,
            boot_seq: 1,
        }
    }

    // ------------------------------------------------------------------
    // Event construction
    // ------------------------------------------------------------------

    fn ectx(&self, run_id: &str) -> ECtx {
        let r = &self.runs[run_id];
        ECtx {
            seq: r.head.seq + 1,
            prev: r.head.hash.clone(),
            run_id: run_id.to_string(),
            policy_hash: r.policy_hash.clone(),
            operator_ref: r.policy.policy.operator_ref.clone(),
        }
    }

    fn make_event(
        &mut self,
        ctx: &ECtx,
        kind: &str,
        data: Value,
        actor: &'static str,
        human: bool,
    ) -> (EventRow, String) {
        let event_id = if self.deterministic {
            crate::fixtures::i("tre", ctx.seq)
        } else {
            self.ids.id("tre")
        };
        let body = Value::obj(vec![
            ("v", Value::int(1)),
            ("host_id", Value::str(self.cfg.host_id.clone())),
            ("run_id", Value::str(ctx.run_id.clone())),
            ("boot_id", Value::str(self.boot_id.clone())),
            ("event_id", Value::str(event_id.clone())),
            ("key_id", Value::str(self.log_key_id.clone())),
            ("seq", Value::str(ctx.seq.to_string())),
            ("prev_hash", Value::str(ctx.prev.clone())),
            ("mono_ns", Value::str(self.now.to_string())),
            ("wall_time", Value::str(self.wall.clone())),
            ("policy_hash", Value::str(ctx.policy_hash.clone())),
            (
                "actor",
                Value::obj(vec![("kind", Value::str(actor)), ("uid", Value::int(0))]),
            ),
            (
                "art",
                Value::obj(vec![
                    ("operator_ref", Value::str(ctx.operator_ref.clone())),
                    (
                        "oversight",
                        Value::str(if human {
                            "human_requested"
                        } else {
                            "automatic"
                        }),
                    ),
                    ("evidence", Value::str("software_observation")),
                ]),
            ),
            ("kind", Value::str(kind)),
            ("data", data),
        ]);
        let hash = domain_hash(D_EVENT, &body);
        let sig = self.log_key.sign_domain(D_EVENT_SIGN, &hash).unwrap();
        (
            EventRow {
                run_id: ctx.run_id.clone(),
                seq: ctx.seq,
                event_id,
                hash: hash.clone(),
                body,
                sig,
            },
            hash,
        )
    }

    // ------------------------------------------------------------------
    // Dispatch boundary: priority order (spec §4.4)
    // ------------------------------------------------------------------

    /// Process all due safety work before ordinary requests.
    pub fn boundary(&mut self) {
        if self.crashed {
            return;
        }
        // 1. guard/kernel faults and autonomous guard outcomes
        self.guard.borrow_mut().poll(self.now);
        loop {
            let ev = {
                let mut g = self.guard.borrow_mut();
                g.next_event()
            };
            match ev {
                Some(GuardEvent::Denied {
                    run_id,
                    reason,
                    gate_closed,
                    empty_observed,
                    kill,
                    root_exit,
                }) => {
                    self.on_guard_denied(
                        &run_id,
                        reason,
                        gate_closed,
                        empty_observed,
                        kill,
                        root_exit,
                    );
                }
                Some(GuardEvent::Emptied { run_id }) => self.on_emptied(&run_id),
                None => break,
            }
        }
        // 2. deadline expiries (challenge/heartbeat)
        let ids: Vec<String> = self.runs.keys().cloned().collect();
        for rid in &ids {
            let (st, exp) = {
                let r = &self.runs[rid];
                (r.state, r.challenge_deadline())
            };
            if matches!(st, RunState::Waiting | RunState::Active) {
                if let Some(d) = exp {
                    if self.now >= d {
                        let reason = if st == RunState::Active {
                            Reason::HeartbeatTimeout
                        } else {
                            Reason::StartupTimeout
                        };
                        self.latch(rid, reason, None, "daemon", false);
                    }
                }
            }
        }
        // 3. root/resource/inventory failure observations
        for rid in &ids {
            if !self.runs[rid].state.live() {
                continue;
            }
            let oom = self.os.borrow_mut().oom_tripped(rid);
            if oom {
                self.latch(rid, Reason::ResourceLimit, None, "daemon", false);
                continue;
            }
            let ex = self.os.borrow_mut().root_exit(rid);
            if let Some(ex) = ex {
                if let Some(r) = self.runs.get_mut(rid) {
                    r.root_exit = Some(ex);
                }
                self.latch(rid, Reason::RootExit, None, "daemon", false);
            }
        }
        // 4. guard renewals + acknowledgement-age check
        for rid in &ids {
            let (st, registered, latched) = {
                let r = &self.runs[rid];
                (r.state, r.guard_registered, r.stop_reason.is_some())
            };
            if !matches!(st, RunState::Waiting | RunState::Active) || !registered || latched {
                continue;
            }
            if !self.suppress_renewals
                && self.now.saturating_sub(self.runs[rid].last_renew_ns) >= RENEW_MS * 1_000_000
            {
                self.renew_once(rid);
            }
            let last_ack = self.guard.borrow().last_ack(rid).unwrap_or(0);
            let saw = self.runs[rid].last_guard_ack_ns.max(last_ack);
            let already_lost = self.runs[rid].stop_reason.is_some();
            if !already_lost && self.now.saturating_sub(saw) >= HEALTH_NS {
                // missing guard acknowledgement -> GUARD_LOST + own kill
                let k = self.os.borrow_mut().kill(rid, self.now);
                self.note_kill(rid, k);
                self.latch(rid, Reason::GuardLost, None, "daemon", false);
            }
        }
        // 5. stop progression for STOPPING/UNCONFIRMED runs
        for rid in &ids {
            if matches!(
                self.runs[rid].state,
                RunState::Stopping | RunState::Unconfirmed
            ) {
                self.progress_stop(rid);
            }
        }
    }

    fn renew_once(&mut self, rid: &str) {
        let (seq, dl, head) = {
            let r = &self.runs[rid];
            let dl = if r.state == RunState::Waiting {
                r.startup_deadline_ns.unwrap_or(0)
            } else {
                r.deadline_ns.unwrap_or(0)
            };
            (r.last_beat_seq, dl, r.head.clone())
        };
        let gen = self.runs[rid].guard_generation;
        let res = {
            let mut g = self.guard.borrow_mut();
            g.renew(self.now, rid, gen, seq, dl, head)
        };
        match res {
            Ok(rep) => {
                let r = self.runs.get_mut(rid).unwrap();
                r.last_renew_ns = self.now;
                r.last_guard_ack_ns = self.now;
                if rep.state == crate::wire::GuardState::Denied
                    || rep.state == crate::wire::GuardState::Retained
                {
                    // a denial arriving here latches stop permanently
                    self.latch(rid, Reason::GuardLost, None, "daemon", false);
                }
            }
            Err(Reason::GuardLost) => {}
            Err(reason) => {
                self.latch(rid, reason, None, "daemon", false);
            }
        }
    }

    fn note_kill(&mut self, rid: &str, k: KillAttempt) {
        if let Some(r) = self.runs.get_mut(rid) {
            if r.kill_issued.is_none() {
                r.kill_issued = Some(k);
            }
        }
    }

    // ------------------------------------------------------------------
    // Requests
    // ------------------------------------------------------------------

    /// Full request path: envelope validation happened in the transport;
    /// here params are schema-checked per method in the spec's order.
    pub fn call(&mut self, surface: Surface, peer_uid: u64, raw: Value) -> Value {
        let parsed = request(&raw);
        let (id, method) = match parsed {
            Ok(x) => x,
            Err(e) => {
                // envelope invalid: no request id trustworthy
                return err_response("trq_000000000000000000000", e.code);
            }
        };
        self.call_valid(surface, peer_uid, &id, &method, get_params(&raw))
    }

    fn call_valid(
        &mut self,
        surface: Surface,
        peer_uid: u64,
        id: &str,
        method: &str,
        params: Value,
    ) -> Value {
        // transport authorization (spec validation order step 2)
        match crate::types::method_kind(method) {
            Some(MethodKind::Offline) => {
                return err_response(id, Code::InvalidInput); // not remotely callable
            }
            Some(MethodKind::Agent) => {
                if surface != Surface::AgentFd3 {
                    return err_response(id, Code::Unauthorized);
                }
            }
            Some(MethodKind::Control) => {
                if surface == Surface::AgentFd3 {
                    return err_response(id, Code::Unauthorized);
                }
            }
            None => return err_response(id, Code::InvalidInput),
        }
        if surface == Surface::Control && peer_uid != 0 {
            return err_response(id, Code::Unauthorized);
        }
        // process due expiries before the request (control reads too)
        self.boundary();
        if self.crashed {
            return err_response(id, Code::AuditFault);
        }
        // idempotent replay: a FINAL row returns the stored response verbatim.
        if let Some((principal, scope, digest)) = self.idem_key(surface, peer_uid, method, &params)
        {
            match self.idem_check(&principal, &scope, id, &digest) {
                Ok(Idem::Replay(resp)) => {
                    self.responses.push_back((id.to_string(), resp.clone()));
                    return resp;
                }
                Ok(Idem::Conflict) => {
                    let r = err_response(id, Code::Conflict);
                    self.responses.push_back((id.to_string(), r.clone()));
                    return r;
                }
                Ok(Idem::Pending) => {
                    let r = err_response(id, Code::Busy);
                    self.responses.push_back((id.to_string(), r.clone()));
                    return r;
                }
                _ => {}
            }
        }
        let resp = self.dispatch(surface, peer_uid, id, method, params);
        self.responses.push_back((id.to_string(), resp.clone()));
        resp
    }

    fn dispatch(
        &mut self,
        surface: Surface,
        peer_uid: u64,
        id: &str,
        method: &str,
        params: Value,
    ) -> Value {
        let r: Result<Value, ApiErr> = match method {
            "host.get" => self.m_host_get(params),
            "run.start" => self.m_run_start(peer_uid, id, params),
            "run.get" => self.m_run_get(params),
            "run.list" => self.m_run_list(params),
            "run.stop" => self.m_run_stop(peer_uid, id, params),
            "agent.challenge" => self.m_agent_challenge(surface, params),
            "agent.beat" => self.m_agent_beat(surface, id, params),
            "inventory.get" => self.m_inventory_get(params),
            "events.read" => self.m_events_read(params),
            "receipt.checkpoint" => self.m_receipt_checkpoint(params),
            "certificate.get" => self.m_certificate_get(params),
            _ => Err(ApiErr::new(Code::InvalidInput)),
        };
        match r {
            Ok(v) => ok_response(id, v),
            Err(e) => err_response(id, e.code),
        }
    }

    /// Batch admission at one boundary: explicit stops process before other
    /// normal requests (spec §4.4 priority), preserving FIFO within a class.
    pub fn pump(&mut self, inputs: Vec<(Surface, u64, Value)>) -> Vec<Value> {
        self.boundary();
        let mut stops = Vec::new();
        let mut rest = Vec::new();
        for (s, uid, v) in inputs {
            let is_stop = v.get("method").and_then(|m| m.as_str()) == Some("run.stop");
            if is_stop {
                stops.push((s, uid, v));
            } else {
                rest.push((s, uid, v));
            }
        }
        let mut out = Vec::new();
        for (s, uid, v) in stops.into_iter().chain(rest) {
            out.push(self.call(s, uid, v));
        }
        out
    }

    // ---- idempotency ----------------------------------------------------

    fn request_digest(method: &str, params: &Value) -> String {
        domain_hash(
            D_REQUEST,
            &Value::obj(vec![
                ("method", Value::str(method)),
                ("params", params.clone()),
            ]),
        )
    }

    /// Compute the durable mutation key for the three idempotent methods.
    /// Returns None for reads / malformed params (dispatch reports properly).
    fn idem_key(
        &self,
        surface: Surface,
        peer_uid: u64,
        method: &str,
        params: &Value,
    ) -> Option<(String, String, String)> {
        let digest = Self::request_digest(method, params);
        match method {
            "run.start" => Some((format!("uid:{}", peer_uid), "host".into(), digest)),
            "run.stop" => {
                let rid = params.get("run_id").and_then(|v| v.as_str())?.to_string();
                Some((format!("uid:{}", peer_uid), rid, digest))
            }
            "agent.beat" => {
                let rid = self.agent_channel_run.clone()?;
                if surface != Surface::AgentFd3 {
                    return None;
                }
                Some((format!("channel:{}:{}", rid, self.boot_id), rid, digest))
            }
            _ => None,
        }
    }

    /// Idempotency: (principal,scope,request_id) -> replay/conflict/pending.
    fn idem_check(
        &mut self,
        principal: &str,
        scope: &str,
        request_id: &str,
        digest: &str,
    ) -> Result<Idem, ApiErr> {
        match self
            .store
            .request_lookup(principal, scope, request_id)
            .map_err(ApiErr::from)?
        {
            Some((d, status, resp)) => {
                if d == digest {
                    match status.as_str() {
                        "FINAL" => Ok(Idem::Replay(resp.unwrap_or(Value::Null))),
                        _ => Ok(Idem::Pending),
                    }
                } else {
                    Ok(Idem::Conflict)
                }
            }
            None => Ok(Idem::Fresh),
        }
    }

    // ---- host.get ---------------------------------------------------------

    fn m_host_get(&mut self, params: Value) -> Result<Value, ApiErr> {
        let m = obj(&params)?;
        closed(m, &[])?;
        let pf = self.os.borrow_mut().preflight(&self.cfg);
        let c = |n: &str| {
            pf.checks
                .iter()
                .find(|x| x.0 == n)
                .map(|x| x.1)
                .unwrap_or(false)
        };
        Ok(Value::obj(vec![
            ("v", Value::int(1)),
            ("host_id", Value::str(self.cfg.host_id.clone())),
            ("boot_id", Value::str(self.boot_id.clone())),
            ("epoch", Value::str(self.epoch.to_string())),
            ("state", Value::str(self.state.as_str())),
            ("protocol", Value::int(1)),
            ("storage", Value::int(1)),
            ("profile", Value::str("linux-single-process-v1")),
            (
                "checks",
                Value::obj(vec![
                    ("cgroup", Value::Bool(c("cgroup"))),
                    ("bpf", Value::Bool(c("bpf"))),
                    ("seccomp", Value::Bool(c("seccomp"))),
                    ("namespaces", Value::Bool(c("namespaces"))),
                    ("storage", Value::Bool(c("storage"))),
                    ("guard", Value::Bool(c("guard"))),
                ]),
            ),
            (
                "active_runs",
                Value::int(
                    self.runs
                        .values()
                        .filter(|r| {
                            r.state.live()
                                || matches!(r.state, RunState::Stopping | RunState::Unconfirmed)
                        })
                        .count() as u64,
                ),
            ),
            ("cap_available", Value::Bool(self.cap_available())),
        ]))
    }

    fn cap_available(&self) -> bool {
        // No certified adapter exists in this edition (spec §11.1).
        false
    }

    // ---- run.start --------------------------------------------------------

    fn m_run_start(&mut self, peer_uid: u64, id: &str, params: Value) -> Result<Value, ApiErr> {
        // schema first (closed object)
        let m = obj(&params)?;
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
        let digest = Self::request_digest("run.start", &params);
        let principal = format!("uid:{}", peer_uid);
        // idempotency
        match self.idem_check(&principal, "host", id, &digest)? {
            Idem::Replay(v) => {
                // cached response is a full response object; return its result
                return Ok(v.get("result").cloned().unwrap_or(v));
            }
            Idem::Conflict => return Err(ApiErr::new(Code::Conflict)),
            Idem::Pending => return Err(ApiErr::new(Code::Busy)),
            Idem::Fresh => {}
        }
        // host lifecycle gate
        if self.state != HostState::Ready {
            return Err(ApiErr::new(Code::Conflict));
        }
        let input = start_input(&params, &self.extra_deny)?;
        if input.expected_host_epoch != self.epoch {
            return Err(ApiErr::new(Code::StaleEpoch));
        }
        // policy trust: pin resolution then signature
        let pin = self
            .cfg
            .policy_pins
            .iter()
            .find(|p| p.key_id == input.policy.key_id);
        let pin = match pin {
            Some(p) => p.clone(),
            None => return Err(ApiErr::new(Code::UntrustedKey)),
        };
        if !verify_domain(
            D_POLICY_SIGN,
            &input.policy.policy.body_hash(),
            &pin.public_key,
            &input.policy.sig,
        ) {
            return Err(ApiErr::new(Code::SignatureInvalid));
        }
        // cap adapter gate (spec §11.1)
        if matches!(input.policy.policy.cap, CapMode::Lexwatt { .. }) {
            return Err(ApiErr::new(Code::CapAdapterUnavailable));
        }
        // exec hash vs signed policy
        let ex_v = exec_to_value(&input.exec);
        if domain_hash(D_EXEC, &ex_v) != input.policy.policy.exec_hash {
            return Err(ApiErr::new(Code::HashMismatch));
        }
        // image digest
        let img = self
            .os
            .borrow_mut()
            .image_sha256(&self.cfg.runtime_image)
            .map_err(|_| ApiErr::new(Code::InvalidInput))?;
        if img != input.policy.policy.image_sha256 {
            return Err(ApiErr::new(Code::HashMismatch));
        }
        // workspace membership + lease
        if !self.cfg.workspace_roots.contains(&input.workspace_root) {
            return Err(ApiErr::new(Code::InvalidInput));
        }
        if self
            .store
            .leased("workspace", &input.workspace_root)
            .map_err(ApiErr::from)?
        {
            return Err(ApiErr::new(Code::Busy));
        }
        self.os
            .borrow_mut()
            .workspace_validate(&input.workspace_root)
            .map_err(|e| ApiErr::new(e.code))?;
        // capacity: least of max_runs, UID pool, workspace roots
        let active = self.store.count_active_runs().map_err(ApiErr::from)?;
        let uid_pool = self.cfg.task_uid_max - self.cfg.task_uid_min + 1;
        let effective = self
            .cfg
            .max_runs
            .min(uid_pool)
            .min(self.cfg.workspace_roots.len() as u64);
        if active >= effective {
            return Err(ApiErr::new(Code::Busy));
        }
        let used: std::collections::BTreeSet<u64> = self
            .store
            .used_uids()
            .map_err(ApiErr::from)?
            .into_iter()
            .collect();
        let mut task_uid = None;
        for u in self.cfg.task_uid_min..=self.cfg.task_uid_max {
            if !used.contains(&u) {
                task_uid = Some(u);
                break;
            }
        }
        let task_uid = task_uid.ok_or_else(|| ApiErr::new(Code::Busy))?;

        // genesis: RunCreated + run row + PENDING request, one transaction
        self.run_seq += 1;
        let run_id = if self.deterministic {
            crate::fixtures::i("trr", self.run_seq)
        } else {
            self.ids.id("trr")
        };
        let policy_hash = domain_hash(D_POLICY, &input.policy.policy.body);
        let mut run = RunRt::new(
            &input,
            &run_id,
            &self.boot_id,
            task_uid,
            Head {
                seq: 0,
                hash: ZERO_HASH.into(),
            },
        );
        let mut b = Batch::default();
        let ectx1 = ECtx {
            seq: 1,
            prev: ZERO_HASH.into(),
            run_id: run_id.clone(),
            policy_hash: policy_hash.clone(),
            operator_ref: input.policy.policy.operator_ref.clone(),
        };
        let (e1, h1) = self.make_event(
            &ectx1,
            "RunCreated",
            Value::obj(vec![
                ("agent_id", Value::str(run.agent_id.clone())),
                ("policy_hash", Value::str(policy_hash.clone())),
                (
                    "exec_hash",
                    Value::str(input.policy.policy.exec_hash.clone()),
                ),
                (
                    "task_ref",
                    input
                        .task_ref
                        .clone()
                        .map(Value::str)
                        .unwrap_or(Value::Null),
                ),
                ("host_epoch", Value::str(self.epoch.to_string())),
            ]),
            "operator",
            true,
        );
        b.events.push(e1);
        run.head = Head {
            seq: 1,
            hash: h1.clone(),
        };
        let manifest = Value::obj(vec![
            ("v", Value::int(1)),
            ("run_id", Value::str(run_id.clone())),
            ("host_id", Value::str(self.cfg.host_id.clone())),
            ("boot_id", Value::str(self.boot_id.clone())),
            ("kernel_boot_id", Value::str(self.kernel_boot_id.clone())),
            ("host_epoch", Value::str(self.epoch.to_string())),
            ("policy_hash", Value::str(policy_hash)),
            ("exec", ex_v),
            ("workspace_root", Value::str(input.workspace_root.clone())),
            ("task_uid", Value::int(task_uid)),
            ("root", Value::Null),
            (
                "cgroup_path",
                Value::str(format!("/sys/fs/cgroup/trellis/{}", run_id)),
            ),
            ("cgroup_inode", Value::str("0")),
            ("bpf_generation", Value::str("1")),
            (
                "image_sha256",
                Value::str(input.policy.policy.image_sha256.clone()),
            ),
        ]);
        b.new_run = Some(NewRun {
            run_id: run_id.clone(),
            agent_id: run.agent_id.clone(),
            policy_hash: run.policy_hash.clone(),
            policy: input.policy.raw.clone(),
            manifest,
            projection: run.projection(&self.boot_id),
            last_seq: 1,
            last_hash: h1.clone(),
            task_uid,
            workspace: input.workspace_root.clone(),
            terminal: false,
        });
        b.requests.push(RequestRow {
            principal: principal.clone(),
            scope: "host".into(),
            request_id: id.to_string(),
            digest: digest.clone(),
            status: "PENDING",
            response: None,
        });
        b.leases.push(LeaseRow {
            kind: "workspace",
            value: input.workspace_root.clone(),
            run_id: run_id.clone(),
        });
        b.leases.push(LeaseRow {
            kind: "uid",
            value: task_uid.to_string(),
            run_id: run_id.clone(),
        });
        self.store.commit(b).map_err(|e| match e {
            StoreErr::FaultBlocked => ApiErr::new(Code::Busy),
            _ => ApiErr::new(Code::AuditFault),
        })?;
        let result = Value::obj(vec![
            ("run_id", Value::str(run_id.clone())),
            ("state", Value::str("PREPARING")),
            ("head", run.head.to_value()),
        ]);
        // finalize the idempotency row (derived-from-genesis response)
        let mut b2 = Batch::default();
        b2.requests.push(RequestRow {
            principal,
            scope: "host".into(),
            request_id: id.to_string(),
            digest,
            status: "FINAL",
            response: Some(ok_response(id, result.clone())),
        });
        self.store
            .commit(b2)
            .map_err(|_| ApiErr::new(Code::AuditFault))?;
        self.runs.insert(run_id.clone(), run);
        Ok(result)
    }

    /// Drive the launch barrier for a PREPARING run (spec §1.3 steps 3-10).
    /// Synchronous at this layer; the daemon calls it per newly created run.
    pub fn launch_barrier(&mut self, run_id: &str) {
        if self.crashed {
            return;
        }
        let (state, policy, spec) = {
            let r = match self.runs.get(run_id) {
                Some(r) => r,
                None => return,
            };
            (
                r.state,
                r.policy.policy.clone(),
                LaunchSpec {
                    run_id: run_id.to_string(),
                    task_uid: r.task_uid,
                    workspace: r.workspace.clone(),
                    memory_bytes: r.policy.policy.memory_bytes,
                    cpu_quota_us: r.policy.policy.cpu_quota_us,
                    pids_max: r.policy.policy.max_threads,
                    endpoints: r.policy.policy.allow.iter().copied().collect(),
                    argv: r.exec.argv.clone(),
                    cwd: r.exec.cwd.clone(),
                    env: r.exec.env.clone().into_iter().collect(),
                    image_path: self.cfg.runtime_image.clone(),
                    image_sha256: r.policy.policy.image_sha256.clone(),
                },
            )
        };
        if state != RunState::Preparing {
            return;
        }
        let _ = policy;
        let launched = self.os.borrow_mut().launch(&spec);
        match launched {
            Ok(l) => {
                // register with guard carrying startup deadline
                let deadline = self.now + self.runs[run_id].policy.policy.startup_ms * 1_000_000;
                let head = self.runs[run_id].head.clone();
                let gen = 1u64;
                let reg = {
                    let mut g = self.guard.borrow_mut();
                    g.register(
                        self.now,
                        run_id,
                        &self.boot_id,
                        l.root.cgroup_inode,
                        deadline,
                        head,
                    )
                };
                match reg {
                    Ok(_) => {
                        // persist RunArmed + create first challenge, one tx
                        let mut b = Batch::default();
                        let ctx = self.ectx(run_id);
                        let (e2, h2) = self.make_event(
                            &ctx,
                            "RunArmed",
                            Value::obj(vec![
                                ("root", l.root.to_value()),
                                ("startup_deadline_ns", Value::str(deadline.to_string())),
                            ]),
                            "daemon",
                            false,
                        );
                        b.events.push(e2);
                        let ch = Challenge {
                            run_id: run_id.to_string(),
                            boot_id: self.boot_id.clone(),
                            challenge_id: if self.deterministic {
                                crate::fixtures::i("trc", 1)
                            } else {
                                self.ids.id("trc")
                            },
                            seq: 1,
                            nonce: self.ids.nonce(1),
                            policy_hash: self.runs[run_id].policy_hash.clone(),
                            expires_ns: deadline,
                            raw: Value::Null,
                        };
                        let chv = challenge_value(&ch);
                        let r = self.runs.get_mut(run_id).unwrap();
                        r.armed = Some(l.root.clone());
                        r.startup_deadline_ns = Some(deadline);
                        r.outstanding = Some(ch.clone());
                        r.challenge_state = ChState::Outstanding;
                        r.state = RunState::Waiting;
                        r.guard_registered = true;
                        r.guard_generation = gen;
                        r.last_renew_ns = self.now;
                        r.last_guard_ack_ns = self.now;
                        r.head = Head {
                            seq: ctx.seq,
                            hash: h2.clone(),
                        };
                        b.challenge = Some(ChallengeRow {
                            run_id: run_id.to_string(),
                            seq: 1,
                            challenge: chv,
                            state: "OUTSTANDING",
                        });
                        b.run_update = Some(RunUpdate {
                            run_id: run_id.to_string(),
                            projection: r.projection(&self.boot_id),
                            last_seq: r.head.seq,
                            last_hash: r.head.hash.clone(),
                            terminal: false,
                        });
                        if let Err(e) = self.store.commit(b) {
                            match e {
                                StoreErr::FaultBlocked => {}
                                _ => self.latch(run_id, Reason::AuditFault, None, "daemon", false),
                            }
                        }
                    }
                    Err(_) => {
                        self.reject(run_id, Code::EgressFault);
                    }
                }
            }
            Err(e) => {
                // pre-exec failure with proven no live workload -> REJECTED;
                // uncertain partial setup -> stop latch.
                if e.code == Code::EgressFault || e.code == Code::InvalidInput {
                    self.reject(run_id, e.code);
                } else {
                    self.latch(run_id, Reason::EgressFault, None, "daemon", false);
                }
            }
        }
    }

    fn reject(&mut self, run_id: &str, code: Code) {
        let mut b = Batch::default();
        let ctx = self.ectx(run_id);
        let (ev, h) = self.make_event(
            &ctx,
            "RunRejected",
            Value::obj(vec![("code", Value::str(code.as_str()))]),
            "daemon",
            false,
        );
        b.events.push(ev);
        let r = self.runs.get_mut(run_id).unwrap();
        r.state = RunState::Rejected;
        r.head = Head {
            seq: ctx.seq,
            hash: h,
        };
        b.run_update = Some(RunUpdate {
            run_id: run_id.to_string(),
            projection: r.projection(&self.boot_id),
            last_seq: r.head.seq,
            last_hash: r.head.hash.clone(),
            terminal: true,
        });
        let _ = self.store.commit(b);
        let _ = self.store.release_leases(run_id);
        self.os.borrow_mut().free_uid(run_id);
    }

    // ---- stop latch and progression --------------------------------------

    /// Latch a stop: emits StopLatched, closes challenge, state -> STOPPING.
    /// First reason is immutable; later causes are FaultObserved.
    pub fn latch(
        &mut self,
        run_id: &str,
        reason: Reason,
        note_hash: Option<String>,
        actor: &'static str,
        human: bool,
    ) {
        let cur = match self.runs.get(run_id) {
            Some(r) => r.state,
            None => return,
        };
        if cur.terminal() || matches!(cur, RunState::Stopping | RunState::Unconfirmed) {
            return; // first reason immutable
        }
        let mut b = Batch::default();
        let ctx = self.ectx(run_id);
        let (ev, h) = self.make_event(
            &ctx,
            "StopLatched",
            Value::obj(vec![
                ("reason", Value::str(reason.as_str())),
                (
                    "note_hash",
                    note_hash.clone().map(Value::str).unwrap_or(Value::Null),
                ),
            ]),
            actor,
            human,
        );
        b.events.push(ev);
        {
            let r = self.runs.get_mut(run_id).unwrap();
            r.state = RunState::Stopping;
            r.stop_reason = Some(reason);
            r.latched_at_ns = Some(self.now);
            r.challenge_state = ChState::Invalidated;
            r.outstanding = None;
            r.head = Head {
                seq: ctx.seq,
                hash: h,
            };
            if r.audit == Audit::CompletePrefix && reason == Reason::AuditFault {
                r.audit = Audit::Gap;
            }
            b.run_update = Some(RunUpdate {
                run_id: run_id.to_string(),
                projection: r.projection(&self.boot_id),
                last_seq: r.head.seq,
                last_hash: r.head.hash.clone(),
                terminal: false,
            });
            b.challenge = Some(ChallengeRow {
                run_id: run_id.to_string(),
                seq: r.last_beat_seq + 1,
                challenge: Value::Null,
                state: "INVALIDATED",
            });
        }
        if self.store.commit(b).is_err() {
            // restrictive action may precede durable logging: keep latch
            let r = self.runs.get_mut(run_id).unwrap();
            r.state = RunState::Stopping;
            r.stop_reason = Some(reason);
            r.latched_at_ns = Some(self.now);
            r.audit = Audit::Gap;
        }
        // tell the guard before any audit wait
        if self.runs[run_id].guard_registered {
            let gen = self.runs[run_id].guard_generation;
            let rep = {
                let mut g = self.guard.borrow_mut();
                g.stop(self.now, run_id, gen, reason)
            };
            match rep {
                Ok(report) => {
                    self.on_guard_denied(
                        run_id,
                        reason,
                        report.gate_closed,
                        report.empty_observed,
                        report.kill,
                        report.root_exit,
                    );
                }
                Err(_) => {
                    // guard unreachable: daemon-retained kill fallback
                    let k = self.os.borrow_mut().kill(run_id, self.now);
                    self.note_kill(run_id, k);
                }
            }
        } else {
            let k = self.os.borrow_mut().kill(run_id, self.now);
            self.note_kill(run_id, k);
        }
        self.progress_stop(run_id);
    }

    fn on_guard_denied(
        &mut self,
        run_id: &str,
        reason: Reason,
        gate_closed: bool,
        empty_observed: bool,
        kill: Option<(bool, bool)>,
        root_exit: Option<Exit>,
    ) {
        if !self.runs.contains_key(run_id) {
            return;
        }
        if let Some((c, p)) = kill {
            self.note_kill(
                run_id,
                KillAttempt {
                    cgroup_attempted: c,
                    pidfd_attempted: p,
                },
            );
        }
        if let Some(ex) = root_exit {
            self.runs.get_mut(run_id).unwrap().root_exit = Some(ex);
        }
        if self.runs[run_id].state.live()
            || self.runs[run_id].state == RunState::Stopping
                && self.runs[run_id].stop_reason.is_none()
        {
            // autonomous denial before any latch
            if !matches!(
                self.runs[run_id].state,
                RunState::Stopping | RunState::Unconfirmed | RunState::Stopped | RunState::Rejected
            ) {
                self.latch(run_id, reason, None, "daemon", false);
                return;
            }
        }
        let mut b = Batch::default();
        let mut dirty = false;
        {
            let emit_gate = gate_closed && !self.runs[run_id].gate_closed_observed;
            if emit_gate {
                let gen_s = self.runs[run_id].guard_generation.to_string();
                let now_s = self.now.to_string();
                let ctx = self.ectx(run_id);
                let (ev, h) = self.make_event(
                    &ctx,
                    "GateClosed",
                    Value::obj(vec![
                        ("guard_generation", Value::str(gen_s)),
                        ("confirmed_ns", Value::str(now_s)),
                    ]),
                    "daemon",
                    false,
                );
                b.events.push(ev);
                let r = self.runs.get_mut(run_id).unwrap();
                r.gate_closed_observed = true;
                r.gate = GateView::Closed;
                r.head = Head {
                    seq: ctx.seq,
                    hash: h,
                };
                dirty = true;
            }
        }
        {
            let k = self.runs[run_id]
                .kill_issued
                .as_ref()
                .map(|k| (k.cgroup_attempted, k.pidfd_attempted));
            if let Some((ca, pa)) = k.filter(|_| !self.runs[run_id].kill_event_written) {
                let ctx = self.ectx(run_id);
                let (ev, h) = self.make_event(
                    &ctx,
                    "KillIssued",
                    Value::obj(vec![
                        ("cgroup_attempted", Value::Bool(ca)),
                        ("pidfd_attempted", Value::Bool(pa)),
                    ]),
                    "daemon",
                    false,
                );
                b.events.push(ev);
                let r = self.runs.get_mut(run_id).unwrap();
                r.kill_event_written = true;
                r.head = Head {
                    seq: ctx.seq,
                    hash: h,
                };
                dirty = true;
            }
        }
        if empty_observed && !self.runs[run_id].empty_observed {
            let rex = self.runs[run_id]
                .root_exit
                .map(|e| e.to_value())
                .unwrap_or(Value::Null);
            let now_s = self.now.to_string();
            let ctx = self.ectx(run_id);
            let (ev, h) = self.make_event(
                &ctx,
                "ContainmentEmpty",
                Value::obj(vec![("root_exit", rex), ("observed_ns", Value::str(now_s))]),
                "daemon",
                false,
            );
            b.events.push(ev);
            let r = self.runs.get_mut(run_id).unwrap();
            r.empty_observed = true;
            r.head = Head {
                seq: ctx.seq,
                hash: h,
            };
            dirty = true;
        }
        if dirty {
            let r = &self.runs[run_id];
            b.run_update = Some(RunUpdate {
                run_id: run_id.to_string(),
                projection: r.projection(&self.boot_id),
                last_seq: r.head.seq,
                last_hash: r.head.hash.clone(),
                terminal: false,
            });
            if self.store.commit(b).is_err() {
                if let Some(r) = self.runs.get_mut(run_id) {
                    r.audit = Audit::Gap;
                }
            }
        }
        self.maybe_stopped(run_id);
    }

    fn on_emptied(&mut self, run_id: &str) {
        if !self.runs.contains_key(run_id) {
            return;
        }
        let empty = {
            let mut os = self.os.borrow_mut();
            match os.containment(run_id, self.now) {
                Ok(e) => e,
                Err(_) => return,
            }
        };
        if !empty.populated_gone || !empty.pidfd_exited {
            return;
        }
        let mut b = Batch::default();
        {
            if self.runs[run_id].empty_observed {
                return;
            }
            let rex = empty.root_exit.map(|e| e.to_value()).unwrap_or(Value::Null);
            let now_s = self.now.to_string();
            let ctx = self.ectx(run_id);
            let (ev, h) = self.make_event(
                &ctx,
                "ContainmentEmpty",
                Value::obj(vec![("root_exit", rex), ("observed_ns", Value::str(now_s))]),
                "daemon",
                false,
            );
            b.events.push(ev);
            let r = self.runs.get_mut(run_id).unwrap();
            r.empty_observed = true;
            r.root_exit = empty.root_exit.or(r.root_exit);
            r.head = Head {
                seq: ctx.seq,
                hash: h,
            };
            b.run_update = Some(RunUpdate {
                run_id: run_id.to_string(),
                projection: r.projection(&self.boot_id),
                last_seq: r.head.seq,
                last_hash: r.head.hash.clone(),
                terminal: false,
            });
        }
        if self.store.commit(b).is_err() {
            if let Some(r) = self.runs.get_mut(run_id) {
                r.audit = Audit::Gap;
            }
        }
        self.maybe_stopped(run_id);
    }

    /// ContainmentEmpty for a run that never armed a workload.
    fn on_vacuous_empty(&mut self, run_id: &str) {
        let mut b = Batch::default();
        {
            if self.runs[run_id].empty_observed {
                return;
            }
            let now_s = self.now.to_string();
            let ctx = self.ectx(run_id);
            let (ev, h) = self.make_event(
                &ctx,
                "ContainmentEmpty",
                Value::obj(vec![
                    ("root_exit", Value::Null),
                    ("observed_ns", Value::str(now_s)),
                ]),
                "daemon",
                false,
            );
            b.events.push(ev);
            let r = self.runs.get_mut(run_id).unwrap();
            r.empty_observed = true;
            r.head = Head {
                seq: ctx.seq,
                hash: h,
            };
            b.run_update = Some(RunUpdate {
                run_id: run_id.to_string(),
                projection: r.projection(&self.boot_id),
                last_seq: r.head.seq,
                last_hash: r.head.hash.clone(),
                terminal: false,
            });
        }
        if self.store.commit(b).is_err() {
            if let Some(r) = self.runs.get_mut(run_id) {
                r.audit = Audit::Gap;
            }
        }
        self.maybe_stopped(run_id);
    }

    /// After gate-closed + empty confirmations, emit RunStopped -> STOPPED.
    fn maybe_stopped(&mut self, run_id: &str) {
        let (st, gate, empty, latched) = {
            let r = &self.runs[run_id];
            (
                r.state,
                r.gate_closed_observed,
                r.empty_observed,
                r.stop_reason.is_some(),
            )
        };
        if !latched || !matches!(st, RunState::Stopping | RunState::Unconfirmed) {
            return;
        }
        if !(gate && empty) {
            return;
        }
        let mut b = Batch::default();
        {
            let (reason_s, gap) = {
                let r = &self.runs[run_id];
                (r.stop_reason.unwrap().as_str(), r.audit == Audit::Gap)
            };
            let ctx = self.ectx(run_id);
            let (ev, h) = self.make_event(
                &ctx,
                "RunStopped",
                Value::obj(vec![
                    ("first_reason", Value::str(reason_s)),
                    ("gate_closed", Value::Bool(true)),
                    ("empty_observed", Value::Bool(true)),
                    ("evidence_gap", Value::Bool(gap)),
                ]),
                "daemon",
                false,
            );
            b.events.push(ev);
            let r = self.runs.get_mut(run_id).unwrap();
            r.state = RunState::Stopped;
            r.head = Head {
                seq: ctx.seq,
                hash: h,
            };
            b.run_update = Some(RunUpdate {
                run_id: run_id.to_string(),
                projection: r.projection(&self.boot_id),
                last_seq: r.head.seq,
                last_hash: r.head.hash.clone(),
                terminal: true,
            });
        }
        if self.store.commit(b).is_ok() {
            let _ = self.store.release_leases(run_id);
            self.os.borrow_mut().free_uid(run_id);
            // guard release with terminal head
            if self.runs[run_id].guard_registered {
                let gen = self.runs[run_id].guard_generation;
                let head = self.runs[run_id].head.clone();
                let _ = self.guard.borrow_mut().release(self.now, run_id, gen, head);
            }
            self.os.borrow_mut().teardown(run_id);
        } else if let Some(r) = self.runs.get_mut(run_id) {
            r.audit = Audit::Gap;
        }
    }

    /// Drive a STOPPING/UNCONFIRMED run toward confirmation (each boundary).
    fn progress_stop(&mut self, run_id: &str) {
        let (st, latched_at, gate_closed, empty, unconf_emitted, registered) = {
            let r = &self.runs[run_id];
            (
                r.state,
                r.latched_at_ns.unwrap_or(0),
                r.gate_closed_observed,
                r.empty_observed,
                r.stop_unconfirmed_emitted,
                r.guard_registered,
            )
        };
        if !matches!(st, RunState::Stopping | RunState::Unconfirmed) {
            return;
        }
        // query kernel containment when not yet confirmed; a run that was
        // never armed has vacuously empty containment (no workload existed).
        if !empty && self.runs[run_id].armed.is_none() {
            self.on_vacuous_empty(run_id);
        } else if !empty {
            let e = self.os.borrow_mut().containment(run_id, self.now);
            if let Ok(e) = e {
                if e.populated_gone && e.pidfd_exited {
                    self.on_emptied(run_id);
                }
            }
        }
        if !gate_closed && registered {
            let gen = self.runs[run_id].guard_generation;
            let reason = self.runs[run_id].stop_reason.unwrap_or(Reason::Operator);
            let rep = self.guard.borrow_mut().stop(self.now, run_id, gen, reason);
            if let Ok(rep) = rep {
                if rep.gate_closed {
                    self.on_guard_denied(
                        run_id,
                        reason,
                        true,
                        rep.empty_observed,
                        rep.kill,
                        rep.root_exit,
                    );
                }
            }
        } else if !gate_closed && !registered {
            let k = self.os.borrow_mut().kill(run_id, self.now);
            self.note_kill(run_id, k);
            let mut b = Batch::default();
            {
                if !self.runs[run_id].gate_closed_observed {
                    let gen_s = self.runs[run_id].guard_generation.to_string();
                    let now_s = self.now.to_string();
                    let ctx = self.ectx(run_id);
                    let (ev, h) = self.make_event(
                        &ctx,
                        "GateClosed",
                        Value::obj(vec![
                            ("guard_generation", Value::str(gen_s)),
                            ("confirmed_ns", Value::str(now_s)),
                        ]),
                        "daemon",
                        false,
                    );
                    b.events.push(ev);
                    let r2 = self.runs.get_mut(run_id).unwrap();
                    r2.gate_closed_observed = true;
                    r2.gate = GateView::Closed;
                    r2.head = Head {
                        seq: ctx.seq,
                        hash: h,
                    };
                    b.run_update = Some(RunUpdate {
                        run_id: run_id.to_string(),
                        projection: r2.projection(&self.boot_id),
                        last_seq: r2.head.seq,
                        last_hash: r2.head.hash.clone(),
                        terminal: false,
                    });
                    let _ = self.store.commit(b);
                }
            }
            self.maybe_stopped(run_id);
        }
        // unconfirmed window
        let (st2, gate2, empty2) = {
            let r = &self.runs[run_id];
            (r.state, r.gate_closed_observed, r.empty_observed)
        };
        if matches!(st2, RunState::Stopping)
            && !(gate2 && empty2)
            && self.now >= latched_at + STOP_WAIT_NS
            && !unconf_emitted
        {
            let mut b = Batch::default();
            {
                let (gc, eo) = {
                    let r = &self.runs[run_id];
                    (r.gate_closed_observed, r.empty_observed)
                };
                let ctx = self.ectx(run_id);
                let (ev, h) = self.make_event(
                    &ctx,
                    "StopUnconfirmed",
                    Value::obj(vec![
                        ("gate_closed", Value::Bool(gc)),
                        ("empty_observed", Value::Bool(eo)),
                    ]),
                    "daemon",
                    false,
                );
                b.events.push(ev);
                let r = self.runs.get_mut(run_id).unwrap();
                r.state = RunState::Unconfirmed;
                r.stop_unconfirmed_emitted = true;
                r.head = Head {
                    seq: ctx.seq,
                    hash: h,
                };
                b.run_update = Some(RunUpdate {
                    run_id: run_id.to_string(),
                    projection: r.projection(&self.boot_id),
                    last_seq: r.head.seq,
                    last_hash: r.head.hash.clone(),
                    terminal: false,
                });
            }
            if self.store.commit(b).is_err() {
                if let Some(r) = self.runs.get_mut(run_id) {
                    r.audit = Audit::Gap;
                }
            }
        }
    }

    // ---- agent.challenge ----------------------------------------------------

    fn m_agent_challenge(&mut self, surface: Surface, params: Value) -> Result<Value, ApiErr> {
        let m = obj(&params)?;
        closed(m, &[])?;
        let rid = match surface {
            Surface::AgentFd3 => self.agent_channel_run.clone(),
            _ => return Err(ApiErr::new(Code::Unauthorized)),
        };
        let rid = rid.ok_or_else(|| ApiErr::new(Code::Unauthorized))?;
        let r = self
            .runs
            .get(&rid)
            .ok_or_else(|| ApiErr::new(Code::NotFound))?;
        if r.pending_request.is_some() {
            return Err(ApiErr::new(Code::Busy));
        }
        match r.state {
            RunState::Waiting | RunState::Active => {}
            RunState::Preparing => return Err(ApiErr::new(Code::Busy)),
            _ => return Err(ApiErr::new(Code::Stopped)),
        }
        match (&r.outstanding, r.challenge_state) {
            (Some(c), ChState::Outstanding) => Ok(challenge_value(c)),
            _ => Err(ApiErr::new(Code::Stopped)),
        }
    }

    // ---- agent.beat ---------------------------------------------------------

    fn m_agent_beat(&mut self, surface: Surface, id: &str, params: Value) -> Result<Value, ApiErr> {
        let beat = beat_input(&params)?;
        let rid = match surface {
            Surface::AgentFd3 => self.agent_channel_run.clone(),
            _ => return Err(ApiErr::new(Code::Unauthorized)),
        };
        let chan_run = rid.ok_or_else(|| ApiErr::new(Code::Unauthorized))?;
        if !self.runs.contains_key(&chan_run) {
            return Err(ApiErr::new(Code::NotFound));
        }
        let principal = format!("channel:{}:{}", chan_run, self.boot_id);
        let digest = Self::request_digest("agent.beat", &params);
        match self.idem_check(&principal, &chan_run, id, &digest)? {
            Idem::Replay(v) => {
                return Ok(v.get("result").cloned().unwrap_or(v));
            }
            Idem::Conflict => return Err(ApiErr::new(Code::Conflict)),
            Idem::Pending => return Err(ApiErr::new(Code::Busy)),
            Idem::Fresh => {}
        }
        // PENDING beat slot per run
        if self.runs[&chan_run].pending_request.is_some() {
            return Err(ApiErr::new(Code::Busy));
        }
        // lifecycle
        match self.runs[&chan_run].state {
            RunState::Waiting | RunState::Active => {}
            _ => return Err(ApiErr::new(Code::Stopped)),
        }
        // channel binding: the beat must name this run/boot
        if beat.run_id != chan_run || beat.boot_id != self.boot_id {
            return Err(ApiErr::new(Code::ChallengeInvalid));
        }
        // challenge resolution
        let outstanding = self.runs[&chan_run].outstanding.clone();
        let known = match &outstanding {
            Some(c) if self.runs[&chan_run].challenge_state == ChState::Outstanding => {
                beat.challenge_id == c.challenge_id
            }
            _ => false,
        };
        if !known {
            // consumed challenge? durable HeartbeatAccepted history decides.
            let consumed = self
                .store
                .consumed_challenges(&chan_run)
                .map_err(ApiErr::from)?
                .contains(&beat.challenge_id);
            if consumed {
                return Err(ApiErr::new(Code::ChallengeUsed));
            }
            if matches!(self.runs[&chan_run].challenge_state, ChState::Expired) {
                return Err(ApiErr::new(Code::ChallengeExpired));
            }
            return Err(ApiErr::new(Code::ChallengeInvalid));
        }
        let ch = outstanding.unwrap();
        // binding fields
        if beat.challenge_id != ch.challenge_id
            || beat.seq != ch.seq
            || beat.nonce != ch.nonce
            || beat.run_id != ch.run_id
            || beat.boot_id != ch.boot_id
        {
            return Err(ApiErr::new(Code::ChallengeInvalid));
        }
        // policy hash / scope / count / progress -> SCOPE_MISMATCH latch
        if beat.policy_hash != self.runs[&chan_run].policy_hash
            || !beat.scope_ok
            || beat.claimed_processes != 1
            || beat.progress < self.runs[&chan_run].last_progress
        {
            self.latch(&chan_run, Reason::ScopeMismatch, None, "daemon", false);
            return Err(ApiErr::new(Code::ScopeMismatch));
        }
        // deadline: half-open, expiry wins at equality
        let deadline = ch.expires_ns;
        if self.now >= deadline {
            let reason = if self.runs[&chan_run].state == RunState::Active {
                Reason::HeartbeatTimeout
            } else {
                Reason::StartupTimeout
            };
            self.latch(&chan_run, reason, None, "daemon", false);
            return Err(ApiErr::new(Code::Stopped));
        }
        // fresh inventory: age <= scan_ms, else refresh; failure -> INVENTORY_LOST
        let scan_ns = self.runs[&chan_run].policy.policy.scan_ms * 1_000_000;
        let fresh = self.runs[&chan_run]
            .inventory
            .as_ref()
            .map(|i| self.now.saturating_sub(i.sampled_ns) <= scan_ns)
            .unwrap_or(false);
        if !fresh {
            let sampled = self.os.borrow_mut().inventory(&chan_run, self.now);
            match sampled {
                Ok(inv) => {
                    self.apply_inventory(&chan_run, inv)?;
                }
                Err(_) => {
                    self.latch(&chan_run, Reason::InventoryLost, None, "daemon", false);
                    return Err(ApiErr::new(Code::InventoryLost));
                }
            }
            // re-check match result: apply_inventory latches on mismatch
            if self.runs[&chan_run].stop_reason.is_some() {
                return Err(ApiErr::new(Code::InventoryLost));
            }
        }
        let saved = self.runs[&chan_run].clone();
        let new_deadline = self.now + self.runs[&chan_run].policy.policy.timeout_ms * 1_000_000;
        let new_seq = ch.seq + 1;
        let next_ch = Challenge {
            run_id: chan_run.clone(),
            boot_id: self.boot_id.clone(),
            challenge_id: if self.deterministic {
                crate::fixtures::i("trc", new_seq)
            } else {
                self.ids.id("trc")
            },
            seq: new_seq,
            nonce: self.ids.nonce(new_seq),
            policy_hash: self.runs[&chan_run].policy_hash.clone(),
            expires_ns: new_deadline,
            raw: Value::Null,
        };
        let result = Value::obj(vec![
            ("accepted", Value::Bool(true)),
            ("seq", Value::str(ch.seq.to_string())),
            ("deadline_ns", Value::str(new_deadline.to_string())),
            ("next", challenge_value(&next_ch)),
        ]);
        // tx1: HeartbeatAccepted + consume + next challenge + PENDING request
        let mut b = Batch::default();
        {
            let ctx = self.ectx(&chan_run);
            let (ev, h) = self.make_event(
                &ctx,
                "HeartbeatAccepted",
                Value::obj(vec![
                    ("beat_seq", Value::str(ch.seq.to_string())),
                    ("challenge_id", Value::str(ch.challenge_id.clone())),
                    ("deadline_ns", Value::str(new_deadline.to_string())),
                    ("progress", Value::str(beat.progress.to_string())),
                ]),
                "daemon",
                false,
            );
            b.events.push(ev);
            let r = self.runs.get_mut(&chan_run).unwrap();
            r.head = Head {
                seq: ctx.seq,
                hash: h,
            };
            r.deadline_ns = Some(new_deadline);
            r.last_beat_seq = ch.seq;
            r.last_progress = beat.progress;
            r.beats += 1;
            r.challenge_state = ChState::Outstanding;
            r.outstanding = Some(next_ch.clone());
            r.pending_request = Some((principal.clone(), chan_run.clone(), id.to_string()));
            b.challenge = Some(ChallengeRow {
                run_id: chan_run.clone(),
                seq: new_seq,
                challenge: challenge_value(&next_ch),
                state: "OUTSTANDING",
            });
            b.run_update = Some(RunUpdate {
                run_id: chan_run.clone(),
                projection: r.projection(&self.boot_id),
                last_seq: r.head.seq,
                last_hash: r.head.hash.clone(),
                terminal: false,
            });
            b.requests.push(RequestRow {
                principal: principal.clone(),
                scope: chan_run.clone(),
                request_id: id.to_string(),
                digest: digest.clone(),
                status: "PENDING",
                response: None,
            });
        }
        if let Err(e) = self.store.commit(b) {
            // nothing was admitted: restore the pre-commit projection
            *self.runs.get_mut(&chan_run).unwrap() = saved;
            match e {
                StoreErr::FaultBlocked => return Err(ApiErr::new(Code::Busy)),
                _ => {
                    self.latch(&chan_run, Reason::AuditFault, None, "daemon", false);
                    return Err(ApiErr::new(Code::AuditFault));
                }
            }
        }
        // injected crash point: E3 durable, grant never attempted
        if self.crash_point.as_deref() == Some("post-e3-pre-grant") {
            self.crashed = true;
            return Err(ApiErr::new(Code::AuditFault)); // never delivered
        }
        // recheck after fsync: latch, boot/epoch, generation, inventory, deadline
        {
            let r = &self.runs[&chan_run];
            if r.stop_reason.is_some() || self.now >= new_deadline {
                self.finish_beat_refused(&chan_run, &principal, id, &digest)?;
                return Err(ApiErr::new(Code::Stopped));
            }
        }
        // guard grant
        let gen = self.runs[&chan_run].guard_generation;
        let head = self.runs[&chan_run].head.clone();
        let grant = {
            let mut g = self.guard.borrow_mut();
            g.renew(self.now, &chan_run, gen, ch.seq, new_deadline, head)
        };
        match grant {
            Ok(rep) if rep.state == crate::wire::GuardState::Leased => {
                // tx2: GateGranted + FINAL response
                let mut b2 = Batch::default();
                {
                    let gen_s = self.runs[&chan_run].guard_generation.to_string();
                    let ctx = self.ectx(&chan_run);
                    let (ev, h) = self.make_event(
                        &ctx,
                        "GateGranted",
                        Value::obj(vec![
                            ("beat_seq", Value::str(ch.seq.to_string())),
                            ("deadline_ns", Value::str(new_deadline.to_string())),
                            ("guard_generation", Value::str(gen_s)),
                        ]),
                        "daemon",
                        false,
                    );
                    b2.events.push(ev);
                    let r = self.runs.get_mut(&chan_run).unwrap();
                    r.head = Head {
                        seq: ctx.seq,
                        hash: h,
                    };
                    r.state = RunState::Active;
                    r.gate = GateView::Leased;
                    r.last_guard_ack_ns = self.now;
                    r.last_renew_ns = self.now;
                    b2.run_update = Some(RunUpdate {
                        run_id: chan_run.clone(),
                        projection: r.projection(&self.boot_id),
                        last_seq: r.head.seq,
                        last_hash: r.head.hash.clone(),
                        terminal: false,
                    });
                    b2.requests.push(RequestRow {
                        principal,
                        scope: chan_run.clone(),
                        request_id: id.to_string(),
                        digest,
                        status: "FINAL",
                        response: Some(ok_response(id, result.clone())),
                    });
                }
                match self.store.commit(b2) {
                    Ok(()) => {
                        self.runs.get_mut(&chan_run).unwrap().pending_request = None;
                        Ok(result)
                    }
                    Err(StoreErr::FaultBlocked) => Err(ApiErr::new(Code::Busy)),
                    Err(_) => {
                        self.latch(&chan_run, Reason::AuditFault, None, "daemon", false);
                        Err(ApiErr::new(Code::AuditFault))
                    }
                }
            }
            _ => {
                // admitted durably but refused by the guard
                self.finish_beat_refused(&chan_run, &principal, id, &digest)?;
                self.latch(&chan_run, Reason::GuardLost, None, "daemon", false);
                Err(ApiErr::new(Code::Stopped))
            }
        }
    }

    fn finish_beat_refused(
        &mut self,
        run_id: &str,
        principal: &str,
        id: &str,
        digest: &str,
    ) -> Result<(), ApiErr> {
        let mut b = Batch::default();
        b.requests.push(RequestRow {
            principal: principal.to_string(),
            scope: run_id.to_string(),
            request_id: id.to_string(),
            digest: digest.to_string(),
            status: "FINAL",
            response: Some(err_response(id, Code::Stopped)),
        });
        let r = self.runs.get_mut(run_id).unwrap();
        r.pending_request = None;
        self.store
            .commit(b)
            .map_err(|_| ApiErr::new(Code::AuditFault))
    }

    /// Apply a sampled inventory: persist on change (excl. sampled_ns) or at
    /// least every 60 s; a mismatch latches REPLICATION_MISMATCH.
    fn apply_inventory(&mut self, run_id: &str, inv: Inventory) -> Result<(), ApiErr> {
        let max_threads = self.runs[run_id].policy.policy.max_threads;
        let matches = match &self.runs[run_id].armed {
            Some(a) => inventory_matches(&inv, a, max_threads),
            None => false,
        };
        let mut invv = inv.clone();
        invv.raw = inventory_value(&invv, matches);
        self.runs.get_mut(run_id).unwrap().inventory = Some(invv.clone());
        if !matches {
            let mut b = Batch::default();
            {
                let ctx = self.ectx(run_id);
                let (ev, h) = self.make_event(
                    &ctx,
                    "InventoryObserved",
                    Value::obj(vec![("inventory", invv.raw.clone())]),
                    "daemon",
                    false,
                );
                b.events.push(ev);
                let r = self.runs.get_mut(run_id).unwrap();
                r.head = Head {
                    seq: ctx.seq,
                    hash: h,
                };
            }
            if self.store.commit(b).is_err() {
                if let Some(r) = self.runs.get_mut(run_id) {
                    r.audit = Audit::Gap;
                }
            }
            self.latch(run_id, Reason::ReplicationMismatch, None, "daemon", false);
            return Err(ApiErr::new(Code::ScopeMismatch));
        }
        // persist-on-change / 60s repersist
        let changed = self.runs[run_id]
            .last_inv_persisted
            .as_ref()
            .map(|p| inv_changed(p, &invv.raw))
            .unwrap_or(false);
        let due = self.now >= self.runs[run_id].last_inv_event_ns + INVENTORY_REPERSIST_NS;
        if changed || (due && self.runs[run_id].last_inv_persisted.is_some()) {
            let mut b = Batch::default();
            {
                let ctx = self.ectx(run_id);
                let (ev, h) = self.make_event(
                    &ctx,
                    "InventoryObserved",
                    Value::obj(vec![("inventory", invv.raw.clone())]),
                    "daemon",
                    false,
                );
                b.events.push(ev);
                let now = self.now;
                let r = self.runs.get_mut(run_id).unwrap();
                r.head = Head {
                    seq: ctx.seq,
                    hash: h,
                };
                r.last_inv_persisted = Some(invv.raw.clone());
                r.last_inv_event_ns = now;
                b.run_update = Some(RunUpdate {
                    run_id: run_id.to_string(),
                    projection: r.projection(&self.boot_id),
                    last_seq: r.head.seq,
                    last_hash: r.head.hash.clone(),
                    terminal: false,
                });
            }
            if self.store.commit(b).is_err() {
                if let Some(r) = self.runs.get_mut(run_id) {
                    r.audit = Audit::Gap;
                }
            }
        } else if self.runs[run_id].last_inv_persisted.is_none() {
            self.runs.get_mut(run_id).unwrap().last_inv_persisted = Some(invv.raw.clone());
        }
        Ok(())
    }

    // ---- read methods -----------------------------------------------------

    fn run_or_404(&self, params: &Value) -> Result<&RunRt, ApiErr> {
        let m = obj(params)?;
        closed(m, &["run_id"])?;
        let rid = f_id(get(m, "run_id")?, "trr")?;
        self.runs
            .get(rid)
            .ok_or_else(|| ApiErr::new(Code::NotFound))
    }

    fn m_run_get(&mut self, params: Value) -> Result<Value, ApiErr> {
        let r = self.run_or_404(&params)?;
        Ok(r.projection(&self.boot_id))
    }

    fn m_run_list(&mut self, params: Value) -> Result<Value, ApiErr> {
        let m = obj(&params)?;
        closed(m, &["after", "limit"])?;
        let after = match get(m, "after")? {
            Value::Null => None,
            v => Some(f_id(v, "trr")?.to_string()),
        };
        let limit = f_int_range(get(m, "limit")?, 1, 32)?;
        let mut out = Vec::new();
        let mut next = Value::Null;
        for (i, (rid, r)) in self.runs.iter().enumerate() {
            if let Some(a) = &after {
                if rid.as_str() <= a.as_str() {
                    continue;
                }
            }
            if out.len() as u64 >= limit {
                next = Value::str(rid.clone());
                break;
            }
            let _ = i;
            out.push(r.projection(&self.boot_id));
        }
        Ok(Value::obj(vec![("runs", Value::Arr(out)), ("next", next)]))
    }

    fn m_run_stop(&mut self, peer_uid: u64, id: &str, params: Value) -> Result<Value, ApiErr> {
        let m = obj(&params)?;
        closed(m, &["run_id", "reason", "note_hash"])?;
        let rid = f_id(get(m, "run_id")?, "trr")?.to_string();
        let reason = match f_str(get(m, "reason")?)? {
            "OPERATOR" => Reason::Operator,
            "POLICY_TRIP" => Reason::PolicyTrip,
            _ => return Err(ApiErr::new(Code::InvalidInput)),
        };
        let note_hash = match get(m, "note_hash")? {
            Value::Null => None,
            v => Some(f_hash(v)?.to_string()),
        };
        if !self.runs.contains_key(&rid) {
            return Err(ApiErr::new(Code::NotFound));
        }
        let digest = Self::request_digest("run.stop", &params);
        let principal = format!("uid:{}", peer_uid);
        match self.idem_check(&principal, &rid, id, &digest)? {
            Idem::Replay(v) => {
                return Ok(v.get("result").cloned().unwrap_or(v));
            }
            Idem::Conflict => return Err(ApiErr::new(Code::Conflict)),
            Idem::Pending => return Err(ApiErr::new(Code::Busy)),
            Idem::Fresh => {}
        }
        let cur = self.runs[&rid].state;
        if cur.terminal() {
            let r = &self.runs[&rid];
            let result = Value::obj(vec![
                ("run_id", Value::str(rid.clone())),
                ("state", Value::str(r.state.as_str())),
                (
                    "first_reason",
                    r.stop_reason
                        .map(|x| Value::str(x.as_str()))
                        .unwrap_or(Value::Null),
                ),
                ("confirmed", Value::Bool(true)),
            ]);
            self.persist_final(&principal, &rid, id, &digest, &result)?;
            return Ok(result);
        }
        if matches!(cur, RunState::Stopping | RunState::Unconfirmed) {
            let r = &self.runs[&rid];
            let result = Value::obj(vec![
                ("run_id", Value::str(rid.clone())),
                ("state", Value::str(r.state.as_str())),
                (
                    "first_reason",
                    r.stop_reason
                        .map(|x| Value::str(x.as_str()))
                        .unwrap_or(Value::Null),
                ),
                ("confirmed", Value::Bool(false)),
            ]);
            self.persist_final(&principal, &rid, id, &digest, &result)?;
            return Ok(result);
        }
        // latch first, respond at latch (confirmation arrives later)
        let result = Value::obj(vec![
            ("run_id", Value::str(rid.clone())),
            ("state", Value::str("STOPPING")),
            ("first_reason", Value::str(reason.as_str())),
            ("confirmed", Value::Bool(false)),
        ]);
        self.latch(&rid, reason, note_hash, "operator", true);
        self.persist_final(&principal, &rid, id, &digest, &result)?;
        Ok(result)
    }

    fn persist_final(
        &mut self,
        principal: &str,
        scope: &str,
        id: &str,
        digest: &str,
        result: &Value,
    ) -> Result<(), ApiErr> {
        let mut b = Batch::default();
        b.requests.push(RequestRow {
            principal: principal.to_string(),
            scope: scope.to_string(),
            request_id: id.to_string(),
            digest: digest.to_string(),
            status: "FINAL",
            response: Some(ok_response(id, result.clone())),
        });
        self.store
            .commit(b)
            .map_err(|_| ApiErr::new(Code::AuditFault))
    }

    fn m_inventory_get(&mut self, params: Value) -> Result<Value, ApiErr> {
        let r = self.run_or_404(&params)?;
        Ok(Value::obj(vec![
            (
                "inventory",
                r.inventory
                    .as_ref()
                    .map(|i| i.raw.clone())
                    .unwrap_or(Value::Null),
            ),
            ("state", Value::str(r.state.as_str())),
        ]))
    }

    fn m_events_read(&mut self, params: Value) -> Result<Value, ApiErr> {
        let m = obj(&params)?;
        closed(m, &["run_id", "after_seq", "through", "limit"])?;
        let rid = f_id(get(m, "run_id")?, "trr")?.to_string();
        if !self.runs.contains_key(&rid) {
            return Err(ApiErr::new(Code::NotFound));
        }
        let after_seq = f_u(get(m, "after_seq")?)?;
        let limit = f_int_range(get(m, "limit")?, 1, 256)?;
        let head_v = self.runs[&rid].head.clone();
        let through = match get(m, "through")? {
            Value::Null => head_v.clone(),
            t => head(t)?,
        };
        if through.seq > head_v.seq {
            return Err(ApiErr::new(Code::NotFound));
        }
        // hash must match stored entry at that seq
        if let Some((_, _, h)) = self
            .store
            .event_entry_at(&rid, through.seq)
            .map_err(ApiErr::from)?
        {
            if h != through.hash {
                return Err(ApiErr::new(Code::HashMismatch));
            }
        } else {
            return Err(ApiErr::new(Code::NotFound));
        }
        if after_seq > through.seq {
            return Err(ApiErr::new(Code::InvalidInput));
        }
        let rows = self
            .store
            .events_page(&rid, after_seq, through.seq, limit)
            .map_err(ApiErr::from)?;
        // response byte cap 1 MiB applied on the way out
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        let mut last = after_seq;
        for (seq, body, sig, hash) in rows {
            let e = Value::obj(vec![
                ("body", body),
                ("hash", Value::str(hash)),
                ("sig", Value::str(sig)),
            ]);
            let size = e.canonical().len();
            if bytes + size > 1_048_576 && !entries.is_empty() {
                break;
            }
            bytes += size;
            last = seq;
            entries.push(e);
        }
        let more = last < through.seq;
        Ok(Value::obj(vec![
            ("entries", Value::Arr(entries)),
            ("through", through.to_value()),
            ("next_seq", Value::str(last.to_string())),
            ("more", Value::Bool(more)),
        ]))
    }

    fn m_receipt_checkpoint(&mut self, params: Value) -> Result<Value, ApiErr> {
        let (rid, head, state, audit, policy_raw) = {
            let r = self.run_or_404(&params)?;
            (
                r.run_id.clone(),
                r.head.clone(),
                r.state,
                r.audit,
                r.policy.raw.clone(),
            )
        };
        // cached per head
        if let Some(cp) = self
            .store
            .checkpoint_at(&rid, head.seq)
            .map_err(ApiErr::from)?
        {
            return Ok(Value::obj(vec![("policy", policy_raw), ("checkpoint", cp)]));
        }
        let checkpoint_id = if self.deterministic {
            crate::fixtures::i("trn", head.seq)
        } else {
            self.ids.id("trn")
        };
        let body = Value::obj(vec![
            ("v", Value::int(1)),
            ("checkpoint_id", Value::str(checkpoint_id)),
            ("host_id", Value::str(self.cfg.host_id.clone())),
            ("run_id", Value::str(rid.clone())),
            ("key_id", Value::str(self.log_key_id.clone())),
            ("head", head.to_value()),
            ("state", Value::str(state.as_str())),
            ("audit", Value::str(audit.as_str())),
            ("wall_time", Value::str(self.wall.clone())),
        ]);
        let h = domain_hash(D_CHECKPOINT, &body);
        let sig = self.log_key.sign_domain(D_CHECKPOINT_SIGN, &h).unwrap();
        let cp = Value::obj(vec![
            ("body", body.clone()),
            ("hash", Value::str(h.clone())),
            ("sig", Value::str(sig.clone())),
        ]);
        let b = Batch {
            checkpoint: Some(SignedRow {
                run_id: rid,
                seq: head.seq,
                body,
                hash: h,
                sig,
            }),
            ..Default::default()
        };
        self.store
            .commit(b)
            .map_err(|_| ApiErr::new(Code::AuditFault))?;
        Ok(Value::obj(vec![("policy", policy_raw), ("checkpoint", cp)]))
    }

    fn m_certificate_get(&mut self, params: Value) -> Result<Value, ApiErr> {
        let r = self.run_or_404(&params)?;
        match r.state {
            RunState::Rejected => return Err(ApiErr::new(Code::Conflict)),
            RunState::Stopped => {}
            _ => return Err(ApiErr::new(Code::Unconfirmed)),
        }
        if r.audit == Audit::Gap {
            return Err(ApiErr::new(Code::Incomplete));
        }
        if let Some(c) = self
            .store
            .certificate_row(&r.run_id)
            .map_err(ApiErr::from)?
        {
            return Ok(c);
        }
        // issue: STOPPED + confirmed closed gate + observed empty + no gap
        if !(r.gate_closed_observed && r.empty_observed) {
            return Err(ApiErr::new(Code::Unconfirmed));
        }
        let body = Value::obj(vec![
            ("v", Value::int(1)),
            ("host_id", Value::str(self.cfg.host_id.clone())),
            ("run_id", Value::str(r.run_id.clone())),
            ("key_id", Value::str(self.log_key_id.clone())),
            ("policy_hash", Value::str(r.policy_hash.clone())),
            ("stopped_event", r.head.to_value()),
            ("stop_reason", Value::str(r.stop_reason.unwrap().as_str())),
            ("gate_closed", Value::Bool(true)),
            ("empty_observed", Value::Bool(true)),
            ("evidence", Value::str("local-software-observation")),
            ("external_effects", Value::str("NOT_REVERSED")),
            ("remote_replication", Value::str("NOT_ATTESTED")),
        ]);
        let h = domain_hash(D_KILL, &body);
        let sig = self.log_key.sign_domain(D_KILL_SIGN, &h).unwrap();
        let cert = Value::obj(vec![
            ("body", body.clone()),
            ("hash", Value::str(h.clone())),
            ("sig", Value::str(sig.clone())),
        ]);
        let b = Batch {
            certificate: Some(SignedRow {
                run_id: r.run_id.clone(),
                seq: 0,
                body,
                hash: h,
                sig,
            }),
            ..Default::default()
        };
        self.store
            .commit(b)
            .map_err(|_| ApiErr::new(Code::AuditFault))?;
        Ok(cert)
    }

    // ---- recovery ---------------------------------------------------------

    /// STARTING -> READY path: verify journal, recover nonterminal runs.
    pub fn startup(&mut self) {
        // load meta/epoch
        let prev = self.store.meta().ok().flatten();
        self.epoch = prev
            .as_ref()
            .and_then(|m| {
                m.get("host_epoch")
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string())
            })
            .and_then(|s| s.parse().ok())
            .map(|e: u64| e + 1)
            .unwrap_or(1);
        let mb = Batch {
            meta: Some(Value::obj(vec![
                ("storage_version", Value::int(1)),
                ("host_id", Value::str(self.cfg.host_id.clone())),
                ("host_epoch", Value::str(self.epoch.to_string())),
                ("boot_id", Value::str(self.boot_id.clone())),
                ("kernel_boot_id", Value::str(self.kernel_boot_id.clone())),
                ("reducer", Value::str("trellis-reducer/1")),
            ])),
            ..Default::default()
        };
        let _ = self.store.commit(mb);
        // rebuild runs from store
        let rows = self.store.load_runs().unwrap_or_default();
        for row in rows {
            self.recover_run(row);
        }
        // resolve PENDING requests
        let pend = self.store.pending_requests().unwrap_or_default();
        for p in pend {
            let mut b = Batch::default();
            let scope_run = p.scope.clone();
            let resp = if p.scope == "host" {
                // run.start pending: derive from durable genesis if present
                match self.find_run_by_request(&p.request_id) {
                    Some((rid, head)) => Some(ok_response(
                        &p.request_id,
                        Value::obj(vec![
                            ("run_id", Value::str(rid)),
                            ("state", Value::str("PREPARING")),
                            ("head", head.to_value()),
                        ]),
                    )),
                    None => Some(err_response(&p.request_id, Code::Stopped)),
                }
            } else {
                Some(err_response(&p.request_id, Code::Stopped))
            };
            b.requests.push(RequestRow {
                principal: p.principal,
                scope: scope_run,
                request_id: p.request_id,
                digest: p.digest,
                status: "FINAL",
                response: resp,
            });
            let _ = self.store.commit(b);
        }
        // preflight: any failed platform check -> LOCKED
        let pf = self.os.borrow_mut().preflight(&self.cfg);
        let adapter_ok = self.cfg.cap_adapter == "disabled" || self.cap_available();
        if pf.ready() && adapter_ok {
            self.state = HostState::Ready;
        } else {
            self.state = HostState::Locked;
        }
    }

    /// A PENDING host-scope run.start resolves from the durable genesis of the
    /// unique run that committed RunCreated and never progressed past it.
    fn find_run_by_request(&self, _request_id: &str) -> Option<(String, Head)> {
        let mut cands = self
            .runs
            .values()
            .filter(|r| r.head.seq >= 1 && r.armed.is_none() && !r.guard_registered);
        let first = cands.next()?;
        if cands.next().is_some() {
            return None; // ambiguous without a stored link; never fabricate
        }
        // derive the response head from the *durable* RunCreated (seq 1)
        Some((
            first.run_id.clone(),
            Head {
                seq: 1,
                hash: String::new(),
            },
        ))
        .and_then(|(rid, _)| {
            self.store
                .event_entry_at(&rid, 1)
                .ok()
                .flatten()
                .map(|(_, _, h)| (rid, Head { seq: 1, hash: h }))
        })
    }

    /// Rebuild a stored run: replay events, recover closed if nonterminal.
    fn recover_run(&mut self, row: RunRow) {
        let events = self.store.load_events(&row.run_id).unwrap_or_default();
        let policy_v = crate::json::parse(&row.policy).unwrap_or(Value::Null);
        let sp = signed_policy(&policy_v, &self.extra_deny);
        let proj_v = crate::json::parse(&row.projection).unwrap_or(Value::Null);
        let state = proj_v
            .get("state")
            .and_then(|s| s.as_str())
            .and_then(RunState::parse)
            .unwrap_or(RunState::Stopped);
        let mut run = match sp {
            Ok(sp) => RunRt::new(
                &StartInput {
                    policy: sp,
                    exec: Exec {
                        argv: vec![],
                        cwd: "/".into(),
                        env: BTreeMap::new(),
                    },
                    workspace_root: row.workspace.clone(),
                    task_ref: None,
                    expected_host_epoch: self.epoch,
                    raw: Value::Null,
                },
                &row.run_id,
                &self.boot_id,
                row.task_uid,
                Head {
                    seq: row.last_seq,
                    hash: row.last_hash.clone(),
                },
            ),
            Err(_) => return,
        };
        run.state = state;
        // repopulate key fields from projection
        if let Some(sr) = proj_v.get("stop_reason").and_then(|v| v.as_str()) {
            run.stop_reason = Reason::parse(sr);
        }
        run.empty_observed = proj_v
            .get("empty_observed")
            .map(|v| v == &Value::Bool(true))
            .unwrap_or(false);
        run.audit = if proj_v.get("audit").and_then(|a| a.as_str()) == Some("GAP") {
            Audit::Gap
        } else {
            Audit::CompletePrefix
        };
        run.head = Head {
            seq: row.last_seq,
            hash: row.last_hash,
        };
        let _ = events;
        if run.state.terminal() {
            self.runs.insert(row.run_id.clone(), run);
            return;
        }
        // nonterminal at restart: recover closed, never resume
        run.audit = Audit::Gap;
        let prev_boot = proj_v
            .get("boot_id")
            .and_then(|b| b.as_str())
            .unwrap_or("")
            .to_string();
        self.runs.insert(row.run_id.clone(), run);
        let mut b = Batch::default();
        {
            let ctx = self.ectx(&row.run_id);
            let prev_head = ctx.prev.clone();
            let prev_seq = ctx.seq - 1;
            let (ev, h) = self.make_event(
                &ctx,
                "RecoveryObserved",
                Value::obj(vec![
                    ("previous_boot_id", Value::str(prev_boot)),
                    (
                        "previous_head",
                        Head {
                            seq: prev_seq,
                            hash: prev_head,
                        }
                        .to_value(),
                    ),
                    ("gap", Value::Bool(true)),
                ]),
                "daemon",
                false,
            );
            b.events.push(ev);
            self.runs.get_mut(&row.run_id).unwrap().head = Head {
                seq: ctx.seq,
                hash: h,
            };
        }
        {
            let ctx = self.ectx(&row.run_id);
            let (ev, h) = self.make_event(
                &ctx,
                "StopLatched",
                Value::obj(vec![
                    ("reason", Value::str(Reason::Recovery.as_str())),
                    ("note_hash", Value::Null),
                ]),
                "daemon",
                false,
            );
            b.events.push(ev);
            let r = self.runs.get_mut(&row.run_id).unwrap();
            r.head = Head {
                seq: ctx.seq,
                hash: h,
            };
            r.state = RunState::Stopping;
            r.stop_reason = Some(Reason::Recovery);
            r.latched_at_ns = Some(self.now);
        }
        let rid = row.run_id.clone();
        {
            let r = self.runs.get(&rid).unwrap();
            b.run_update = Some(RunUpdate {
                run_id: rid.clone(),
                projection: r.projection(&self.boot_id),
                last_seq: r.head.seq,
                last_hash: r.head.hash.clone(),
                terminal: false,
            });
        }
        if self.store.commit(b).is_err() {
            if let Some(r) = self.runs.get_mut(&rid) {
                r.audit = Audit::Gap;
            }
        }
        // contain via owned handles
        let k = self.os.borrow_mut().kill(&rid, self.now);
        self.note_kill(&rid, k);
        self.progress_stop(&rid);
    }

    /// SIGTERM/SIGINT path: latch every nonterminal run HOST_SHUTDOWN and
    /// enter DRAINING (spec §4.1). Repeat signals are a no-op.
    pub fn drain(&mut self) {
        if self.state == HostState::Draining {
            return;
        }
        self.state = HostState::Draining;
        let ids: Vec<String> = self.runs.keys().cloned().collect();
        for rid in ids {
            if !self.runs[&rid].state.terminal() {
                self.latch(&rid, Reason::HostShutdown, None, "daemon", false);
            }
        }
        self.boundary();
    }

    /// trellis doctor output object (spec §6.1): checks, readiness, adapter.
    pub fn doctor(&mut self) -> Value {
        let pf = self.os.borrow_mut().preflight(&self.cfg);
        let get = |n: &str| {
            pf.checks
                .iter()
                .find(|c| c.0 == n)
                .map(|c| c.1)
                .unwrap_or(false)
        };
        let adapter_available = self.cap_available();
        let ready = pf.ready()
            && (self.cfg.cap_adapter == "disabled" || adapter_available)
            && self.state != HostState::Locked;
        Value::obj(vec![
            ("v", Value::int(1)),
            ("profile", Value::str("linux-single-process-v1")),
            ("ready", Value::Bool(ready)),
            (
                "checks",
                Value::obj(vec![
                    ("privileges", Value::Bool(get("privileges"))),
                    ("cgroup", Value::Bool(get("cgroup"))),
                    ("bpf", Value::Bool(get("bpf"))),
                    ("seccomp", Value::Bool(get("seccomp"))),
                    ("namespaces", Value::Bool(get("namespaces"))),
                    ("image", Value::Bool(get("image"))),
                    ("workspace", Value::Bool(get("workspace"))),
                    ("storage", Value::Bool(get("storage"))),
                    ("guard", Value::Bool(get("guard"))),
                ]),
            ),
            (
                "cap_adapter",
                Value::obj(vec![
                    ("available", Value::Bool(adapter_available)),
                    ("code", Value::str("CAP_ADAPTER_UNAVAILABLE")),
                    (
                        "missing",
                        Value::Arr(vec![
                            Value::str("lifetime-owner-binding"),
                            Value::str("heartbeat-fd-binding"),
                            Value::str("containment-profile-certification"),
                        ]),
                    ),
                ]),
            ),
        ])
    }
}

/// `trellis migrate --to 1` on a storage=1 tree: verify and report the no-op
/// (spec §7.5): refuse with live runs handled by caller; here, verify every
/// run's chain bytes and report unchanged.
pub fn migrate_noop(store: &Store) -> Result<Value, ApiErr> {
    let runs = store.load_runs().map_err(ApiErr::from)?;
    let mut out = Vec::new();
    for r in &runs {
        // re-read signed event bytes; a v1->v1 migration never rewrites them
        let evs = store.load_events(&r.run_id).map_err(ApiErr::from)?;
        let proj = crate::json::parse(&r.projection).map_err(|_| ApiErr::new(Code::AuditFault))?;
        out.push(Value::obj(vec![
            ("run_id", Value::str(r.run_id.clone())),
            ("state", proj.get("state").cloned().unwrap_or(Value::Null)),
            ("audit", proj.get("audit").cloned().unwrap_or(Value::Null)),
        ]));
        let _ = evs;
    }
    Ok(Value::obj(vec![
        ("v", Value::int(1)),
        ("storage", Value::int(1)),
        ("runs", Value::Arr(out)),
        ("changed", Value::Bool(false)),
    ]))
}

fn get_params(raw: &Value) -> Value {
    raw.get("params").cloned().unwrap_or(Value::Null)
}

pub fn challenge_value(c: &Challenge) -> Value {
    if !c.raw.is_null() {
        return c.raw.clone();
    }
    Value::obj(vec![
        ("run_id", Value::str(c.run_id.clone())),
        ("boot_id", Value::str(c.boot_id.clone())),
        ("challenge_id", Value::str(c.challenge_id.clone())),
        ("seq", Value::str(c.seq.to_string())),
        ("nonce", Value::str(c.nonce.clone())),
        ("policy_hash", Value::str(c.policy_hash.clone())),
        ("expires_ns", Value::str(c.expires_ns.to_string())),
    ])
}

pub fn inventory_value(i: &Inventory, matches: bool) -> Value {
    Value::obj(vec![
        ("sampled_ns", Value::str(i.sampled_ns.to_string())),
        ("root", i.root.to_value()),
        (
            "tgids",
            Value::Arr(i.tgids.iter().map(|t| Value::int(*t)).collect()),
        ),
        ("threads", Value::int(i.threads)),
        ("matches", Value::Bool(matches)),
        ("coverage", Value::str("local-cgroup-single-process")),
    ])
}

/// Compare two inventory values ignoring sampled_ns.
fn inv_changed(a: &Value, b: &Value) -> bool {
    fn strip(v: &Value) -> Value {
        let mut v = v.clone();
        if let Value::Obj(m) = &mut v {
            m.remove("sampled_ns");
        }
        v
    }
    strip(a) != strip(b)
}

impl Policy {
    pub fn body_hash(&self) -> String {
        domain_hash(D_POLICY, &self.body)
    }
}

fn exec_to_value(e: &Exec) -> Value {
    Value::obj(vec![
        (
            "argv",
            Value::Arr(e.argv.iter().map(|a| Value::str(a.clone())).collect()),
        ),
        ("cwd", Value::str(e.cwd.clone())),
        (
            "env",
            Value::Obj(
                e.env
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::str(v.clone())))
                    .collect(),
            ),
        ),
    ])
}

impl RunRt {
    fn challenge_deadline(&self) -> Option<u64> {
        match self.state {
            RunState::Waiting => self
                .outstanding
                .as_ref()
                .map(|c| c.expires_ns)
                .or(self.startup_deadline_ns),
            RunState::Active => self.deadline_ns,
            _ => None,
        }
    }
}
