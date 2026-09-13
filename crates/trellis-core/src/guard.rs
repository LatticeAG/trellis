//! The guard automaton (spec §4.3, §5.4): CLOSED -> LEASED -> DENIED ->
//! RETAINED -> UNREGISTERED, the 750 ms independent lease, health deadline,
//! and the kill path. `GuardModel` is the in-process model used by the
//! conformance harness; the privileged `trellis-guard` binary implements the
//! same logic over the private seqpacket channel with real fds.

use crate::os::Os;
use crate::types::{Head, Reason};
use crate::wire::GuardState;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

pub const LEASE_NS: u64 = 750_000_000;
pub const HEALTH_NS: u64 = 750_000_000;

#[derive(Debug, Clone)]
pub struct GuardReport {
    pub state: GuardState,
    pub generation: u64,
    pub lease_until_ns: u64,
    pub gate_closed: bool,
    pub empty_observed: bool,
    pub kill: Option<(bool, bool)>, // (cgroup_attempted, pidfd_attempted)
    pub root_exit: Option<crate::schema::Exit>,
    pub reason: Option<Reason>,
}

impl GuardReport {
    pub fn wire(&self) -> crate::json::Value {
        crate::wire::guard_result(
            self.state,
            self.generation,
            self.lease_until_ns,
            self.gate_closed,
            self.empty_observed,
        )
    }
}

#[derive(Debug)]
pub enum GuardEvent {
    /// Guard denied a run autonomously (health/agent expiry, channel loss).
    Denied {
        run_id: String,
        reason: Reason,
        gate_closed: bool,
        empty_observed: bool,
        kill: Option<(bool, bool)>,
        root_exit: Option<crate::schema::Exit>,
    },
    /// A previously denied run is now observed empty.
    Emptied { run_id: String },
}

pub struct GuardRun {
    pub state: GuardState,
    pub generation: u64,
    pub boot_id: String,
    pub cgroup_inode: u64,
    pub agent_deadline_ns: u64, // startup deadline until first grant
    pub health_deadline_ns: u64,
    pub beat_seq: u64,
    pub head: Head,
    pub startup_deadline_ns: u64,
    pub had_grant: bool,
}

/// The guard service. `os` is shared with the daemon's model so the guard's
/// lease-map writes and kills act on the same kernel objects.
pub struct GuardModel {
    pub os: Rc<RefCell<dyn Os>>,
    pub runs: HashMap<String, GuardRun>,
    /// When true the guard process is frozen: it performs no work, answers no
    /// RPCs, and only the kernel lease still expires on its own.
    pub frozen: bool,
    pub events: VecDeque<GuardEvent>,
    /// Last instant the guard produced an acknowledgement per run (for the
    /// daemon's 750 ms acknowledgement-age check).
    pub last_ack: HashMap<String, u64>,
}

impl GuardModel {
    pub fn new(os: Rc<RefCell<dyn Os>>) -> Self {
        GuardModel {
            os,
            runs: HashMap::new(),
            frozen: false,
            events: VecDeque::new(),
            last_ack: HashMap::new(),
        }
    }

    fn deny(&mut self, run_id: &str, now: u64, reason: Reason) {
        let kill;
        let mut root_exit = None;
        let empty;
        if let Some(r) = self.runs.get_mut(run_id) {
            if r.state == GuardState::Denied || r.state == GuardState::Retained {
                return;
            }
            r.state = GuardState::Denied;
        }
        // denied=true before any logging or signaling
        {
            let mut os = self.os.borrow_mut();
            if let Some(g) = os.gate(run_id) {
                g.denied = true;
                g.lease_until_ns = 0;
            }
            let k = os.kill(run_id, now);
            kill = Some((k.cgroup_attempted, k.pidfd_attempted));
            let mut e_ = false;
            if let Ok(e) = os.containment(run_id, now) {
                e_ = e.populated_gone && e.pidfd_exited;
                root_exit = e.root_exit;
            }
            empty = e_;
        }
        if empty {
            if let Some(r) = self.runs.get_mut(run_id) {
                r.state = GuardState::Retained;
            }
        }
        self.events.push_back(GuardEvent::Denied {
            run_id: run_id.to_string(),
            reason,
            gate_closed: true,
            empty_observed: empty,
            kill,
            root_exit,
        });
    }

    /// Periodic work: health and agent-deadline expiries, and empty
    /// re-checks for denied runs awaiting confirmation.
    pub fn poll(&mut self, now: u64) {
        if self.frozen {
            return; // kernel lease expiry needs no userspace
        }
        let ids: Vec<String> = self.runs.keys().cloned().collect();
        for id in ids {
            let (state, agent_dl, health_dl) = {
                let r = &self.runs[&id];
                (r.state, r.agent_deadline_ns, r.health_deadline_ns)
            };
            match state {
                GuardState::Closed | GuardState::Leased => {
                    // agent deadline expiry preferred over health on tie
                    if now >= agent_dl {
                        let reason = if state == GuardState::Leased {
                            Reason::HeartbeatTimeout
                        } else {
                            Reason::StartupTimeout
                        };
                        self.deny(&id, now, reason);
                    } else if now >= health_dl {
                        self.deny(&id, now, Reason::DaemonLost);
                    }
                }
                GuardState::Denied => {
                    // safety retry until confirmed empty
                    let mut os = self.os.borrow_mut();
                    if let Ok(e) = os.containment(&id, now) {
                        if e.populated_gone && e.pidfd_exited {
                            drop(os);
                            if let Some(r) = self.runs.get_mut(&id) {
                                r.state = GuardState::Retained;
                            }
                            self.events.push_back(GuardEvent::Emptied { run_id: id });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn ack(&mut self, run_id: &str, now: u64) {
        self.last_ack.insert(run_id.to_string(), now);
    }

    /// guard.register
    pub fn register(
        &mut self,
        now: u64,
        run_id: &str,
        boot_id: &str,
        cgroup_inode: u64,
        startup_deadline_ns: u64,
        durable_head: Head,
    ) -> Result<GuardReport, crate::types::Code> {
        if self.frozen {
            return Err(crate::types::Code::Busy);
        }
        if self.runs.contains_key(run_id) {
            return Err(crate::types::Code::Conflict);
        }
        let r = GuardRun {
            state: GuardState::Closed,
            generation: 1,
            boot_id: boot_id.to_string(),
            cgroup_inode,
            agent_deadline_ns: startup_deadline_ns,
            health_deadline_ns: now + HEALTH_NS,
            beat_seq: 0,
            head: durable_head,
            startup_deadline_ns,
            had_grant: false,
        };
        self.runs.insert(run_id.to_string(), r);
        self.ack(run_id, now);
        Ok(GuardReport {
            state: GuardState::Closed,
            generation: 1,
            lease_until_ns: 0,
            gate_closed: true,
            empty_observed: false,
            kill: None,
            root_exit: None,
            reason: None,
        })
    }

    /// guard.renew
    pub fn renew(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        beat_seq: u64,
        agent_deadline_ns: u64,
        durable_head: Head,
    ) -> Result<GuardReport, Reason> {
        if self.frozen {
            return Err(Reason::GuardLost);
        }
        {
            let r = match self.runs.get(run_id) {
                Some(r) => r,
                None => return Err(Reason::GuardLost),
            };
            if generation != r.generation {
                return Err(Reason::GuardLost);
            }
            if matches!(r.state, GuardState::Denied | GuardState::Retained) {
                // never a grant again
                return Err(Reason::GuardLost);
            }
            // Grant/renew must arrive before both deadlines.
            if now >= r.agent_deadline_ns || now >= r.health_deadline_ns {
                let reason = if now >= r.agent_deadline_ns {
                    if r.state == GuardState::Leased {
                        Reason::HeartbeatTimeout
                    } else {
                        Reason::StartupTimeout
                    }
                } else {
                    Reason::DaemonLost
                };
                self.deny(run_id, now, reason);
                return Err(reason);
            }
        }
        if beat_seq == 0 {
            // CLOSED setup-health renewal only; never an egress grant.
            let r = self.runs.get_mut(run_id).unwrap();
            if agent_deadline_ns != r.startup_deadline_ns {
                return Err(Reason::GuardLost);
            }
            r.health_deadline_ns = now + HEALTH_NS;
            r.head = durable_head;
            let gen = r.generation;
            self.ack(run_id, now);
            return Ok(GuardReport {
                state: GuardState::Closed,
                generation: gen,
                lease_until_ns: 0,
                gate_closed: true,
                empty_observed: false,
                kill: None,
                root_exit: None,
                reason: None,
            });
        }
        // beat_seq >= 1 path
        {
            let r = self.runs.get_mut(run_id).unwrap();
            if r.had_grant {
                if beat_seq == r.beat_seq {
                    // same beat requires identical deadline
                    if agent_deadline_ns != r.agent_deadline_ns {
                        return Err(Reason::GuardLost);
                    }
                } else if beat_seq == r.beat_seq + 1 {
                    // must name a durable head at or beyond HeartbeatAccepted
                    if durable_head.seq <= r.head.seq {
                        return Err(Reason::GuardLost);
                    }
                    r.beat_seq = beat_seq;
                    r.agent_deadline_ns = agent_deadline_ns;
                    r.head = durable_head;
                } else {
                    return Err(Reason::GuardLost);
                }
            } else {
                if beat_seq != 1 {
                    return Err(Reason::GuardLost);
                }
                r.had_grant = true;
                r.beat_seq = beat_seq;
                r.agent_deadline_ns = agent_deadline_ns;
                r.head = durable_head;
            }
        }
        // lease extends only toward the already-accepted agent deadline
        let lease = agent_deadline_ns.min(now + LEASE_NS);
        {
            let mut os = self.os.borrow_mut();
            if let Some(g) = os.gate(run_id) {
                g.denied = false;
                g.lease_until_ns = lease;
            } else {
                return Err(Reason::EgressFault);
            }
        }
        {
            let r = self.runs.get_mut(run_id).unwrap();
            r.state = GuardState::Leased;
            r.health_deadline_ns = now + HEALTH_NS;
        }
        self.ack(run_id, now);
        let gen = self.runs[run_id].generation;
        Ok(GuardReport {
            state: GuardState::Leased,
            generation: gen,
            lease_until_ns: lease,
            gate_closed: false,
            empty_observed: false,
            kill: None,
            root_exit: None,
            reason: None,
        })
    }

    /// guard.stop
    pub fn stop(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        reason: Reason,
    ) -> Result<GuardReport, Reason> {
        if self.frozen {
            return Err(Reason::GuardLost);
        }
        let has = self.runs.contains_key(run_id);
        if !has {
            return Err(Reason::GuardLost);
        }
        if self.runs[run_id].generation != generation {
            return Err(Reason::GuardLost);
        }
        if matches!(
            self.runs[run_id].state,
            GuardState::Denied | GuardState::Retained
        ) {
            let (st, gen) = {
                let r = &self.runs[run_id];
                (r.state, r.generation)
            };
            self.ack(run_id, now);
            return Ok(GuardReport {
                state: st,
                generation: gen,
                lease_until_ns: 0,
                gate_closed: true,
                empty_observed: st == GuardState::Retained,
                kill: None,
                root_exit: None,
                reason: None,
            });
        }
        self.deny(run_id, now, reason);
        self.ack(run_id, now);
        let (st, gen) = {
            let r = &self.runs[run_id];
            (r.state, r.generation)
        };
        let ev = self.events.back();
        Ok(GuardReport {
            state: st,
            generation: gen,
            lease_until_ns: 0,
            gate_closed: true,
            empty_observed: st == GuardState::Retained,
            kill: ev.and_then(|e| match e {
                GuardEvent::Denied { kill, .. } => *kill,
                _ => None,
            }),
            root_exit: ev.and_then(|e| match e {
                GuardEvent::Denied { root_exit, .. } => *root_exit,
                _ => None,
            }),
            reason: None,
        })
    }

    /// guard.release: requires RETAINED + fresh empty check + terminal head.
    pub fn release(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        terminal_head: Head,
    ) -> Result<bool, crate::types::Code> {
        let r = match self.runs.get(run_id) {
            Some(r) => r,
            None => return Err(crate::types::Code::NotFound),
        };
        if r.generation != generation {
            return Err(crate::types::Code::InvalidInput);
        }
        if r.state != GuardState::Retained {
            return Err(crate::types::Code::Unconfirmed);
        }
        // fresh populated=0 / pidfd-exited check
        let mut os = self.os.borrow_mut();
        match os.containment(run_id, now) {
            Ok(e) if e.populated_gone && e.pidfd_exited => {
                drop(os);
                let r = self.runs.get_mut(run_id).unwrap();
                r.head = terminal_head;
                r.state = GuardState::Unregistered;
                self.ack(run_id, now);
                Ok(true)
            }
            _ => Err(crate::types::Code::Unconfirmed),
        }
    }
}

// ---------------------------------------------------------------------------
// GuardRpc — the daemon↔guard boundary. GuardModel is the in-process model;
// a RemoteGuard (trellisd) implements the same contract over the seqpacket
// RPC to the independent trellis-guard process.
// ---------------------------------------------------------------------------

pub trait GuardRpc {
    fn poll(&mut self, now: u64);
    fn next_event(&mut self) -> Option<GuardEvent>;
    fn last_ack(&self, run_id: &str) -> Option<u64>;
    fn register(
        &mut self,
        now: u64,
        run_id: &str,
        boot_id: &str,
        cgroup_inode: u64,
        startup_deadline_ns: u64,
        durable_head: Head,
    ) -> Result<GuardReport, crate::types::Code>;
    fn renew(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        beat_seq: u64,
        agent_deadline_ns: u64,
        durable_head: Head,
    ) -> Result<GuardReport, Reason>;
    fn stop(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        reason: Reason,
    ) -> Result<GuardReport, Reason>;
    fn release(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        terminal_head: Head,
    ) -> Result<bool, crate::types::Code>;
}

impl GuardRpc for GuardModel {
    fn poll(&mut self, now: u64) {
        GuardModel::poll(self, now)
    }
    fn next_event(&mut self) -> Option<GuardEvent> {
        self.events.pop_front()
    }
    fn last_ack(&self, run_id: &str) -> Option<u64> {
        self.last_ack.get(run_id).copied()
    }
    fn register(
        &mut self,
        now: u64,
        run_id: &str,
        boot_id: &str,
        cgroup_inode: u64,
        startup_deadline_ns: u64,
        durable_head: Head,
    ) -> Result<GuardReport, crate::types::Code> {
        GuardModel::register(
            self,
            now,
            run_id,
            boot_id,
            cgroup_inode,
            startup_deadline_ns,
            durable_head,
        )
    }
    fn renew(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        beat_seq: u64,
        agent_deadline_ns: u64,
        durable_head: Head,
    ) -> Result<GuardReport, Reason> {
        GuardModel::renew(
            self,
            now,
            run_id,
            generation,
            beat_seq,
            agent_deadline_ns,
            durable_head,
        )
    }
    fn stop(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        reason: Reason,
    ) -> Result<GuardReport, Reason> {
        GuardModel::stop(self, now, run_id, generation, reason)
    }
    fn release(
        &mut self,
        now: u64,
        run_id: &str,
        generation: u64,
        terminal_head: Head,
    ) -> Result<bool, crate::types::Code> {
        GuardModel::release(self, now, run_id, generation, terminal_head)
    }
}
