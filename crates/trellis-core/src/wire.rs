//! Request/Response envelopes, guard RPC, and export stream records.

use crate::json::Value;
use crate::schema::*;
use crate::types::Head;
use crate::types::{ApiErr, Code};

/// Wire request envelope: {v:1, id:trq_*, method, params}.
pub fn request(v: &Value) -> Res<(String, String)> {
    let m = obj(v)?;
    closed(m, &["v", "id", "method", "params"])?;
    f_v1(m)?;
    let id = f_id(get(m, "id")?, "trq")?.to_string();
    let method = f_str(get(m, "method")?)?.to_string();
    if !crate::types::METHODS.contains(&method.as_str()) {
        return Err(ApiErr::new(Code::InvalidInput));
    }
    Ok((id, method))
}

pub fn ok_response(id: &str, result: Value) -> Value {
    Value::obj(vec![
        ("v", Value::int(1)),
        ("id", Value::str(id)),
        ("ok", Value::Bool(true)),
        ("result", result),
    ])
}

pub fn err_response(id: &str, code: Code) -> Value {
    Value::obj(vec![
        ("v", Value::int(1)),
        ("id", Value::str(id)),
        ("ok", Value::Bool(false)),
        (
            "error",
            Value::obj(vec![
                ("code", Value::str(code.as_str())),
                ("retryable", Value::Bool(code.retryable())),
            ]),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Guard RPC (spec §5.4): closed method schema on the private seqpacket pair.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum GuardRequest {
    Register {
        run_id: String,
        boot_id: String,
        cgroup_inode: u64,
        startup_deadline_ns: u64,
        durable_head: Head,
    },
    Renew {
        run_id: String,
        generation: u64,
        beat_seq: u64,
        agent_deadline_ns: u64,
        durable_head: Head,
    },
    Stop {
        run_id: String,
        generation: u64,
        reason: crate::types::Reason,
    },
    Release {
        run_id: String,
        generation: u64,
        terminal_head: Head,
    },
}

pub fn guard_request(v: &Value) -> Res<(String, GuardRequest)> {
    let m = obj(v)?;
    closed(m, &["v", "id", "method", "params"])?;
    f_v1(m)?;
    let id = f_id(get(m, "id")?, "trq")?.to_string();
    let method = f_str(get(m, "method")?)?;
    let p = obj(get(m, "params")?)?;
    let r = match method {
        "guard.register" => {
            closed(
                p,
                &[
                    "run_id",
                    "boot_id",
                    "cgroup_inode",
                    "generation",
                    "startup_deadline_ns",
                    "durable_head",
                ],
            )?;
            if f_u(get(p, "generation")?)? != 1 {
                return Err(ApiErr::new(Code::InvalidInput));
            }
            GuardRequest::Register {
                run_id: f_id(get(p, "run_id")?, "trr")?.to_string(),
                boot_id: f_id(get(p, "boot_id")?, "trb")?.to_string(),
                cgroup_inode: f_u(get(p, "cgroup_inode")?)?,
                startup_deadline_ns: f_u(get(p, "startup_deadline_ns")?)?,
                durable_head: head(get(p, "durable_head")?)?,
            }
        }
        "guard.renew" => {
            closed(
                p,
                &[
                    "run_id",
                    "generation",
                    "beat_seq",
                    "agent_deadline_ns",
                    "durable_head",
                ],
            )?;
            GuardRequest::Renew {
                run_id: f_id(get(p, "run_id")?, "trr")?.to_string(),
                generation: f_u(get(p, "generation")?)?,
                beat_seq: f_u(get(p, "beat_seq")?)?,
                agent_deadline_ns: f_u(get(p, "agent_deadline_ns")?)?,
                durable_head: head(get(p, "durable_head")?)?,
            }
        }
        "guard.stop" => {
            closed(p, &["run_id", "generation", "reason"])?;
            let reason = crate::types::Reason::parse(f_str(get(p, "reason")?)?)
                .ok_or_else(|| ApiErr::new(Code::InvalidInput))?;
            GuardRequest::Stop {
                run_id: f_id(get(p, "run_id")?, "trr")?.to_string(),
                generation: f_u(get(p, "generation")?)?,
                reason,
            }
        }
        "guard.release" => {
            closed(p, &["run_id", "generation", "terminal_head"])?;
            GuardRequest::Release {
                run_id: f_id(get(p, "run_id")?, "trr")?.to_string(),
                generation: f_u(get(p, "generation")?)?,
                terminal_head: head(get(p, "terminal_head")?)?,
            }
        }
        _ => return Err(ApiErr::new(Code::InvalidInput)),
    };
    Ok((id, r))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardState {
    Unregistered,
    Closed,
    Leased,
    Denied,
    Retained,
}

impl GuardState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unregistered => "UNREGISTERED",
            Self::Closed => "CLOSED",
            Self::Leased => "LEASED",
            Self::Denied => "DENIED",
            Self::Retained => "RETAINED",
        }
    }
}

/// GuardResult wire form.
pub fn guard_result(
    state: GuardState,
    generation: u64,
    lease_until_ns: u64,
    gate_closed: bool,
    empty_observed: bool,
) -> Value {
    Value::obj(vec![
        ("state", Value::str(state.as_str())),
        ("generation", Value::str(generation.to_string())),
        ("lease_until_ns", Value::str(lease_until_ns.to_string())),
        ("gate_closed", Value::Bool(gate_closed)),
        ("empty_observed", Value::Bool(empty_observed)),
    ])
}

// ---------------------------------------------------------------------------
// Streaming export records (spec §7.4)
// ---------------------------------------------------------------------------

pub const EXPORT_FORMAT: &str = "trellis-stream/1";
pub const EXPORT_LINE_MAX: usize = 65536;
pub const EXPORT_MAX_BYTES: u64 = 12 * 1024 * 1024 * 1024;
pub const BUNDLE_MAX_ENTRIES: usize = 256;
pub const BUNDLE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Recovery pin file (spec §6.2).
pub fn recovery_pin_file(host_id: &str, heads: &[(String, Head)]) -> Value {
    Value::obj(vec![
        ("v", Value::int(1)),
        ("host_id", Value::str(host_id)),
        (
            "heads",
            Value::Arr(
                heads
                    .iter()
                    .map(|(r, h)| {
                        Value::obj(vec![
                            ("run_id", Value::str(r.clone())),
                            ("head", h.to_value()),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}
