//! Protocol enums, error codes, and shared typed views (spec §2.3, §5.1).

use crate::json::Value;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Code {
    InvalidInput,
    UnknownField,
    UnsupportedVersion,
    UnsupportedHost,
    Unauthorized,
    NotFound,
    Conflict,
    StaleEpoch,
    Busy,
    Stopped,
    ChallengeUsed,
    ChallengeExpired,
    ChallengeInvalid,
    ScopeMismatch,
    SignatureInvalid,
    UntrustedKey,
    HashMismatch,
    ChainInvalid,
    TransitionInvalid,
    Incomplete,
    Unconfirmed,
    AuditFault,
    EgressFault,
    InventoryLost,
    CapAdapterUnavailable,
    OutputLimit,
    CounterExhausted,
    RecoveryPinRequired,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        use Code::*;
        match self {
            InvalidInput => "INVALID_INPUT",
            UnknownField => "UNKNOWN_FIELD",
            UnsupportedVersion => "UNSUPPORTED_VERSION",
            UnsupportedHost => "UNSUPPORTED_HOST",
            Unauthorized => "UNAUTHORIZED",
            NotFound => "NOT_FOUND",
            Conflict => "CONFLICT",
            StaleEpoch => "STALE_EPOCH",
            Busy => "BUSY",
            Stopped => "STOPPED",
            ChallengeUsed => "CHALLENGE_USED",
            ChallengeExpired => "CHALLENGE_EXPIRED",
            ChallengeInvalid => "CHALLENGE_INVALID",
            ScopeMismatch => "SCOPE_MISMATCH",
            SignatureInvalid => "SIGNATURE_INVALID",
            UntrustedKey => "UNTRUSTED_KEY",
            HashMismatch => "HASH_MISMATCH",
            ChainInvalid => "CHAIN_INVALID",
            TransitionInvalid => "TRANSITION_INVALID",
            Incomplete => "INCOMPLETE",
            Unconfirmed => "UNCONFIRMED",
            AuditFault => "AUDIT_FAULT",
            EgressFault => "EGRESS_FAULT",
            InventoryLost => "INVENTORY_LOST",
            CapAdapterUnavailable => "CAP_ADAPTER_UNAVAILABLE",
            OutputLimit => "OUTPUT_LIMIT",
            CounterExhausted => "COUNTER_EXHAUSTED",
            RecoveryPinRequired => "RECOVERY_PIN_REQUIRED",
        }
    }
    pub fn parse(s: &str) -> Option<Code> {
        use Code::*;
        Some(match s {
            "INVALID_INPUT" => InvalidInput,
            "UNKNOWN_FIELD" => UnknownField,
            "UNSUPPORTED_VERSION" => UnsupportedVersion,
            "UNSUPPORTED_HOST" => UnsupportedHost,
            "UNAUTHORIZED" => Unauthorized,
            "NOT_FOUND" => NotFound,
            "CONFLICT" => Conflict,
            "STALE_EPOCH" => StaleEpoch,
            "BUSY" => Busy,
            "STOPPED" => Stopped,
            "CHALLENGE_USED" => ChallengeUsed,
            "CHALLENGE_EXPIRED" => ChallengeExpired,
            "CHALLENGE_INVALID" => ChallengeInvalid,
            "SCOPE_MISMATCH" => ScopeMismatch,
            "SIGNATURE_INVALID" => SignatureInvalid,
            "UNTRUSTED_KEY" => UntrustedKey,
            "HASH_MISMATCH" => HashMismatch,
            "CHAIN_INVALID" => ChainInvalid,
            "TRANSITION_INVALID" => TransitionInvalid,
            "INCOMPLETE" => Incomplete,
            "UNCONFIRMED" => Unconfirmed,
            "AUDIT_FAULT" => AuditFault,
            "EGRESS_FAULT" => EgressFault,
            "INVENTORY_LOST" => InventoryLost,
            "CAP_ADAPTER_UNAVAILABLE" => CapAdapterUnavailable,
            "OUTPUT_LIMIT" => OutputLimit,
            "COUNTER_EXHAUSTED" => CounterExhausted,
            "RECOVERY_PIN_REQUIRED" => RecoveryPinRequired,
            _ => return None,
        })
    }
    /// Only BUSY is retryable (spec §5.1).
    pub fn retryable(self) -> bool {
        self == Code::Busy
    }
    /// CLI exit code mapping (spec §6.1).
    pub fn exit_code(self) -> i32 {
        use Code::*;
        match self {
            InvalidInput | UnknownField | UnsupportedVersion => 64,
            UnsupportedHost
            | SignatureInvalid
            | UntrustedKey
            | CapAdapterUnavailable
            | RecoveryPinRequired => 65,
            Unauthorized => 69,
            Busy => 75,
            _ => 70,
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Starting,
    Ready,
    Locked,
    Draining,
}

impl HostState {
    pub fn as_str(self) -> &'static str {
        match self {
            HostState::Starting => "STARTING",
            HostState::Ready => "READY",
            HostState::Locked => "LOCKED",
            HostState::Draining => "DRAINING",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "STARTING" => Self::Starting,
            "READY" => Self::Ready,
            "LOCKED" => Self::Locked,
            "DRAINING" => Self::Draining,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Preparing,
    Waiting,
    Active,
    Stopping,
    Unconfirmed,
    Stopped,
    Rejected,
}

impl RunState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "PREPARING",
            Self::Waiting => "WAITING",
            Self::Active => "ACTIVE",
            Self::Stopping => "STOPPING",
            Self::Unconfirmed => "UNCONFIRMED",
            Self::Stopped => "STOPPED",
            Self::Rejected => "REJECTED",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "PREPARING" => Self::Preparing,
            "WAITING" => Self::Waiting,
            "ACTIVE" => Self::Active,
            "STOPPING" => Self::Stopping,
            "UNCONFIRMED" => Self::Unconfirmed,
            "STOPPED" => Self::Stopped,
            "REJECTED" => Self::Rejected,
            _ => return None,
        })
    }
    pub fn terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Rejected)
    }
    pub fn live(self) -> bool {
        matches!(self, Self::Preparing | Self::Waiting | Self::Active)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Operator,
    PolicyTrip,
    StartupTimeout,
    HeartbeatTimeout,
    ScopeMismatch,
    ReplicationMismatch,
    InventoryLost,
    DaemonLost,
    GuardLost,
    AuditFault,
    CapTrip,
    CapLost,
    ResourceLimit,
    RootExit,
    HostShutdown,
    Recovery,
    EgressFault,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "OPERATOR",
            Self::PolicyTrip => "POLICY_TRIP",
            Self::StartupTimeout => "STARTUP_TIMEOUT",
            Self::HeartbeatTimeout => "HEARTBEAT_TIMEOUT",
            Self::ScopeMismatch => "SCOPE_MISMATCH",
            Self::ReplicationMismatch => "REPLICATION_MISMATCH",
            Self::InventoryLost => "INVENTORY_LOST",
            Self::DaemonLost => "DAEMON_LOST",
            Self::GuardLost => "GUARD_LOST",
            Self::AuditFault => "AUDIT_FAULT",
            Self::CapTrip => "CAP_TRIP",
            Self::CapLost => "CAP_LOST",
            Self::ResourceLimit => "RESOURCE_LIMIT",
            Self::RootExit => "ROOT_EXIT",
            Self::HostShutdown => "HOST_SHUTDOWN",
            Self::Recovery => "RECOVERY",
            Self::EgressFault => "EGRESS_FAULT",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "OPERATOR" => Self::Operator,
            "POLICY_TRIP" => Self::PolicyTrip,
            "STARTUP_TIMEOUT" => Self::StartupTimeout,
            "HEARTBEAT_TIMEOUT" => Self::HeartbeatTimeout,
            "SCOPE_MISMATCH" => Self::ScopeMismatch,
            "REPLICATION_MISMATCH" => Self::ReplicationMismatch,
            "INVENTORY_LOST" => Self::InventoryLost,
            "DAEMON_LOST" => Self::DaemonLost,
            "GUARD_LOST" => self::Reason::GuardLost,
            "AUDIT_FAULT" => Self::AuditFault,
            "CAP_TRIP" => Self::CapTrip,
            "CAP_LOST" => Self::CapLost,
            "RESOURCE_LIMIT" => Self::ResourceLimit,
            "ROOT_EXIT" => Self::RootExit,
            "HOST_SHUTDOWN" => Self::HostShutdown,
            "RECOVERY" => Self::Recovery,
            "EGRESS_FAULT" => Self::EgressFault,
            _ => return None,
        })
    }
    /// CLI wait-path exit class (spec §6.1): true -> 10, root-exit handled
    /// separately, infrastructure -> 70.
    pub fn is_safety_stop(self) -> bool {
        matches!(
            self,
            Self::Operator
                | Self::PolicyTrip
                | Self::HostShutdown
                | Self::StartupTimeout
                | Self::HeartbeatTimeout
                | Self::ScopeMismatch
                | Self::ReplicationMismatch
                | Self::ResourceLimit
                | Self::CapTrip
        )
    }
    pub fn is_infra(self) -> bool {
        matches!(
            self,
            Self::InventoryLost
                | Self::DaemonLost
                | Self::GuardLost
                | Self::AuditFault
                | Self::CapLost
                | Self::Recovery
                | Self::EgressFault
        )
    }
}

/// Wire Call method names.
pub const METHODS: &[&str] = &[
    "host.get",
    "run.start",
    "run.get",
    "run.list",
    "run.stop",
    "agent.challenge",
    "agent.beat",
    "inventory.get",
    "events.read",
    "receipt.checkpoint",
    "certificate.get",
    "receipt.verify",
];

pub const AGENT_METHODS: &[&str] = &["agent.challenge", "agent.beat"];

pub fn method_kind(m: &str) -> Option<MethodKind> {
    match m {
        "agent.challenge" | "agent.beat" => Some(MethodKind::Agent),
        "receipt.verify" => Some(MethodKind::Offline),
        m if METHODS.contains(&m) => Some(MethodKind::Control),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    Control,
    Agent,
    Offline,
}

/// In-band API error.
#[derive(Debug, Clone)]
pub struct ApiErr {
    pub code: Code,
}

impl ApiErr {
    pub fn new(code: Code) -> Self {
        ApiErr { code }
    }
}

impl fmt::Display for ApiErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)
    }
}

impl std::error::Error for ApiErr {}

impl From<Code> for ApiErr {
    fn from(c: Code) -> Self {
        ApiErr { code: c }
    }
}

/// Typed head {seq, hash}.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
}

impl Head {
    pub fn to_value(&self) -> Value {
        Value::obj(vec![
            ("seq", Value::str(self.seq.to_string())),
            ("hash", Value::str(self.hash.clone())),
        ])
    }
}
