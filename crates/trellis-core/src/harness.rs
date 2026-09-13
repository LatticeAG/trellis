//! Deterministic conformance harness: Engine + ModelOs + GuardModel wired
//! with the §5.2 fixture identity (host trh_…1, boot trb_…1, key trk_…1,
//! run trr_…1, epoch 1, BOOTTIME 0, fixed wall clock). `timer` advances the
//! fake monotonic clock and runs one reducer boundary.

use crate::engine::{DeterministicIds, Engine, Surface};
use crate::fixtures::{self, Fixtures};
use crate::guard::GuardModel;
use crate::json::Value;
use crate::os::ModelOs;
use crate::schema::{host_config, HostConfig};
use crate::store::Store;
use crate::types::Reason;
use std::cell::RefCell;
use std::rc::Rc;

pub struct Harness {
    pub eng: Engine,
    pub os: Rc<RefCell<ModelOs>>,
    pub guard: Rc<RefCell<GuardModel>>,
    pub f: Fixtures,
}

/// The raw host-config value before schema validation.
pub fn fixture_config_value() -> Value {
    let f = fixtures::build();
    Value::obj(vec![
        ("v", Value::int(1)),
        ("host_id", f.get("H").clone()),
        ("control_socket", Value::str("/run/trellis/control.sock")),
        ("data_root", Value::str("/var/lib/trellis")),
        ("runtime_image", Value::str("/trellis/runtime.img")),
        (
            "workspace_roots",
            Value::Arr(vec![Value::str("/srv/trellis/work-a")]),
        ),
        ("task_uid_min", Value::int(63_000)),
        ("task_uid_max", Value::int(63_003)),
        ("max_runs", Value::int(4)),
        ("policy_pins", Value::Arr(vec![f.get("PIN").clone()])),
        ("log_key_id", f.get("K").clone()),
        (
            "guard",
            Value::obj(vec![
                ("renew_ms", Value::int(250)),
                ("lease_ms", Value::int(750)),
                ("stop_wait_ms", Value::int(2000)),
            ]),
        ),
        (
            "audit",
            Value::obj(vec![
                ("max_bytes_per_run", Value::str("67108864")),
                ("reserve_bytes", Value::str("1048576")),
                ("retention_days", Value::int(365)),
            ]),
        ),
        ("cap_adapter", Value::str("disabled")),
    ])
}

pub fn fixture_config() -> HostConfig {
    host_config(&fixture_config_value()).expect("fixture host config")
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    /// Engine freshly started and READY (startup() already ran).
    pub fn new() -> Self {
        Self::with_store(Store::memory().unwrap())
    }

    fn with_store(store: Store) -> Self {
        let f = fixtures::build();
        let cfg = fixture_config();
        let os = Rc::new(RefCell::new(ModelOs::new()));
        let guard = Rc::new(RefCell::new(GuardModel::new(os.clone())));
        let mut eng = Engine::new(
            cfg,
            store,
            os.clone(),
            guard.clone(),
            Box::new(DeterministicIds),
            f.kp.clone(),
            "kboot-fixture-1".into(),
        );
        eng.deterministic = true;
        eng.boot_id = fixtures::i("trb", 1);
        eng.log_key_id = fixtures::i("trk", 1);
        eng.now = 0;
        eng.wall = fixtures::wall_time().to_string();
        eng.startup();
        Harness { eng, os, guard, f }
    }

    pub fn rid(&self) -> String {
        fixtures::i("trr", 1)
    }

    /// A wire call: (surface, peer_uid, request_id, method, params).
    pub fn call(&mut self, surface: Surface, method: &str, params: Value, id: &str) -> Value {
        let raw = Value::obj(vec![
            ("v", Value::int(1)),
            ("id", Value::str(id)),
            ("method", Value::str(method)),
            ("params", params),
        ]);
        self.eng.call(surface, 0, raw)
    }

    pub fn control(&mut self, method: &str, params: Value, id: &str) -> Value {
        self.call(Surface::Control, method, params, id)
    }

    /// Agent-channel call bound to run R's fd-3 surface.
    pub fn agent(&mut self, method: &str, params: Value, id: &str) -> Value {
        self.eng.agent_channel_run = Some(self.rid());
        self.call(Surface::AgentFd3, method, params, id)
    }

    /// Start with the §5.2 StartInput; returns the raw response.
    pub fn start(&mut self, params: Value, id: &str) -> Value {
        self.control("run.start", params, id)
    }

    pub fn start_params(&self) -> Value {
        self.f.get("START").clone()
    }

    /// S0: RunCreated only -> PREPARING.
    pub fn s0(&mut self) -> Value {
        self.start(self.start_params(), &fixtures::i("trq", 1))
    }

    /// S1: E1+E2 -> WAITING, CH1 outstanding, INV observed.
    pub fn s1(&mut self) -> Value {
        let r = self.s0();
        assert!(
            r.get("ok") == Some(&Value::Bool(true)),
            "run.start: {}",
            r.canonical_string()
        );
        self.eng.launch_barrier(&self.rid());
        r
    }

    /// S2: + first beat at t=0 -> ACTIVE (E1..E4), CH2 outstanding.
    pub fn s2(&mut self) -> Value {
        self.s1();
        self.agent(
            "agent.beat",
            self.f.get("BEAT").clone(),
            &fixtures::i("trq", 1),
        )
    }

    /// S9: + operator stop -> STOPPED (E1..E9).
    pub fn s9(&mut self) -> Value {
        self.s2();
        self.control(
            "run.stop",
            Value::obj(vec![
                ("run_id", Value::str(self.rid())),
                ("reason", Value::str("OPERATOR")),
                ("note_hash", Value::Null),
            ]),
            &fixtures::i("trq", 2),
        )
    }

    /// SR: E1 + RunRejected(EGRESS_FAULT) -> REJECTED.
    pub fn sr(&mut self) -> Value {
        let r = self.s0();
        self.os.borrow_mut().barrier_fail = Some(crate::os::OsErr::new(
            crate::types::Code::EgressFault,
            "egress attach failed",
        ));
        self.eng.launch_barrier(&self.rid());
        r
    }

    /// N2: S2 under the alternate signed policy PB (allow 93.184.216.34:443).
    pub fn n2(&mut self) -> Value {
        let start = self.f.get("START_N2").clone();
        let r = self.control("run.start", start, &fixtures::i("trq", 1));
        assert!(
            r.get("ok") == Some(&Value::Bool(true)),
            "N2 start: {}",
            r.canonical_string()
        );
        self.eng.launch_barrier(&self.rid());
        self.agent(
            "agent.beat",
            self.f.get("BEAT_N2").clone(),
            &fixtures::i("trq", 1),
        )
    }

    /// Advance the fake monotonic clock to `ns` and run one boundary.
    pub fn timer(&mut self, ns: u64) {
        self.eng.now = ns;
        self.eng.boundary();
    }

    /// Step the clock in `step` increments through `target`, boundary each.
    pub fn tick_to(&mut self, target: u64, step: u64) {
        while self.eng.now < target {
            self.eng.now = (self.eng.now + step).min(target);
            self.eng.boundary();
        }
    }

    /// Crash and restart the daemon on the same store (kernel state survives:
    /// the same ModelOs; a fresh guard process denies everything by default).
    pub fn reboot(&mut self) {
        let store = std::mem::replace(&mut self.eng.store, Store::memory().unwrap());
        let os = self.os.clone();
        let guard = Rc::new(RefCell::new(GuardModel::new(os.clone())));
        let cfg = fixture_config();
        let mut eng = Engine::new(
            cfg,
            store,
            os,
            guard.clone(),
            Box::new(DeterministicIds),
            self.f.kp.clone(),
            "kboot-fixture-1".into(),
        );
        eng.deterministic = true;
        eng.boot_seq = 2;
        eng.boot_id = fixtures::i("trb", 2);
        eng.log_key_id = fixtures::i("trk", 1);
        eng.now = self.eng.now;
        eng.wall = fixtures::wall_time().to_string();
        eng.startup();
        self.eng = eng;
        self.guard = guard;
    }

    /// The current run view fields of interest.
    pub fn view(&mut self) -> Value {
        let r = self.control(
            "run.get",
            Value::obj(vec![("run_id", Value::str(self.rid()))]),
            &fixtures::i("trq", 99),
        );
        r.get("result").cloned().unwrap_or(Value::Null)
    }

    pub fn reason(&mut self) -> Option<Reason> {
        self.view()
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .and_then(Reason::parse)
    }

    pub fn state(&mut self) -> String {
        self.view()
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }
}

/// Deep-replace a JSON path (dot segments + [n] array indices) in a clone.
pub fn mutate(v: &Value, path: &str, new: Value) -> Value {
    let mut out = v.clone();
    let mut cur = &mut out;
    let segs: Vec<String> = path
        .split(['.', '['])
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches(']').to_string())
        .collect();
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        cur = match cur {
            Value::Obj(m) => m.get_mut(seg).unwrap(),
            Value::Arr(a) => {
                let idx: usize = seg.parse().unwrap();
                &mut a[idx]
            }
            _ => panic!("mutate: not a container at {}", seg),
        };
        if last {
            *cur = new.clone();
        }
    }
    out
}
