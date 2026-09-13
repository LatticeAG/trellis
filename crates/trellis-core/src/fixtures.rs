//! The §5.2 fixture set: deterministic keys, IDs, signed policy, events,
//! checkpoints, certificate, and bundles — used by tests and the conformance
//! harness. The RFC 8032 seed is deliberately public and must never be used
//! for deployment or trusted production pins.

use crate::crypto::*;
use crate::json::Value;
use crate::scalars::b64url_encode;
use std::collections::BTreeMap;

pub const FIXTURE_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

pub fn i(prefix: &str, n: u64) -> String {
    format!("{}_{:021}", prefix, n)
}

pub fn wall_time() -> &'static str {
    "2026-09-12T00:00:00.000Z"
}

/// All fixture values, keyed exactly like the §5.2 `F` map.
pub struct Fixtures {
    pub map: BTreeMap<String, Value>,
    pub kp: Keypair,
    pub policy_body: Value,
    pub events: Vec<Value>, // E1..=E9
}

impl Fixtures {
    pub fn get(&self, name: &str) -> &Value {
        &self.map[name]
    }
    pub fn event(&self, n: usize) -> &Value {
        &self.events[n - 1]
    }
}

/// Deterministic nonce for fixture challenge seq n: B64(bytes([n-1])*32).
/// Sign a policy body with the fixture key, producing the {body,key_id,sig}
/// signed-policy envelope used on the wire.
pub fn sign_policy(body: &Value) -> Value {
    let kp = Keypair::from_seed(&FIXTURE_SEED);
    let ph = domain_hash(D_POLICY, body);
    Value::obj(vec![
        ("body", body.clone()),
        ("key_id", Value::str(i("trk", 1))),
        (
            "sig",
            Value::str(kp.sign_domain(D_POLICY_SIGN, &ph).unwrap()),
        ),
    ])
}

pub fn fixture_nonce(seq: u64) -> String {
    b64url_encode(&[(seq - 1) as u8; 32])
}

pub fn build() -> Fixtures {
    let kp = Keypair::from_seed(&FIXTURE_SEED);
    let mut f: BTreeMap<String, Value> = BTreeMap::new();

    f.insert("R".into(), Value::str(i("trr", 1)));
    f.insert("A".into(), Value::str(i("tra", 1)));
    f.insert("H".into(), Value::str(i("trh", 1)));
    f.insert("B".into(), Value::str(i("trb", 1)));
    f.insert("Q".into(), Value::str(i("trq", 1)));
    f.insert("K".into(), Value::str(i("trk", 1)));
    f.insert("Z".into(), Value::str(crate::scalars::ZERO_HASH));
    f.insert("PUB".into(), Value::str(kp.public_b64()));

    let ex = Value::obj(vec![
        (
            "argv",
            Value::Arr(vec![
                Value::str("/usr/bin/python3"),
                Value::str("/work/agent.py"),
            ]),
        ),
        ("cwd", Value::str("/work")),
        ("env", Value::obj(vec![("LANG", Value::str("C.UTF-8"))])),
    ]);
    f.insert("EX".into(), ex.clone());

    let image_sha = sha256_hex(b"trellis-runtime-fixture");
    let pb = Value::obj(vec![
        ("v", Value::int(1)),
        ("kind", Value::str("trellis-policy")),
        ("policy_id", Value::str(i("trp", 1))),
        ("revision", Value::str("1")),
        ("agent_id", Value::str(i("tra", 1))),
        ("image_sha256", Value::str(image_sha)),
        ("exec_hash", Value::str(domain_hash(D_EXEC, &ex))),
        (
            "heartbeat",
            Value::obj(vec![
                ("interval_ms", Value::int(1000)),
                ("timeout_ms", Value::int(3000)),
                ("startup_ms", Value::int(5000)),
            ]),
        ),
        (
            "replication",
            Value::obj(vec![
                ("profile", Value::str("single-process")),
                ("max_threads", Value::int(64)),
                ("scan_ms", Value::int(100)),
            ]),
        ),
        (
            "egress",
            Value::obj(vec![
                ("profile", Value::str("ipv4-tcp-static")),
                ("allow", Value::Arr(vec![])),
            ]),
        ),
        (
            "resources",
            Value::obj(vec![
                ("memory_bytes", Value::str("536870912")),
                ("cpu_quota_us", Value::int(50000)),
                ("cpu_period_us", Value::int(100000)),
            ]),
        ),
        ("cap", Value::obj(vec![("mode", Value::str("none"))])),
        ("operator_ref", Value::str("operator-local")),
    ]);
    let ph = domain_hash(D_POLICY, &pb);
    f.insert("PH".into(), Value::str(ph.clone()));
    let psig = kp.sign_domain(D_POLICY_SIGN, &ph).unwrap();
    let p = Value::obj(vec![
        ("body", pb.clone()),
        ("key_id", Value::str(i("trk", 1))),
        ("sig", Value::str(psig)),
    ]);
    f.insert("P".into(), p);
    f.insert(
        "PIN".into(),
        Value::obj(vec![
            ("key_id", Value::str(i("trk", 1))),
            ("public_key", Value::str(kp.public_b64())),
        ]),
    );

    // Event/checkpoint builders mirroring §5.2.
    let mk_event = |n: u64, kind: &str, data: Value, prev: &str, ns: &str, human: bool| -> Value {
        let body = Value::obj(vec![
            ("v", Value::int(1)),
            ("host_id", Value::str(i("trh", 1))),
            ("run_id", Value::str(i("trr", 1))),
            ("boot_id", Value::str(i("trb", 1))),
            ("event_id", Value::str(i("tre", n))),
            ("key_id", Value::str(i("trk", 1))),
            ("seq", Value::str(n.to_string())),
            ("prev_hash", Value::str(prev)),
            ("mono_ns", Value::str(ns)),
            ("wall_time", Value::str(wall_time())),
            ("policy_hash", Value::str(ph.clone())),
            (
                "actor",
                Value::obj(vec![
                    (
                        "kind",
                        Value::str(if human { "operator" } else { "daemon" }),
                    ),
                    ("uid", Value::int(0)),
                ]),
            ),
            (
                "art",
                Value::obj(vec![
                    ("operator_ref", Value::str("operator-local")),
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
        let h = domain_hash(D_EVENT, &body);
        let sig = kp.sign_domain(D_EVENT_SIGN, &h).unwrap();
        Value::obj(vec![
            ("body", body),
            ("hash", Value::str(h)),
            ("sig", Value::str(sig)),
        ])
    };
    let mk_checkpoint = |n: u64, entry: &Value, state: &str| -> Value {
        let body = Value::obj(vec![
            ("v", Value::int(1)),
            ("checkpoint_id", Value::str(i("trn", n))),
            ("host_id", Value::str(i("trh", 1))),
            ("run_id", Value::str(i("trr", 1))),
            ("key_id", Value::str(i("trk", 1))),
            (
                "head",
                Value::obj(vec![
                    (
                        "seq",
                        entry.get("body").unwrap().get("seq").unwrap().clone(),
                    ),
                    ("hash", entry.get("hash").unwrap().clone()),
                ]),
            ),
            ("state", Value::str(state)),
            ("audit", Value::str("COMPLETE_PREFIX")),
            ("wall_time", Value::str(wall_time())),
        ]);
        let h = domain_hash(D_CHECKPOINT, &body);
        let sig = kp.sign_domain(D_CHECKPOINT_SIGN, &h).unwrap();
        Value::obj(vec![
            ("body", body),
            ("hash", Value::str(h)),
            ("sig", Value::str(sig)),
        ])
    };

    let e1 = mk_event(
        1,
        "RunCreated",
        Value::obj(vec![
            ("agent_id", Value::str(i("tra", 1))),
            ("policy_hash", Value::str(ph.clone())),
            ("exec_hash", pb.get("exec_hash").unwrap().clone()),
            ("task_ref", Value::Null),
            ("host_epoch", Value::str("1")),
        ]),
        &"0".repeat(64),
        "0",
        true,
    );
    f.insert("E1".into(), e1.clone());
    f.insert(
        "H1".into(),
        Value::obj(vec![
            ("seq", Value::str("1")),
            ("hash", e1.get("hash").unwrap().clone()),
        ]),
    );
    let cp1 = mk_checkpoint(1, &e1, "PREPARING");
    f.insert("CP1".into(), cp1.clone());

    let inv = Value::obj(vec![
        ("sampled_ns", Value::str("0")),
        (
            "root",
            Value::obj(vec![
                ("pid", Value::int(4200)),
                ("start_ticks", Value::str("100")),
                ("cgroup_inode", Value::str("500")),
                ("uid", Value::int(63000)),
            ]),
        ),
        ("tgids", Value::Arr(vec![Value::int(4200)])),
        ("threads", Value::int(1)),
        ("matches", Value::Bool(true)),
        ("coverage", Value::str("local-cgroup-single-process")),
    ]);
    f.insert("INV".into(), inv);

    let ch1 = Value::obj(vec![
        ("run_id", Value::str(i("trr", 1))),
        ("boot_id", Value::str(i("trb", 1))),
        ("challenge_id", Value::str(i("trc", 1))),
        ("seq", Value::str("1")),
        ("nonce", Value::str(b64url_encode(&[0u8; 32]))),
        ("policy_hash", Value::str(ph.clone())),
        ("expires_ns", Value::str("5000000000")),
    ]);
    f.insert("CH1".into(), ch1.clone());
    let mut ch2 = ch1.clone();
    if let Value::Obj(m) = &mut ch2 {
        m.insert("challenge_id".into(), Value::str(i("trc", 2)));
        m.insert("seq".into(), Value::str("2"));
        m.insert("nonce".into(), Value::str(b64url_encode(&[1u8; 32])));
        m.insert("expires_ns".into(), Value::str("3000000000"));
    }
    f.insert("CH2".into(), ch2);

    let mut beat = Value::obj(vec![]);
    if let (Value::Obj(b), Value::Obj(c)) = (&mut beat, &ch1) {
        for (k, v) in c {
            if k != "expires_ns" {
                b.insert(k.clone(), v.clone());
            }
        }
        b.insert("scope_ok".into(), Value::Bool(true));
        b.insert("claimed_processes".into(), Value::int(1));
        b.insert("progress".into(), Value::str("0"));
    }
    f.insert("BEAT".into(), beat);

    f.insert(
        "BUNDLE1".into(),
        Value::obj(vec![
            ("v", Value::int(1)),
            ("format", Value::str("trellis-bundle/1")),
            ("policy", f["P"].clone()),
            ("entries", Value::Arr(vec![e1.clone()])),
            ("checkpoint", cp1.clone()),
            ("certificate", Value::Null),
        ]),
    );
    f.insert(
        "VIEW1".into(),
        Value::obj(vec![
            ("run_id", Value::str(i("trr", 1))),
            ("agent_id", Value::str(i("tra", 1))),
            ("boot_id", Value::str(i("trb", 1))),
            ("state", Value::str("PREPARING")),
            ("policy_hash", Value::str(ph.clone())),
            ("last_beat_seq", Value::str("0")),
            ("deadline_ns", Value::Null),
            ("gate", Value::str("CLOSED")),
            ("stop_reason", Value::Null),
            ("empty_observed", Value::Bool(false)),
            ("root_exit", Value::Null),
            ("inventory", Value::Null),
            ("head", f["H1"].clone()),
            ("audit", Value::str("COMPLETE_PREFIX")),
            ("cap", Value::str("NONE")),
        ]),
    );

    let root_id = f["INV"].get("root").unwrap().clone();
    let e2 = mk_event(
        2,
        "RunArmed",
        Value::obj(vec![
            ("root", root_id),
            ("startup_deadline_ns", Value::str("5000000000")),
        ]),
        e1.get("hash").unwrap().as_str().unwrap(),
        "0",
        false,
    );
    let e3 = mk_event(
        3,
        "HeartbeatAccepted",
        Value::obj(vec![
            ("beat_seq", Value::str("1")),
            ("challenge_id", Value::str(i("trc", 1))),
            ("deadline_ns", Value::str("3000000000")),
            ("progress", Value::str("0")),
        ]),
        e2.get("hash").unwrap().as_str().unwrap(),
        "0",
        false,
    );
    let e4 = mk_event(
        4,
        "GateGranted",
        Value::obj(vec![
            ("beat_seq", Value::str("1")),
            ("deadline_ns", Value::str("3000000000")),
            ("guard_generation", Value::str("1")),
        ]),
        e3.get("hash").unwrap().as_str().unwrap(),
        "0",
        false,
    );
    let e5 = mk_event(
        5,
        "StopLatched",
        Value::obj(vec![
            ("reason", Value::str("OPERATOR")),
            ("note_hash", Value::Null),
        ]),
        e4.get("hash").unwrap().as_str().unwrap(),
        "0",
        true,
    );
    let e6 = mk_event(
        6,
        "GateClosed",
        Value::obj(vec![
            ("guard_generation", Value::str("1")),
            ("confirmed_ns", Value::str("0")),
        ]),
        e5.get("hash").unwrap().as_str().unwrap(),
        "0",
        false,
    );
    let e7 = mk_event(
        7,
        "KillIssued",
        Value::obj(vec![
            ("cgroup_attempted", Value::Bool(true)),
            ("pidfd_attempted", Value::Bool(true)),
        ]),
        e6.get("hash").unwrap().as_str().unwrap(),
        "0",
        false,
    );
    let e8 = mk_event(
        8,
        "ContainmentEmpty",
        Value::obj(vec![
            (
                "root_exit",
                Value::obj(vec![("code", Value::Null), ("signal", Value::int(9))]),
            ),
            ("observed_ns", Value::str("0")),
        ]),
        e7.get("hash").unwrap().as_str().unwrap(),
        "0",
        false,
    );
    let e9 = mk_event(
        9,
        "RunStopped",
        Value::obj(vec![
            ("first_reason", Value::str("OPERATOR")),
            ("gate_closed", Value::Bool(true)),
            ("empty_observed", Value::Bool(true)),
            ("evidence_gap", Value::Bool(false)),
        ]),
        e8.get("hash").unwrap().as_str().unwrap(),
        "0",
        false,
    );
    for (n, e) in [
        e1.clone(),
        e2.clone(),
        e3.clone(),
        e4.clone(),
        e5.clone(),
        e6.clone(),
        e7.clone(),
        e8.clone(),
        e9.clone(),
    ]
    .iter()
    .enumerate()
    {
        f.insert(format!("E{}", n + 1), e.clone());
    }
    let events = vec![e1, e2, e3, e4, e5, e6, e7, e8, e9];

    let cp9 = mk_checkpoint(9, &events[8], "STOPPED");
    f.insert("CP9".into(), cp9.clone());

    let kb = Value::obj(vec![
        ("v", Value::int(1)),
        ("host_id", Value::str(i("trh", 1))),
        ("run_id", Value::str(i("trr", 1))),
        ("key_id", Value::str(i("trk", 1))),
        ("policy_hash", Value::str(ph)),
        (
            "stopped_event",
            cp9.get("body").unwrap().get("head").unwrap().clone(),
        ),
        ("stop_reason", Value::str("OPERATOR")),
        ("gate_closed", Value::Bool(true)),
        ("empty_observed", Value::Bool(true)),
        ("evidence", Value::str("local-software-observation")),
        ("external_effects", Value::str("NOT_REVERSED")),
        ("remote_replication", Value::str("NOT_ATTESTED")),
    ]);
    let kh = domain_hash(D_KILL, &kb);
    let ksig = kp.sign_domain(D_KILL_SIGN, &kh).unwrap();
    let cert = Value::obj(vec![
        ("body", kb),
        ("hash", Value::str(kh)),
        ("sig", Value::str(ksig)),
    ]);
    f.insert("CERT".into(), cert);
    f.insert(
        "BUNDLE9".into(),
        Value::obj(vec![
            ("v", Value::int(1)),
            ("format", Value::str("trellis-bundle/1")),
            ("policy", f["P"].clone()),
            ("entries", Value::Arr(events.clone())),
            ("checkpoint", cp9),
            ("certificate", f["CERT"].clone()),
        ]),
    );
    f.insert("E3_HASH".into(), events[2].get("hash").unwrap().clone());
    f.insert("E9_HASH".into(), events[8].get("hash").unwrap().clone());

    // Canonical StartInput used by the harness (spec §5.2 example).
    f.insert(
        "START".into(),
        Value::obj(vec![
            ("policy", f["P"].clone()),
            ("exec", ex.clone()),
            ("workspace_root", Value::str("/srv/trellis/work-a")),
            ("task_ref", Value::Null),
            ("expected_host_epoch", Value::str("1")),
        ]),
    );

    // N2 policy: same body with a one-entry egress allowlist; all dependent
    // hashes are recomputed and the variant is freshly signed.
    let mut pb2 = pb.clone();
    if let Value::Obj(m) = &mut pb2 {
        m.insert(
            "egress".into(),
            Value::obj(vec![
                ("profile", Value::str("ipv4-tcp-static")),
                (
                    "allow",
                    Value::Arr(vec![Value::obj(vec![
                        ("ipv4", Value::str("93.184.216.34")),
                        ("port", Value::int(443)),
                    ])]),
                ),
            ]),
        );
    }
    let ph2 = domain_hash(D_POLICY, &pb2);
    f.insert("PH_N2".into(), Value::str(ph2.clone()));
    let p2 = Value::obj(vec![
        ("body", pb2.clone()),
        ("key_id", Value::str(i("trk", 1))),
        (
            "sig",
            Value::str(kp.sign_domain(D_POLICY_SIGN, &ph2).unwrap()),
        ),
    ]);
    f.insert("P_N2".into(), p2.clone());
    f.insert(
        "START_N2".into(),
        Value::obj(vec![
            ("policy", p2),
            ("exec", ex.clone()),
            ("workspace_root", Value::str("/srv/trellis/work-a")),
            ("task_ref", Value::Null),
            ("expected_host_epoch", Value::str("1")),
        ]),
    );
    f.insert(
        "BEAT_N2".into(),
        Value::obj(vec![
            ("run_id", Value::str(i("trr", 1))),
            ("boot_id", Value::str(i("trb", 1))),
            ("challenge_id", Value::str(i("trc", 1))),
            ("seq", Value::str("1")),
            ("nonce", Value::str(b64url_encode(&[0u8; 32]))),
            ("policy_hash", Value::str(ph2)),
            ("scope_ok", Value::Bool(true)),
            ("claimed_processes", Value::int(1)),
            ("progress", Value::str("0")),
        ]),
    );

    Fixtures {
        map: f,
        kp,
        policy_body: pb,
        events,
    }
}
