//! trellis-conformance: the TV-T--01..81 vector suite.
//!   --profile offline-v1                protocol/model/verifier vectors
//!   --profile linux-single-process-v1   + kernel-enforcement vectors
//!   --vectors all | TV-T--NN[,NN..]     subset selection
//! Prints a JSON report: per-vector pass/fail/unsupported + totals.

use std::os::unix::io::AsRawFd;
use trellis_core::crypto::*;
use trellis_core::engine::{Engine, Surface};
use trellis_core::frame;
use trellis_core::gate::{self, Verdict};
use trellis_core::harness::{fixture_config, fixture_config_value, mutate, Harness};
use trellis_core::json::{self, Value};
use trellis_core::os::Os as _;
use trellis_core::scalars::*;
use trellis_core::schema;
use trellis_core::seccomp::{self, Decision};
use trellis_core::store::Store;
use trellis_core::types::*;
use trellis_core::verify::{self, Completeness, VerifyInput};

type R = Result<(), String>;

fn ok() -> R {
    Ok(())
}
fn fail(m: impl Into<String>) -> R {
    Err(m.into())
}

/// Expect an ERR envelope with code.
fn expect_err(resp: &Value, code: Code) -> R {
    match resp.get("ok") {
        Some(Value::Bool(false)) => {}
        _ => {
            return fail(format!(
                "expected ERR({}), got {}",
                code,
                resp.canonical_string()
            ))
        }
    }
    let got = resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or("");
    if got != code.as_str() {
        return fail(format!("expected ERR({}), got ERR({})", code, got));
    }
    ok()
}

fn expect_ok(resp: &Value) -> Result<&Value, String> {
    match resp.get("ok") {
        Some(Value::Bool(true)) => Ok(resp.get("result").unwrap()),
        _ => Err(format!("expected OK, got {}", resp.canonical_string())),
    }
}

fn b64(n: u8) -> Value {
    Value::str(b64url_encode(&[n; 32]))
}

/// CH2-based beat (the outstanding challenge in S2).
fn beat2(f: &trellis_core::fixtures::Fixtures) -> Value {
    let ch2 = f.get("CH2");
    let mut b = json::Value::Obj(Default::default());
    if let (Value::Obj(bm), Value::Obj(c)) = (&mut b, ch2) {
        for (k, v) in c {
            if k != "expires_ns" {
                bm.insert(k.clone(), v.clone());
            }
        }
        bm.insert("scope_ok".into(), Value::Bool(true));
        bm.insert("claimed_processes".into(), Value::int(1));
        bm.insert("progress".into(), Value::str("0"));
    }
    b
}

fn pin(f: &trellis_core::fixtures::Fixtures) -> schema::Pin {
    schema::pin(f.get("PIN")).unwrap()
}

fn verify_bundle(
    bundle: &Value,
    expected: Option<Head>,
    require_terminal: bool,
) -> Result<verify::VerifyResult, ApiErr> {
    let f = trellis_core::fixtures::build();
    let p = pin(&f);
    verify::verify(&VerifyInput {
        bundle,
        log_pins: std::slice::from_ref(&p),
        policy_pins: std::slice::from_ref(&p),
        expected_head: expected,
        require_terminal,
    })
}

fn head_of(f: &trellis_core::fixtures::Fixtures, name: &str) -> Head {
    // dotted path: first segment indexes the fixture map, rest navigate Value
    let mut segs = name.split('.');
    let mut v = f.get(segs.next().unwrap()).clone();
    for s in segs {
        v = v.get(s).cloned().unwrap_or(Value::Null);
    }
    schema::head(&v).unwrap()
}

fn beats(h: &Harness) -> u64 {
    h.eng.runs.get(&h.rid()).map(|r| r.beats).unwrap_or(0)
}

// ===========================================================================
// The vectors
// ===========================================================================

fn tv01(_: &mut ()) -> R {
    let out = json::canonicalize(br#"{"b":2,"a":"1"}"#).map_err(|e| e.to_string())?;
    if out != br#"{"a":"1","b":2}"# {
        return fail("canonical bytes wrong");
    }
    ok()
}

fn tv02(_: &mut ()) -> R {
    match json::parse(br#"{"v":1,"v":1}"#) {
        Err(json::JsonError::DuplicateKey(_)) => ok(),
        e => fail(format!("expected DuplicateKey, got {:?}", e)),
    }
}

fn tv03(_: &mut ()) -> R {
    match json::parse(br#"{"v":1,"x":-0}"#) {
        Err(json::JsonError::NonSafeNumber) => ok(),
        e => fail(format!("expected NonSafeNumber, got {:?}", e)),
    }
}

fn tv04(_: &mut ()) -> R {
    for s in ["00", "9223372036854775808", "1e3"] {
        if parse_u(s).is_some() || is_u(s) {
            return fail(format!("U {:?} accepted", s));
        }
    }
    ok()
}

fn tv05(_: &mut ()) -> R {
    let mut h = Harness::new();
    let r = h.control(
        "host.get",
        Value::obj(vec![("allow_all", Value::Bool(true))]),
        &trellis_core::fixtures::i("trq", 9),
    );
    expect_err(&r, Code::UnknownField)
}

fn tv06(_: &mut ()) -> R {
    if is_id("trr_00000000000000000001", "trr") {
        return fail("20-char suffix accepted");
    }
    ok()
}

fn tv07(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    let e1 = f.get("E1");
    let h = e1.get("hash").and_then(|v| v.as_str()).unwrap_or("");
    if h != "020e6617d991d4d049d2ecd76a588ce320d2eec119977b73b4bb8a6273a6a82b" {
        return fail(format!("E1 hash {} != anchor", h));
    }
    let sig = e1.get("sig").and_then(|v| v.as_str()).unwrap_or("");
    if sig
        != "YHG2BztLMbjEXHvq8my2G-0CKpN5vQdOppeKsOfy03IQKFg6joYWhMPZjB5vytrvD-GLw52v6_Xq4orLrLgBDA"
    {
        return fail(format!("E1 sig {} != anchor", sig));
    }
    ok()
}

fn tv08(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    let e1 = f.get("E1");
    let h = e1.get("hash").and_then(|v| v.as_str()).unwrap();
    let sig = e1.get("sig").and_then(|v| v.as_str()).unwrap();
    let pubkey = f.kp.public_b64();
    if !verify_domain(D_EVENT_SIGN, h, &pubkey, sig) {
        return fail("E1 signature did not verify");
    }
    if verify_domain(D_KILL_SIGN, h, &pubkey, sig) {
        return fail("domain separation failed: sig verified under KILL");
    }
    ok()
}

fn tv09(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    let b = mutate(
        f.get("BUNDLE1"),
        "entries[0].body.data.host_epoch",
        Value::str("2"),
    );
    match verify_bundle(&b, Some(head_of(&f, "H1")), false) {
        Err(e) if e.code == Code::HashMismatch => ok(),
        e => fail(format!("expected HASH_MISMATCH, got {:?}", e.map(|_| ()))),
    }
}

fn tv10(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    let p = pin(&f);
    match verify::verify(&VerifyInput {
        bundle: f.get("BUNDLE1"),
        log_pins: &[],
        policy_pins: &[p],
        expected_head: Some(head_of(&f, "H1")),
        require_terminal: false,
    }) {
        Err(e) if e.code == Code::UntrustedKey => ok(),
        e => fail(format!("expected UNTRUSTED_KEY, got {:?}", e.map(|_| ()))),
    }
}

fn tv11(_: &mut ()) -> R {
    let mut h = Harness::new();
    // policy body timeout_ms 3000->4000, sig retained
    let p = mutate(h.f.get("P"), "body.heartbeat.timeout_ms", Value::int(4000));
    let start = mutate(&h.start_params(), "policy", p);
    let r = h.start(start, &trellis_core::fixtures::i("trq", 1));
    expect_err(&r, Code::SignatureInvalid)?;
    if !h.eng.runs.is_empty() {
        return fail("run created");
    }
    ok()
}

fn tv12(_: &mut ()) -> R {
    let a = json::canonicalize("{\"x\":\"é\"}".as_bytes()).unwrap();
    let b = json::canonicalize("{\"x\":\"e\u{301}\"}".as_bytes()).unwrap();
    if a == b {
        return fail("canon normalized unicode");
    }
    if sha256(&a) == sha256(&b) {
        return fail("same sha256");
    }
    ok()
}

fn tv13(_: &mut ()) -> R {
    let mut h = Harness::new();
    let raw = Value::obj(vec![
        ("v", Value::int(2)),
        ("id", f_id_val()),
        ("method", Value::str("host.get")),
        ("params", Value::obj(vec![])),
    ]);
    let r = h.eng.call(Surface::Control, 0, raw);
    expect_err(&r, Code::UnsupportedVersion)
}

fn f_id_val() -> Value {
    Value::str(trellis_core::fixtures::i("trq", 1))
}

fn tv14(_: &mut ()) -> R {
    let mut buf: &[u8] = &65537u32.to_be_bytes();
    match frame::read_frame(&mut buf, frame::REQ_MAX) {
        Err(e) if e.code == Code::InvalidInput => ok(),
        e => fail(format!("expected INVALID_INPUT, got {:?}", e.map(|_| ()))),
    }
}

fn tv15(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let c1 = h.agent(
        "agent.challenge",
        Value::obj(vec![]),
        &trellis_core::fixtures::i("trq", 10),
    );
    let c2 = h.agent(
        "agent.challenge",
        Value::obj(vec![]),
        &trellis_core::fixtures::i("trq", 11),
    );
    let ch1 = h.f.get("CH1").clone();
    if expect_ok(&c1)? != &ch1 || expect_ok(&c2)? != &ch1 {
        return fail(format!(
            "challenge mismatch {} {}",
            c1.canonical_string(),
            c2.canonical_string()
        ));
    }
    ok()
}

fn tv16(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let r = h.agent(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 1),
    );
    let res = expect_ok(&r)?.clone();
    if res.get("accepted") != Some(&Value::Bool(true))
        || res.get("seq") != Some(&Value::str("1"))
        || res.get("deadline_ns") != Some(&Value::str("3000000000"))
        || res.get("next") != Some(h.f.get("CH2"))
    {
        return fail(format!("bad beat result {}", res.canonical_string()));
    }
    if h.state() != "ACTIVE" {
        return fail(format!("state {}", h.state()));
    }
    ok()
}

fn tv17(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    let beat = h.f.get("BEAT").clone();
    let id = trellis_core::fixtures::i("trq", 1);
    h.timer(100_000_000);
    let r1 = h.agent("agent.beat", beat.clone(), &id);
    let r2 = h.agent("agent.beat", beat, &id);
    if r1.canonical_string() != r2.canonical_string() {
        return fail("cached response not byte-identical");
    }
    if beats(&h) != 1 {
        return fail(format!("beats {}", beats(&h)));
    }
    let v = h.view();
    if v.get("deadline_ns") != Some(&Value::str("3000000000")) {
        return fail("deadline moved");
    }
    ok()
}

fn tv18(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    let r = h.agent(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 2),
    );
    expect_err(&r, Code::ChallengeUsed)
}

fn tv19(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    let bad = mutate(h.f.get("BEAT"), "progress", Value::str("1"));
    let r = h.agent("agent.beat", bad, &trellis_core::fixtures::i("trq", 1));
    expect_err(&r, Code::Conflict)?;
    if beats(&h) != 1 {
        return fail("beat count moved");
    }
    ok()
}

fn tv20(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let bad = mutate(
        h.f.get("BEAT"),
        "run_id",
        Value::str(trellis_core::fixtures::i("trr", 2)),
    );
    let r = h.agent("agent.beat", bad, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ChallengeInvalid)?;
    if h.state() != "WAITING" {
        return fail("state moved");
    }
    ok()
}

fn tv21(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let bad = mutate(
        h.f.get("BEAT"),
        "boot_id",
        Value::str(trellis_core::fixtures::i("trb", 2)),
    );
    let r = h.agent("agent.beat", bad, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ChallengeInvalid)
}

fn tv22(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let bad = mutate(h.f.get("BEAT"), "nonce", b64(2));
    let r = h.agent("agent.beat", bad, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ChallengeInvalid)
}

fn tv23(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let bad = mutate(h.f.get("BEAT"), "scope_ok", Value::Bool(false));
    let r = h.agent("agent.beat", bad, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ScopeMismatch)?;
    if h.reason() != Some(Reason::ScopeMismatch) {
        return fail(format!("reason {:?}", h.reason()));
    }
    if h.view().get("gate") != Some(&Value::str("CLOSED")) {
        return fail("gate not closed");
    }
    ok()
}

fn tv24(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let bad = mutate(h.f.get("BEAT"), "policy_hash", Value::str(ZERO_HASH));
    let r = h.agent("agent.beat", bad, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ScopeMismatch)
}

fn tv25(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let bad = mutate(h.f.get("BEAT"), "claimed_processes", Value::int(2));
    let r = h.agent("agent.beat", bad, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ScopeMismatch)
}

fn tv26(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    // health renewals every 250 ms through 4.75 s, then expiry at 5 s
    h.tick_to(4_750_000_000, 250_000_000);
    h.timer(5_000_000_000);
    let r = h.agent(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 2),
    );
    expect_err(&r, Code::Stopped)?;
    if h.reason() != Some(Reason::StartupTimeout) {
        return fail(format!("reason {:?}", h.reason()));
    }
    ok()
}

fn tv27(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    h.tick_to(2_500_000_000, 500_000_000);
    h.timer(3_000_000_000);
    let b = beat2(&h.f);
    let r = h.agent("agent.beat", b, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::Stopped)?;
    if h.reason() != Some(Reason::HeartbeatTimeout) {
        return fail(format!("reason {:?}", h.reason()));
    }
    if h.view().get("gate") != Some(&Value::str("CLOSED")) {
        return fail("gate not closed");
    }
    ok()
}

fn tv28(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    h.eng.wall = "2020-01-01T00:00:00.000Z".into();
    h.eng.suppress_renewals = true;
    h.timer(750_000_000);
    if h.reason() != Some(Reason::DaemonLost) {
        return fail(format!("reason {:?}", h.reason()));
    }
    if h.view().get("gate") != Some(&Value::str("CLOSED")) {
        return fail("gate not closed");
    }
    ok()
}

fn tv29(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.n2();
    // daemon + guard frozen: the kernel lease still expires on its own
    h.guard.borrow_mut().frozen = true;
    let pkt = gate::test_packet(0x5DB8_D822, 443, true, 5, false);
    let mut os = h.os.borrow_mut();
    let g = os.gate(&h.rid()).unwrap();
    match g.check_packet(750_000_000, &pkt) {
        Verdict::Drop(_) => ok(),
        Verdict::Accept => fail("packet accepted after lease expiry"),
    }
}

fn tv30(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let stop = Value::obj(vec![
        ("v", Value::int(1)),
        ("id", Value::str(trellis_core::fixtures::i("trq", 90))),
        ("method", Value::str("run.stop")),
        (
            "params",
            Value::obj(vec![
                ("run_id", Value::str(h.rid())),
                ("reason", Value::str("OPERATOR")),
                ("note_hash", Value::Null),
            ]),
        ),
    ]);
    let beat = Value::obj(vec![
        ("v", Value::int(1)),
        ("id", Value::str(trellis_core::fixtures::i("trq", 91))),
        ("method", Value::str("agent.beat")),
        ("params", h.f.get("BEAT").clone()),
    ]);
    h.eng.agent_channel_run = Some(h.rid());
    // beat enqueued first, stop second — stop still wins at the boundary
    let out = h.eng.pump(vec![
        (Surface::AgentFd3, 0, beat),
        (Surface::Control, 0, stop),
    ]);
    let beat_resp = out
        .iter()
        .find(|r| {
            r.get("id").and_then(|i| i.as_str())
                == Some(trellis_core::fixtures::i("trq", 91).as_str())
        })
        .unwrap();
    expect_err(beat_resp, Code::Stopped)?;
    if h.reason() != Some(Reason::Operator) {
        return fail(format!("reason {:?}", h.reason()));
    }
    let evs = h.eng.store.load_events(&h.rid()).unwrap();
    if evs
        .iter()
        .any(|(_, b, _)| b.get("kind").and_then(|k| k.as_str()) == Some("GateGranted"))
    {
        return fail("grant issued after stop");
    }
    ok()
}

fn tv31(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let beat = h.f.get("BEAT").clone();
    let mk = |id: &str| {
        Value::obj(vec![
            ("v", Value::int(1)),
            ("id", Value::str(id)),
            ("method", Value::str("agent.beat")),
            ("params", beat.clone()),
        ])
    };
    h.eng.agent_channel_run = Some(h.rid());
    let out = h.eng.pump(vec![
        (
            Surface::AgentFd3,
            0,
            mk(&trellis_core::fixtures::i("trq", 2)),
        ),
        (
            Surface::AgentFd3,
            0,
            mk(&trellis_core::fixtures::i("trq", 3)),
        ),
    ]);
    let (a, b) = (&out[0], &out[1]);
    let oks = [a, b]
        .iter()
        .filter(|r| r.get("ok") == Some(&Value::Bool(true)))
        .count();
    if oks != 1 {
        return fail("expected exactly one OK");
    }
    let other = if a.get("ok") == Some(&Value::Bool(true)) {
        b
    } else {
        a
    };
    expect_err(other, Code::ChallengeUsed)?;
    if beats(&h) != 1 {
        return fail("beat count");
    }
    ok()
}

fn tv32(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    h.eng.store.fault = Some(trellis_core::store::StoreErr::FaultBlocked);
    h.eng.suppress_renewals = true; // the stuck fsync stalls the daemon loop
    let r = h.agent(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 1),
    );
    expect_err(&r, Code::Busy)?;
    h.timer(750_000_000);
    if h.reason() != Some(Reason::DaemonLost) {
        return fail(format!("reason {:?}", h.reason()));
    }
    let evs = h.eng.store.load_events(&h.rid()).unwrap();
    if evs
        .iter()
        .any(|(_, b, _)| b.get("kind").and_then(|k| k.as_str()) == Some("GateGranted"))
    {
        return fail("grant issued");
    }
    if h.view().get("gate") != Some(&Value::str("CLOSED")) {
        return fail("gate not closed");
    }
    ok()
}

fn tv33(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    h.timer(100_000_000);
    let b = beat2(&h.f);
    let r = h.agent("agent.beat", b, &trellis_core::fixtures::i("trq", 2));
    let res = expect_ok(&r)?.clone();
    if res.get("accepted") != Some(&Value::Bool(true))
        || res.get("seq") != Some(&Value::str("2"))
        || res.get("deadline_ns") != Some(&Value::str("3100000000"))
    {
        return fail(format!("bad result {}", res.canonical_string()));
    }
    let next = res.get("next").unwrap();
    if next.get("seq") != Some(&Value::str("3"))
        || next.get("challenge_id") != Some(&Value::str(trellis_core::fixtures::i("trc", 3)))
        || next.get("nonce") != Some(&b64(2))
    {
        return fail("bad next challenge");
    }
    ok()
}

fn tv34(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    h.os.borrow_mut()
        .containers
        .get_mut(&h.rid())
        .unwrap()
        .inventory_err = Some(trellis_core::os::OsErr::new(Code::InventoryLost, "EIO"));
    h.timer(100_000_001);
    let r = h.agent(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 1),
    );
    expect_err(&r, Code::InventoryLost)?;
    if h.reason() != Some(Reason::InventoryLost) {
        return fail(format!("reason {:?}", h.reason()));
    }
    ok()
}

// ---- kernel-boundary vectors: offline profile checks the reference model --
fn tv35(_: &mut ()) -> R {
    for n in ["fork", "vfork"] {
        if seccomp::decide(n, &[]) != Decision::Eperm {
            return fail(format!("{} allowed", n));
        }
    }
    // clone(SIGCHLD-only): exit-signal bits set -> process clone -> EPERM
    if seccomp::decide("clone", &[17]) != Decision::Eperm {
        return fail("clone(SIGCHLD) allowed");
    }
    ok()
}

fn tv36(_: &mut ()) -> R {
    if seccomp::decide("clone3", &[]) != Decision::Enosys {
        return fail("clone3 not ENOSYS");
    }
    ok()
}

fn tv37(_: &mut ()) -> R {
    let req = seccomp::CLONE_VM
        | seccomp::CLONE_FS
        | seccomp::CLONE_FILES
        | seccomp::CLONE_SIGHAND
        | seccomp::CLONE_THREAD
        | seccomp::CLONE_SYSVSEM
        | seccomp::CLONE_SETTLS
        | seccomp::CLONE_PARENT_SETTID
        | seccomp::CLONE_CHILD_CLEARTID;
    if seccomp::decide("clone", &[req]) != Decision::Allow {
        return fail("exact thread clone denied");
    }
    ok()
}

fn tv38(_: &mut ()) -> R {
    // pids.max enforcement is kernel-side; the policy bound check is offline.
    let mut h = Harness::new();
    let p = mutate(h.f.get("P"), "body.replication.max_threads", Value::int(0));
    let body = p.get("body").unwrap().clone();
    let signed = trellis_core::fixtures::sign_policy(&body);
    let start = mutate(&h.start_params(), "policy", signed);
    expect_err(
        &h.start(start, &trellis_core::fixtures::i("trq", 1)),
        Code::InvalidInput,
    )
}

fn tv39(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    {
        let mut os = h.os.borrow_mut();
        let c = os.containers.get_mut(&h.rid()).unwrap();
        c.inventory.tgids = vec![4200, 4201];
        c.inventory.threads = 2;
    }
    h.timer(100_000_001);
    let b = beat2(&h.f);
    let r = h.agent("agent.beat", b, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ScopeMismatch)?;
    if h.reason() != Some(Reason::ReplicationMismatch) {
        return fail(format!("reason {:?}", h.reason()));
    }
    if !h
        .os
        .borrow()
        .containers
        .get(&h.rid())
        .map(|c| c.killed)
        .unwrap_or(true)
    {
        return fail("cgroup kill not attempted");
    }
    ok()
}

fn tv40(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    {
        let mut os = h.os.borrow_mut();
        let c = os.containers.get_mut(&h.rid()).unwrap();
        c.inventory.root.start_ticks = 101;
    }
    h.timer(100_000_001);
    let b = beat2(&h.f);
    let r = h.agent("agent.beat", b, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ScopeMismatch)?;
    if h.reason() != Some(Reason::ReplicationMismatch) {
        return fail(format!("reason {:?}", h.reason()));
    }
    ok()
}

fn tv41(_: &mut ()) -> R {
    if seccomp::decide("unshare", &[seccomp::CLONE_NEWNET]) != Decision::Eperm {
        return fail("unshare allowed");
    }
    if seccomp::decide("setns", &[0, seccomp::CLONE_NEWNET]) != Decision::Eperm {
        return fail("setns allowed");
    }
    ok()
}

fn tv42(_: &mut ()) -> R {
    if seccomp::decide("socket", &[seccomp::AF_INET6, seccomp::SOCK_STREAM, 0]) != Decision::Eperm {
        return fail("AF_INET6 allowed");
    }
    if seccomp::decide("socket", &[40 /*AF_VSOCK*/, seccomp::SOCK_STREAM, 0]) != Decision::Eperm {
        return fail("AF_VSOCK allowed");
    }
    if seccomp::decide("socket", &[16 /*AF_NETLINK*/, 3 /*SOCK_RAW*/, 0]) != Decision::Eperm {
        return fail("AF_NETLINK allowed");
    }
    if seccomp::decide("io_uring_setup", &[1, 0]) != Decision::Eperm {
        return fail("io_uring allowed");
    }
    ok()
}

fn tv43(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.n2();
    let mut os = h.os.borrow_mut();
    let g = os.gate(&h.rid()).unwrap();
    let p443 = gate::test_packet(0x5DB8_D822, 443, true, 5, false);
    let p80 = gate::test_packet(0x5DB8_D822, 80, true, 5, false);
    if g.check_packet(0, &p443) != Verdict::Accept {
        return fail(":443 not accepted");
    }
    if g.check_packet(0, &p80) == Verdict::Accept {
        return fail(":80 accepted");
    }
    ok()
}

fn tv44(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.n2();
    // SYN at t=0 accepts; operator stop; retransmit drops
    let pkt = gate::test_packet(0x5DB8_D822, 443, true, 5, false);
    if h.os
        .borrow_mut()
        .gate(&h.rid())
        .unwrap()
        .check_packet(0, &pkt)
        != Verdict::Accept
    {
        return fail("initial SYN dropped");
    }
    h.control(
        "run.stop",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("reason", Value::str("OPERATOR")),
            ("note_hash", Value::Null),
        ]),
        &trellis_core::fixtures::i("trq", 5),
    );
    // After teardown the map is gone (default-deny); if it persists it must
    // be denial-latched.
    let mut os = h.os.borrow_mut();
    let verdict = os.gate(&h.rid()).map(|g| g.check_packet(1_000_000, &pkt));
    if verdict == Some(Verdict::Accept) {
        return fail("retransmit accepted after denial");
    }
    ok()
}

fn tv45(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.n2();
    let mut os = h.os.borrow_mut();
    let g = os.gate(&h.rid()).unwrap();
    for (proto, ihl, frag) in [(false, 5, false), (true, 6, false), (true, 5, true)] {
        let p = gate::test_packet(0x5DB8_D822, 443, proto, ihl, frag);
        if g.check_packet(0, &p) == Verdict::Accept {
            return fail(format!(
                "proto={} ihl={} frag={} accepted",
                proto, ihl, frag
            ));
        }
    }
    ok()
}

fn tv46(_: &mut ()) -> R {
    let mut h = Harness::new();
    let p = mutate(
        h.f.get("P"),
        "body.egress.allow",
        Value::Arr(vec![Value::obj(vec![
            ("ipv4", Value::str("169.254.169.254")),
            ("port", Value::int(80)),
        ])]),
    );
    let body = p.get("body").unwrap().clone();
    let signed = trellis_core::fixtures::sign_policy(&body);
    let start = mutate(&h.start_params(), "policy", signed);
    let r = h.start(start, &trellis_core::fixtures::i("trq", 1));
    expect_err(&r, Code::InvalidInput)?;
    if !h.eng.runs.is_empty() {
        return fail("RunCreated emitted");
    }
    ok()
}

fn tv47(_: &mut ()) -> R {
    // fd-3 channel must reject SCM_RIGHTS and close; verified with a real
    // socketpair (works unprivileged).
    let (a, b) = std::os::unix::net::UnixStream::pair().map_err(|e| e.to_string())?;
    trellis_core::chan::send_with_fd(&a, b"x", a.as_raw_fd()).map_err(|e| e.to_string())?;
    match trellis_core::chan::agent_recv(&b) {
        Err(trellis_core::types::ApiErr {
            code: Code::InvalidInput,
        }) => ok(),
        other => fail(format!("fd pass accepted: {:?}", other.map(|_| ()))),
    }
}

fn tv48(_: &mut ()) -> R {
    // setsid is on the unconditional allowlist (spec §1.4); the vector's
    // point is that stop targets the owned cgroup regardless: kill confirms
    // empty.
    let mut h = Harness::new();
    h.s2();
    h.control(
        "run.stop",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("reason", Value::str("OPERATOR")),
            ("note_hash", Value::Null),
        ]),
        &trellis_core::fixtures::i("trq", 5),
    );
    if h.state() != "STOPPED" || h.view().get("empty_observed") != Some(&Value::Bool(true)) {
        return fail(format!("state {}", h.state()));
    }
    ok()
}

fn tv49(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.n2();
    {
        let mut os = h.os.borrow_mut();
        os.containers.get_mut(&h.rid()).unwrap().kill_delay_ns = Some(2_250_000_000);
    }
    h.control(
        "run.stop",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("reason", Value::str("OPERATOR")),
            ("note_hash", Value::Null),
        ]),
        &trellis_core::fixtures::i("trq", 5),
    );
    h.timer(2_000_000_000);
    if h.state() != "UNCONFIRMED" {
        return fail(format!("state {}", h.state()));
    }
    let v = h.view();
    if v.get("gate") != Some(&Value::str("CLOSED"))
        || v.get("empty_observed") != Some(&Value::Bool(false))
    {
        return fail("gate/empty wrong");
    }
    let c = h.control(
        "certificate.get",
        Value::obj(vec![("run_id", Value::str(h.rid()))]),
        &trellis_core::fixtures::i("trq", 6),
    );
    expect_err(&c, Code::Unconfirmed)
}

fn tv50(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.n2();
    {
        let mut os = h.os.borrow_mut();
        os.containers.get_mut(&h.rid()).unwrap().kill_delay_ns = Some(2_250_000_000);
    }
    h.control(
        "run.stop",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("reason", Value::str("OPERATOR")),
            ("note_hash", Value::Null),
        ]),
        &trellis_core::fixtures::i("trq", 5),
    );
    h.timer(2_000_000_000);
    h.timer(2_250_000_000);
    if h.state() != "STOPPED" {
        return fail(format!("state {}", h.state()));
    }
    if h.view().get("empty_observed") != Some(&Value::Bool(true)) {
        return fail("not empty");
    }
    ok()
}

fn tv51(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    {
        let mut os = h.os.borrow_mut();
        let c = os.containers.get_mut(&h.rid()).unwrap();
        c.oom = true;
        c.exit = Some(schema::Exit {
            code: Some(0),
            signal: None,
        });
    }
    h.timer(1);
    if h.reason() != Some(Reason::ResourceLimit) {
        return fail(format!("reason {:?}", h.reason()));
    }
    if !h.reason().unwrap().is_safety_stop() {
        return fail("not a safety-stop exit class");
    }
    ok()
}

fn tv52(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    h.guard.borrow_mut().frozen = true;
    h.eng.suppress_renewals = true;
    h.timer(750_000_000);
    if h.reason() != Some(Reason::GuardLost) {
        return fail(format!("reason {:?}", h.reason()));
    }
    if !h
        .os
        .borrow()
        .containers
        .get(&h.rid())
        .map(|c| c.killed)
        .unwrap_or(true)
    {
        return fail("daemon fallback kill not attempted");
    }
    ok()
}

fn tv53(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    let r = verify_bundle(f.get("BUNDLE1"), Some(head_of(&f, "H1")), false)
        .map_err(|e| e.to_string())?;
    if r.completeness != Completeness::Prefix || r.state != RunState::Preparing {
        return fail(format!("{:?} {:?}", r.completeness, r.state));
    }
    if r.head != head_of(&f, "H1") {
        return fail("head");
    }
    ok()
}

fn tv54(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    match verify_bundle(f.get("BUNDLE1"), Some(head_of(&f, "H1")), true) {
        Err(e) if e.code == Code::Incomplete => ok(),
        e => fail(format!("expected INCOMPLETE, got {:?}", e.map(|_| ()))),
    }
}

fn tv55(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    let cp9h = head_of(&f, "CP9.body.head");
    let r = verify_bundle(f.get("BUNDLE9"), Some(cp9h.clone()), true).map_err(|e| e.to_string())?;
    if r.completeness != Completeness::Terminal || r.state != RunState::Stopped {
        return fail(format!("{:?} {:?}", r.completeness, r.state));
    }
    ok()
}

fn tv56(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    // remove E4 (index 3) from BUNDLE9 entries
    let mut b = f.get("BUNDLE9").clone();
    if let Value::Obj(m) = &mut b {
        if let Value::Arr(es) = m.get_mut("entries").unwrap() {
            es.remove(3);
        }
    }
    match verify_bundle(&b, None, true) {
        Err(e) if e.code == Code::ChainInvalid => ok(),
        e => fail(format!("expected CHAIN_INVALID, got {:?}", e.map(|_| ()))),
    }
}

fn tv57(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    let cp9h = head_of(&f, "CP9.body.head");
    match verify_bundle(f.get("BUNDLE1"), Some(cp9h), false) {
        Err(e) if e.code == Code::Incomplete => ok(),
        e => fail(format!("expected INCOMPLETE, got {:?}", e.map(|_| ()))),
    }
}

fn tv58(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    // E1 + freshly signed event(2,"RunStopped",E9.data,E1.hash), CP head=that event
    let e9d = f
        .get("E9")
        .get("body")
        .unwrap()
        .get("data")
        .unwrap()
        .clone();
    let e1h = f
        .get("E1")
        .get("hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let body = Value::obj(vec![
        ("v", Value::int(1)),
        ("host_id", f.get("H").clone()),
        ("run_id", f.get("R").clone()),
        ("boot_id", f.get("B").clone()),
        ("event_id", Value::str(trellis_core::fixtures::i("tre", 2))),
        ("key_id", f.get("K").clone()),
        ("seq", Value::str("2")),
        ("prev_hash", Value::str(e1h)),
        ("mono_ns", Value::str("0")),
        ("wall_time", Value::str(trellis_core::fixtures::wall_time())),
        ("policy_hash", f.get("PH").clone()),
        (
            "actor",
            Value::obj(vec![("kind", Value::str("daemon")), ("uid", Value::int(0))]),
        ),
        (
            "art",
            Value::obj(vec![
                ("operator_ref", Value::str("operator-local")),
                ("oversight", Value::str("automatic")),
                ("evidence", Value::str("software_observation")),
            ]),
        ),
        ("kind", Value::str("RunStopped")),
        ("data", e9d),
    ]);
    let h = domain_hash(D_EVENT, &body);
    let sig = f.kp.sign_domain(D_EVENT_SIGN, &h).unwrap();
    let e2 = Value::obj(vec![
        ("body", body),
        ("hash", Value::str(h)),
        ("sig", Value::str(sig)),
    ]);
    // checkpoint head = E2, state STOPPED
    let cp_body = Value::obj(vec![
        ("v", Value::int(1)),
        (
            "checkpoint_id",
            Value::str(trellis_core::fixtures::i("trn", 2)),
        ),
        ("host_id", f.get("H").clone()),
        ("run_id", f.get("R").clone()),
        ("key_id", f.get("K").clone()),
        (
            "head",
            Value::obj(vec![
                ("seq", Value::str("2")),
                ("hash", e2.get("hash").unwrap().clone()),
            ]),
        ),
        ("state", Value::str("STOPPED")),
        ("audit", Value::str("COMPLETE_PREFIX")),
        ("wall_time", Value::str(trellis_core::fixtures::wall_time())),
    ]);
    let ch = domain_hash(D_CHECKPOINT, &cp_body);
    let cs = f.kp.sign_domain(D_CHECKPOINT_SIGN, &ch).unwrap();
    let cp = Value::obj(vec![
        ("body", cp_body),
        ("hash", Value::str(ch)),
        ("sig", Value::str(cs)),
    ]);
    let bundle = Value::obj(vec![
        ("v", Value::int(1)),
        ("format", Value::str("trellis-bundle/1")),
        ("policy", f.get("P").clone()),
        ("entries", Value::Arr(vec![f.get("E1").clone(), e2])),
        ("checkpoint", cp),
        ("certificate", Value::Null),
    ]);
    match verify_bundle(&bundle, None, true) {
        Err(e) if e.code == Code::TransitionInvalid => ok(),
        e => fail(format!(
            "expected TRANSITION_INVALID, got {:?}",
            e.map(|_| ())
        )),
    }
}

fn tv59(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    h.eng.store.fault = Some(trellis_core::store::StoreErr::FaultEio);
    let b = beat2(&h.f);
    let r = h.agent("agent.beat", b, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::AuditFault)?;
    if h.reason() != Some(Reason::AuditFault) {
        return fail(format!("reason {:?}", h.reason()));
    }
    if h.view().get("gate") != Some(&Value::str("CLOSED")) {
        return fail("gate");
    }
    let c = h.control(
        "certificate.get",
        Value::obj(vec![("run_id", Value::str(h.rid()))]),
        &trellis_core::fixtures::i("trq", 6),
    );
    // audit GAP -> INCOMPLETE once stopped
    match expect_err(&c, Code::Incomplete).or_else(|_| expect_err(&c, Code::Unconfirmed)) {
        Ok(()) => ok(),
        Err(e) => fail(e),
    }
}

fn tv60(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    h.eng.crash_point = Some("post-e3-pre-grant".into());
    let _ = h.agent(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 1),
    );
    // crash: engine is dead; reboot on the same store
    h.reboot();
    h.timer(h.eng.now);
    if h.state() != "STOPPED" {
        return fail(format!("state {}", h.state()));
    }
    if h.view().get("audit") != Some(&Value::str("GAP")) {
        return fail("audit not GAP");
    }
    // no grant was replayed
    let evs = h.eng.store.load_events(&h.rid()).unwrap();
    if evs
        .iter()
        .any(|(_, b, _)| b.get("kind").and_then(|k| k.as_str()) == Some("GateGranted"))
    {
        return fail("grant replayed");
    }
    // pending request resolves to the cached STOPPED error on retry
    let r = h.agent(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 1),
    );
    expect_err(&r, Code::Stopped)?;
    ok()
}

fn tv61(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    // unlogged physical stop: kernel kills directly; emergency slot records it
    {
        let mut os = h.os.borrow_mut();
        os.kill(&h.rid(), 0);
        if let Some(g) = os.gate(&h.rid()) {
            g.denied = true;
            g.lease_until_ns = 0;
        }
    }
    h.reboot();
    h.timer(h.eng.now);
    if h.state() != "STOPPED" {
        return fail(format!("state {}", h.state()));
    }
    if h.view().get("audit") != Some(&Value::str("GAP")) {
        return fail("audit not GAP");
    }
    let c = h.control(
        "certificate.get",
        Value::obj(vec![("run_id", Value::str(h.rid()))]),
        &trellis_core::fixtures::i("trq", 6),
    );
    expect_err(&c, Code::Incomplete)
}

fn tv62(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s9();
    let head_before = h.view().get("head").cloned().unwrap();
    let r = h.control(
        "run.stop",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("reason", Value::str("OPERATOR")),
            ("note_hash", Value::Null),
        ]),
        &trellis_core::fixtures::i("trq", 3),
    );
    let res = expect_ok(&r)?.clone();
    if res.get("state") != Some(&Value::str("STOPPED"))
        || res.get("first_reason") != Some(&Value::str("OPERATOR"))
        || res.get("confirmed") != Some(&Value::Bool(true))
    {
        return fail(format!("bad stop result {}", res.canonical_string()));
    }
    if h.view().get("head") != Some(&head_before) {
        return fail("head changed");
    }
    ok()
}

fn tv63(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s0();
    let r = h.control(
        "events.read",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("after_seq", Value::str("1")),
            ("through", h.f.get("H1").clone()),
            ("limit", Value::int(1)),
        ]),
        &trellis_core::fixtures::i("trq", 2),
    );
    let res = expect_ok(&r)?.clone();
    if res.get("entries") != Some(&Value::Arr(vec![]))
        || res.get("through") != Some(h.f.get("H1"))
        || res.get("next_seq") != Some(&Value::str("1"))
        || res.get("more") != Some(&Value::Bool(false))
    {
        return fail(format!("bad page {}", res.canonical_string()));
    }
    ok()
}

fn tv64(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s0();
    let raw = Value::obj(vec![
        ("v", Value::int(1)),
        ("id", Value::str(trellis_core::fixtures::i("trq", 2))),
        ("method", Value::str("run.get")),
        ("params", Value::obj(vec![("run_id", Value::str(h.rid()))])),
    ]);
    let r = h.eng.call(Surface::Control, 63_000, raw);
    expect_err(&r, Code::Unauthorized)
}

fn tv65(_: &mut ()) -> R {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let lock = dir.path().join("owner.lock");
    let _g = trellis_core::daemon::owner_lock(&lock).map_err(|e| e.to_string())?;
    match trellis_core::daemon::owner_lock(&lock) {
        Err(e) if e.code == Code::Busy => ok(),
        _ => fail("second owner lock acquired"),
    }
}

fn tv66(_: &mut ()) -> R {
    // `trellis run --policy p.json --workspace /srv/trellis/work-a /usr/bin/true`
    // without `--` must exit 64 with no RPC. Exercised against the built CLI.
    let cli =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/ts/dist/src/cli.js");
    if !cli.exists() {
        return Err("cli not built".into());
    }
    let out = std::process::Command::new("node")
        .arg(&cli)
        .args([
            "run",
            "--policy",
            "p.json",
            "--workspace",
            "/srv/trellis/work-a",
            "/usr/bin/true",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.code() == Some(64) {
        ok()
    } else {
        fail(format!("exit {:?}", out.status.code()))
    }
}

fn tv67(_: &mut ()) -> R {
    Err("requires the CLI + live daemon profile".into())
}

fn tv68(_: &mut ()) -> R {
    let mut h = Harness::new();
    // valid signed lexwatt policy on cap_adapter=disabled
    let mut body = h.f.policy_body.clone();
    if let Value::Obj(m) = &mut body {
        m.insert(
            "cap".into(),
            Value::obj(vec![
                ("mode", Value::str("lexwatt")),
                ("config_hash", Value::str(sha256_hex(b"cfg"))),
                ("required", Value::Bool(true)),
            ]),
        );
    }
    let signed = trellis_core::fixtures::sign_policy(&body);
    let start = mutate(&h.start_params(), "policy", signed);
    let r = h.start(start, &trellis_core::fixtures::i("trq", 1));
    expect_err(&r, Code::CapAdapterUnavailable)?;
    if !h.eng.runs.is_empty() {
        return fail("run created");
    }
    ok()
}

fn tv69(_: &mut ()) -> R {
    // host config unknown key
    let mut cfg = fixture_config_value();
    if let Value::Obj(m) = &mut cfg {
        m.insert("workers_url".into(), Value::str("https://x"));
    }
    match schema::host_config(&cfg) {
        Err(e) if e.code == Code::UnknownField => {}
        _ => return fail("workers_url accepted"),
    }
    // policy unknown key
    let f = trellis_core::fixtures::build();
    let mut pb = f.policy_body.clone();
    if let Value::Obj(m) = &mut pb {
        m.insert("amendment_court".into(), Value::str("x"));
    }
    match schema::policy_body(&pb, &[]) {
        Err(e) if e.code == Code::UnknownField => ok(),
        _ => fail("amendment_court accepted"),
    }
}

fn tv70(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    // stream: header + E1 entry line, EOF without trailer
    let header = Value::obj(vec![
        ("record", Value::str("header")),
        ("v", Value::int(1)),
        ("format", Value::str("trellis-stream/1")),
        ("policy", f.get("P").clone()),
        ("checkpoint", f.get("CP1").clone()),
    ]);
    let entry = Value::obj(vec![
        ("record", Value::str("entry")),
        ("entry", f.get("E1").clone()),
    ]);
    let mut bytes = header.canonical();
    bytes.push(b'\n');
    bytes.extend_from_slice(&entry.canonical());
    bytes.push(b'\n');
    let p = pin(&f);
    match verify::verify_stream(
        &bytes,
        std::slice::from_ref(&p),
        std::slice::from_ref(&p),
        None,
        false,
    ) {
        Err(e) if e.code == Code::Incomplete => ok(),
        e => fail(format!("expected INCOMPLETE, got {:?}", e.map(|_| ()))),
    }
}

fn tv71(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    let b = mutate(
        f.get("BUNDLE9"),
        "certificate.body.external_effects",
        Value::str("REVERSED"),
    );
    match verify_bundle(&b, None, true) {
        Err(e) if e.code == Code::InvalidInput => ok(),
        e => fail(format!("expected INVALID_INPUT, got {:?}", e.map(|_| ()))),
    }
}

fn tv72(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s9();
    // snapshot every signed event byte
    let before: Vec<Vec<u8>> = h
        .eng
        .store
        .load_events(&h.rid())
        .unwrap()
        .into_iter()
        .map(|(_, b, _)| b.canonical())
        .collect();
    let res = trellis_core::engine::migrate_noop(&h.eng.store).map_err(|e| e.to_string())?;
    if res.get("changed") != Some(&Value::Bool(false)) {
        return fail("changed != false");
    }
    let after: Vec<Vec<u8>> = h
        .eng
        .store
        .load_events(&h.rid())
        .unwrap()
        .into_iter()
        .map(|(_, b, _)| b.canonical())
        .collect();
    if before != after {
        return fail("event bytes changed");
    }
    ok()
}

fn tv73(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    let b1 = mutate(h.f.get("BEAT"), "progress", Value::str("5"));
    let r = h.agent("agent.beat", b1, &trellis_core::fixtures::i("trq", 1));
    expect_ok(&r)?;
    // second beat: valid CH2 binding but progress decreases to "4"
    let mut b2 = beat2(&h.f);
    if let Value::Obj(m) = &mut b2 {
        m.insert("progress".into(), Value::str("4"));
    }
    let r = h.agent("agent.beat", b2, &trellis_core::fixtures::i("trq", 2));
    expect_err(&r, Code::ScopeMismatch)?;
    if h.reason() != Some(Reason::ScopeMismatch) {
        return fail(format!("reason {:?}", h.reason()));
    }
    if h.view().get("gate") != Some(&Value::str("CLOSED")) {
        return fail("gate");
    }
    // grant_count for beat two = 0: only one GateGranted exists
    let evs = h.eng.store.load_events(&h.rid()).unwrap();
    let grants = evs
        .iter()
        .filter(|(_, b, _)| b.get("kind").and_then(|k| k.as_str()) == Some("GateGranted"))
        .count();
    if grants != 1 {
        return fail(format!("grants {}", grants));
    }
    ok()
}

fn tv74(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s1();
    // control method over fd-3
    let r1 = h.agent(
        "run.get",
        Value::obj(vec![("run_id", Value::str(h.rid()))]),
        &trellis_core::fixtures::i("trq", 7),
    );
    expect_err(&r1, Code::Unauthorized)?;
    // agent method over control socket
    let r2 = h.control(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 8),
    );
    expect_err(&r2, Code::Unauthorized)?;
    // offline method over control socket
    let r3 = h.control(
        "receipt.verify",
        Value::obj(vec![
            ("bundle", h.f.get("BUNDLE1").clone()),
            ("log_pins", Value::Arr(vec![h.f.get("PIN").clone()])),
            ("policy_pins", Value::Arr(vec![h.f.get("PIN").clone()])),
            ("expected_head", h.f.get("H1").clone()),
            ("require_terminal", Value::Bool(false)),
        ]),
        &trellis_core::fixtures::i("trq", 9),
    );
    expect_err(&r3, Code::InvalidInput)?;
    if h.state() != "WAITING" {
        return fail("state changed");
    }
    ok()
}

fn tv75(_: &mut ()) -> R {
    // workspace outside roots -> INVALID_INPUT
    let mut h = Harness::new();
    let s = mutate(
        &h.start_params(),
        "workspace_root",
        Value::str("/srv/trellis/other"),
    );
    let r = h.start(s, &trellis_core::fixtures::i("trq", 1));
    expect_err(&r, Code::InvalidInput)?;
    if !h.eng.runs.is_empty() {
        return fail("run created");
    }
    // stale epoch -> STALE_EPOCH
    let mut h = Harness::new();
    let s = mutate(&h.start_params(), "expected_host_epoch", Value::str("9"));
    let r = h.start(s, &trellis_core::fixtures::i("trq", 1));
    expect_err(&r, Code::StaleEpoch)?;
    // exec argv[0] /usr/bin/false -> HASH_MISMATCH
    let mut h = Harness::new();
    let s = mutate(
        &h.start_params(),
        "exec.argv[0]",
        Value::str("/usr/bin/false"),
    );
    let r = h.start(s, &trellis_core::fixtures::i("trq", 1));
    expect_err(&r, Code::HashMismatch)?;
    ok()
}

fn tv76(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.eng.drain();
    let r = h.start(h.start_params(), &trellis_core::fixtures::i("trq", 1));
    expect_err(&r, Code::Conflict)
}

fn tv77(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s0();
    let e1h = h.f.get("E1").get("hash").unwrap().clone();
    let r = h.control(
        "events.read",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("after_seq", Value::str("0")),
            (
                "through",
                Value::obj(vec![("seq", Value::str("7")), ("hash", e1h.clone())]),
            ),
            ("limit", Value::int(1)),
        ]),
        &trellis_core::fixtures::i("trq", 2),
    );
    expect_err(&r, Code::NotFound)?;
    let r = h.control(
        "events.read",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("after_seq", Value::str("0")),
            (
                "through",
                Value::obj(vec![
                    ("seq", Value::str("1")),
                    ("hash", Value::str(ZERO_HASH)),
                ]),
            ),
            ("limit", Value::int(1)),
        ]),
        &trellis_core::fixtures::i("trq", 3),
    );
    expect_err(&r, Code::HashMismatch)?;
    let r = h.control(
        "events.read",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("after_seq", Value::str("2")),
            ("through", h.f.get("H1").clone()),
            ("limit", Value::int(1)),
        ]),
        &trellis_core::fixtures::i("trq", 4),
    );
    expect_err(&r, Code::InvalidInput)
}

fn tv78(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.sr();
    if h.state() != "REJECTED" {
        return fail(format!("SR state {}", h.state()));
    }
    let head_before = h.view().get("head").cloned().unwrap();
    let r = h.control(
        "run.stop",
        Value::obj(vec![
            ("run_id", Value::str(h.rid())),
            ("reason", Value::str("OPERATOR")),
            ("note_hash", Value::Null),
        ]),
        &trellis_core::fixtures::i("trq", 2),
    );
    let res = expect_ok(&r)?.clone();
    if res.get("state") != Some(&Value::str("REJECTED"))
        || res.get("first_reason") != Some(&Value::Null)
        || res.get("confirmed") != Some(&Value::Bool(true))
    {
        return fail(format!("bad {}", res.canonical_string()));
    }
    if h.view().get("head") != Some(&head_before) {
        return fail("head changed");
    }
    ok()
}

fn tv79(_: &mut ()) -> R {
    let f = trellis_core::fixtures::build();
    match verify_bundle(f.get("BUNDLE9"), Some(head_of(&f, "H1")), true) {
        Err(e) if e.code == Code::Conflict => {}
        e => return fail(format!("expected CONFLICT, got {:?}", e.map(|_| ()))),
    }
    let bad = Head {
        seq: 5,
        hash: ZERO_HASH.into(),
    };
    match verify_bundle(f.get("BUNDLE9"), Some(bad), true) {
        Err(e) if e.code == Code::HashMismatch => ok(),
        e => fail(format!("expected HASH_MISMATCH, got {:?}", e.map(|_| ()))),
    }
}

fn tv80(_: &mut ()) -> R {
    let mut h = Harness::new();
    h.s2();
    h.timer(100_000_000);
    let b = beat2(&h.f);
    let r = h.agent("agent.beat", b, &trellis_core::fixtures::i("trq", 2));
    expect_ok(&r)?; // CH3 now outstanding
                    // stale CH1 beat, new id
    let r = h.agent(
        "agent.beat",
        h.f.get("BEAT").clone(),
        &trellis_core::fixtures::i("trq", 3),
    );
    expect_err(&r, Code::ChallengeUsed)?;
    // never-issued challenge id
    let bad = mutate(
        h.f.get("BEAT"),
        "challenge_id",
        Value::str(trellis_core::fixtures::i("trc", 9)),
    );
    let r = h.agent("agent.beat", bad, &trellis_core::fixtures::i("trq", 4));
    expect_err(&r, Code::ChallengeInvalid)?;
    if h.state() != "ACTIVE" {
        return fail("state moved");
    }
    ok()
}

fn tv81(_: &mut ()) -> R {
    // cap_adapter=lexwatt-contained-v1 without a certified adapter -> LOCKED
    let mut cfg = fixture_config_value();
    if let Value::Obj(m) = &mut cfg {
        m.insert("cap_adapter".into(), Value::str("lexwatt-contained-v1"));
    }
    let cfg = schema::host_config(&cfg).map_err(|e| e.to_string())?;
    let f = trellis_core::fixtures::build();
    let os = std::rc::Rc::new(std::cell::RefCell::new(trellis_core::os::ModelOs::new()));
    let guard = std::rc::Rc::new(std::cell::RefCell::new(
        trellis_core::guard::GuardModel::new(os.clone()),
    ));
    let mut eng = Engine::new(
        cfg,
        Store::memory().unwrap(),
        os,
        guard,
        Box::new(trellis_core::engine::DeterministicIds),
        f.kp.clone(),
        "kboot".into(),
    );
    eng.log_key_id = trellis_core::fixtures::i("trk", 1);
    eng.startup();
    if eng.state != HostState::Locked {
        return fail(format!("state {}", eng.state.as_str()));
    }
    let d = eng.doctor();
    if d.get("ready") != Some(&Value::Bool(false)) {
        return fail("doctor ready=true");
    }
    let r = eng.call(
        Surface::Control,
        0,
        Value::obj(vec![
            ("v", Value::int(1)),
            ("id", Value::str(trellis_core::fixtures::i("trq", 1))),
            ("method", Value::str("run.start")),
            ("params", f.get("START").clone()),
        ]),
    );
    expect_err(&r, Code::Conflict)
}

// ===========================================================================
// Runner
// ===========================================================================

struct VecDef {
    id: &'static str,
    f: fn(&mut ()) -> R,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut profile = "offline-v1";
    let mut vectors = "all";
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                profile = &args[i + 1];
                i += 2;
            }
            "--vectors" => {
                vectors = &args[i + 1];
                i += 2;
            }
            "--isolated-netns" => i += 1,
            _ => i += 1,
        }
    }
    let all: Vec<VecDef> = vec![
        vd("TV-T--01", tv01),
        vd("TV-T--02", tv02),
        vd("TV-T--03", tv03),
        vd("TV-T--04", tv04),
        vd("TV-T--05", tv05),
        vd("TV-T--06", tv06),
        vd("TV-T--07", tv07),
        vd("TV-T--08", tv08),
        vd("TV-T--09", tv09),
        vd("TV-T--10", tv10),
        vd("TV-T--11", tv11),
        vd("TV-T--12", tv12),
        vd("TV-T--13", tv13),
        vd("TV-T--14", tv14),
        vd("TV-T--15", tv15),
        vd("TV-T--16", tv16),
        vd("TV-T--17", tv17),
        vd("TV-T--18", tv18),
        vd("TV-T--19", tv19),
        vd("TV-T--20", tv20),
        vd("TV-T--21", tv21),
        vd("TV-T--22", tv22),
        vd("TV-T--23", tv23),
        vd("TV-T--24", tv24),
        vd("TV-T--25", tv25),
        vd("TV-T--26", tv26),
        vd("TV-T--27", tv27),
        vd("TV-T--28", tv28),
        vd("TV-T--29", tv29),
        vd("TV-T--30", tv30),
        vd("TV-T--31", tv31),
        vd("TV-T--32", tv32),
        vd("TV-T--33", tv33),
        vd("TV-T--34", tv34),
        vd("TV-T--35", tv35),
        vd("TV-T--36", tv36),
        vd("TV-T--37", tv37),
        vd("TV-T--38", tv38),
        vd("TV-T--39", tv39),
        vd("TV-T--40", tv40),
        vd("TV-T--41", tv41),
        vd("TV-T--42", tv42),
        vd("TV-T--43", tv43),
        vd("TV-T--44", tv44),
        vd("TV-T--45", tv45),
        vd("TV-T--46", tv46),
        vd("TV-T--47", tv47),
        vd("TV-T--48", tv48),
        vd("TV-T--49", tv49),
        vd("TV-T--50", tv50),
        vd("TV-T--51", tv51),
        vd("TV-T--52", tv52),
        vd("TV-T--53", tv53),
        vd("TV-T--54", tv54),
        vd("TV-T--55", tv55),
        vd("TV-T--56", tv56),
        vd("TV-T--57", tv57),
        vd("TV-T--58", tv58),
        vd("TV-T--59", tv59),
        vd("TV-T--60", tv60),
        vd("TV-T--61", tv61),
        vd("TV-T--62", tv62),
        vd("TV-T--63", tv63),
        vd("TV-T--64", tv64),
        vd("TV-T--65", tv65),
        vd("TV-T--66", tv66),
        vd("TV-T--67", tv67),
        vd("TV-T--68", tv68),
        vd("TV-T--69", tv69),
        vd("TV-T--70", tv70),
        vd("TV-T--71", tv71),
        vd("TV-T--72", tv72),
        vd("TV-T--73", tv73),
        vd("TV-T--74", tv74),
        vd("TV-T--75", tv75),
        vd("TV-T--76", tv76),
        vd("TV-T--77", tv77),
        vd("TV-T--78", tv78),
        vd("TV-T--79", tv79),
        vd("TV-T--80", tv80),
        vd("TV-T--81", tv81),
    ];
    let want: Vec<String> = if vectors == "all" {
        Vec::new()
    } else {
        vectors
            .split(',')
            .map(|s| format!("TV-T--{}", s.trim_start_matches("TV-T--")))
            .collect()
    };
    // Under the enforcement profile, mandatory containment vectors require a
    // certified host (spec §2.4: no fallback). Probe once; a failed check
    // marks those vectors UNSUPPORTED_HOST rather than letting the reference
    // model stand in for a kernel we do not have.
    const CONTAINMENT: &[&str] = &[
        "TV-T--35", "TV-T--36", "TV-T--37", "TV-T--38", "TV-T--41", "TV-T--42", "TV-T--43",
        "TV-T--44", "TV-T--45", "TV-T--48",
    ];
    let mut preflight_report = Value::Null;
    let mut host_unsupported: Option<String> = None;
    if profile == "linux-single-process-v1" {
        let mut os = trellis_core::os::LinuxOs::new();
        let cfg = fixture_config();
        let pf = os.preflight(&cfg);
        let failed: Vec<String> = pf
            .checks
            .iter()
            .filter(|c| !c.1)
            .map(|c| c.0.to_string())
            .collect();
        preflight_report = Value::obj(
            pf.checks
                .iter()
                .map(|c| (c.0, Value::Bool(c.1)))
                .collect::<Vec<_>>(),
        );
        if !pf.ready() {
            host_unsupported = Some(format!("UNSUPPORTED_HOST({})", failed.join(",")));
        }
    }
    let mut results = Vec::new();
    let (mut pass, mut failc, mut unsup) = (0u64, 0u64, 0u64);
    for v in &all {
        if !want.is_empty() && !want.iter().any(|w| w == v.id) {
            continue;
        }
        if let Some(reason) = &host_unsupported {
            if CONTAINMENT.contains(&v.id) {
                unsup += 1;
                results.push(format!("unsupported {}: {}", v.id, reason));
                continue;
            }
        }
        let status = match (v.f)(&mut ()) {
            Ok(()) => {
                pass += 1;
                "pass"
            }
            Err(e) if e.starts_with("requires") || e.starts_with("cli not built") => {
                unsup += 1;
                "unsupported"
            }
            Err(e) => {
                failc += 1;
                results.push(format!("FAIL {}: {}", v.id, e));
                "fail"
            }
        };
        if status != "fail" {
            results.push(format!("{} {}", status, v.id));
        }
    }
    let report = Value::obj(vec![
        ("profile", Value::str(profile)),
        ("preflight", preflight_report),
        (
            "vectors",
            Value::Arr(results.iter().map(|s| Value::str(s.clone())).collect()),
        ),
        (
            "totals",
            Value::obj(vec![
                ("pass", Value::int(pass)),
                ("fail", Value::int(failc)),
                ("unsupported", Value::int(unsup)),
            ]),
        ),
    ]);
    println!("{}", report.canonical_string());
    std::process::exit(if failc > 0 { 1 } else { 0 });
}

fn vd(id: &'static str, f: fn(&mut ()) -> R) -> VecDef {
    VecDef { id, f }
}
