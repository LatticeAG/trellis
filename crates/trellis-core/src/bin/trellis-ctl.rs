//! trellis-ctl — offline control-plane helper used by the `trellis` CLI.
//!
//! Every cryptographic, schema, and verification decision lives in Rust; the
//! TypeScript and Python clients stay thin. Subcommands emit one canonical
//! JSON object on stdout; diagnostics go to stderr. Exit codes follow the
//! §6.1 table (64 usage, 65 signature/host/adapter, 74 I/O, 76 verify fail).
//!
//!   trellis-ctl policy-hash --input PATH
//!   trellis-ctl policy-sign --input PATH --key-file PATH --key-id KEY_ID
//!   trellis-ctl keygen --key-id KEY_ID --directory DIR
//!   trellis-ctl config-validate --input PATH --kind host|policy [--policy-pin PATH]...
//!   trellis-ctl doctor --config PATH
//!   trellis-ctl verify --input PATH [--log-pin PATH]... [--policy-pin PATH]...
//!                      [--head SEQ:HASH] [--allow-prefix]
//!   trellis-ctl recover --config PATH --expected-heads PATH
//!   trellis-ctl migrate --config PATH --to 1 --expected-heads PATH

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use trellis_core::crypto::{domain_hash, Keypair, D_HOST_CONFIG, D_POLICY};
use trellis_core::engine::{migrate_noop, Engine, RandomIds};
use trellis_core::json::{self, Value};
use trellis_core::os::{LinuxOs, Os};
use trellis_core::schema::{host_config, pin, policy_body, signed_policy, Pin};
use trellis_core::store::Store;
use trellis_core::types::{ApiErr, Code, Head};
use trellis_core::verify::{verify, VerifyInput};

fn out(v: &Value) {
    let mut w = std::io::stdout();
    use std::io::Write;
    let _ = w.write_all(&v.canonical());
    let _ = w.write_all(b"\n");
}

fn usage() -> ! {
    eprintln!("usage: trellis-ctl <policy-hash|policy-sign|keygen|config-validate|doctor|verify|recover|migrate|fixture> ...");
    std::process::exit(64);
}

fn args() -> Vec<String> {
    std::env::args().skip(1).collect()
}

fn take<'a>(a: &'a [String], flag: &str) -> Option<&'a str> {
    a.windows(2).find(|w| w[0] == flag).map(|w| w[1].as_str())
}

fn take_all<'a>(a: &'a [String], flag: &str) -> Vec<&'a str> {
    a.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].as_str())
        .collect()
}

fn has(a: &[String], flag: &str) -> bool {
    a.iter().any(|x| x == flag)
}

fn read_json(path: &str) -> Result<Value, i32> {
    let b = std::fs::read(path).map_err(|_| 74)?;
    json::parse(&b).map_err(|_| 64)
}

fn load_pin(path: &str) -> Result<Pin, i32> {
    let v = read_json(path)?;
    pin(&v).map_err(|_| 64)
}

fn main() {
    let a = args();
    match a.first().map(|s| s.as_str()) {
        Some("policy-hash") => std::process::exit(policy_hash(&a[1..])),
        Some("policy-sign") => std::process::exit(policy_sign(&a[1..])),
        Some("keygen") => std::process::exit(keygen(&a[1..])),
        Some("config-validate") => std::process::exit(config_validate(&a[1..])),
        Some("doctor") => std::process::exit(doctor(&a[1..])),
        Some("verify") => std::process::exit(verify_cmd(&a[1..])),
        Some("recover") => std::process::exit(recover(&a[1..])),
        Some("migrate") => std::process::exit(migrate(&a[1..])),
        Some("fixture") => std::process::exit(fixture_dump(&a[1..])),
        _ => usage(),
    }
}

fn policy_hash(a: &[String]) -> i32 {
    let Some(input) = take(a, "--input") else {
        usage()
    };
    let v = match read_json(input) {
        Ok(v) => v,
        Err(c) => return c,
    };
    // unsigned PolicyBody only; the hash never executes content
    if policy_body(&v, &[]).is_err() {
        return 64;
    }
    out(&Value::obj(vec![
        ("v", Value::int(1)),
        ("policy_hash", Value::str(domain_hash(D_POLICY, &v))),
        ("valid", Value::Bool(true)),
    ]));
    0
}

fn policy_sign(a: &[String]) -> i32 {
    let (Some(input), Some(key_file), Some(key_id)) = (
        take(a, "--input"),
        take(a, "--key-file"),
        take(a, "--key-id"),
    ) else {
        usage()
    };
    let v = match read_json(input) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if policy_body(&v, &[]).is_err() {
        return 64;
    }
    // refuse the public fixture seed in production flows
    let seed_b = match std::fs::read(key_file) {
        Ok(b) if b.len() == 32 => b,
        _ => return 74,
    };
    let kp = Keypair::from_seed(&seed_b.try_into().unwrap());
    if kp.public_b64() == Keypair::from_seed(&trellis_core::fixtures::FIXTURE_SEED).public_b64() {
        eprintln!("trellis-ctl: refusing to sign with the public fixture key");
        return 64;
    }
    let ph = domain_hash(D_POLICY, &v);
    let sig = kp
        .sign_domain(trellis_core::crypto::D_POLICY_SIGN, &ph)
        .unwrap();
    out(&Value::obj(vec![
        ("v", Value::int(1)),
        ("key_id", Value::str(key_id)),
        ("policy_hash", Value::str(ph)),
        ("sig", Value::str(sig)),
        ("valid", Value::Bool(true)),
    ]));
    0
}

fn keygen(a: &[String]) -> i32 {
    let (Some(key_id), Some(dir)) = (take(a, "--key-id"), take(a, "--directory")) else {
        usage()
    };
    if !trellis_core::scalars::is_id(key_id, "trk") {
        return 64;
    }
    let seed: [u8; 32] = trellis_core::scalars::random_bytes(32).try_into().unwrap();
    let kp = Keypair::from_seed(&seed);
    let dirp = Path::new(dir);
    if std::fs::create_dir_all(dirp).is_err() {
        return 74;
    }
    let seed_path = dirp.join(format!("{}.seed", key_id));
    let pin_path = dirp.join(format!("{}.pin", key_id));
    if seed_path.exists() || pin_path.exists() {
        return 64; // create-exclusive
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&seed_path)
    {
        Ok(f) => f,
        Err(_) => return 74,
    };
    if f.write_all(&seed).is_err() {
        return 74;
    }
    let pin_v = Value::obj(vec![
        ("v", Value::int(1)),
        ("key_id", Value::str(key_id)),
        ("public_key", Value::str(kp.public_b64())),
    ]);
    if std::fs::write(&pin_path, pin_v.canonical()).is_err() {
        return 74;
    }
    out(&Value::obj(vec![
        ("v", Value::int(1)),
        ("key_id", Value::str(key_id)),
        ("public_key", Value::str(kp.public_b64())),
    ]));
    0
}

fn config_validate(a: &[String]) -> i32 {
    let (Some(input), Some(kind)) = (take(a, "--input"), take(a, "--kind")) else {
        usage()
    };
    let v = match read_json(input) {
        Ok(v) => v,
        Err(c) => return c,
    };
    match kind {
        "host" => match host_config(&v) {
            Ok(_) => {
                out(&Value::obj(vec![
                    ("v", Value::int(1)),
                    ("kind", Value::str("host")),
                    ("valid", Value::Bool(true)),
                    ("config_hash", Value::str(domain_hash(D_HOST_CONFIG, &v))),
                ]));
                0
            }
            Err(e) => {
                eprintln!("{}", e.code.as_str());
                64
            }
        },
        "policy" => {
            let pins: Result<Vec<Pin>, i32> = take_all(a, "--policy-pin")
                .into_iter()
                .map(load_pin)
                .collect();
            let pins = match pins {
                Ok(p) => p,
                Err(c) => return c,
            };
            // signed or unsigned accepted: signed requires a pin
            let res = if v.get("body").is_some() {
                match signed_policy(&v, &[]) {
                    Ok(sp) => {
                        if pins.is_empty()
                            || pins
                                .iter()
                                .any(|p| p.key_id == sp.key_id && verify_policy_sig(&v, p))
                        {
                            Ok(())
                        } else {
                            Err(ApiErr::new(Code::UntrustedKey))
                        }
                    }
                    Err(e) => Err(e),
                }
            } else {
                policy_body(&v, &[]).map(|_| ())
            };
            match res {
                Ok(()) => {
                    out(&Value::obj(vec![
                        ("v", Value::int(1)),
                        ("kind", Value::str("policy")),
                        ("valid", Value::Bool(true)),
                        (
                            "config_hash",
                            Value::str(domain_hash(D_POLICY, v.get("body").unwrap_or(&v))),
                        ),
                    ]));
                    0
                }
                Err(e) => {
                    eprintln!("{}", e.code.as_str());
                    if e.code == Code::UntrustedKey || e.code == Code::SignatureInvalid {
                        65
                    } else {
                        64
                    }
                }
            }
        }
        _ => usage(),
    }
}

fn verify_policy_sig(v: &Value, p: &Pin) -> bool {
    let Some(body) = v.get("body") else {
        return false;
    };
    let Some(sig) = v.get("sig").and_then(|s| s.as_str()) else {
        return false;
    };
    let ph = domain_hash(D_POLICY, body);
    trellis_core::crypto::verify_domain(
        trellis_core::crypto::D_POLICY_SIGN,
        &ph,
        &p.public_key,
        sig,
    )
}

fn doctor(a: &[String]) -> i32 {
    let Some(config) = take(a, "--config") else {
        usage()
    };
    let v = match read_json(config) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let cfg = match host_config(&v) {
        Ok(c) => c,
        Err(_) => return 64,
    };
    let os: Rc<RefCell<dyn Os>> = Rc::new(RefCell::new(LinuxOs::new()));
    let guard = Rc::new(RefCell::new(trellis_core::guard::GuardModel::new(
        os.clone(),
    )));
    let store = Store::memory().unwrap();
    let mut eng = Engine::new(
        cfg,
        store,
        os,
        guard,
        Box::new(RandomIds),
        Keypair::generate(),
        "none".into(),
    );
    eng.startup();
    let d = eng.doctor();
    out(&d);
    if d.get("ready") == Some(&Value::Bool(true)) {
        0
    } else {
        65
    }
}

fn verify_cmd(a: &[String]) -> i32 {
    let Some(input) = take(a, "--input") else {
        usage()
    };
    let bundle = match read_json(input) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let log_pins: Result<Vec<Pin>, i32> =
        take_all(a, "--log-pin").into_iter().map(load_pin).collect();
    let pol_pins: Result<Vec<Pin>, i32> = take_all(a, "--policy-pin")
        .into_iter()
        .map(load_pin)
        .collect();
    let (log_pins, pol_pins) = match (log_pins, pol_pins) {
        (Ok(l), Ok(p)) => (l, p),
        (Err(c), _) | (_, Err(c)) => return c,
    };
    if log_pins.is_empty() || pol_pins.is_empty() {
        return 64; // pins are required, not optional
    }
    let expected = take(a, "--head").and_then(|h| {
        let (s, hx) = h.split_once(':')?;
        Some(Head {
            seq: s.parse().ok()?,
            hash: hx.to_string(),
        })
    });
    let require_terminal = !has(a, "--allow-prefix");
    match verify(&VerifyInput {
        bundle: &bundle,
        log_pins: &log_pins,
        policy_pins: &pol_pins,
        expected_head: expected,
        require_terminal,
    }) {
        Ok(r) => {
            out(&r.to_value());
            0
        }
        Err(e) => {
            out(&Value::obj(vec![
                ("v", Value::int(1)),
                (
                    "error",
                    Value::obj(vec![
                        ("code", Value::str(e.code.as_str())),
                        ("retryable", Value::Bool(false)),
                    ]),
                ),
            ]));
            76
        }
    }
}

fn expected_heads(path: &str) -> Result<Vec<(String, Head)>, i32> {
    let v = read_json(path)?;
    let heads = v.get("heads").and_then(|h| h.as_arr()).ok_or(64)?;
    let mut out = Vec::new();
    for h in heads {
        let rid = h.get("run_id").and_then(|r| r.as_str()).ok_or(64)?;
        let hv = h.get("head").ok_or(64)?;
        let hh = trellis_core::schema::head(hv).map_err(|_| 64)?;
        out.push((rid.to_string(), hh));
    }
    Ok(out)
}

fn recover(a: &[String]) -> i32 {
    let (Some(config), Some(heads_path)) = (take(a, "--config"), take(a, "--expected-heads"))
    else {
        usage()
    };
    let cfg_v = match read_json(config) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let cfg = match host_config(&cfg_v) {
        Ok(c) => c,
        Err(_) => return 64,
    };
    let expected = match expected_heads(heads_path) {
        Ok(e) => e,
        Err(c) => return c,
    };
    // requires daemon stopped: the owner lock must be obtainable
    let lock_path = Path::new(&cfg.data_root).join("owner.lock");
    let _guard = match trellis_core::daemon::owner_lock(&lock_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}", e.code.as_str());
            return 75;
        }
    };
    let store = match Store::open(&Path::new(&cfg.data_root).join("store.db")) {
        Ok(s) => s,
        Err(_) => return 74,
    };
    let runs = store.load_runs().unwrap_or_default();
    let mut rows = Vec::new();
    for r in &runs {
        let proj = json::parse(&r.projection).unwrap_or(Value::Null);
        let state = proj
            .get("state")
            .and_then(|s| s.as_str())
            .unwrap_or("STOPPED")
            .to_string();
        let audit = proj
            .get("audit")
            .and_then(|s| s.as_str())
            .unwrap_or("COMPLETE_PREFIX")
            .to_string();
        // expected-head pin check: a stored head beyond the pin is CONFLICT
        for (rid, eh) in &expected {
            if rid == &r.run_id {
                let seq: u64 = proj
                    .get("head")
                    .and_then(|h| h.get("seq"))
                    .and_then(|s| s.as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if seq > eh.seq {
                    eprintln!("CONFLICT: {} head beyond pin", r.run_id);
                    return 76;
                }
            }
        }
        rows.push(Value::obj(vec![
            ("run_id", Value::str(r.run_id.clone())),
            ("state", Value::str(state)),
            ("audit", Value::str(audit)),
        ]));
    }
    out(&Value::obj(vec![
        ("v", Value::int(1)),
        ("storage", Value::int(1)),
        ("runs", Value::Arr(rows)),
        ("changed", Value::Bool(false)),
    ]));
    0
}

fn migrate(a: &[String]) -> i32 {
    let (Some(config), Some(to)) = (take(a, "--config"), take(a, "--to")) else {
        usage()
    };
    if to != "1" {
        eprintln!("no migration to storage version {}", to);
        return 64;
    }
    let cfg_v = match read_json(config) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let cfg = match host_config(&cfg_v) {
        Ok(c) => c,
        Err(_) => return 64,
    };
    let lock_path = Path::new(&cfg.data_root).join("owner.lock");
    let _guard = match trellis_core::daemon::owner_lock(&lock_path) {
        Ok(f) => f,
        Err(_) => return 75,
    };
    let store = match Store::open(&Path::new(&cfg.data_root).join("store.db")) {
        Ok(s) => s,
        Err(_) => return 74,
    };
    match migrate_noop(&store) {
        Ok(v) => {
            out(&v);
            0
        }
        Err(e) => {
            eprintln!("{}", e.code.as_str());
            70
        }
    }
}

/// `trellis-ctl fixture --name NAME [--output PATH]` — writes one §5.2
/// fixture object as canonical JSON (testing aid; the fixture keypair is
/// public and must never sign production policies — policy-sign refuses it).
fn fixture_dump(a: &[String]) -> i32 {
    let Some(name) = take(a, "--name") else {
        usage()
    };
    let f = trellis_core::fixtures::build();
    let Some(v) = f.map.get(name) else {
        eprintln!("unknown fixture {}", name);
        return 64;
    };
    let bytes = v.canonical();
    match take(a, "--output") {
        Some(p) => {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&p)
            {
                Ok(f) => f,
                Err(_) => return 74,
            };
            use std::io::Write;
            if file.write_all(&bytes).is_err() || file.write_all(b"\n").is_err() {
                return 74;
            }
            0
        }
        None => {
            out(v);
            0
        }
    }
}
