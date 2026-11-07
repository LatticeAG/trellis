use std::process::Command;
use trellis_core::json::{self, Value};

#[test]
fn doctor_reports_failed_checks_and_matching_exit_status() {
    let config = format!("{}/../../examples/host.json", env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(env!("CARGO_BIN_EXE_trellis-ctl"))
        .args(["doctor", "--config", &config, "--json"])
        .output()
        .expect("run doctor");
    let report = json::parse(&output.stdout).expect("doctor JSON");
    let checks = report.get("checks").expect("checks");
    let failed = match report.get("failed_checks") {
        Some(Value::Arr(failed)) => failed,
        _ => panic!("missing failed_checks"),
    };
    for name in [
        "privileges",
        "cgroup",
        "bpf",
        "seccomp",
        "namespaces",
        "image",
        "workspace",
        "storage",
        "guard",
    ] {
        assert_eq!(
            failed.contains(&Value::str(name)),
            checks.get(name) == Some(&Value::Bool(false))
        );
    }
    if !failed.is_empty() {
        assert_eq!(report.get("reason"), Some(&Value::str("UNSUPPORTED_HOST")));
        assert_eq!(report.get("ready"), Some(&Value::Bool(false)));
        assert_eq!(output.status.code(), Some(65));
    } else if report.get("ready") == Some(&Value::Bool(true)) {
        assert_eq!(report.get("reason"), Some(&Value::Null));
        assert!(output.status.success());
    } else {
        assert_eq!(output.status.code(), Some(65));
        assert_ne!(report.get("reason"), Some(&Value::Null));
    }
}
