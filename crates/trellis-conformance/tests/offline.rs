use std::process::Command;

#[test]
fn offline_conformance_suite_has_no_failures() {
    let output = Command::new(env!("CARGO_BIN_EXE_trellis-conformance"))
        .args(["--profile", "offline-v1"])
        .output()
        .expect("run conformance suite");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report = trellis_core::json::parse(&output.stdout).expect("JSON report");
    let totals = report.get("totals").expect("totals");
    assert_eq!(totals.get("fail"), Some(&trellis_core::json::Value::int(0)));
    assert_eq!(
        totals.get("pass"),
        Some(&trellis_core::json::Value::int(79))
    );
    assert_eq!(
        totals.get("unsupported"),
        Some(&trellis_core::json::Value::int(2))
    );
}
