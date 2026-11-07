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
    let vectors = report.get("vectors").and_then(|v| v.as_arr()).unwrap();
    assert_eq!(vectors.len(), 81);
    for id in 1..=81 {
        let passed = trellis_core::json::Value::str(format!("pass TV-T--{id:02}"));
        let unsupported = trellis_core::json::Value::str(format!("unsupported TV-T--{id:02}"));
        if id == 67 {
            assert!(vectors.contains(&unsupported));
        } else if id == 66 {
            // This vector runs when the TypeScript CLI has been built.
            assert!(vectors.contains(&passed) || vectors.contains(&unsupported));
        } else {
            assert!(vectors.contains(&passed), "vector {id} did not pass");
        }
    }
    let passes = totals.get("pass").and_then(|v| v.as_int()).unwrap();
    let unsupported = totals.get("unsupported").and_then(|v| v.as_int()).unwrap();
    assert_eq!(passes + unsupported, 81);
    assert!((79..=80).contains(&passes));
}
