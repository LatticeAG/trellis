use std::process::Command;

#[test]
fn missing_or_invalid_fd_reports_usage() {
    for args in [vec![], vec!["--fd", "invalid"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_trellis-guard"))
            .args(args)
            .output()
            .expect("run guard");
        assert_eq!(output.status.code(), Some(64));
        assert!(String::from_utf8_lossy(&output.stderr).contains("usage: trellis-guard --fd N"));
    }
}
