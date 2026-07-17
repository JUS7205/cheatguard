//! Integration test: the `cheatguard scan <pid>` CLI must produce valid JSON
//! with the expected schema, regardless of platform support.

use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cheatguard"))
}

#[test]
fn scan_cli_outputs_valid_json_with_schema() {
    // Scan our own process — always exists on every platform.
    let pid = std::process::id();
    let output = cli()
        .arg("scan")
        .arg(pid.to_string())
        .output()
        .expect("failed to launch cheatguard binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "scan produced no stdout (stderr: {})",
        String::from_utf8_lossy(&output.stderr)
    );

    // Must be parseable JSON.
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("scan stdout is not valid JSON");

    // Required schema fields present.
    let obj = value.as_object().expect("report is a JSON object");
    for field in [
        "pid",
        "engine",
        "scanned_at",
        "module_count",
        "matches",
        "active_signals",
        "score",
        "verdict",
        "supported",
    ] {
        assert!(obj.contains_key(field), "report missing field '{field}'");
    }

    // score is an integer 0..=100.
    let score = value["score"].as_u64().expect("score is integer");
    assert!(score <= 100, "score out of range: {score}");

    // verdict is one of the known tiers (case-sensitive).
    let verdict = value["verdict"].as_str().expect("verdict is string");
    assert!(
        matches!(verdict, "CLEAN" | "SUSPICIOUS" | "MALICIOUS"),
        "unexpected verdict: {verdict}"
    );

    // matches is an array.
    assert!(value["matches"].is_array(), "matches must be an array");
    assert!(value["active_signals"].is_array(), "active_signals must be an array");
}

#[test]
fn scan_cli_rejects_missing_pid() {
    let output = cli().arg("scan").output().expect("launch");
    assert!(!output.status.success(), "scan with no pid must fail");
}

#[test]
fn scan_cli_rejects_invalid_pid() {
    let output = cli().arg("scan").arg("not-a-number").output().expect("launch");
    assert!(!output.status.success(), "scan with bad pid must fail");
}
