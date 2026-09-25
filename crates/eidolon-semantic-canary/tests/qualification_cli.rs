use std::process::Command;

use eidolon_semantic_canary::{export_qualification_summary_json, qualify_held_out};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_eidolon-semantic-canary-qualify");

#[test]
fn cli_emits_exact_summary_only_qualification_artifact() {
    let output = Command::new(BIN).output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let expected = export_qualification_summary_json(&qualify_held_out().unwrap()).unwrap();
    assert_eq!(output.stdout.strip_suffix(b"\n").unwrap(), expected);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["held_out"], true);
    assert_eq!(value["repetitions"], 3);
    assert!(value["fixed_seed"].as_u64().is_some());
    for forbidden in [
        "reference",
        "candidate",
        "results",
        "Synthetic kiln",
        "heldout_equivalent_reordered",
    ] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(forbidden));
    }
}

#[test]
fn cli_help_and_argument_rejection_are_bounded() {
    let help = Command::new(BIN).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(
        String::from_utf8_lossy(&help.stdout).contains("Usage: eidolon-semantic-canary-qualify")
    );

    let rejected = Command::new(BIN).arg("--bogus").output().unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("accepts no arguments"));
}
