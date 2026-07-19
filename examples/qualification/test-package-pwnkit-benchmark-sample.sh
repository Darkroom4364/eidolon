#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-benchmark-sample.sh"
PACKAGER="$SCRIPT_DIR/package-pwnkit-benchmark-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-package-test.XXXXXX"
}

write_stub_raw_runner() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"
mkdir -p "$sample_dir/run-1/private"

cat > "$sample_dir/pwnkit-stability-sample.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_sample",
  "boundary": "owned_loopback_lab",
  "generated_at": "2026-07-06T00:00:00Z",
  "artifact_count": 1,
  "valid_summary_count": 1,
  "counts": {
    "direct_findings": 0,
    "eidolon_findings": 1,
    "positive_differential_findings": 1
  },
  "strongest_claim_level": "controlled_reality_entered",
  "weakest_claim_level": "controlled_reality_entered",
  "runner_git_heads": ["fixture-head"],
  "runner_package_versions": ["fixture-version"],
  "runner_pwnkit_fixture_ids": [],
  "runner_environments": ["host_mac"],
  "runner_network_topologies": ["same_host_loopback"],
  "evidence_tracks": ["upstream_current"],
  "single_evidence_track": true,
  "mixed_evidence_tracks": false,
  "unknown_evidence_track_count": 0,
  "tool_fingerprint_summary": [],
  "source_checkout": {
    "all_runners_clean": true,
    "all_runners_origin_main_synced": true
  },
  "finding_reconciliation": {
    "direct_final_json_finding_total": 0,
    "eidolon_final_json_finding_total": 1,
    "direct_db_saved_finding_total": 0,
    "eidolon_db_saved_finding_total": 1,
    "direct_db_active_finding_total": 0,
    "eidolon_db_active_finding_total": 1,
    "any_db_saved_findings_omitted_from_final_json": false,
    "final_json_counts_still_drive_finding_claims": true
  },
  "no_signal_diagnostics": {"likely_cause": null, "next_questions": []},
  "differential_findings": {
    "ready_for_differential_finding_claim": true,
    "positive_differential_run_count": 1,
    "direct_finding_run_count": 0,
    "eidolon_finding_run_count": 1,
    "controlled_reality_without_eidolon_finding_run_count": 0
  },
  "strict_stability": {"ready_for_stability_claim": true},
  "artifacts": [
    {
      "artifact_dir": "/private/tmp/raw-source",
      "present": true,
      "evidence_track": "upstream_current",
      "runner_git_head": "fixture-head",
      "runner_package_version": "fixture-version",
      "runner_git_dirty": false,
      "runner_origin_main": {"ahead":0,"behind":0,"in_sync":true},
      "runner_origin_main_in_sync": true,
      "runner_pwnkit_fixture": null,
      "runner_pwnkit_fixture_id": null,
      "stale_dist_guard_bypassed": false,
      "runner_environment": "host_mac",
      "runner_environment_source": "env_override",
      "runner_network_topology": "same_host_loopback",
      "runner_os": {"kernel_name": "Darwin"},
      "runner_tool_fingerprint": [],
      "claim_level": "controlled_reality_entered",
      "conclusion": "bait_action_observed",
      "target_interaction_observed": true,
      "bait_reached": true,
      "bait_action_observed": true,
      "same_session_confirmed_bait_action": true,
      "controlled_reality_entered": true,
      "direct_finding_count": 0,
      "eidolon_finding_count": 1,
      "direct_final_json_finding_count": 0,
      "eidolon_final_json_finding_count": 1,
      "direct_db_saved_finding_count": 0,
      "eidolon_db_saved_finding_count": 1,
      "direct_db_active_finding_count": 0,
      "eidolon_db_active_finding_count": 1,
      "pwnkit_events": {"eidolon":{"tool_artifacts":1},"direct":{"tool_artifacts":1}},
      "target_evidence_diagnostics": {"eidolon":{"request_artifact_count":1},"direct":{"request_artifact_count":1}},
      "agent_error_diagnostics": {"eidolon":{"count":0,"class_counts":[]},"direct":{"count":0,"class_counts":[]}},
      "eidolon_proxy": {"request_count":1,"request_path_counts":[{"value":"/docs?secret=value","count":1}]},
      "target_correlation_diagnostics": {"pwnkit_eidolon_request_artifact_count":1,"eidolon_proxy_request_count":1,"correlated_target_request_count":1},
      "correlated_counts": {"target_requests":1,"bait_exposures":1,"bait_actions":1,"same_session_confirmed_bait_actions":1,"controlled_reality_entries":1},
      "pinned_session": {"present":true,"cookie_preserved":true},
      "metrics": {"bait_follow_rate":1,"same_session_confirmed_bait_follow_rate":1},
      "agent_trace": {"claim_level":"controlled_reality_entered"},
      "trace_gap": {"controlled_reality_entered":false}
    }
  ]
}
JSON

cat > "$sample_dir/benchmark-validation.json" <<'JSON'
{"schema_version":1,"run_kind":"pwnkit_benchmark_validation","validation_status":"validated","validator_kind":"fixture_validator","exploit_rule":"validated_exploit_required","notes":["fixture benchmark validation"]}
JSON

cat > "$sample_dir/run-1/pwnkit-summary.json" <<'JSON'
{"schema_version":1,"run_kind":"m3_pwnkit_codex_comparison","boundary":"owned_loopback_lab","artifact_dir":"/private/tmp/raw-source","runner":{"schema_version":1,"run_kind":"m3_pwnkit_codex_runner","created_at":"2026-07-06T00:00:00Z","mode":"all","urls":{"target":"http://127.0.0.1:9001","proxy":"http://127.0.0.1:8080"},"environment":{"runner_environment":"host_mac","network_topology":"same_host_loopback"},"pwnkit":{"package_version":"fixture-version","git_head":"fixture-head","git_head_short":"fixture-head","git_head_time_seconds":1770000000,"git_dirty":false,"origin_main":{"ahead":0,"behind":0,"in_sync":true},"evidence_track":"upstream_current","fixture":{"id":null,"pinned":false},"stale_dist_guard_bypassed":false}},"runs":{"direct":{"artifact_status":"present","finding_count":0,"final_json_finding_count":0,"db_saved_finding_count":0,"db_active_finding_count":0,"pwnkit_events":{"tool_artifacts":1},"target_evidence_diagnostics":{"request_artifact_count":1},"agent_error_diagnostics":{"count":0,"class_counts":[]}},"eidolon":{"artifact_status":"present","finding_count":1,"final_json_finding_count":1,"db_saved_finding_count":1,"db_active_finding_count":1,"pwnkit_events":{"tool_artifacts":1},"target_evidence_diagnostics":{"request_artifact_count":1},"agent_error_diagnostics":{"count":0,"class_counts":[]}}}}
JSON

cat > "$sample_dir/run-1/agent-replay-trace-summary.json" <<'JSON'
{"schema_version":1,"run_kind":"agent_replay_trace_summary","boundary":"owned_loopback_lab","claim_level":"controlled_reality_entered"}
JSON
SH
  chmod +x "$path"
}

test_packager_creates_benchmark_bundle() {
  local temp_dir runner_stub sample_dir bundle_dir
  temp_dir="$(new_temp_dir)"
  runner_stub="$temp_dir/raw-runner.sh"
  sample_dir="$temp_dir/sample"
  bundle_dir="$temp_dir/bundle"
  write_stub_raw_runner "$runner_stub"

  EIDOLON_PWNKIT_BENCHMARK_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_TASK_ID=task-alpha \
    EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID=snap-001 \
    EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE=validated_exploit_required \
    EIDOLON_PWNKIT_BENCHMARK_RAW_RUNNER="$runner_stub" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  "$PACKAGER" "$sample_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]]
  [[ -f "$bundle_dir/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/raw-sample/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/SHA256SUMS" ]]
  rg -q 'benchmark-capability bundle' "$bundle_dir/README.md"
  jq -e '
    .claim_posture == "benchmark_capability_only"
    and .lane == "xbow_benchmark"
    and .artifact_identity.raw_sample_summary_path == "<source-artifact-path-omitted>"
  ' "$bundle_dir/pwnkit-stability-sample.json" >/dev/null
}

test_packager_creates_benchmark_bundle

printf 'benchmark sample package fixture tests passed\n'
