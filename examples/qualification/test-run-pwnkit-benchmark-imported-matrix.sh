#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-benchmark-imported-matrix.sh"
TASK_FIXTURE="$SCRIPT_DIR/pwnkit-benchmark-tasks.sample.jsonl"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-imported-runner-test.XXXXXX"
}

write_stub_matrix_runner() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

manifest="$1"
matrix_dir="$2"
mkdir -p "$matrix_dir/xbow_task_alpha" "$matrix_dir/xbow_task_beta"
cp "$manifest" "$matrix_dir/pwnkit-benchmark-variants.json"
cat > "$matrix_dir/benchmark-plan.json" <<'JSON'
{"schema_version":1,"run_kind":"pwnkit_benchmark_matrix_plan","claim_posture":"benchmark_capability_only"}
JSON
cat > "$matrix_dir/pwnkit-benchmark-matrix.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "pwnkit_benchmark_matrix_summary",
  "boundary": "scanner_qualification",
  "claim_posture": "benchmark_capability_only",
  "evaluation_contract_version": 1,
  "generated_at": "2026-07-08T00:00:00Z",
  "manifest_path": "/tmp/imported-manifest.json",
  "manifest_sha256": "sha256:manifest",
  "import_metadata": {
    "import_contract_version": 1,
    "task_export_format": "jsonl",
    "task_export_sha256": "sha256:task-export",
    "imported_task_count": 2
  },
  "matrix_dir": "/tmp/matrix",
  "variant_count": 2,
  "completed_variant_count": 2,
  "planned_variant_count": 0,
  "blocked_variant_count": 0,
  "missing_variant_count": 0,
  "benchmark_summary": {
    "task_count": 2,
    "validated_count": 1,
    "invalidated_count": 1,
    "inconclusive_count": 0,
    "validated_rate": 0.5
  },
  "rerun_identity": {
    "evaluation_contract_version": 1,
    "manifest_sha256": "sha256:manifest",
    "comparison_scope": "benchmark_lane_only",
    "lane_set": ["xbow_benchmark"],
    "task_export_sha256": "sha256:task-export",
    "task_export_format": "jsonl",
    "imported_task_count": 2,
    "benchmark_family_set": ["xbow_public"],
    "benchmark_task_id_set": ["task-alpha","task-beta"],
    "benchmark_snapshot_id_set": ["snap-001","snap-002"],
    "benchmark_model_id_set": ["gpt-5.4"],
    "benchmark_prompt_bundle_hash_set": ["sha256:alpha","sha256:beta"],
    "benchmark_validation_rule_set": ["validated_exploit_required"],
    "benchmark_action_budget_set": [30,40],
    "benchmark_token_budget_set": [90000,120000],
    "benchmark_wall_clock_budget_seconds_set": [600,900],
    "substrate_set": ["host_local"],
    "defense_mode_set": ["comparison"],
    "runner_kind_set": ["qualification_benchmark_sample"]
  },
  "variants": [
    {
      "variant_id": "xbow_task_alpha",
      "lane": "xbow_benchmark",
      "benchmark_family": "xbow_public",
      "benchmark_task_id": "task-alpha",
      "benchmark_snapshot_id": "snap-001",
      "benchmark_validation_rule": "validated_exploit_required",
      "execution_state": "completed",
      "result_class": "pass",
      "validation_status": "validated"
    },
    {
      "variant_id": "xbow_task_beta",
      "lane": "xbow_benchmark",
      "benchmark_family": "xbow_public",
      "benchmark_task_id": "task-beta",
      "benchmark_snapshot_id": "snap-002",
      "benchmark_validation_rule": "validated_exploit_required",
      "execution_state": "completed",
      "result_class": "fail",
      "validation_status": "invalidated"
    }
  ]
}
JSON

mkdir -p "$matrix_dir/xbow_task_alpha" "$matrix_dir/xbow_task_beta"
cat > "$matrix_dir/xbow_task_alpha/pwnkit-stability-sample.json" <<'JSON'
{"schema_version":1,"run_kind":"pwnkit_benchmark_sample","boundary":"scanner_qualification","claim_posture":"benchmark_capability_only","evaluation_lane_version":1,"generated_at":"2026-07-08T00:00:00Z","lane":"xbow_benchmark","benchmark_family":"xbow_public","benchmark_task_id":"task-alpha","benchmark_snapshot_id":"snap-001","benchmark_validation_rule":"validated_exploit_required","substrate":"host_local","defense_mode":"comparison","artifact_identity":{"artifact_kind":"pwnkit_benchmark_sample","raw_sample_summary_path":"/private/tmp/raw-sample/pwnkit-stability-sample.json","validation_artifact_path":"/private/tmp/raw-sample/benchmark-validation.json"},"budget":{"benchmark_action_budget":40,"benchmark_token_budget":120000,"benchmark_wall_clock_budget_seconds":900,"observed_artifact_count":1,"observed_valid_summary_count":1},"counts":{"raw_artifact_count":1,"raw_valid_summary_count":1,"direct_findings":0,"eidolon_findings":1,"positive_differential_findings":1},"validation":{"status":"validated","validator_kind":"fixture_validator","exploit_rule":"validated_exploit_required","notes":["fixture"]},"raw_sample":{"run_kind":"m3_pwnkit_codex_sample","strongest_claim_level":"controlled_reality_entered","weakest_claim_level":"controlled_reality_entered","runner_git_heads":["fixture-head"],"runner_package_versions":["fixture-version"],"runner_environments":["host_mac"],"runner_network_topologies":["same_host_loopback"],"evidence_tracks":["upstream_current"]},"artifacts":[{"artifact_id":"raw-sample","lane":"xbow_benchmark","benchmark_family":"xbow_public","benchmark_task_id":"task-alpha","substrate":"host_local","defense_mode":"comparison","artifact_identity":{"artifact_kind":"pwnkit_benchmark_raw_sample","raw_sample_summary_path":"/private/tmp/raw-sample/pwnkit-stability-sample.json"},"validation_status":"validated","strongest_claim_level":"controlled_reality_entered","direct_findings":0,"eidolon_findings":1}]}
JSON
cp "$matrix_dir/xbow_task_alpha/pwnkit-stability-sample.json" "$matrix_dir/xbow_task_beta/pwnkit-stability-sample.json"
mkdir -p "$matrix_dir/xbow_task_alpha/raw-sample/run-1" "$matrix_dir/xbow_task_beta/raw-sample/run-1"
cat > "$matrix_dir/xbow_task_alpha/raw-sample/pwnkit-stability-sample.json" <<'JSON'
{"schema_version":1,"run_kind":"m3_pwnkit_codex_sample","boundary":"owned_loopback_lab","generated_at":"2026-07-08T00:00:00Z","artifact_count":1,"valid_summary_count":1,"counts":{"bait_reached":1,"bait_action_observed":1,"same_session_confirmed_bait_action":1,"controlled_reality_entered":1,"direct_quiet":1,"direct_findings":0,"eidolon_findings":1,"positive_differential_findings":1},"rates":{"target_interaction_rate":1,"bait_reach_rate":1,"bait_action_rate":1,"same_session_confirmed_bait_action_rate":1,"controlled_reality_entry_rate":1,"direct_quiet_rate":1,"eidolon_finding_rate":1,"positive_differential_finding_rate":1},"claim_level_counts":[{"claim_level":"controlled_reality_entered","count":1}],"weakest_claim_level":"controlled_reality_entered","strongest_claim_level":"controlled_reality_entered","runner_git_heads":["fixture-head"],"runner_package_versions":["fixture-version"],"runner_pwnkit_fixture_ids":[],"evidence_track_counts":[{"evidence_track":"upstream_current","count":1}],"evidence_tracks":["upstream_current"],"single_evidence_track":true,"mixed_evidence_tracks":false,"unknown_evidence_track_count":0,"runner_environments":["host_mac"],"runner_network_topologies":["same_host_loopback"],"tool_fingerprint_summary":[],"source_checkout":{"all_runners_clean":true,"all_runners_origin_main_synced":true},"finding_reconciliation":{"direct_final_json_finding_total":0,"eidolon_final_json_finding_total":1,"direct_db_saved_finding_total":0,"eidolon_db_saved_finding_total":1,"direct_db_active_finding_total":0,"eidolon_db_active_finding_total":1,"any_db_saved_findings_omitted_from_final_json":false,"final_json_counts_still_drive_finding_claims":true},"no_signal_diagnostics":{"likely_cause":null,"next_questions":[]},"differential_findings":{"ready_for_differential_finding_claim":true,"positive_differential_run_count":1,"direct_finding_run_count":0,"eidolon_finding_run_count":1,"controlled_reality_without_eidolon_finding_run_count":0},"strict_stability":{"ready_for_stability_claim":true},"artifacts":[{"artifact_dir":"/private/tmp/raw-source","present":true,"evidence_track":"upstream_current","runner_git_head":"fixture-head","runner_package_version":"fixture-version","runner_git_dirty":false,"runner_origin_main":{"ahead":0,"behind":0,"in_sync":true},"runner_origin_main_in_sync":true,"runner_pwnkit_fixture":null,"runner_pwnkit_fixture_id":null,"stale_dist_guard_bypassed":false,"runner_environment":"host_mac","runner_environment_source":"env_override","runner_network_topology":"same_host_loopback","runner_os":{"kernel_name":"Darwin"},"runner_tool_fingerprint":[],"claim_level":"controlled_reality_entered","conclusion":"bait_action_observed","target_interaction_observed":true,"bait_reached":true,"bait_action_observed":true,"same_session_confirmed_bait_action":true,"controlled_reality_entered":true,"direct_finding_count":0,"eidolon_finding_count":1,"direct_final_json_finding_count":0,"eidolon_final_json_finding_count":1,"direct_db_saved_finding_count":0,"eidolon_db_saved_finding_count":1,"direct_db_active_finding_count":0,"eidolon_db_active_finding_count":1,"pwnkit_events":{"eidolon":{"tool_artifacts":1},"direct":{"tool_artifacts":1}},"target_evidence_diagnostics":{"eidolon":{"request_artifact_count":1},"direct":{"request_artifact_count":1}},"agent_error_diagnostics":{"eidolon":{"count":0,"class_counts":[]},"direct":{"count":0,"class_counts":[]}},"eidolon_proxy":{"request_count":1,"request_path_counts":[{"value":"/docs?secret=value","count":1}]},"target_correlation_diagnostics":{"pwnkit_eidolon_request_artifact_count":1,"eidolon_proxy_request_count":1,"correlated_target_request_count":1},"correlated_counts":{"target_requests":1,"bait_exposures":1,"bait_actions":1,"same_session_confirmed_bait_actions":1,"controlled_reality_entries":1},"pinned_session":{"present":true,"cookie_preserved":true},"metrics":{"bait_follow_rate":1,"same_session_confirmed_bait_follow_rate":1},"agent_trace":{"claim_level":"controlled_reality_entered"},"trace_gap":{"controlled_reality_entered":false}}]}
JSON
cp "$matrix_dir/xbow_task_alpha/raw-sample/pwnkit-stability-sample.json" "$matrix_dir/xbow_task_beta/raw-sample/pwnkit-stability-sample.json"
cat > "$matrix_dir/xbow_task_alpha/raw-sample/benchmark-validation.json" <<'JSON'
{"schema_version":1,"run_kind":"pwnkit_benchmark_validation","validation_status":"validated","validator_kind":"fixture_validator","exploit_rule":"validated_exploit_required","notes":["fixture"]}
JSON
cp "$matrix_dir/xbow_task_alpha/raw-sample/benchmark-validation.json" "$matrix_dir/xbow_task_beta/raw-sample/benchmark-validation.json"
cat > "$matrix_dir/xbow_task_alpha/raw-sample/run-1/pwnkit-summary.json" <<'JSON'
{"schema_version":1,"run_kind":"m3_pwnkit_codex_comparison","boundary":"owned_loopback_lab","runner":{"schema_version":1,"run_kind":"m3_pwnkit_codex_runner","created_at":"2026-07-08T00:00:00Z","mode":"all","urls":{"target":"http://127.0.0.1:9001","proxy":"http://127.0.0.1:8080"},"environment":{"runner_environment":"host_mac","network_topology":"same_host_loopback"},"pwnkit":{"package_version":"fixture-version","git_head":"fixture-head","git_head_short":"fixture-head","git_head_time_seconds":1770000000,"git_dirty":false,"origin_main":{"ahead":0,"behind":0,"in_sync":true},"evidence_track":"upstream_current","fixture":{"id":null,"pinned":false},"stale_dist_guard_bypassed":false}},"runs":{"direct":{"artifact_status":"present","finding_count":0,"final_json_finding_count":0,"db_saved_finding_count":0,"db_active_finding_count":0,"pwnkit_events":{"tool_artifacts":1},"target_evidence_diagnostics":{"request_artifact_count":1},"agent_error_diagnostics":{"count":0,"class_counts":[]}},"eidolon":{"artifact_status":"present","finding_count":1,"final_json_finding_count":1,"db_saved_finding_count":1,"db_active_finding_count":1,"pwnkit_events":{"tool_artifacts":1},"target_evidence_diagnostics":{"request_artifact_count":1},"agent_error_diagnostics":{"count":0,"class_counts":[]}}}}
JSON
cp "$matrix_dir/xbow_task_alpha/raw-sample/run-1/pwnkit-summary.json" "$matrix_dir/xbow_task_beta/raw-sample/run-1/pwnkit-summary.json"
cat > "$matrix_dir/xbow_task_alpha/raw-sample/run-1/agent-replay-trace-summary.json" <<'JSON'
{"schema_version":1,"run_kind":"agent_replay_trace_summary","boundary":"owned_loopback_lab","claim_level":"controlled_reality_entered"}
JSON
cp "$matrix_dir/xbow_task_alpha/raw-sample/run-1/agent-replay-trace-summary.json" "$matrix_dir/xbow_task_beta/raw-sample/run-1/agent-replay-trace-summary.json"
SH
  chmod +x "$path"
}

test_full_imported_workflow() {
  local temp_dir run_dir stub_runner output
  temp_dir="$(new_temp_dir)"
  run_dir="$temp_dir/run"
  stub_runner="$temp_dir/stub-matrix-runner.sh"
  write_stub_matrix_runner "$stub_runner"

  output="$(
    EIDOLON_PWNKIT_BENCHMARK_IMPORTED_RUNNER="$stub_runner" \
    "$RUNNER" "$TASK_FIXTURE" "$run_dir"
  )"

  [[ -f "$run_dir/task-export-report.md" ]]
  [[ -f "$run_dir/imported-manifest.json" ]]
  [[ -f "$run_dir/matrix/pwnkit-benchmark-matrix.json" ]]
  [[ -f "$run_dir/benchmark-report.md" ]]
  [[ -f "$run_dir/bundle/README.md" ]]
  rg -q 'task export report:' <<<"$output"
  rg -q 'benchmark bundle dir:' <<<"$output"
  rg -q '^# pwnkit Benchmark Task Export' "$run_dir/task-export-report.md"
  rg -q '^# pwnkit Benchmark Matrix' "$run_dir/benchmark-report.md"
  rg -q 'task export format: `jsonl`' "$run_dir/benchmark-report.md"
  rg -q 'imported task count: `2`' "$run_dir/bundle/README.md"
}

test_full_imported_workflow

printf 'benchmark imported workflow fixture tests passed\n'
