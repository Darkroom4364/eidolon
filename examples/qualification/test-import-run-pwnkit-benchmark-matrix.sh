#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
IMPORTER="$SCRIPT_DIR/import-pwnkit-benchmark-tasks.sh"
RUNNER="$SCRIPT_DIR/run-pwnkit-benchmark-matrix.sh"
PACKAGER="$SCRIPT_DIR/package-pwnkit-benchmark-matrix.sh"
TASK_FIXTURE="$SCRIPT_DIR/pwnkit-benchmark-tasks.sample.jsonl"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-import-run-test.XXXXXX"
}

write_stub_runner() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"
mkdir -p "$sample_dir/raw-sample/run-1/private"

case "${EIDOLON_PWNKIT_BENCHMARK_TASK_ID:-}" in
  task-alpha)
    validation_status="validated"
    ;;
  task-beta)
    validation_status="invalidated"
    ;;
  *)
    validation_status="inconclusive"
    ;;
esac

cat > "$sample_dir/pwnkit-stability-sample.json" <<JSON
{
  "schema_version": 1,
  "run_kind": "pwnkit_benchmark_sample",
  "boundary": "scanner_qualification",
  "claim_posture": "benchmark_capability_only",
  "evaluation_lane_version": 1,
  "generated_at": "2026-07-08T00:00:00Z",
  "lane": "xbow_benchmark",
  "benchmark_family": "${EIDOLON_PWNKIT_BENCHMARK_FAMILY:-xbow_public}",
  "benchmark_task_id": "${EIDOLON_PWNKIT_BENCHMARK_TASK_ID:-unknown}",
  "benchmark_snapshot_id": "${EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID:-unknown}",
  "benchmark_model_id": "${EIDOLON_PWNKIT_BENCHMARK_MODEL_ID:-gpt-5.4}",
  "benchmark_prompt_bundle_hash": "${EIDOLON_PWNKIT_BENCHMARK_PROMPT_BUNDLE_HASH:-sha256:none}",
  "benchmark_validation_rule": "${EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE:-validated_exploit_required}",
  "substrate": "host_local",
  "defense_mode": "${EIDOLON_PWNKIT_BENCHMARK_DEFENSE_MODE:-comparison}",
  "artifact_identity": {
    "artifact_kind": "pwnkit_benchmark_sample",
    "raw_sample_summary_path": "/private/tmp/raw-sample/pwnkit-stability-sample.json",
    "validation_artifact_path": "/private/tmp/raw-sample/benchmark-validation.json"
  },
  "budget": {
    "benchmark_action_budget": ${EIDOLON_PWNKIT_BENCHMARK_ACTION_BUDGET:-40},
    "benchmark_token_budget": ${EIDOLON_PWNKIT_BENCHMARK_TOKEN_BUDGET:-120000},
    "benchmark_wall_clock_budget_seconds": ${EIDOLON_PWNKIT_BENCHMARK_WALL_CLOCK_BUDGET_SECONDS:-900},
    "observed_artifact_count": 1,
    "observed_valid_summary_count": 1
  },
  "counts": {
    "raw_artifact_count": 1,
    "raw_valid_summary_count": 1,
    "direct_findings": 0,
    "eidolon_findings": 1,
    "positive_differential_findings": 1
  },
  "validation": {
    "status": "${validation_status}",
    "validator_kind": "fixture_validator",
    "exploit_rule": "${EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE:-validated_exploit_required}",
    "notes": ["fixture benchmark validation"]
  },
  "raw_sample": {
    "run_kind": "m3_pwnkit_codex_sample",
    "strongest_claim_level": "controlled_reality_entered",
    "weakest_claim_level": "controlled_reality_entered",
    "runner_git_heads": ["fixture-head"],
    "runner_package_versions": ["fixture-version"],
    "runner_environments": ["host_mac"],
    "runner_network_topologies": ["same_host_loopback"],
    "evidence_tracks": ["upstream_current"]
  },
  "artifacts": [
    {
      "artifact_id": "raw-sample",
      "lane": "xbow_benchmark",
      "benchmark_family": "${EIDOLON_PWNKIT_BENCHMARK_FAMILY:-xbow_public}",
      "benchmark_task_id": "${EIDOLON_PWNKIT_BENCHMARK_TASK_ID:-unknown}",
      "substrate": "host_local",
      "defense_mode": "${EIDOLON_PWNKIT_BENCHMARK_DEFENSE_MODE:-comparison}",
      "artifact_identity": {
        "artifact_kind": "pwnkit_benchmark_raw_sample",
        "raw_sample_summary_path": "/private/tmp/raw-sample/pwnkit-stability-sample.json"
      },
      "validation_status": "${validation_status}",
      "strongest_claim_level": "controlled_reality_entered",
      "direct_findings": 0,
      "eidolon_findings": 1
    }
  ]
}
JSON

cat > "$sample_dir/raw-sample/pwnkit-stability-sample.json" <<'JSON'
{"schema_version":1,"run_kind":"m3_pwnkit_codex_sample","boundary":"owned_loopback_lab","generated_at":"2026-07-08T00:00:00Z","artifact_count":1,"valid_summary_count":1,"counts":{"bait_reached":1,"bait_action_observed":1,"same_session_confirmed_bait_action":1,"controlled_reality_entered":1,"direct_quiet":1,"direct_findings":0,"eidolon_findings":1,"positive_differential_findings":1},"rates":{"target_interaction_rate":1,"bait_reach_rate":1,"bait_action_rate":1,"same_session_confirmed_bait_action_rate":1,"controlled_reality_entry_rate":1,"direct_quiet_rate":1,"eidolon_finding_rate":1,"positive_differential_finding_rate":1},"claim_level_counts":[{"claim_level":"controlled_reality_entered","count":1}],"weakest_claim_level":"controlled_reality_entered","strongest_claim_level":"controlled_reality_entered","runner_git_heads":["fixture-head"],"runner_package_versions":["fixture-version"],"runner_pwnkit_fixture_ids":[],"evidence_track_counts":[{"evidence_track":"upstream_current","count":1}],"evidence_tracks":["upstream_current"],"single_evidence_track":true,"mixed_evidence_tracks":false,"unknown_evidence_track_count":0,"runner_environments":["host_mac"],"runner_network_topologies":["same_host_loopback"],"tool_fingerprint_summary":[],"source_checkout":{"all_runners_clean":true,"all_runners_origin_main_synced":true},"finding_reconciliation":{"direct_final_json_finding_total":0,"eidolon_final_json_finding_total":1,"direct_db_saved_finding_total":0,"eidolon_db_saved_finding_total":1,"direct_db_active_finding_total":0,"eidolon_db_active_finding_total":1,"any_db_saved_findings_omitted_from_final_json":false,"final_json_counts_still_drive_finding_claims":true},"no_signal_diagnostics":{"likely_cause":null,"next_questions":[]},"differential_findings":{"ready_for_differential_finding_claim":true,"positive_differential_run_count":1,"direct_finding_run_count":0,"eidolon_finding_run_count":1,"controlled_reality_without_eidolon_finding_run_count":0},"strict_stability":{"ready_for_stability_claim":true},"artifacts":[{"artifact_dir":"/private/tmp/raw-source","present":true,"evidence_track":"upstream_current","runner_git_head":"fixture-head","runner_package_version":"fixture-version","runner_git_dirty":false,"runner_origin_main":{"ahead":0,"behind":0,"in_sync":true},"runner_origin_main_in_sync":true,"runner_pwnkit_fixture":null,"runner_pwnkit_fixture_id":null,"stale_dist_guard_bypassed":false,"runner_environment":"host_mac","runner_environment_source":"env_override","runner_network_topology":"same_host_loopback","runner_os":{"kernel_name":"Darwin"},"runner_tool_fingerprint":[],"claim_level":"controlled_reality_entered","conclusion":"bait_action_observed","target_interaction_observed":true,"bait_reached":true,"bait_action_observed":true,"same_session_confirmed_bait_action":true,"controlled_reality_entered":true,"direct_finding_count":0,"eidolon_finding_count":1,"direct_final_json_finding_count":0,"eidolon_final_json_finding_count":1,"direct_db_saved_finding_count":0,"eidolon_db_saved_finding_count":1,"direct_db_active_finding_count":0,"eidolon_db_active_finding_count":1,"pwnkit_events":{"eidolon":{"tool_artifacts":1},"direct":{"tool_artifacts":1}},"target_evidence_diagnostics":{"eidolon":{"request_artifact_count":1},"direct":{"request_artifact_count":1}},"agent_error_diagnostics":{"eidolon":{"count":0,"class_counts":[]},"direct":{"count":0,"class_counts":[]}},"eidolon_proxy":{"request_count":1,"request_path_counts":[{"value":"/docs?secret=value","count":1}]},"target_correlation_diagnostics":{"pwnkit_eidolon_request_artifact_count":1,"eidolon_proxy_request_count":1,"correlated_target_request_count":1},"correlated_counts":{"target_requests":1,"bait_exposures":1,"bait_actions":1,"same_session_confirmed_bait_actions":1,"controlled_reality_entries":1},"pinned_session":{"present":true,"cookie_preserved":true},"metrics":{"bait_follow_rate":1,"same_session_confirmed_bait_follow_rate":1},"agent_trace":{"claim_level":"controlled_reality_entered"},"trace_gap":{"controlled_reality_entered":false}}]}
JSON
cat > "$sample_dir/raw-sample/benchmark-validation.json" <<JSON
{"schema_version":1,"run_kind":"pwnkit_benchmark_validation","validation_status":"${validation_status}","validator_kind":"fixture_validator","exploit_rule":"${EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE:-validated_exploit_required}","notes":["fixture benchmark validation"]}
JSON
cat > "$sample_dir/raw-sample/run-1/pwnkit-summary.json" <<'JSON'
{"schema_version":1,"run_kind":"m3_pwnkit_codex_comparison","boundary":"owned_loopback_lab","runner":{"schema_version":1,"run_kind":"m3_pwnkit_codex_runner","created_at":"2026-07-08T00:00:00Z","mode":"all","urls":{"target":"http://127.0.0.1:9001","proxy":"http://127.0.0.1:8080"},"environment":{"runner_environment":"host_mac","network_topology":"same_host_loopback"},"pwnkit":{"package_version":"fixture-version","git_head":"fixture-head","git_head_short":"fixture-head","git_head_time_seconds":1770000000,"git_dirty":false,"origin_main":{"ahead":0,"behind":0,"in_sync":true},"evidence_track":"upstream_current","fixture":{"id":null,"pinned":false},"stale_dist_guard_bypassed":false}},"runs":{"direct":{"artifact_status":"present","finding_count":0,"final_json_finding_count":0,"db_saved_finding_count":0,"db_active_finding_count":0,"pwnkit_events":{"tool_artifacts":1},"target_evidence_diagnostics":{"request_artifact_count":1},"agent_error_diagnostics":{"count":0,"class_counts":[]}},"eidolon":{"artifact_status":"present","finding_count":1,"final_json_finding_count":1,"db_saved_finding_count":1,"db_active_finding_count":1,"pwnkit_events":{"tool_artifacts":1},"target_evidence_diagnostics":{"request_artifact_count":1},"agent_error_diagnostics":{"count":0,"class_counts":[]}}}}
JSON
cat > "$sample_dir/raw-sample/run-1/agent-replay-trace-summary.json" <<'JSON'
{"schema_version":1,"run_kind":"agent_replay_trace_summary","boundary":"owned_loopback_lab","claim_level":"controlled_reality_entered"}
JSON

printf 'run_count=%s\n' "$run_count" > "$sample_dir/run-count.txt"
SH
  chmod +x "$path"
}

test_import_run_and_package_fixture_tasks() {
  local temp_dir manifest matrix_dir bundle_dir runner_stub
  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/imported-manifest.json"
  matrix_dir="$temp_dir/matrix"
  bundle_dir="$temp_dir/bundle"
  runner_stub="$temp_dir/runner.sh"

  write_stub_runner "$runner_stub"
  "$IMPORTER" "$TASK_FIXTURE" "$manifest"

  jq -e '
    .run_kind == "pwnkit_benchmark_matrix_manifest"
    and .import_metadata.import_contract_version == 1
    and .import_metadata.task_export_format == "jsonl"
    and .import_metadata.imported_task_count == 2
    and (.import_metadata.task_export_sha256 | type) == "string"
    and (.variants | length) == 2
    and .variants[0].variant_id == "xbow_task_alpha"
    and .variants[1].variant_id == "xbow_task_beta"
  ' "$manifest" >/dev/null

  EIDOLON_PWNKIT_BENCHMARK_MATRIX_RUNNER="$runner_stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  jq -e '
    .claim_posture == "benchmark_capability_only"
    and .import_metadata.import_contract_version == 1
    and .import_metadata.task_export_format == "jsonl"
    and .import_metadata.imported_task_count == 2
    and (.import_metadata.task_export_sha256 | type) == "string"
    and .rerun_identity.task_export_sha256 == .import_metadata.task_export_sha256
    and .rerun_identity.task_export_format == "jsonl"
    and .rerun_identity.imported_task_count == 2
    and .completed_variant_count == 2
    and .benchmark_summary.task_count == 2
    and .benchmark_summary.validated_count == 1
    and .benchmark_summary.invalidated_count == 1
    and .rerun_identity.benchmark_task_id_set == ["task-alpha", "task-beta"]
    and (.variants[] | select(.variant_id == "xbow_task_alpha") | .result_class == "pass")
    and (.variants[] | select(.variant_id == "xbow_task_beta") | .result_class == "fail")
  ' "$matrix_dir/pwnkit-benchmark-matrix.json" >/dev/null

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null
  [[ -f "$bundle_dir/pwnkit-benchmark-variants.json" ]]
  [[ -f "$bundle_dir/benchmark-report.md" ]]
  [[ -f "$bundle_dir/variants/xbow_task_alpha/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/variants/xbow_task_beta/pwnkit-stability-sample.json" ]]
  rg -q 'validated: `1`' "$bundle_dir/benchmark-report.md"
  rg -q 'invalidated: `1`' "$bundle_dir/benchmark-report.md"
  rg -q 'task export format: `jsonl`' "$bundle_dir/benchmark-report.md"
  rg -q 'imported task count: `2`' "$bundle_dir/benchmark-report.md"
  rg -q 'task export format: `jsonl`' "$bundle_dir/README.md"
  rg -q 'imported task count: `2`' "$bundle_dir/README.md"
}

test_import_run_and_package_fixture_tasks

printf 'benchmark import-run matrix fixture tests passed\n'
