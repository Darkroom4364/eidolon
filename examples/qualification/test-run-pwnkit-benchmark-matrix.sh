#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-benchmark-matrix.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-matrix-run-test.XXXXXX"
}

write_stub_runner() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"
mkdir -p "$sample_dir/raw-sample/run-1/private"

if [[ "${EIDOLON_PWNKIT_BENCHMARK_DRY_RUN:-0}" == "1" ]]; then
  printf 'run_count=%s\n' "$run_count" > "$sample_dir/sample-plan.txt"
  exit 0
fi

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

mkdir -p "$sample_dir/raw-sample/run-1/private"
cat > "$sample_dir/raw-sample/pwnkit-stability-sample.json" <<'JSON'
{"schema_version":1,"run_kind":"m3_pwnkit_codex_sample","artifact_count":1,"valid_summary_count":1,"counts":{"direct_findings":0,"eidolon_findings":1,"positive_differential_findings":1},"strongest_claim_level":"controlled_reality_entered","weakest_claim_level":"controlled_reality_entered","runner_git_heads":["fixture-head"],"runner_package_versions":["fixture-version"],"runner_environments":["host_mac"],"runner_network_topologies":["same_host_loopback"],"evidence_tracks":["upstream_current"]}
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
SH
  chmod +x "$path"
}

write_manifest() {
  local manifest="$1"
  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_benchmark_matrix_manifest",
    boundary: "scanner_qualification",
    claim_posture: "benchmark_capability_only",
    variants: [
      {
        variant_id: "xbow_task_alpha",
        enabled: true,
        lane: "xbow_benchmark",
        benchmark_family: "xbow_public",
        benchmark_task_id: "task-alpha",
        benchmark_snapshot_id: "snap-001",
        benchmark_model_id: "gpt-5.4",
        benchmark_prompt_bundle_hash: "sha256:alpha",
        benchmark_validation_rule: "validated_exploit_required",
        benchmark_action_budget: 40,
        benchmark_token_budget: 120000,
        benchmark_wall_clock_budget_seconds: 900,
        substrate: "host_local",
        defense_mode: "comparison",
        runner_kind: "qualification_benchmark_sample",
        run_count: 1
      },
      {
        variant_id: "xbow_task_beta",
        enabled: true,
        lane: "xbow_benchmark",
        benchmark_family: "xbow_public",
        benchmark_task_id: "task-beta",
        benchmark_snapshot_id: "snap-002",
        benchmark_model_id: "gpt-5.4",
        benchmark_prompt_bundle_hash: "sha256:beta",
        benchmark_validation_rule: "validated_exploit_required",
        benchmark_action_budget: 30,
        benchmark_token_budget: 90000,
        benchmark_wall_clock_budget_seconds: 600,
        substrate: "host_local",
        defense_mode: "comparison",
        runner_kind: "qualification_benchmark_sample",
        run_count: 1
      },
      {
        variant_id: "xbow_task_blocked",
        enabled: false,
        lane: "xbow_benchmark",
        benchmark_family: "xbow_public",
        benchmark_task_id: "task-gamma",
        benchmark_snapshot_id: "snap-003",
        benchmark_validation_rule: "validated_exploit_required",
        substrate: "host_local",
        defense_mode: "comparison",
        runner_kind: "qualification_benchmark_sample",
        blocked_reason: "task export pending"
      }
    ]
  }' > "$manifest"
}

test_dry_run_writes_plan() {
  local temp_dir manifest matrix_dir runner_stub
  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  runner_stub="$temp_dir/runner.sh"
  write_manifest "$manifest"
  write_stub_runner "$runner_stub"

  EIDOLON_PWNKIT_BENCHMARK_MATRIX_DRY_RUN=1 \
    EIDOLON_PWNKIT_BENCHMARK_MATRIX_RUNNER="$runner_stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  [[ -f "$matrix_dir/benchmark-plan.json" ]]
  [[ -f "$matrix_dir/xbow_task_alpha/sample-plan.txt" ]]
  [[ -f "$matrix_dir/xbow_task_beta/sample-plan.txt" ]]
  [[ -f "$matrix_dir/xbow_task_blocked/variant-status.txt" ]]
  jq -e '
    .run_kind == "pwnkit_benchmark_matrix_summary"
    and .planned_variant_count == 2
    and .blocked_variant_count == 1
    and .benchmark_summary.validated_count == 0
    and .benchmark_summary.inconclusive_count == 3
    and .rerun_identity.comparison_scope == "benchmark_lane_only"
  ' "$matrix_dir/pwnkit-benchmark-matrix.json" >/dev/null
}

test_execution_collects_benchmark_matrix() {
  local temp_dir manifest matrix_dir runner_stub
  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  runner_stub="$temp_dir/runner.sh"
  write_manifest "$manifest"
  write_stub_runner "$runner_stub"

  EIDOLON_PWNKIT_BENCHMARK_MATRIX_RUNNER="$runner_stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  jq -e '
    .run_kind == "pwnkit_benchmark_matrix_summary"
    and .claim_posture == "benchmark_capability_only"
    and .completed_variant_count == 2
    and .blocked_variant_count == 1
    and .benchmark_summary.task_count == 3
    and .benchmark_summary.validated_count == 1
    and .benchmark_summary.invalidated_count == 1
    and .benchmark_summary.inconclusive_count == 1
    and .rerun_identity.benchmark_task_id_set == ["task-alpha", "task-beta", "task-gamma"]
    and .rerun_identity.benchmark_prompt_bundle_hash_set == ["sha256:alpha", "sha256:beta"]
    and .rerun_identity.benchmark_validation_rule_set == ["validated_exploit_required"]
    and .rerun_identity.benchmark_action_budget_set == [30, 40]
    and .rerun_identity.benchmark_token_budget_set == [90000, 120000]
    and .rerun_identity.benchmark_wall_clock_budget_seconds_set == [600, 900]
    and (.variants[] | select(.variant_id == "xbow_task_alpha") | .result_class == "pass")
    and (.variants[] | select(.variant_id == "xbow_task_beta") | .result_class == "fail")
    and (.variants[] | select(.variant_id == "xbow_task_blocked") | .execution_state == "blocked")
  ' "$matrix_dir/pwnkit-benchmark-matrix.json" >/dev/null
}

test_dry_run_writes_plan
test_execution_collects_benchmark_matrix

printf 'benchmark matrix runner fixture tests passed\n'
