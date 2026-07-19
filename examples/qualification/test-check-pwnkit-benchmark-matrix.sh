#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="$SCRIPT_DIR/check-pwnkit-benchmark-matrix.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-matrix-check-test.XXXXXX"
}

write_summary() {
  local path="$1"
  cat > "$path" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "pwnkit_benchmark_matrix_summary",
  "boundary": "scanner_qualification",
  "claim_posture": "benchmark_capability_only",
  "evaluation_contract_version": 1,
  "generated_at": "2026-07-08T00:00:00Z",
  "manifest_path": "/tmp/manifest.json",
  "manifest_sha256": "sha256:manifest",
  "matrix_dir": "/tmp/matrix",
  "variant_count": 2,
  "completed_variant_count": 1,
  "planned_variant_count": 0,
  "blocked_variant_count": 1,
  "missing_variant_count": 0,
  "benchmark_summary": {
    "task_count": 2,
    "validated_count": 1,
    "invalidated_count": 0,
    "inconclusive_count": 1,
    "validated_rate": 0.5
  },
  "rerun_identity": {
    "evaluation_contract_version": 1,
    "manifest_sha256": "sha256:manifest",
    "comparison_scope": "benchmark_lane_only",
    "lane_set": ["xbow_benchmark"],
    "benchmark_family_set": ["xbow_public"],
    "benchmark_task_id_set": ["task-alpha", "task-beta"],
    "benchmark_snapshot_id_set": ["snap-001", "snap-002"],
    "benchmark_model_id_set": ["gpt-5.4"],
    "benchmark_prompt_bundle_hash_set": ["sha256:alpha", "sha256:beta"],
    "benchmark_validation_rule_set": ["validated_exploit_required"],
    "benchmark_action_budget_set": [30, 40],
    "benchmark_token_budget_set": [90000, 120000],
    "benchmark_wall_clock_budget_seconds_set": [600, 900],
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
      "execution_state": "blocked",
      "result_class": "inconclusive",
      "validation_status": "blocked"
    }
  ]
}
JSON
}

test_checker_accepts_valid_matrix() {
  local temp_dir summary
  temp_dir="$(new_temp_dir)"
  summary="$temp_dir/pwnkit-benchmark-matrix.json"
  write_summary "$summary"
  "$CHECKER" "$summary"
}

test_checker_rejects_lane_drift() {
  local temp_dir summary output status=0
  temp_dir="$(new_temp_dir)"
  summary="$temp_dir/pwnkit-benchmark-matrix.json"
  write_summary "$summary"
  jq '.variants[1].lane = "eidolon_owned_target"' "$summary" > "$summary.tmp"
  mv "$summary.tmp" "$summary"
  output="$("$CHECKER" "$summary" 2>&1)" || status="$?"
  [[ "$status" -eq 2 ]]
  rg -q 'invalid benchmark matrix contract' <<<"$output"
}

test_checker_rejects_inconsistent_counts() {
  local temp_dir summary output status=0
  temp_dir="$(new_temp_dir)"
  summary="$temp_dir/pwnkit-benchmark-matrix.json"
  write_summary "$summary"
  jq '.benchmark_summary.validated_count = 2' "$summary" > "$summary.tmp"
  mv "$summary.tmp" "$summary"
  output="$("$CHECKER" "$summary" 2>&1)" || status="$?"
  [[ "$status" -eq 2 ]]
  rg -q 'invalid benchmark matrix contract' <<<"$output"
}

test_checker_accepts_valid_matrix
test_checker_rejects_lane_drift
test_checker_rejects_inconsistent_counts

printf 'benchmark matrix checker fixture tests passed\n'
