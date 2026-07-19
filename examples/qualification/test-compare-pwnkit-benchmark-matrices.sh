#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COMPARER="$SCRIPT_DIR/compare-pwnkit-benchmark-matrices.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-compare-test.XXXXXX"
}

write_summary() {
  local path="$1"
  local manifest_sha="$2"
  local task_id="$3"
  local validated="$4"
  local invalidated="$5"
  local inconclusive="$6"

  cat > "$path" <<JSON
{
  "schema_version": 1,
  "run_kind": "pwnkit_benchmark_matrix_summary",
  "boundary": "scanner_qualification",
  "claim_posture": "benchmark_capability_only",
  "evaluation_contract_version": 1,
  "generated_at": "2026-07-08T00:00:00Z",
  "manifest_path": "/tmp/manifest.json",
  "manifest_sha256": "$manifest_sha",
  "import_metadata": {
    "import_contract_version": 1,
    "task_export_format": "jsonl",
    "task_export_sha256": "sha256:task-export",
    "imported_task_count": 1
  },
  "matrix_dir": "/tmp/matrix",
  "variant_count": 1,
  "completed_variant_count": 1,
  "planned_variant_count": 0,
  "blocked_variant_count": 0,
  "missing_variant_count": 0,
  "benchmark_summary": {
    "task_count": 1,
    "validated_count": $validated,
    "invalidated_count": $invalidated,
    "inconclusive_count": $inconclusive,
    "validated_rate": $validated
  },
  "rerun_identity": {
    "evaluation_contract_version": 1,
    "manifest_sha256": "$manifest_sha",
    "comparison_scope": "benchmark_lane_only",
    "task_export_sha256": "sha256:task-export",
    "task_export_format": "jsonl",
    "imported_task_count": 1,
    "lane_set": ["xbow_benchmark"],
    "benchmark_family_set": ["xbow_public"],
    "benchmark_task_id_set": ["$task_id"],
    "benchmark_snapshot_id_set": ["snap-001"],
    "benchmark_model_id_set": ["gpt-5.4"],
    "benchmark_prompt_bundle_hash_set": ["sha256:alpha"],
    "benchmark_validation_rule_set": ["validated_exploit_required"],
    "benchmark_action_budget_set": [40],
    "benchmark_token_budget_set": [120000],
    "benchmark_wall_clock_budget_seconds_set": [900],
    "substrate_set": ["host_local"],
    "defense_mode_set": ["comparison"],
    "runner_kind_set": ["qualification_benchmark_sample"]
  },
  "variants": [
    {
      "variant_id": "xbow_task_alpha",
      "lane": "xbow_benchmark",
      "benchmark_family": "xbow_public",
      "benchmark_task_id": "$task_id",
      "benchmark_snapshot_id": "snap-001",
      "benchmark_validation_rule": "validated_exploit_required",
      "execution_state": "completed",
      "result_class": "$(if [[ "$validated" -eq 1 ]]; then printf pass; elif [[ "$invalidated" -eq 1 ]]; then printf fail; else printf inconclusive; fi)",
      "validation_status": "$(if [[ "$validated" -eq 1 ]]; then printf validated; elif [[ "$invalidated" -eq 1 ]]; then printf invalidated; else printf inconclusive; fi)"
    }
  ]
}
JSON
}

test_comparable_when_identity_matches() {
  local temp_dir left right output
  temp_dir="$(new_temp_dir)"
  left="$temp_dir/left.json"
  right="$temp_dir/right.json"
  write_summary "$left" "sha-left" "task-alpha" 0 1 0
  write_summary "$right" "sha-right" "task-alpha" 1 0 0

  output="$("$COMPARER" "$left" "$right")"
  rg -q 'Comparable: `true`' <<<"$output"
  rg -q 'Strict manifest match: `false`' <<<"$output"
  rg -q 'validated delta: `1`' <<<"$output"
  rg -q 'left task export format: `jsonl`' <<<"$output"
  rg -q 'Blocking Reasons' <<<"$output"
  rg -q -- '- none' <<<"$output"
  rg -q 'manifest_sha256_differs' <<<"$output"
}

test_not_comparable_when_task_set_differs() {
  local temp_dir left right output
  temp_dir="$(new_temp_dir)"
  left="$temp_dir/left.json"
  right="$temp_dir/right.json"
  write_summary "$left" "sha-same" "task-alpha" 1 0 0
  write_summary "$right" "sha-same" "task-beta" 1 0 0

  output="$("$COMPARER" "$left" "$right")"
  rg -q 'Comparable: `false`' <<<"$output"
  rg -q 'Strict manifest match: `true`' <<<"$output"
  rg -q 'mismatch:benchmark_task_id_set' <<<"$output"
}

test_not_comparable_when_prompt_bundle_differs() {
  local temp_dir left right output
  temp_dir="$(new_temp_dir)"
  left="$temp_dir/left.json"
  right="$temp_dir/right.json"
  write_summary "$left" "sha-same" "task-alpha" 1 0 0
  write_summary "$right" "sha-same" "task-alpha" 1 0 0

  jq '.rerun_identity.benchmark_prompt_bundle_hash_set = ["sha256:beta"]' "$right" > "$right.tmp"
  mv "$right.tmp" "$right"

  output="$("$COMPARER" "$left" "$right")"
  rg -q 'Comparable: `false`' <<<"$output"
  rg -q 'mismatch:benchmark_prompt_bundle_hash_set' <<<"$output"
}

test_not_comparable_when_budget_differs() {
  local temp_dir left right output
  temp_dir="$(new_temp_dir)"
  left="$temp_dir/left.json"
  right="$temp_dir/right.json"
  write_summary "$left" "sha-same" "task-alpha" 1 0 0
  write_summary "$right" "sha-same" "task-alpha" 1 0 0

  jq '.rerun_identity.benchmark_action_budget_set = [80]' "$right" > "$right.tmp"
  mv "$right.tmp" "$right"

  output="$("$COMPARER" "$left" "$right")"
  rg -q 'Comparable: `false`' <<<"$output"
  rg -q 'mismatch:benchmark_action_budget_set' <<<"$output"
}

test_not_comparable_when_task_export_differs() {
  local temp_dir left right output
  temp_dir="$(new_temp_dir)"
  left="$temp_dir/left.json"
  right="$temp_dir/right.json"
  write_summary "$left" "sha-same" "task-alpha" 1 0 0
  write_summary "$right" "sha-same" "task-alpha" 1 0 0

  jq '.rerun_identity.task_export_sha256 = "sha256:other-export" | .import_metadata.task_export_sha256 = "sha256:other-export"' "$right" > "$right.tmp"
  mv "$right.tmp" "$right"

  output="$("$COMPARER" "$left" "$right")"
  rg -q 'Comparable: `false`' <<<"$output"
  rg -q 'mismatch:task_export_sha256' <<<"$output"
}

test_comparable_when_identity_matches
test_not_comparable_when_task_set_differs
test_not_comparable_when_prompt_bundle_differs
test_not_comparable_when_budget_differs
test_not_comparable_when_task_export_differs

printf 'benchmark matrix comparison fixture tests passed\n'
