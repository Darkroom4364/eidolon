#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="$SCRIPT_DIR/check-pwnkit-benchmark-task-export.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-task-check-test.XXXXXX"
}

test_accepts_valid_jsonl() {
  local temp_dir input
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.jsonl"
  cat > "$input" <<'JSONL'
{"id":"task-alpha","snapshot_id":"snap-001","prompt_bundle_hash":"sha256:alpha","action_budget":40}
{"id":"task-beta","snapshot_id":"snap-002","prompt_bundle_hash":"sha256:beta","run_count":2}
JSONL

  EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE=validated_exploit_required \
    "$CHECKER" "$input"
}

test_rejects_duplicate_task_ids() {
  local temp_dir input output status=0
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.jsonl"
  cat > "$input" <<'JSONL'
{"id":"task-alpha","snapshot_id":"snap-001"}
{"id":"task-alpha","snapshot_id":"snap-002"}
JSONL

  output="$(
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE=validated_exploit_required \
    "$CHECKER" "$input" 2>&1
  )" || status="$?"
  [[ "$status" -ne 0 ]]
  rg -q 'duplicate benchmark task ids' <<<"$output"
}

test_rejects_variant_id_collisions() {
  local temp_dir input output status=0
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.json"
  cat > "$input" <<'JSON'
[
  {"id":"task alpha","snapshot_id":"snap-001"},
  {"id":"task-alpha","snapshot_id":"snap-002"}
]
JSON

  output="$(
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE=validated_exploit_required \
    "$CHECKER" "$input" 2>&1
  )" || status="$?"
  [[ "$status" -ne 0 ]]
  rg -q 'duplicate benchmark variant ids' <<<"$output"
}

test_rejects_invalid_budgets() {
  local temp_dir input output status=0
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.jsonl"
  cat > "$input" <<'JSONL'
{"id":"task-alpha","snapshot_id":"snap-001","action_budget":0}
JSONL

  output="$(
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE=validated_exploit_required \
    "$CHECKER" "$input" 2>&1
  )" || status="$?"
  [[ "$status" -ne 0 ]]
  rg -q 'non-positive or non-integer benchmark budgets' <<<"$output"
}

test_accepts_valid_jsonl
test_rejects_duplicate_task_ids
test_rejects_variant_id_collisions
test_rejects_invalid_budgets

printf 'benchmark task export checker fixture tests passed\n'
