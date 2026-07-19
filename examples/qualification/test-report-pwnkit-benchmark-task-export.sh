#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPORTER="$SCRIPT_DIR/report-pwnkit-benchmark-task-export.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-task-report-test.XXXXXX"
}

test_reports_valid_jsonl_export() {
  local temp_dir input output
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.jsonl"
  cat > "$input" <<'JSONL'
{"id":"task-alpha","snapshot_id":"snap-001","prompt_bundle_hash":"sha256:alpha","action_budget":40}
{"id":"task-beta","snapshot_id":"snap-002","prompt_bundle_hash":"sha256:beta","token_budget":90000}
JSONL

  output="$(
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE=validated_exploit_required \
    "$REPORTER" "$input"
  )"

  rg -q '^# pwnkit Benchmark Task Export' <<<"$output"
  rg -q 'task export format: `jsonl`' <<<"$output"
  rg -q 'imported task count: `2`' <<<"$output"
  rg -q 'normalized variant ids: `xbow_task_alpha`, `xbow_task_beta`' <<<"$output"
  rg -q 'validation rules: `validated_exploit_required`' <<<"$output"
}

test_rejects_invalid_export() {
  local temp_dir input status=0
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.jsonl"
  cat > "$input" <<'JSONL'
{"id":"task-alpha","snapshot_id":"snap-001"}
{"id":"task-alpha","snapshot_id":"snap-002"}
JSONL

  output="$(
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE=validated_exploit_required \
    "$REPORTER" "$input" 2>&1
  )" || status="$?"

  [[ "$status" -ne 0 ]]
  rg -q 'duplicate benchmark task ids' <<<"$output"
}

test_reports_valid_jsonl_export
test_rejects_invalid_export

printf 'benchmark task export reporter fixture tests passed\n'
