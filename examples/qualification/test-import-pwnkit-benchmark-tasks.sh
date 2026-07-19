#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
IMPORTER="$SCRIPT_DIR/import-pwnkit-benchmark-tasks.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-import-test.XXXXXX"
}

test_imports_json_array() {
  local temp_dir input output
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.json"
  output="$temp_dir/manifest.json"

  cat > "$input" <<'JSON'
[
  {
    "family": "xbow_public",
    "task_id": "task-alpha",
    "snapshot_id": "snap-001",
    "model_id": "gpt-5.4",
    "prompt_bundle_hash": "sha256:alpha",
    "validation_rule": "validated_exploit_required",
    "action_budget": 40,
    "token_budget": 120000,
    "wall_clock_budget_seconds": 900
  },
  {
    "family": "xbow_public",
    "task_id": "task-beta",
    "snapshot_id": "snap-002",
    "validation_rule": "validated_exploit_required",
    "enabled": false,
    "notes": "disabled fixture"
  }
]
JSON

  "$IMPORTER" "$input" "$output"

  jq -e '
    .run_kind == "pwnkit_benchmark_matrix_manifest"
    and .import_metadata.import_contract_version == 1
    and .import_metadata.task_export_format == "json_array"
    and .import_metadata.imported_task_count == 2
    and (.import_metadata.task_export_sha256 | type) == "string"
    and (.variants | length) == 2
    and .variants[0].variant_id == "xbow_task_alpha"
    and .variants[0].benchmark_family == "xbow_public"
    and .variants[0].benchmark_task_id == "task-alpha"
    and .variants[0].benchmark_snapshot_id == "snap-001"
    and .variants[0].benchmark_model_id == "gpt-5.4"
    and .variants[0].benchmark_prompt_bundle_hash == "sha256:alpha"
    and .variants[0].benchmark_action_budget == 40
    and .variants[1].enabled == false
    and .variants[1].notes == "disabled fixture"
  ' "$output" >/dev/null
}

test_imports_jsonl_with_defaults() {
  local temp_dir input output
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.jsonl"
  output="$temp_dir/manifest.json"

  cat > "$input" <<'JSONL'
{"id":"task-gamma","snapshot_id":"snap-003","prompt_bundle_hash":"sha256:gamma"}
{"id":"task-delta","snapshot_id":"snap-004","action_budget":25,"run_count":2}
JSONL

  EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE=validated_exploit_required \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_SUBSTRATE=host_local \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_DEFENSE_MODE=comparison \
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_RUN_COUNT=1 \
    "$IMPORTER" "$input" "$output"

  jq -e '
    (.variants | length) == 2
    and .import_metadata.import_contract_version == 1
    and .import_metadata.task_export_format == "jsonl"
    and .import_metadata.imported_task_count == 2
    and (.import_metadata.task_export_sha256 | type) == "string"
    and .variants[0].benchmark_family == "xbow_public"
    and .variants[0].benchmark_task_id == "task-gamma"
    and .variants[0].benchmark_validation_rule == "validated_exploit_required"
    and .variants[0].substrate == "host_local"
    and .variants[0].defense_mode == "comparison"
    and .variants[0].run_count == 1
    and .variants[1].run_count == 2
    and .variants[1].benchmark_action_budget == 25
  ' "$output" >/dev/null
}

test_rejects_missing_required_fields() {
  local temp_dir input output status=0
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.jsonl"
  output="$temp_dir/manifest.json"

  cat > "$input" <<'JSONL'
{"id":"task-epsilon"}
JSONL

  output_text="$("$IMPORTER" "$input" "$output" 2>&1)" || status="$?"
  [[ "$status" -ne 0 ]]
  rg -q 'task export missing required benchmark fields' <<<"$output_text"
}

test_rejects_duplicate_task_ids() {
  local temp_dir input output status=0
  temp_dir="$(new_temp_dir)"
  input="$temp_dir/tasks.jsonl"
  output="$temp_dir/manifest.json"

  cat > "$input" <<'JSONL'
{"id":"task-alpha","snapshot_id":"snap-001"}
{"id":"task-alpha","snapshot_id":"snap-002"}
JSONL

  output_text="$(
    EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY=xbow_public \
    "$IMPORTER" "$input" "$output" 2>&1
  )" || status="$?"
  [[ "$status" -ne 0 ]]
  rg -q 'duplicate benchmark task ids' <<<"$output_text"
}

test_imports_json_array
test_imports_jsonl_with_defaults
test_rejects_missing_required_fields
test_rejects_duplicate_task_ids

printf 'benchmark task import fixture tests passed\n'
