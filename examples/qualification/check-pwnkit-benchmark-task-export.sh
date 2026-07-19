#!/usr/bin/env bash
set -euo pipefail

INPUT_PATH="${1:-}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/check-pwnkit-benchmark-task-export.sh <tasks.json|tasks.jsonl>

Fails closed when a benchmark task export is malformed, missing required task
identity after defaults, contains duplicate task ids, or would collapse into
duplicate benchmark variant ids during import.

Accepted input shapes:
  1. JSON array of task objects
  2. JSONL stream with one task object per line

Optional defaults via environment:
  EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY
  EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

canonical_json_array() {
  local input="$1"
  if jq -e 'type == "array"' "$input" >/dev/null 2>&1; then
    cat "$input"
    return
  fi
  jq -e -s '.' "$input"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ -n "$INPUT_PATH" ]] || { usage >&2; exit 2; }
command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"
[[ -f "$INPUT_PATH" ]] || fail "input file not found: $INPUT_PATH"

canonical_json_array "$INPUT_PATH" | jq -e \
  --arg default_family "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY:-}" \
  --arg default_validation_rule "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE:-validated_exploit_required}" '
  def variant_id_for($task_id):
    ("xbow_" + ($task_id | gsub("[^A-Za-z0-9]+"; "_") | ascii_downcase | gsub("^_+"; "") | gsub("_+$"; "")));
  def normalized:
    map(
      (.benchmark_task_id // .task_id // .id // null) as $task_id
      | (.benchmark_snapshot_id // .snapshot_id // null) as $snapshot_id
      | (.benchmark_family // .family // $default_family) as $family
      | (.benchmark_validation_rule // .validation_rule // $default_validation_rule) as $validation_rule
      | {
          task_id: $task_id,
          snapshot_id: $snapshot_id,
          family: $family,
          validation_rule: $validation_rule,
          variant_id: (if $task_id == null or $task_id == "" then null else variant_id_for($task_id) end),
          action_budget: (.benchmark_action_budget // .action_budget // null),
          token_budget: (.benchmark_token_budget // .token_budget // null),
          wall_clock_budget_seconds: (.benchmark_wall_clock_budget_seconds // .wall_clock_budget_seconds // null),
          enabled: (if has("enabled") then .enabled else true end),
          run_count: (.run_count // null),
          env: (.env // null)
        }
    );
  def valid_budget($value):
    ($value == null) or (($value | type) == "number" and ($value | floor) == $value and $value > 0);
  def valid_boolean($value):
    ($value | type) == "boolean";
  def valid_run_count($value):
    ($value == null) or (($value | type) == "number" and ($value | floor) == $value and $value > 0);
  def valid_env($value):
    ($value == null) or (
      ($value | type) == "object"
      and all(($value | to_entries[]) ; (
        (.key | type) == "string"
        and (
          (.value | type) == "string"
          or (.value | type) == "number"
          or (.value | type) == "boolean"
        )
      ))
    );
  normalized as $tasks
  | ($tasks | map(select(.task_id == null or .task_id == "" or .snapshot_id == null or .snapshot_id == "" or .family == "" or .validation_rule == ""))) as $missing
  | ($tasks | group_by(.task_id) | map(select((.[0].task_id != null) and (length > 1))) | map(.[0].task_id)) as $duplicate_tasks
  | ($tasks | group_by(.variant_id) | map(select((.[0].variant_id != null) and (length > 1))) | map(.[0].variant_id)) as $duplicate_variants
  | if ($missing | length) > 0 then
      error("task export missing required benchmark fields")
    elif ($duplicate_tasks | length) > 0 then
      error("task export contains duplicate benchmark task ids: " + ($duplicate_tasks | join(",")))
    elif ($duplicate_variants | length) > 0 then
      error("task export collapses to duplicate benchmark variant ids: " + ($duplicate_variants | join(",")))
    elif any($tasks[]; (valid_budget(.action_budget) | not) or (valid_budget(.token_budget) | not) or (valid_budget(.wall_clock_budget_seconds) | not)) then
      error("task export contains non-positive or non-integer benchmark budgets")
    elif any($tasks[]; valid_boolean(.enabled) | not) then
      error("task export contains non-boolean enabled values")
    elif any($tasks[]; valid_run_count(.run_count) | not) then
      error("task export contains invalid run_count values")
    elif any($tasks[]; valid_env(.env) | not) then
      error("task export contains invalid env payloads")
    else
      true
    end
  ' >/dev/null || exit $?

