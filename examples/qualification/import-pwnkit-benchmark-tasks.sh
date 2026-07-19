#!/usr/bin/env bash
set -euo pipefail

INPUT_PATH="${1:-}"
OUTPUT_PATH="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="${EIDOLON_PWNKIT_BENCHMARK_IMPORT_CHECKER:-$SCRIPT_DIR/check-pwnkit-benchmark-task-export.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/import-pwnkit-benchmark-tasks.sh <tasks.json|tasks.jsonl> <manifest.json>

Converts a benchmark task export into a pwnkit benchmark-matrix manifest.

Accepted input shapes:
  1. JSON array of task objects
  2. JSONL stream with one task object per line

Supported task fields:
  benchmark_family | family
  benchmark_task_id | task_id | id
  benchmark_snapshot_id | snapshot_id
  benchmark_model_id | model_id
  benchmark_prompt_bundle_hash | prompt_bundle_hash
  benchmark_validation_rule | validation_rule
  benchmark_action_budget | action_budget
  benchmark_token_budget | token_budget
  benchmark_wall_clock_budget_seconds | wall_clock_budget_seconds
  substrate
  defense_mode
  enabled
  run_count
  notes
  env

Optional defaults via environment:
  EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY
  EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE
  EIDOLON_PWNKIT_BENCHMARK_IMPORT_SUBSTRATE
  EIDOLON_PWNKIT_BENCHMARK_IMPORT_DEFENSE_MODE
  EIDOLON_PWNKIT_BENCHMARK_IMPORT_RUN_COUNT
  EIDOLON_PWNKIT_BENCHMARK_IMPORT_CHECKER
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_positive_integer_or_empty() {
  local name="$1"
  local value="$2"
  if [[ -n "$value" && ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be empty or a positive integer, got: $value"
  fi
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  shasum -a 256 "$path" | awk '{print $1}'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ -n "$INPUT_PATH" && -n "$OUTPUT_PATH" ]] || { usage >&2; exit 2; }
command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  fail "missing required tool: sha256sum or shasum"
fi
[[ -f "$INPUT_PATH" ]] || fail "input file not found: $INPUT_PATH"
[[ -x "$CHECKER" ]] || fail "benchmark task export checker is not executable: $CHECKER"

require_positive_integer_or_empty "EIDOLON_PWNKIT_BENCHMARK_IMPORT_RUN_COUNT" "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_RUN_COUNT:-}"
"$CHECKER" "$INPUT_PATH"
input_sha256="$(sha256_file "$INPUT_PATH")"

if jq -e 'type == "array"' "$INPUT_PATH" >/dev/null 2>&1; then
  task_count="$(jq 'length' "$INPUT_PATH")"
  INPUT_SHA256="$input_sha256" TASK_COUNT="$task_count" jq -e -n \
    --slurpfile tasks "$INPUT_PATH" \
    --arg default_family "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY:-}" \
    --arg default_validation_rule "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE:-validated_exploit_required}" \
    --arg default_substrate "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_SUBSTRATE:-host_local}" \
    --arg default_defense_mode "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_DEFENSE_MODE:-comparison}" \
    --arg default_run_count "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_RUN_COUNT:-1}" '
    def variant_id_for($task_id):
      ("xbow_" + ($task_id | gsub("[^A-Za-z0-9]+"; "_") | ascii_downcase | gsub("^_+"; "") | gsub("_+$"; "")));
    {
      schema_version: 1,
      run_kind: "pwnkit_benchmark_matrix_manifest",
      boundary: "scanner_qualification",
      claim_posture: "benchmark_capability_only",
      import_metadata: {
        import_contract_version: 1,
        task_export_format: "json_array",
        task_export_sha256: $ENV.INPUT_SHA256,
        imported_task_count: ($ENV.TASK_COUNT | tonumber)
      },
      variants: (
        $tasks[0]
        | map(
            (.benchmark_task_id // .task_id // .id // null) as $task_id
            | (.benchmark_snapshot_id // .snapshot_id // null) as $snapshot_id
            | (.benchmark_family // .family // $default_family) as $family
            | (.benchmark_validation_rule // .validation_rule // $default_validation_rule) as $validation_rule
            | if ($task_id == null or $task_id == "" or $snapshot_id == null or $snapshot_id == "" or $family == "" or $validation_rule == "") then
                error("task export missing required benchmark fields")
              else
                {
                  variant_id: (variant_id_for($task_id)),
                  enabled: (if has("enabled") then .enabled else true end),
                  lane: "xbow_benchmark",
                  benchmark_family: $family,
                  benchmark_task_id: $task_id,
                  benchmark_snapshot_id: $snapshot_id,
                  benchmark_model_id: (.benchmark_model_id // .model_id // null),
                  benchmark_prompt_bundle_hash: (.benchmark_prompt_bundle_hash // .prompt_bundle_hash // null),
                  benchmark_validation_rule: $validation_rule,
                  benchmark_action_budget: (.benchmark_action_budget // .action_budget // null),
                  benchmark_token_budget: (.benchmark_token_budget // .token_budget // null),
                  benchmark_wall_clock_budget_seconds: (.benchmark_wall_clock_budget_seconds // .wall_clock_budget_seconds // null),
                  substrate: (.substrate // $default_substrate),
                  defense_mode: (.defense_mode // $default_defense_mode),
                  runner_kind: "qualification_benchmark_sample",
                  run_count: (.run_count // ($default_run_count | tonumber)),
                  notes: (.notes // null),
                  env: (.env // null)
                }
              end
          )
      )
    }
  ' > "$OUTPUT_PATH"
  exit 0
fi

task_count="$(jq -s 'length' "$INPUT_PATH")"
INPUT_SHA256="$input_sha256" TASK_COUNT="$task_count" jq -e -s \
  --arg default_family "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY:-}" \
  --arg default_validation_rule "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE:-validated_exploit_required}" \
  --arg default_substrate "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_SUBSTRATE:-host_local}" \
  --arg default_defense_mode "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_DEFENSE_MODE:-comparison}" \
  --arg default_run_count "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_RUN_COUNT:-1}" '
  def variant_id_for($task_id):
    ("xbow_" + ($task_id | gsub("[^A-Za-z0-9]+"; "_") | ascii_downcase | gsub("^_+"; "") | gsub("_+$"; "")));
  {
    schema_version: 1,
    run_kind: "pwnkit_benchmark_matrix_manifest",
    boundary: "scanner_qualification",
    claim_posture: "benchmark_capability_only",
    import_metadata: {
      import_contract_version: 1,
      task_export_format: "jsonl",
      task_export_sha256: $ENV.INPUT_SHA256,
      imported_task_count: ($ENV.TASK_COUNT | tonumber)
    },
    variants: (
      map(
        (.benchmark_task_id // .task_id // .id // null) as $task_id
        | (.benchmark_snapshot_id // .snapshot_id // null) as $snapshot_id
        | (.benchmark_family // .family // $default_family) as $family
        | (.benchmark_validation_rule // .validation_rule // $default_validation_rule) as $validation_rule
        | if ($task_id == null or $task_id == "" or $snapshot_id == null or $snapshot_id == "" or $family == "" or $validation_rule == "") then
            error("task export missing required benchmark fields")
          else
            {
              variant_id: (variant_id_for($task_id)),
              enabled: (if has("enabled") then .enabled else true end),
              lane: "xbow_benchmark",
              benchmark_family: $family,
              benchmark_task_id: $task_id,
              benchmark_snapshot_id: $snapshot_id,
              benchmark_model_id: (.benchmark_model_id // .model_id // null),
              benchmark_prompt_bundle_hash: (.benchmark_prompt_bundle_hash // .prompt_bundle_hash // null),
              benchmark_validation_rule: $validation_rule,
              benchmark_action_budget: (.benchmark_action_budget // .action_budget // null),
              benchmark_token_budget: (.benchmark_token_budget // .token_budget // null),
              benchmark_wall_clock_budget_seconds: (.benchmark_wall_clock_budget_seconds // .wall_clock_budget_seconds // null),
              substrate: (.substrate // $default_substrate),
              defense_mode: (.defense_mode // $default_defense_mode),
              runner_kind: "qualification_benchmark_sample",
              run_count: (.run_count // ($default_run_count | tonumber)),
              notes: (.notes // null),
              env: (.env // null)
            }
          end
      )
    )
  }
' "$INPUT_PATH" > "$OUTPUT_PATH"
