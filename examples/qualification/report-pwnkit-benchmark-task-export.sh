#!/usr/bin/env bash
set -euo pipefail

INPUT_PATH="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="${EIDOLON_PWNKIT_BENCHMARK_IMPORT_CHECKER:-$SCRIPT_DIR/check-pwnkit-benchmark-task-export.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/report-pwnkit-benchmark-task-export.sh <tasks.json|tasks.jsonl>

Validates a benchmark task export and emits a Markdown preflight summary for the
external task set before manifest import or benchmark execution.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  shasum -a 256 "$path" | awk '{print $1}'
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
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  fail "missing required tool: sha256sum or shasum"
fi
[[ -f "$INPUT_PATH" ]] || fail "input file not found: $INPUT_PATH"
[[ -x "$CHECKER" ]] || fail "benchmark task export checker is not executable: $CHECKER"

"$CHECKER" "$INPUT_PATH"

export_format="jsonl"
if jq -e 'type == "array"' "$INPUT_PATH" >/dev/null 2>&1; then
  export_format="json_array"
fi

canonical_json_array "$INPUT_PATH" | jq -r \
  --arg input_path "$INPUT_PATH" \
  --arg task_export_sha256 "$(sha256_file "$INPUT_PATH")" \
  --arg export_format "$export_format" \
  --arg default_family "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_FAMILY:-}" \
  --arg default_validation_rule "${EIDOLON_PWNKIT_BENCHMARK_IMPORT_VALIDATION_RULE:-validated_exploit_required}" '
  def maybe_list($values):
    if ($values // []) | length == 0 then
      "none"
    else
      ($values | map("`" + . + "`") | join(", "))
    end;
  def variant_id_for($task_id):
    ("xbow_" + ($task_id | gsub("[^A-Za-z0-9]+"; "_") | ascii_downcase | gsub("^_+"; "") | gsub("_+$"; "")));
  map(
    (.benchmark_task_id // .task_id // .id) as $task_id
    | {
        task_id: $task_id,
        variant_id: variant_id_for($task_id),
        family: (.benchmark_family // .family // $default_family),
        snapshot_id: (.benchmark_snapshot_id // .snapshot_id),
        model_id: (.benchmark_model_id // .model_id // null),
        prompt_bundle_hash: (.benchmark_prompt_bundle_hash // .prompt_bundle_hash // null),
        validation_rule: (.benchmark_validation_rule // .validation_rule // $default_validation_rule),
        action_budget: (.benchmark_action_budget // .action_budget // null),
        token_budget: (.benchmark_token_budget // .token_budget // null),
        wall_clock_budget_seconds: (.benchmark_wall_clock_budget_seconds // .wall_clock_budget_seconds // null)
      }
  ) as $tasks
  | [
      "# pwnkit Benchmark Task Export",
      "",
      "- input path: `\($input_path)`",
      "- task export sha256: `\($task_export_sha256)`",
      "- task export format: `\($export_format)`",
      "- imported task count: `\($tasks | length)`",
      "- benchmark families: \(maybe_list($tasks | map(.family) | unique))",
      "- benchmark task ids: \(maybe_list($tasks | map(.task_id) | unique))",
      "- benchmark snapshots: \(maybe_list($tasks | map(.snapshot_id) | unique))",
      "- benchmark models: \(maybe_list($tasks | map(.model_id) | map(select(. != null and . != "")) | unique))",
      "- prompt bundles: \(maybe_list($tasks | map(.prompt_bundle_hash) | map(select(. != null and . != "")) | unique))",
      "- validation rules: \(maybe_list($tasks | map(.validation_rule) | unique))",
      "- normalized variant ids: \(maybe_list($tasks | map(.variant_id) | unique))",
      "- action budgets: \(maybe_list(($tasks | map(.action_budget) | map(select(. != null)) | unique) | map(tostring)))",
      "- token budgets: \(maybe_list(($tasks | map(.token_budget) | map(select(. != null)) | unique) | map(tostring)))",
      "- wall clock budgets: \(maybe_list(($tasks | map(.wall_clock_budget_seconds) | map(select(. != null)) | unique) | map(tostring)))",
      "",
      "## Tasks",
      ""
    ]
    + ($tasks | map("- task=`\(.task_id)` variant=`\(.variant_id)` family=`\(.family)` snapshot=`\(.snapshot_id)` validation=`\(.validation_rule)`"))
    | join("\n")
  '
