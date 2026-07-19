#!/usr/bin/env bash
set -euo pipefail

BENCHMARK_ARTIFACT="${1:-${EIDOLON_PWNKIT_BENCHMARK_ARTIFACT:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="${EIDOLON_PWNKIT_BENCHMARK_MATRIX_CHECKER:-$SCRIPT_DIR/check-pwnkit-benchmark-matrix.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/report-pwnkit-benchmark-matrix.sh <matrix-dir|pwnkit-benchmark-matrix.json>
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

resolve_summary_path() {
  local path="$1"
  if [[ -d "$path" ]]; then
    path="$path/pwnkit-benchmark-matrix.json"
  fi
  [[ -f "$path" ]] || fail "benchmark matrix summary not found: $path"
  printf '%s' "$path"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ -n "$BENCHMARK_ARTIFACT" ]] || fail "pass a matrix directory or pwnkit-benchmark-matrix.json"
command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"
[[ -x "$CHECKER" ]] || fail "benchmark matrix checker is not executable: $CHECKER"

SUMMARY_PATH="$(resolve_summary_path "$BENCHMARK_ARTIFACT")"
"$CHECKER" "$SUMMARY_PATH"

jq -r '
  def maybe_list($values):
    if ($values // []) | length == 0 then "none" else ($values | map("`" + . + "`") | join(", ")) end;
  def variant_line:
    "- `\(.variant_id)` task=`\(.benchmark_task_id)` family=`\(.benchmark_family)` snapshot=`\(.benchmark_snapshot_id)` state=`\(.execution_state)` result=`\(.result_class)` validation=`\(.validation_status)` defense=`\(.defense_mode)` substrate=`\(.substrate)` basis=`\(.interpretation_basis)`";
  [
    "# pwnkit Benchmark Matrix",
    "",
    "Generated: `\(.generated_at)`",
    "",
    "Claim posture: `benchmark_capability_only`",
    "## Scoreboard",
    "",
    "- tasks: `\(.benchmark_summary.task_count)`",
    "- validated: `\(.benchmark_summary.validated_count)`",
    "- invalidated: `\(.benchmark_summary.invalidated_count)`",
    "- inconclusive: `\(.benchmark_summary.inconclusive_count)`",
    "- validated rate: `\(.benchmark_summary.validated_rate)`",
    "",
    "## Rerun Identity",
    "",
    "- manifest sha256: `\(.rerun_identity.manifest_sha256)`",
    "- comparison scope: `\(.rerun_identity.comparison_scope)`",
    "- task export sha256: `\(.rerun_identity.task_export_sha256 // "none")`",
    "- task export format: `\(.rerun_identity.task_export_format // "none")`",
    "- imported task count: `\(.rerun_identity.imported_task_count // "none")`",
    "- benchmark families: \(maybe_list(.rerun_identity.benchmark_family_set))",
    "- benchmark tasks: \(maybe_list(.rerun_identity.benchmark_task_id_set))",
    "- benchmark snapshots: \(maybe_list(.rerun_identity.benchmark_snapshot_id_set))",
    "- benchmark models: \(maybe_list(.rerun_identity.benchmark_model_id_set))",
    "- prompt bundles: \(maybe_list(.rerun_identity.benchmark_prompt_bundle_hash_set))",
    "- validation rules: \(maybe_list(.rerun_identity.benchmark_validation_rule_set))",
    "- action budgets: \(maybe_list((.rerun_identity.benchmark_action_budget_set // []) | map(tostring)))",
    "- token budgets: \(maybe_list((.rerun_identity.benchmark_token_budget_set // []) | map(tostring)))",
    "- wall clock budgets: \(maybe_list((.rerun_identity.benchmark_wall_clock_budget_seconds_set // []) | map(tostring)))",
    "- substrates: \(maybe_list(.rerun_identity.substrate_set))",
    "- defense modes: \(maybe_list(.rerun_identity.defense_mode_set))",
    "",
    "## Variants",
    ""
  ] + (.variants | map(variant_line)) | join("\n")
' "$SUMMARY_PATH"
