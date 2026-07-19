#!/usr/bin/env bash
set -euo pipefail

LEFT_INPUT="${1:-}"
RIGHT_INPUT="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="${EIDOLON_PWNKIT_BENCHMARK_MATRIX_CHECKER:-$SCRIPT_DIR/check-pwnkit-benchmark-matrix.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/compare-pwnkit-benchmark-matrices.sh <left-matrix-dir|summary.json> <right-matrix-dir|summary.json>

Compares two benchmark-only pwnkit matrix summaries and determines whether the
results are comparable without blending them into qualification or Eidolon
defensive claims.
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

[[ -n "$LEFT_INPUT" && -n "$RIGHT_INPUT" ]] || { usage >&2; exit 2; }
command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"
[[ -x "$CHECKER" ]] || fail "benchmark matrix checker is not executable: $CHECKER"

LEFT_SUMMARY="$(resolve_summary_path "$LEFT_INPUT")"
RIGHT_SUMMARY="$(resolve_summary_path "$RIGHT_INPUT")"
"$CHECKER" "$LEFT_SUMMARY"
"$CHECKER" "$RIGHT_SUMMARY"

jq -n \
  --slurpfile left "$LEFT_SUMMARY" \
  --slurpfile right "$RIGHT_SUMMARY" '
  def same($a; $b): $a == $b;
  def maybe_array($value): ($value // []);
  def mismatch_reason($label; $left; $right):
    if same($left; $right) then
      empty
    else
      {
        reason: ("mismatch:" + $label),
        left: $left,
        right: $right
      }
    end;
  def count_delta($left; $right): ($right - $left);
  ($left[0]) as $lhs
  | ($right[0]) as $rhs
  | [
      mismatch_reason("comparison_scope"; $lhs.rerun_identity.comparison_scope; $rhs.rerun_identity.comparison_scope),
      mismatch_reason("task_export_sha256"; $lhs.rerun_identity.task_export_sha256; $rhs.rerun_identity.task_export_sha256),
      mismatch_reason("task_export_format"; $lhs.rerun_identity.task_export_format; $rhs.rerun_identity.task_export_format),
      mismatch_reason("imported_task_count"; $lhs.rerun_identity.imported_task_count; $rhs.rerun_identity.imported_task_count),
      mismatch_reason("benchmark_family_set"; maybe_array($lhs.rerun_identity.benchmark_family_set); maybe_array($rhs.rerun_identity.benchmark_family_set)),
      mismatch_reason("benchmark_task_id_set"; maybe_array($lhs.rerun_identity.benchmark_task_id_set); maybe_array($rhs.rerun_identity.benchmark_task_id_set)),
      mismatch_reason("benchmark_snapshot_id_set"; maybe_array($lhs.rerun_identity.benchmark_snapshot_id_set); maybe_array($rhs.rerun_identity.benchmark_snapshot_id_set)),
      mismatch_reason("benchmark_model_id_set"; maybe_array($lhs.rerun_identity.benchmark_model_id_set); maybe_array($rhs.rerun_identity.benchmark_model_id_set)),
      mismatch_reason("benchmark_prompt_bundle_hash_set"; maybe_array($lhs.rerun_identity.benchmark_prompt_bundle_hash_set); maybe_array($rhs.rerun_identity.benchmark_prompt_bundle_hash_set)),
      mismatch_reason("benchmark_validation_rule_set"; maybe_array($lhs.rerun_identity.benchmark_validation_rule_set); maybe_array($rhs.rerun_identity.benchmark_validation_rule_set)),
      mismatch_reason("benchmark_action_budget_set"; maybe_array($lhs.rerun_identity.benchmark_action_budget_set); maybe_array($rhs.rerun_identity.benchmark_action_budget_set)),
      mismatch_reason("benchmark_token_budget_set"; maybe_array($lhs.rerun_identity.benchmark_token_budget_set); maybe_array($rhs.rerun_identity.benchmark_token_budget_set)),
      mismatch_reason("benchmark_wall_clock_budget_seconds_set"; maybe_array($lhs.rerun_identity.benchmark_wall_clock_budget_seconds_set); maybe_array($rhs.rerun_identity.benchmark_wall_clock_budget_seconds_set)),
      mismatch_reason("substrate_set"; maybe_array($lhs.rerun_identity.substrate_set); maybe_array($rhs.rerun_identity.substrate_set)),
      mismatch_reason("defense_mode_set"; maybe_array($lhs.rerun_identity.defense_mode_set); maybe_array($rhs.rerun_identity.defense_mode_set)),
      mismatch_reason("runner_kind_set"; maybe_array($lhs.rerun_identity.runner_kind_set); maybe_array($rhs.rerun_identity.runner_kind_set))
    ] | map(select(. != null)) as $blocking
  | {
      schema_version: 1,
      run_kind: "pwnkit_benchmark_matrix_comparison",
      claim_posture: "benchmark_capability_only",
      generated_at: (now | todateiso8601),
      left_summary_path: $lhs.matrix_dir,
      right_summary_path: $rhs.matrix_dir,
      comparable: (($blocking | length) == 0),
      strict_manifest_match: (($lhs.manifest_sha256 // null) == ($rhs.manifest_sha256 // null)),
      blocking_reasons: $blocking,
      advisory_notes: (
        [
          if ($lhs.manifest_sha256 // null) != ($rhs.manifest_sha256 // null) then
            {
              note: "manifest_sha256_differs",
              left: ($lhs.manifest_sha256 // null),
              right: ($rhs.manifest_sha256 // null)
            }
          else
            empty
          end
        ]
      ),
      left: {
        manifest_sha256: ($lhs.manifest_sha256 // null),
        variant_count: ($lhs.variant_count // 0),
        scoreboard: ($lhs.benchmark_summary // {}),
        rerun_identity: ($lhs.rerun_identity // {})
      },
      right: {
        manifest_sha256: ($rhs.manifest_sha256 // null),
        variant_count: ($rhs.variant_count // 0),
        scoreboard: ($rhs.benchmark_summary // {}),
        rerun_identity: ($rhs.rerun_identity // {})
      },
      delta: {
        task_count: count_delta(($lhs.benchmark_summary.task_count // 0); ($rhs.benchmark_summary.task_count // 0)),
        validated_count: count_delta(($lhs.benchmark_summary.validated_count // 0); ($rhs.benchmark_summary.validated_count // 0)),
        invalidated_count: count_delta(($lhs.benchmark_summary.invalidated_count // 0); ($rhs.benchmark_summary.invalidated_count // 0)),
        inconclusive_count: count_delta(($lhs.benchmark_summary.inconclusive_count // 0); ($rhs.benchmark_summary.inconclusive_count // 0)),
        validated_rate: (($rhs.benchmark_summary.validated_rate // 0) - ($lhs.benchmark_summary.validated_rate // 0))
      }
    }
  | [
      "# pwnkit Benchmark Matrix Comparison",
      "",
      "Generated: `\(.generated_at)`",
      "",
      "Comparable: `\(.comparable)`",
      "Strict manifest match: `\(.strict_manifest_match)`",
      "",
      "## Source Export",
      "",
      "- left task export sha256: `\(.left.rerun_identity.task_export_sha256 // "none")`",
      "- right task export sha256: `\(.right.rerun_identity.task_export_sha256 // "none")`",
      "- left task export format: `\(.left.rerun_identity.task_export_format // "none")`",
      "- right task export format: `\(.right.rerun_identity.task_export_format // "none")`",
      "- left imported task count: `\(.left.rerun_identity.imported_task_count // "none")`",
      "- right imported task count: `\(.right.rerun_identity.imported_task_count // "none")`",
      "",
      "## Delta",
      "",
      "- task count delta: `\(.delta.task_count)`",
      "- validated delta: `\(.delta.validated_count)`",
      "- invalidated delta: `\(.delta.invalidated_count)`",
      "- inconclusive delta: `\(.delta.inconclusive_count)`",
      "- validated rate delta: `\(.delta.validated_rate)`",
      "",
      "## Blocking Reasons",
      ""
    ]
    + (
      if (.blocking_reasons | length) == 0 then
        ["- none"]
      else
        (.blocking_reasons | map("- `\(.reason)`"))
      end
    )
    + [
      "",
      "## Advisory Notes",
      ""
    ]
    + (
      if (.advisory_notes | length) == 0 then
        ["- none"]
      else
        (.advisory_notes | map("- `\(.note)`"))
      end
    )
    | join("\n")
' 
