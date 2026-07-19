#!/usr/bin/env bash
set -euo pipefail

SUMMARY_FILE="${1:-}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/check-pwnkit-benchmark-matrix.sh <pwnkit-benchmark-matrix.json>

Fails closed when a benchmark matrix summary drifts outside the benchmark-only
contract, carries mixed lanes, or reports inconsistent aggregate counts.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$SUMMARY_FILE" || ! -f "$SUMMARY_FILE" ]]; then
  fail "benchmark matrix summary not found; pass pwnkit-benchmark-matrix.json"
fi

command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"

jq -e '
  .schema_version == 1
  and .run_kind == "pwnkit_benchmark_matrix_summary"
  and .boundary == "scanner_qualification"
  and .claim_posture == "benchmark_capability_only"
  and .evaluation_contract_version == 1
  and (
    .import_metadata == null
    or (
      (.import_metadata | type == "object")
      and ((.import_metadata.import_contract_version // 1) == 1)
      and (.import_metadata.task_export_format == null or (.import_metadata.task_export_format | IN("json_array", "jsonl")))
      and (.import_metadata.task_export_sha256 == null or (.import_metadata.task_export_sha256 | type == "string"))
      and (.import_metadata.imported_task_count == null or (.import_metadata.imported_task_count | type == "number" and floor == . and . > 0))
    )
  )
  and (.variants | type == "array")
  and (.variant_count == (.variants | length))
  and (.completed_variant_count == ([.variants[] | select(.execution_state == "completed")] | length))
  and (.planned_variant_count == ([.variants[] | select(.execution_state == "planned")] | length))
  and (.blocked_variant_count == ([.variants[] | select(.execution_state == "blocked")] | length))
  and (.missing_variant_count == ([.variants[] | select(.execution_state == "missing")] | length))
  and (.benchmark_summary.task_count == (.variants | length))
  and (.benchmark_summary.validated_count == ([.variants[] | select(.validation_status == "validated")] | length))
  and (.benchmark_summary.invalidated_count == ([.variants[] | select(.validation_status == "invalidated")] | length))
  and (.benchmark_summary.inconclusive_count == ([.variants[] | select(.validation_status != "validated" and .validation_status != "invalidated")] | length))
  and (.rerun_identity.comparison_scope == "benchmark_lane_only")
  and (.rerun_identity.lane_set == ["xbow_benchmark"])
  and (.rerun_identity.task_export_sha256 == (.import_metadata.task_export_sha256 // null))
  and (.rerun_identity.task_export_format == (.import_metadata.task_export_format // null))
  and (.rerun_identity.imported_task_count == (.import_metadata.imported_task_count // null))
  and all(.variants[]; (
    .lane == "xbow_benchmark"
    and (.benchmark_family | type == "string" and length > 0)
    and (.benchmark_task_id | type == "string" and length > 0)
    and (.benchmark_snapshot_id | type == "string" and length > 0)
    and (.benchmark_validation_rule | type == "string" and length > 0)
    and (.execution_state | IN("completed", "planned", "blocked", "missing"))
    and (.result_class | IN("pass", "fail", "inconclusive"))
    and (.validation_status | IN("validated", "invalidated", "inconclusive", "planned", "blocked", "missing"))
  ))
' "$SUMMARY_FILE" >/dev/null || fail "invalid benchmark matrix contract: $SUMMARY_FILE"
