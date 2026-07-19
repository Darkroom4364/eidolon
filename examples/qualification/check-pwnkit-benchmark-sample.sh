#!/usr/bin/env bash
set -euo pipefail

SUMMARY_FILE="${1:-}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/check-pwnkit-benchmark-sample.sh <pwnkit-stability-sample.json>

Fails closed when a benchmark-capability pwnkit sample is missing required
benchmark identity, drifts outside the benchmark-only contract, or inherits
claim-unsafe raw-sample evidence-track shape.
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
  fail "benchmark sample summary not found; pass pwnkit-stability-sample.json"
fi

command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"

jq -e '
  .schema_version == 1
  and .run_kind == "pwnkit_benchmark_sample"
  and .boundary == "scanner_qualification"
  and .claim_posture == "benchmark_capability_only"
  and .evaluation_lane_version == 1
  and .lane == "xbow_benchmark"
  and (.benchmark_family | type == "string" and length > 0)
  and (.benchmark_task_id | type == "string" and length > 0)
  and (.benchmark_snapshot_id | type == "string" and length > 0)
  and (.benchmark_validation_rule | type == "string" and length > 0)
  and (.validation.status | IN("validated", "invalidated", "inconclusive"))
  and (.validation.exploit_rule | type == "string" and length > 0)
  and (.artifacts | type == "array" and length > 0)
  and all(.artifacts[]; .lane == "xbow_benchmark")
' "$SUMMARY_FILE" >/dev/null || fail "invalid benchmark sample contract: $SUMMARY_FILE"

track_summary="$(
  jq -r '
    {
      tracks: (.raw_sample.evidence_tracks // []),
      track_count: ((.raw_sample.evidence_tracks // []) | length),
      mixed: (.raw_sample.mixed_evidence_tracks // false),
      unknown_count: (.raw_sample.unknown_evidence_track_count // 0)
    }
  ' "$SUMMARY_FILE"
)"

track_count="$(printf '%s' "$track_summary" | jq '.track_count')"
unknown_track_count="$(printf '%s' "$track_summary" | jq '.unknown_count')"
mixed_tracks="$(printf '%s' "$track_summary" | jq -r '.mixed')"
if [[ "$track_count" -eq 0 || "$unknown_track_count" -gt 0 || "$mixed_tracks" == "true" ]]; then
  echo "error: benchmark sample evidence tracks are not claim-safe: $SUMMARY_FILE" >&2
  printf '%s' "$track_summary" | jq -r '"       tracks=\((.tracks // []) | join(",")) unknown=\(.unknown_count) mixed=\(.mixed)"' >&2
  exit 1
fi

