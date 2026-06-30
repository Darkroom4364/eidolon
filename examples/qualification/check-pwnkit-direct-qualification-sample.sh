#!/usr/bin/env bash
set -euo pipefail

SUMMARY_FILE="${1:-}"
EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS="${EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS:-0}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/check-pwnkit-direct-qualification-sample.sh <pwnkit-stability-sample.json>

Fails closed when a direct-only pwnkit qualification sample has missing direct
artifacts, mixed/unknown evidence tracks, or pwnkit agent_error events.
USAGE
}

truthy() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
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
  fail "direct qualification sample summary not found; pass pwnkit-stability-sample.json"
fi

if ! command -v jq >/dev/null 2>&1; then
  fail "missing required tool: jq"
fi

missing_runs="$(
  jq -r '
    [.artifacts[]? | select(.present != true) | .artifact_dir] | join(",")
  ' "$SUMMARY_FILE"
)"
if [[ -n "$missing_runs" ]]; then
  echo "error: direct qualification sample is missing run summaries in $SUMMARY_FILE" >&2
  echo "       missing_runs=$missing_runs" >&2
  exit 1
fi

track_summary="$(
  jq -r '
    {
      tracks: (.evidence_tracks // []),
      mixed: (.mixed_evidence_tracks // false),
      unknown_count: (.unknown_evidence_track_count // 0)
    }
  ' "$SUMMARY_FILE"
)"
track_count="$(printf '%s' "$track_summary" | jq '.tracks | length')"
unknown_track_count="$(printf '%s' "$track_summary" | jq '.unknown_count')"
mixed_tracks="$(printf '%s' "$track_summary" | jq -r '.mixed')"
if [[ "$track_count" -eq 0 || "$unknown_track_count" -gt 0 || "$mixed_tracks" == "true" ]]; then
  echo "error: direct qualification sample evidence tracks are not claim-safe: $SUMMARY_FILE" >&2
  printf '%s' "$track_summary" | jq -r '"       tracks=\((.tracks // []) | join(",")) unknown=\(.unknown_count) mixed=\(.mixed)"' >&2
  exit 1
fi

agent_error_count="$(jq '[.artifacts[]? | (.agent_error_diagnostics.count // 0)] | add // 0' "$SUMMARY_FILE")"
if [[ "$agent_error_count" -eq 0 ]] || truthy "$EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS"; then
  exit 0
fi

echo "error: pwnkit agent errors detected in direct qualification sample $SUMMARY_FILE" >&2
jq -r '
  .artifacts[]
  | select((.agent_error_diagnostics.count // 0) > 0)
  | "       \(.artifact_dir): count=\(.agent_error_diagnostics.count // 0) classes=\((.agent_error_diagnostics.class_counts // []) | map((.error_class // "unknown") + "=" + ((.count // 0) | tostring)) | join(","))"
' "$SUMMARY_FILE" >&2
exit 1
