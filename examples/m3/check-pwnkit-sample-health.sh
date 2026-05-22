#!/usr/bin/env bash
set -euo pipefail

SAMPLE_FILE="${1:-}"
EIDOLON_M3_ALLOW_AGENT_ERRORS="${EIDOLON_M3_ALLOW_AGENT_ERRORS:-0}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/check-pwnkit-sample-health.sh <pwnkit-stability-sample.json>

Fails closed when an aggregated M3 pwnkit sample contains pwnkit agent_error
events. The check prints only sanitized counts and coarse error classes.

Environment:
  EIDOLON_M3_ALLOW_AGENT_ERRORS  If true, allow agent-error samples to pass.
                                 Defaults to 0.
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

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$SAMPLE_FILE" || ! -f "$SAMPLE_FILE" ]]; then
  fail "pwnkit sample summary not found; pass pwnkit-stability-sample.json"
fi

require_command jq

if truthy "$EIDOLON_M3_ALLOW_AGENT_ERRORS"; then
  exit 0
fi

agent_error_count="$(
  jq '
    def aggregate_total:
      (.no_signal_diagnostics.totals.direct_pwnkit_agent_errors // 0)
      + (.no_signal_diagnostics.totals.eidolon_pwnkit_agent_errors // 0);
    def artifact_total:
      [
        (.artifacts // [])[] |
        (.agent_error_diagnostics.direct.count // 0)
        + (.agent_error_diagnostics.eidolon.count // 0)
      ] | add // 0;
    [aggregate_total, artifact_total] | max
  ' "$SAMPLE_FILE"
)"

if [[ "$agent_error_count" -eq 0 ]]; then
  exit 0
fi

echo "error: pwnkit agent errors detected in sample $SAMPLE_FILE" >&2
echo "       clear pwnkit runtime/auth failures before collecting M3 evidence," >&2
echo "       or set EIDOLON_M3_ALLOW_AGENT_ERRORS=1 for diagnostic no-signal artifacts." >&2
jq -r '
  def class_counts:
    .no_signal_diagnostics.eidolon_agent_error_class_counts // []
    | map((.error_class // "unknown") + "=" + ((.count // 0) | tostring))
    | join(",");
  .no_signal_diagnostics.totals as $totals
  | "       totals: direct=\($totals.direct_pwnkit_agent_errors // 0) eidolon=\($totals.eidolon_pwnkit_agent_errors // 0)",
    "       eidolon classes=\(class_counts)"
' "$SAMPLE_FILE" >&2
exit 1
