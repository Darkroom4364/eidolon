#!/usr/bin/env bash
set -euo pipefail

SUMMARY_FILE="${1:-}"
EIDOLON_M3_ALLOW_AGENT_ERRORS="${EIDOLON_M3_ALLOW_AGENT_ERRORS:-0}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/check-pwnkit-summary-health.sh <pwnkit-summary.json>

Fails closed when an M3 pwnkit summary contains pwnkit agent_error events.
The check prints only sanitized counts and coarse error classes.

Environment:
  EIDOLON_M3_ALLOW_AGENT_ERRORS  If true, allow agent-error summaries to pass.
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

if [[ -z "$SUMMARY_FILE" || ! -f "$SUMMARY_FILE" ]]; then
  fail "pwnkit summary not found; pass pwnkit-summary.json"
fi

require_command jq

if truthy "$EIDOLON_M3_ALLOW_AGENT_ERRORS"; then
  exit 0
fi

agent_error_count="$(
  jq '
    [
      .runs.direct.agent_error_diagnostics.count // 0,
      .runs.eidolon.agent_error_diagnostics.count // 0
    ]
    | add
  ' "$SUMMARY_FILE"
)"

if [[ "$agent_error_count" -eq 0 ]]; then
  exit 0
fi

echo "error: pwnkit agent errors detected in $SUMMARY_FILE" >&2
echo "       clear pwnkit runtime/auth failures before collecting M3 evidence," >&2
echo "       or set EIDOLON_M3_ALLOW_AGENT_ERRORS=1 for diagnostic no-signal runs." >&2
jq -r '
  .runs
  | to_entries[]
  | select((.value.agent_error_diagnostics.count // 0) > 0)
  | {
      leg: .key,
      count: (.value.agent_error_diagnostics.count // 0),
      classes: (
        .value.agent_error_diagnostics.class_counts
        // []
        | map((.error_class // "unknown") + "=" + ((.count // 0) | tostring))
        | join(",")
      )
    }
  | "       \(.leg): count=\(.count) classes=\(.classes)"
' "$SUMMARY_FILE" >&2
exit 1
