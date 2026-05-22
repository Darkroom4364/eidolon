#!/usr/bin/env bash
set -euo pipefail

METADATA_FILE="${1:-}"
EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE="${EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE:-0}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/check-pwnkit-runner-freshness.sh <pwnkit-runner-metadata.json>

Fails closed when an M3 pwnkit source-checkout runner is dirty, missing
origin/main freshness metadata, or not synced with origin/main.

Environment:
  EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE
      If true, allow dirty or unsynced source-checkout metadata. Defaults to 0.
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

if [[ -z "$METADATA_FILE" || ! -f "$METADATA_FILE" ]]; then
  fail "pwnkit runner metadata not found; pass pwnkit-runner-metadata.json"
fi

require_command jq

if truthy "$EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE"; then
  exit 0
fi

repo_dir="$(jq -r '.pwnkit.repo_dir // empty' "$METADATA_FILE")"
if [[ -z "$repo_dir" ]]; then
  exit 0
fi

fresh="$(
  jq -r '
    (.pwnkit.git_dirty == false)
    and (.pwnkit.origin_main.in_sync == true)
  ' "$METADATA_FILE"
)"

if [[ "$fresh" == "true" ]]; then
  exit 0
fi

echo "error: pwnkit source checkout is not fresh for M3 evidence: $METADATA_FILE" >&2
jq -r '
  def present($value):
    if $value == null then "unknown" else ($value | tostring) end;
  .pwnkit
  | "       repo_dir=\(.repo_dir // "unknown") git_dirty=\(present(.git_dirty)) origin_main.in_sync=\(present(.origin_main.in_sync)) ahead=\(present(.origin_main.ahead)) behind=\(present(.origin_main.behind))"
' "$METADATA_FILE" >&2
echo "       sync pwnkit to origin/main and rebuild dist, or set EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE=1 for diagnostics." >&2
exit 1
