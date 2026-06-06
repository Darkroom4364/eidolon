#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

RUN_COUNT="${1:-${EIDOLON_M3_SAMPLE_RUNS:-3}}"
PARITY_DIR="${2:-${EIDOLON_M3_PARITY_DIR:-/tmp/eidolon-m3-pwnkit-parity-$(date +%Y%m%d-%H%M%S)}}"
UPSTREAM_DIR="${EIDOLON_M3_PARITY_UPSTREAM_DIR:-$PARITY_DIR/upstream-current}"
LOCAL_PATCHED_DIR="${EIDOLON_M3_PARITY_LOCAL_PATCHED_DIR:-$PARITY_DIR/local-patched}"
PARITY_SUMMARY_BASENAME="${EIDOLON_M3_PARITY_SUMMARY_BASENAME:-pwnkit-parity-summary.json}"
PARITY_SUMMARY_PATH="$PARITY_DIR/$PARITY_SUMMARY_BASENAME"
EIDOLON_M3_PARITY_UPSTREAM_PWNKIT_SOURCE_DIR="${EIDOLON_M3_PARITY_UPSTREAM_PWNKIT_SOURCE_DIR:-}"
EIDOLON_M3_PARITY_LOCAL_PATCHED_PWNKIT_SOURCE_DIR="${EIDOLON_M3_PARITY_LOCAL_PATCHED_PWNKIT_SOURCE_DIR:-}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/run-pwnkit-parity-kali-vm.sh [--preflight] [run-count] [parity-dir]

Runs the upstream-current and canonical local-patched Kali VM wrappers back to
back, then emits a parity summary JSON.

Outputs:
  <parity-dir>/upstream-current/pwnkit-stability-sample.json
  <parity-dir>/local-patched/pwnkit-stability-sample.json
  <parity-dir>/pwnkit-parity-summary.json

Optional environment:
  EIDOLON_M3_PARITY_UPSTREAM_PWNKIT_SOURCE_DIR
      Explicit upstream-current pwnkit checkout path.
  EIDOLON_M3_PARITY_LOCAL_PATCHED_PWNKIT_SOURCE_DIR
      Explicit local-patched pwnkit checkout path.
  EIDOLON_M3_PARITY_UPSTREAM_DIR
      Override the upstream-current sample directory.
  EIDOLON_M3_PARITY_LOCAL_PATCHED_DIR
      Override the local-patched sample directory.
  EIDOLON_M3_PARITY_SUMMARY_BASENAME
      Override the summary filename. Defaults to pwnkit-parity-summary.json.

The wrapper delegates track-specific contracts to:
  examples/m3/run-pwnkit-upstream-current-kali-vm.sh
  examples/m3/run-pwnkit-local-patched-kali-vm.sh

Use the individual wrappers when you want only one evidence track.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
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

require_positive_integer() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be a positive integer, got: $value"
  fi
}

canonicalize_path_allow_missing() {
  local path="$1"
  local current="$path"
  local suffix=""
  local base
  local resolved

  while [[ ! -e "$current" ]]; do
    base="$(basename "$current")"
    suffix="/$base$suffix"
    current="$(dirname "$current")"
  done

  if [[ ! -d "$current" ]]; then
    fail "parity-dir must resolve through directories only: $path"
  fi

  resolved="$(cd "$current" && pwd -P)"
  if [[ "$resolved" == "/" ]]; then
    printf '/%s' "${suffix#/}"
  else
    printf '%s%s' "$resolved" "$suffix"
  fi
}

require_parity_dir_outside_repo() {
  local resolved_dir

  [[ "$PARITY_DIR" == /* ]] || fail "parity-dir must be an absolute path outside the Eidolon repo"
  resolved_dir="$(canonicalize_path_allow_missing "$PARITY_DIR")"

  case "$resolved_dir" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
      fail "parity-dir must be outside the Eidolon repo"
      ;;
  esac
}

write_plan() {
  mkdir -p "$PARITY_DIR"
  cat > "$PARITY_DIR/parity-plan.txt" <<EOF
run_count=$RUN_COUNT
parity_dir=$PARITY_DIR
upstream_dir=$UPSTREAM_DIR
local_patched_dir=$LOCAL_PATCHED_DIR
parity_summary=$PARITY_SUMMARY_PATH
upstream_pwnkit_source_dir=${EIDOLON_M3_PARITY_UPSTREAM_PWNKIT_SOURCE_DIR:-auto}
local_patched_pwnkit_source_dir=${EIDOLON_M3_PARITY_LOCAL_PATCHED_PWNKIT_SOURCE_DIR:-auto}
EOF
}

run_upstream_wrapper() {
  if [[ -n "$EIDOLON_M3_PARITY_UPSTREAM_PWNKIT_SOURCE_DIR" ]]; then
    PWNKIT_SOURCE_DIR="$EIDOLON_M3_PARITY_UPSTREAM_PWNKIT_SOURCE_DIR" \
      "$SCRIPT_DIR/run-pwnkit-upstream-current-kali-vm.sh" "$@"
  else
    "$SCRIPT_DIR/run-pwnkit-upstream-current-kali-vm.sh" "$@"
  fi
}

run_local_patched_wrapper() {
  if [[ -n "$EIDOLON_M3_PARITY_LOCAL_PATCHED_PWNKIT_SOURCE_DIR" ]]; then
    PWNKIT_SOURCE_DIR="$EIDOLON_M3_PARITY_LOCAL_PATCHED_PWNKIT_SOURCE_DIR" \
      "$SCRIPT_DIR/run-pwnkit-local-patched-kali-vm.sh" "$@"
  else
    "$SCRIPT_DIR/run-pwnkit-local-patched-kali-vm.sh" "$@"
  fi
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  local preflight=0
  if [[ "${1:-}" == "--preflight" ]]; then
    preflight=1
    shift
    RUN_COUNT="${1:-${EIDOLON_M3_SAMPLE_RUNS:-3}}"
    PARITY_DIR="${2:-${EIDOLON_M3_PARITY_DIR:-/tmp/eidolon-m3-pwnkit-parity-$(date +%Y%m%d-%H%M%S)}}"
    UPSTREAM_DIR="${EIDOLON_M3_PARITY_UPSTREAM_DIR:-$PARITY_DIR/upstream-current}"
    LOCAL_PATCHED_DIR="${EIDOLON_M3_PARITY_LOCAL_PATCHED_DIR:-$PARITY_DIR/local-patched}"
    PARITY_SUMMARY_PATH="$PARITY_DIR/$PARITY_SUMMARY_BASENAME"
  fi

  require_positive_integer "run-count" "$RUN_COUNT"
  require_parity_dir_outside_repo
  write_plan

  if truthy "${EIDOLON_M3_KALI_VM_DRY_RUN:-0}"; then
    run_upstream_wrapper "$RUN_COUNT" "$UPSTREAM_DIR"
    run_local_patched_wrapper "$RUN_COUNT" "$LOCAL_PATCHED_DIR"
    echo "dry-run parity plan: $PARITY_DIR/parity-plan.txt"
    exit 0
  fi

  if [[ "$preflight" -eq 1 ]]; then
    run_upstream_wrapper --preflight "$RUN_COUNT" "$UPSTREAM_DIR"
    run_local_patched_wrapper --preflight "$RUN_COUNT" "$LOCAL_PATCHED_DIR"
    echo "kali-vm parity preflight ok: $PARITY_DIR"
    exit 0
  fi

  run_upstream_wrapper "$RUN_COUNT" "$UPSTREAM_DIR"
  run_local_patched_wrapper "$RUN_COUNT" "$LOCAL_PATCHED_DIR"

  "$SCRIPT_DIR/collect-pwnkit-parity.sh" \
    "$UPSTREAM_DIR/pwnkit-stability-sample.json" \
    "$LOCAL_PATCHED_DIR/pwnkit-stability-sample.json" \
    > "$PARITY_SUMMARY_PATH"

  echo "m3 pwnkit parity summary: $PARITY_SUMMARY_PATH"
}

main "$@"
