#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
source "$SCRIPT_DIR/../lib/local-lab.sh"

RUN_COUNT="${1:-${EIDOLON_M3_SAMPLE_RUNS:-3}}"
SAMPLE_DIR="${2:-${EIDOLON_M3_SAMPLE_DIR:-/tmp/eidolon-m3-pwnkit-kali-vm-$(date +%Y%m%d-%H%M%S)}}"
TARGET_URL="${EIDOLON_LAB_TARGET_URL:-http://127.0.0.1:9001}"
PROXY_URL="${EIDOLON_LAB_PROXY_URL:-http://127.0.0.1:8080}"
EIDOLON_M3_RUNNER_ENVIRONMENT="${EIDOLON_M3_RUNNER_ENVIRONMENT:-kali_vm}"
EIDOLON_M3_NETWORK_TOPOLOGY="${EIDOLON_M3_NETWORK_TOPOLOGY:-same_vm_loopback}"
EIDOLON_M3_KALI_VM_DRY_RUN="${EIDOLON_M3_KALI_VM_DRY_RUN:-0}"
EIDOLON_M3_ALLOW_NON_KALI_VM="${EIDOLON_M3_ALLOW_NON_KALI_VM:-0}"
EIDOLON_M3_KALI_VM_PREFLIGHT="${EIDOLON_M3_KALI_VM_PREFLIGHT:-0}"
EIDOLON_M3_PWNKIT_FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/run-pwnkit-kali-vm.sh [--preflight] [run-count] [sample-dir]

Runs the M3 pwnkit sample runner inside a Kali Linux VM, including OrbStack
Kali machines, with target, proxy, and pwnkit all on VM-local loopback.

This script does not create or manage the VM. Start a Kali VM first, clone or
copy the Eidolon and local pwnkit checkouts into the VM, build pwnkit, then run
this wrapper from inside the VM.

Environment:
  EIDOLON_LAB_TARGET_URL       VM-local demo target URL. Defaults to http://127.0.0.1:9001.
  EIDOLON_LAB_PROXY_URL        VM-local Eidolon proxy URL. Defaults to http://127.0.0.1:8080.
  EIDOLON_M3_SAMPLE_RUNS       Run count if [run-count] is omitted. Defaults to 3.
  EIDOLON_M3_SAMPLE_DIR        Sample root if [sample-dir] is omitted.
  EIDOLON_M3_KALI_VM_DRY_RUN   If true, write the sample plan without running scans.
  EIDOLON_M3_KALI_VM_PREFLIGHT If true, validate VM runner plumbing and exit.
  EIDOLON_M3_ALLOW_NON_KALI_VM Allow dry-run/planning outside Kali. Defaults to 0.
  EIDOLON_M3_PWNKIT_FIXTURE_ID Optional safe label for archived/private pinned
                               pwnkit fixtures.
  PWNKIT_NODE_ENTRY/PWNKIT_BIN Passed through to run-pwnkit-sample.sh.

The wrapper forces the evidence labels:
  EIDOLON_M3_RUNNER_ENVIRONMENT=kali_vm
  EIDOLON_M3_NETWORK_TOPOLOGY=same_vm_loopback

Use the regular run-pwnkit-sample.sh wrapper for host-mac or bridged-network
diagnostics. This wrapper is for VM-local loopback evidence only.
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

os_release_value() {
  local key="$1"
  local line

  if [[ ! -f /etc/os-release ]]; then
    return
  fi

  line="$(grep -E "^${key}=" /etc/os-release 2>/dev/null | sed -n '1p' || true)"
  line="${line#*=}"
  line="${line%\"}"
  line="${line#\"}"
  printf '%s' "$line"
}

is_kali_linux() {
  if truthy "${EIDOLON_M3_TEST_FORCE_NON_KALI:-0}"; then
    return 1
  fi

  [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]] || return 1
  [[ "$(os_release_value ID)" == "kali" ]]
}

require_positive_integer() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be a positive integer, got: $value"
  fi
}

require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

require_vm_contract() {
  local on_kali=0

  if [[ "$EIDOLON_M3_RUNNER_ENVIRONMENT" != "kali_vm" ]]; then
    fail "EIDOLON_M3_RUNNER_ENVIRONMENT must be kali_vm for this wrapper"
  fi

  if [[ "$EIDOLON_M3_NETWORK_TOPOLOGY" != "same_vm_loopback" ]]; then
    fail "EIDOLON_M3_NETWORK_TOPOLOGY must be same_vm_loopback for this wrapper"
  fi

  if is_kali_linux; then
    on_kali=1
  fi

  if [[ "$on_kali" -eq 0 ]] && ! truthy "$EIDOLON_M3_ALLOW_NON_KALI_VM"; then
    fail "run this inside a Kali Linux VM, or set EIDOLON_M3_ALLOW_NON_KALI_VM=1 for plan-only diagnostics"
  fi

  if [[ "$on_kali" -eq 0 ]] && ! truthy "$EIDOLON_M3_KALI_VM_DRY_RUN"; then
    fail "EIDOLON_M3_ALLOW_NON_KALI_VM is only allowed with EIDOLON_M3_KALI_VM_DRY_RUN=1"
  fi
}

require_pwnkit_runner_available() {
  if [[ -n "${PWNKIT_NODE_ENTRY:-}" ]]; then
    if [[ ! -f "$PWNKIT_NODE_ENTRY" ]]; then
      fail "PWNKIT_NODE_ENTRY does not exist: $PWNKIT_NODE_ENTRY"
    fi
    require_command node
    return
  fi

  if [[ -n "${PWNKIT_BIN:-}" ]]; then
    require_command "$PWNKIT_BIN"
    return
  fi

  if [[ -f "$HOME/Projects/pwnkit/dist/pwnkit.js" ]]; then
    require_command node
    return
  fi

  if command -v pwnkit >/dev/null 2>&1 || command -v pwnkit-cli >/dev/null 2>&1; then
    return
  fi

  fail "could not find pwnkit; set PWNKIT_NODE_ENTRY or PWNKIT_BIN"
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
    fail "sample-dir must resolve through directories only: $path"
  fi

  resolved="$(cd "$current" && pwd -P)"
  if [[ "$resolved" == "/" ]]; then
    printf '/%s' "${suffix#/}"
  else
    printf '%s%s' "$resolved" "$suffix"
  fi
}

require_sample_dir_outside_repo() {
  local resolved_sample_dir

  if [[ "$SAMPLE_DIR" != /* ]]; then
    fail "sample-dir must be an absolute path outside the Eidolon repo"
  fi

  resolved_sample_dir="$(canonicalize_path_allow_missing "$SAMPLE_DIR")"

  case "$resolved_sample_dir" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
      fail "sample-dir must be outside the Eidolon repo so pwnkit is not handed repo-local artifact paths"
      ;;
  esac
}

run_preflight() {
  local preflight_dir="$SAMPLE_DIR/private/kali-vm-preflight"

  require_command cargo
  require_command curl
  require_command jq
  require_command sqlite3
  require_command git
  require_pwnkit_runner_available

  mkdir -p "$preflight_dir"
  EIDOLON_LAB_TARGET_URL="$TARGET_URL" \
    EIDOLON_LAB_PROXY_URL="$PROXY_URL" \
    EIDOLON_M3_PIN_SESSION="${EIDOLON_M3_PIN_SESSION:-1}" \
    EIDOLON_M3_RUNNER_ENVIRONMENT="$EIDOLON_M3_RUNNER_ENVIRONMENT" \
    EIDOLON_M3_NETWORK_TOPOLOGY="$EIDOLON_M3_NETWORK_TOPOLOGY" \
    EIDOLON_M3_PWNKIT_FIXTURE_ID="$EIDOLON_M3_PWNKIT_FIXTURE_ID" \
    "$SCRIPT_DIR/pwnkit-codex.sh" preflight "$preflight_dir" >/dev/null
  EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE="${EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE:-0}" \
    "$SCRIPT_DIR/check-pwnkit-runner-freshness.sh" \
    "$preflight_dir/pwnkit-runner-metadata.json"

  echo "kali-vm preflight ok: $preflight_dir"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ "${1:-}" == "--preflight" ]]; then
    EIDOLON_M3_KALI_VM_PREFLIGHT=1
    shift
    RUN_COUNT="${1:-${EIDOLON_M3_SAMPLE_RUNS:-3}}"
    SAMPLE_DIR="${2:-${EIDOLON_M3_SAMPLE_DIR:-/tmp/eidolon-m3-pwnkit-kali-vm-$(date +%Y%m%d-%H%M%S)}}"
  fi

  require_positive_integer "run-count" "$RUN_COUNT"
  require_vm_contract
  require_sample_dir_outside_repo
  eidolon_lab_require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  eidolon_lab_require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"

  export EIDOLON_LAB_TARGET_URL="$TARGET_URL"
  export EIDOLON_LAB_PROXY_URL="$PROXY_URL"
  export EIDOLON_M3_RUNNER_ENVIRONMENT
  export EIDOLON_M3_NETWORK_TOPOLOGY
  export EIDOLON_M3_PWNKIT_FIXTURE_ID

  if truthy "$EIDOLON_M3_KALI_VM_DRY_RUN"; then
    export EIDOLON_M3_SAMPLE_DRY_RUN=1
  fi

  if truthy "$EIDOLON_M3_KALI_VM_PREFLIGHT"; then
    run_preflight
    exit 0
  fi

  "$SCRIPT_DIR/run-pwnkit-sample.sh" "$RUN_COUNT" "$SAMPLE_DIR"
}

main "$@"
