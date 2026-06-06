#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/../lib/pwnkit-worktree.sh"
if [[ -n "${PWNKIT_SOURCE_DIR+x}" ]]; then
  PWNKIT_SOURCE_DIR_EXPLICIT=1
else
  PWNKIT_SOURCE_DIR_EXPLICIT=0
fi
PWNKIT_SOURCE_DIR="${PWNKIT_SOURCE_DIR-$HOME/Projects/pwnkit}"
EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD="${EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD:-abd034b61042f14a0b9b3a2cf9b0dbfa5ef4f2b4}"
EIDOLON_M3_PWNKIT_FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02}"
EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-local_patched_pwnkit}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/run-pwnkit-local-patched-kali-vm.sh [--preflight] [run-count] [sample-dir]

Runs the Kali VM M3 sample wrapper against the validated local patched pwnkit
fixture used for the June 2 canonical M3 sample.

Defaults enforced by this wrapper:
  EIDOLON_M3_PWNKIT_FIXTURE_ID=eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02
  EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit
  EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD=abd034b61042f14a0b9b3a2cf9b0dbfa5ef4f2b4
  PWNKIT_SOURCE_DIR=~/Projects/pwnkit

The wrapper fails closed unless:
  - PWNKIT_SOURCE_DIR exists and is a git checkout
  - the checkout is clean
  - HEAD matches EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD

If PWNKIT_SOURCE_DIR is left unset and the default checkout does not match,
the wrapper will auto-discover a clean sibling worktree for the expected head.

Use examples/m3/run-pwnkit-kali-vm.sh directly for other upstream-current or
custom pinned-fixture runs.
USAGE
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

require_clean_pinned_checkout() {
  local expected_head="$EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD"
  local actual_head
  local status_output
  local auto_discovered_path

  [[ -d "$PWNKIT_SOURCE_DIR" ]] || fail "PWNKIT_SOURCE_DIR does not exist: $PWNKIT_SOURCE_DIR"
  pwnkit_worktree_is_git_checkout "$PWNKIT_SOURCE_DIR" \
    || fail "PWNKIT_SOURCE_DIR is not a git checkout: $PWNKIT_SOURCE_DIR"

  actual_head="$(git -C "$PWNKIT_SOURCE_DIR" rev-parse HEAD)"
  if [[ "$actual_head" != "$expected_head" ]]; then
    if [[ "$PWNKIT_SOURCE_DIR_EXPLICIT" -eq 0 ]]; then
      auto_discovered_path="$(pwnkit_worktree_find_clean_path_by_head "$PWNKIT_SOURCE_DIR" "$expected_head" || true)"
      if [[ -n "$auto_discovered_path" ]]; then
        PWNKIT_SOURCE_DIR="$auto_discovered_path"
        actual_head="$expected_head"
        printf 'info: using auto-discovered local patched pwnkit worktree: %s\n' "$PWNKIT_SOURCE_DIR" >&2
      fi
    fi
  fi

  if [[ "$actual_head" != "$expected_head" ]]; then
    fail "local patched pwnkit checkout head mismatch: expected $expected_head, got $actual_head"
  fi

  status_output="$(git -C "$PWNKIT_SOURCE_DIR" status --short)"
  if [[ -n "$status_output" ]]; then
    fail "local patched pwnkit checkout must be clean: $PWNKIT_SOURCE_DIR"
  fi
}

require_local_patched_contract() {
  if [[ "$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" != "local_patched_pwnkit" ]]; then
    fail "run-pwnkit-local-patched-kali-vm.sh only supports EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit"
  fi

  if [[ -z "$EIDOLON_M3_PWNKIT_FIXTURE_ID" ]]; then
    fail "EIDOLON_M3_PWNKIT_FIXTURE_ID must not be empty for the local patched wrapper"
  fi
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

require_command git
require_local_patched_contract
require_clean_pinned_checkout

export PWNKIT_SOURCE_DIR
export EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD
export EIDOLON_M3_PWNKIT_FIXTURE_ID
export EIDOLON_M3_PWNKIT_EVIDENCE_TRACK

exec "$SCRIPT_DIR/run-pwnkit-kali-vm.sh" "$@"
