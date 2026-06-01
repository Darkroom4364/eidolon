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
EIDOLON_M3_UPSTREAM_CURRENT_REF="${EIDOLON_M3_UPSTREAM_CURRENT_REF:-origin/main}"
EIDOLON_M3_PWNKIT_FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"
EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-upstream_current}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/run-pwnkit-upstream-current-kali-vm.sh [--preflight] [run-count] [sample-dir]

Runs the Kali VM M3 sample wrapper against the local upstream-current pwnkit
checkout.

Defaults enforced by this wrapper:
  EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current
  EIDOLON_M3_UPSTREAM_CURRENT_REF=origin/main
  PWNKIT_SOURCE_DIR=~/Projects/pwnkit

The wrapper fails closed unless:
  - PWNKIT_SOURCE_DIR exists and is a git checkout
  - the checkout is clean
  - EIDOLON_M3_PWNKIT_FIXTURE_ID is unset
  - HEAD matches EIDOLON_M3_UPSTREAM_CURRENT_REF

If PWNKIT_SOURCE_DIR is left unset and the default checkout does not match,
the wrapper will auto-discover a clean sibling worktree for the upstream ref.

Use examples/m3/run-pwnkit-kali-vm.sh directly for custom pinned-fixture or
diagnostic runs.
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

require_clean_upstream_checkout() {
  local expected_ref="$EIDOLON_M3_UPSTREAM_CURRENT_REF"
  local actual_head
  local expected_head
  local status_output
  local auto_discovered_path

  [[ -d "$PWNKIT_SOURCE_DIR" ]] || fail "PWNKIT_SOURCE_DIR does not exist: $PWNKIT_SOURCE_DIR"
  pwnkit_worktree_is_git_checkout "$PWNKIT_SOURCE_DIR" \
    || fail "PWNKIT_SOURCE_DIR is not a git checkout: $PWNKIT_SOURCE_DIR"

  expected_head="$(git -C "$PWNKIT_SOURCE_DIR" rev-parse "$expected_ref" 2>/dev/null)" \
    || fail "upstream-current ref not found in PWNKIT_SOURCE_DIR: $expected_ref"
  actual_head="$(git -C "$PWNKIT_SOURCE_DIR" rev-parse HEAD)"

  if [[ "$actual_head" != "$expected_head" ]]; then
    if [[ "$PWNKIT_SOURCE_DIR_EXPLICIT" -eq 0 ]]; then
      auto_discovered_path="$(pwnkit_worktree_find_clean_path_by_head "$PWNKIT_SOURCE_DIR" "$expected_head" || true)"
      if [[ -n "$auto_discovered_path" ]]; then
        PWNKIT_SOURCE_DIR="$auto_discovered_path"
        actual_head="$expected_head"
        printf 'info: using auto-discovered upstream-current pwnkit worktree: %s\n' "$PWNKIT_SOURCE_DIR" >&2
      fi
    fi
  fi

  if [[ "$actual_head" != "$expected_head" ]]; then
    fail "upstream-current pwnkit checkout head mismatch: expected $expected_head from $expected_ref, got $actual_head"
  fi

  status_output="$(git -C "$PWNKIT_SOURCE_DIR" status --short)"
  if [[ -n "$status_output" ]]; then
    fail "upstream-current pwnkit checkout must be clean: $PWNKIT_SOURCE_DIR"
  fi
}

require_upstream_current_contract() {
  if [[ "$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" != "upstream_current" ]]; then
    fail "run-pwnkit-upstream-current-kali-vm.sh only supports EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current"
  fi

  if [[ -n "$EIDOLON_M3_PWNKIT_FIXTURE_ID" ]]; then
    fail "EIDOLON_M3_PWNKIT_FIXTURE_ID must be unset for the upstream-current wrapper"
  fi
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

require_command git
require_upstream_current_contract
require_clean_upstream_checkout

export PWNKIT_SOURCE_DIR
export EIDOLON_M3_UPSTREAM_CURRENT_REF
export EIDOLON_M3_PWNKIT_EVIDENCE_TRACK

exec "$SCRIPT_DIR/run-pwnkit-kali-vm.sh" "$@"
