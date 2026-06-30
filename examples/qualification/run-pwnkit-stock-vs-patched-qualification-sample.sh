#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
source "$REPO_ROOT/examples/lib/pwnkit-worktree.sh"

RUN_COUNT="${1:-${EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_RUNS:-3}}"
SAMPLE_DIR="${2:-${EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DIR:-/tmp/eidolon-pwnkit-stock-compare-$(date +%Y%m%d-%H%M%S)}}"
EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DRY_RUN="${EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DRY_RUN:-0}"

if [[ -n "${EIDOLON_PWNKIT_QUAL_UPSTREAM_CURRENT_SOURCE_DIR+x}" ]]; then
  UPSTREAM_SOURCE_DIR_EXPLICIT=1
else
  UPSTREAM_SOURCE_DIR_EXPLICIT=0
fi
if [[ -n "${EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_SOURCE_DIR+x}" ]]; then
  LOCAL_PATCHED_SOURCE_DIR_EXPLICIT=1
else
  LOCAL_PATCHED_SOURCE_DIR_EXPLICIT=0
fi

DEFAULT_PWNKIT_SOURCE_DIR="${PWNKIT_SOURCE_DIR-$HOME/Projects/pwnkit}"
UPSTREAM_SOURCE_DIR="${EIDOLON_PWNKIT_QUAL_UPSTREAM_CURRENT_SOURCE_DIR:-$DEFAULT_PWNKIT_SOURCE_DIR}"
LOCAL_PATCHED_SOURCE_DIR="${EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_SOURCE_DIR:-$DEFAULT_PWNKIT_SOURCE_DIR}"
UPSTREAM_CURRENT_REF="${EIDOLON_PWNKIT_QUAL_UPSTREAM_CURRENT_REF:-origin/main}"
LOCAL_PATCHED_HEAD="${EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_HEAD:-abd034b61042f14a0b9b3a2cf9b0dbfa5ef4f2b4}"
LOCAL_PATCHED_FIXTURE_ID="${EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_FIXTURE_ID:-eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02}"
RUNNER_UPSTREAM_CURRENT="${EIDOLON_PWNKIT_QUAL_RUNNER_UPSTREAM_CURRENT_SAMPLE:-$REPO_ROOT/examples/m3/run-pwnkit-sample.sh}"
RUNNER_LOCAL_PATCHED="${EIDOLON_PWNKIT_QUAL_RUNNER_LOCAL_PATCHED_SAMPLE:-$REPO_ROOT/examples/m3/run-pwnkit-sample.sh}"
PARITY_COLLECTOR="${EIDOLON_PWNKIT_QUAL_PARITY_COLLECTOR:-$REPO_ROOT/examples/m3/collect-pwnkit-parity.sh}"
SUMMARY_COLLECTOR="${EIDOLON_PWNKIT_QUAL_STOCK_SUMMARY_COLLECTOR:-$REPO_ROOT/examples/qualification/collect-pwnkit-stock-vs-patched-qualification-sample.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/run-pwnkit-stock-vs-patched-qualification-sample.sh [run-count] [sample-dir]

Runs one upstream_current local sample and one canonical local_patched_pwnkit
local sample, then records their parity separately from M3 closeout.

Environment:
  EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_RUNS      Run count if [run-count] is omitted.
  EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DIR       Sample root if [sample-dir] is omitted.
  EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DRY_RUN   If true, write plans only.
  EIDOLON_PWNKIT_QUAL_UPSTREAM_CURRENT_SOURCE_DIR
                                              Optional upstream-current checkout base path.
  EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_SOURCE_DIR
                                              Optional local-patched checkout base path.
  EIDOLON_PWNKIT_QUAL_UPSTREAM_CURRENT_REF    Upstream ref for the stock track.
                                              Defaults to origin/main.
  EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_HEAD      Canonical patched head for the
                                              local patched track.
  EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_FIXTURE_ID
                                              Safe fixture id for the canonical
                                              local patched track.
  EIDOLON_PWNKIT_QUAL_RUNNER_UPSTREAM_CURRENT_SAMPLE
                                              Override the upstream-current
                                              local sample runner.
  EIDOLON_PWNKIT_QUAL_RUNNER_LOCAL_PATCHED_SAMPLE
                                              Override the local-patched local
                                              sample runner.
  EIDOLON_PWNKIT_QUAL_PARITY_COLLECTOR        Override collect-pwnkit-parity.sh.
  EIDOLON_PWNKIT_QUAL_STOCK_SUMMARY_COLLECTOR Override the qualification summary
                                              collector.
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

require_positive_integer() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be a positive integer, got: $value"
  fi
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || fail "missing required tool: $command_name"
}

require_executable_file() {
  local path="$1"
  [[ -x "$path" ]] || fail "runner or helper is not executable: $path"
}

resolve_clean_checkout_for_ref() {
  local source_dir="$1"
  local source_dir_explicit="$2"
  local expected_ref="$3"
  local expected_head
  local actual_head
  local status_output
  local auto_discovered_path

  [[ -d "$source_dir" ]] || fail "pwnkit source directory does not exist: $source_dir"
  pwnkit_worktree_is_git_checkout "$source_dir" \
    || fail "pwnkit source directory is not a git checkout: $source_dir"

  expected_head="$(git -C "$source_dir" rev-parse "$expected_ref" 2>/dev/null)" \
    || fail "upstream-current ref not found in pwnkit checkout: $expected_ref"
  actual_head="$(git -C "$source_dir" rev-parse HEAD)"

  if [[ "$actual_head" != "$expected_head" && "$source_dir_explicit" -eq 0 ]]; then
    auto_discovered_path="$(pwnkit_worktree_find_clean_path_by_head "$source_dir" "$expected_head" || true)"
    if [[ -n "$auto_discovered_path" ]]; then
      source_dir="$auto_discovered_path"
      actual_head="$expected_head"
      printf 'info: using auto-discovered upstream-current pwnkit worktree: %s\n' "$source_dir" >&2
    fi
  fi

  [[ "$actual_head" == "$expected_head" ]] \
    || fail "upstream-current pwnkit checkout head mismatch: expected $expected_head from $expected_ref, got $actual_head"

  status_output="$(git -C "$source_dir" status --short)"
  [[ -z "$status_output" ]] || fail "upstream-current pwnkit checkout must be clean: $source_dir"

  printf '%s' "$source_dir"
}

resolve_clean_checkout_for_head() {
  local source_dir="$1"
  local source_dir_explicit="$2"
  local expected_head="$3"
  local actual_head
  local status_output
  local auto_discovered_path

  [[ -d "$source_dir" ]] || fail "pwnkit source directory does not exist: $source_dir"
  pwnkit_worktree_is_git_checkout "$source_dir" \
    || fail "pwnkit source directory is not a git checkout: $source_dir"

  actual_head="$(git -C "$source_dir" rev-parse HEAD)"
  if [[ "$actual_head" != "$expected_head" && "$source_dir_explicit" -eq 0 ]]; then
    auto_discovered_path="$(pwnkit_worktree_find_clean_path_by_head "$source_dir" "$expected_head" || true)"
    if [[ -n "$auto_discovered_path" ]]; then
      source_dir="$auto_discovered_path"
      actual_head="$expected_head"
      printf 'info: using auto-discovered local patched pwnkit worktree: %s\n' "$source_dir" >&2
    fi
  fi

  [[ "$actual_head" == "$expected_head" ]] \
    || fail "local patched pwnkit checkout head mismatch: expected $expected_head, got $actual_head"

  status_output="$(git -C "$source_dir" status --short)"
  [[ -z "$status_output" ]] || fail "local patched pwnkit checkout must be clean: $source_dir"

  printf '%s' "$source_dir"
}

write_dry_run_plan() {
  local upstream_dir="$1"
  local local_dir="$2"

  mkdir -p "$SAMPLE_DIR"
  {
    printf 'run_count=%s\n' "$RUN_COUNT"
    printf 'sample_dir=%s\n' "$SAMPLE_DIR"
    printf 'upstream_current_dir=upstream-current\n'
    printf 'local_patched_dir=local-patched\n'
    printf 'upstream_current_ref=%s\n' "$UPSTREAM_CURRENT_REF"
    printf 'upstream_current_source_dir=%s\n' "$upstream_dir"
    printf 'local_patched_head=%s\n' "$LOCAL_PATCHED_HEAD"
    printf 'local_patched_fixture_id=%s\n' "$LOCAL_PATCHED_FIXTURE_ID"
    printf 'local_patched_source_dir=%s\n' "$local_dir"
    printf 'parity_summary=pwnkit-parity.json\n'
    printf 'sample_summary=pwnkit-stability-sample.json\n'
  } > "$SAMPLE_DIR/sample-plan.txt"
  echo "dry-run sample plan: $SAMPLE_DIR/sample-plan.txt"
}

main() {
  local upstream_dir
  local local_dir
  local sample_dry_run_value=0

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_command git
  require_command jq
  require_positive_integer "run-count" "$RUN_COUNT"
  [[ -n "$LOCAL_PATCHED_FIXTURE_ID" ]] || fail "EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_FIXTURE_ID must not be empty"
  require_executable_file "$RUNNER_UPSTREAM_CURRENT"
  require_executable_file "$RUNNER_LOCAL_PATCHED"
  require_executable_file "$PARITY_COLLECTOR"
  require_executable_file "$SUMMARY_COLLECTOR"

  upstream_dir="$(resolve_clean_checkout_for_ref "$UPSTREAM_SOURCE_DIR" "$UPSTREAM_SOURCE_DIR_EXPLICIT" "$UPSTREAM_CURRENT_REF")"
  local_dir="$(resolve_clean_checkout_for_head "$LOCAL_PATCHED_SOURCE_DIR" "$LOCAL_PATCHED_SOURCE_DIR_EXPLICIT" "$LOCAL_PATCHED_HEAD")"

  if truthy "$EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DRY_RUN"; then
    sample_dry_run_value=1
  fi

  mkdir -p "$SAMPLE_DIR"
  EIDOLON_M3_SAMPLE_DRY_RUN="$sample_dry_run_value" \
    EIDOLON_M3_UPSTREAM_CURRENT_REF="$UPSTREAM_CURRENT_REF" \
    EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current \
    EIDOLON_M3_PWNKIT_FIXTURE_ID= \
    PWNKIT_SOURCE_DIR="$upstream_dir" \
    "$RUNNER_UPSTREAM_CURRENT" "$RUN_COUNT" "$SAMPLE_DIR/upstream-current"

  if [[ "$sample_dry_run_value" -eq 1 ]]; then
    EIDOLON_M3_SAMPLE_DRY_RUN="$sample_dry_run_value" \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
      EIDOLON_M3_PWNKIT_FIXTURE_ID="$LOCAL_PATCHED_FIXTURE_ID" \
      PWNKIT_SOURCE_DIR="$local_dir" \
      "$RUNNER_LOCAL_PATCHED" "$RUN_COUNT" "$SAMPLE_DIR/local-patched"
    write_dry_run_plan "$upstream_dir" "$local_dir"
    return
  fi

  EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
    EIDOLON_M3_PWNKIT_FIXTURE_ID="$LOCAL_PATCHED_FIXTURE_ID" \
    PWNKIT_SOURCE_DIR="$local_dir" \
    "$RUNNER_LOCAL_PATCHED" "$RUN_COUNT" "$SAMPLE_DIR/local-patched"

  "$PARITY_COLLECTOR" \
    "$SAMPLE_DIR/upstream-current/pwnkit-stability-sample.json" \
    "$SAMPLE_DIR/local-patched/pwnkit-stability-sample.json" \
    > "$SAMPLE_DIR/pwnkit-parity.json"

  "$SUMMARY_COLLECTOR" \
    "$SAMPLE_DIR/upstream-current/pwnkit-stability-sample.json" \
    "$SAMPLE_DIR/local-patched/pwnkit-stability-sample.json" \
    "$SAMPLE_DIR/pwnkit-parity.json" \
    > "$SAMPLE_DIR/pwnkit-stability-sample.json"
}

main "$@"
