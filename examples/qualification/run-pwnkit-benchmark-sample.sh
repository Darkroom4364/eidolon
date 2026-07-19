#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

RUN_COUNT="${1:-${EIDOLON_PWNKIT_BENCHMARK_RUNS:-1}}"
SAMPLE_DIR="${2:-${EIDOLON_PWNKIT_BENCHMARK_DIR:-/tmp/eidolon-pwnkit-benchmark-$(date +%Y%m%d-%H%M%S)}}"
EIDOLON_PWNKIT_BENCHMARK_DRY_RUN="${EIDOLON_PWNKIT_BENCHMARK_DRY_RUN:-0}"
RAW_RUNNER="${EIDOLON_PWNKIT_BENCHMARK_RAW_RUNNER:-}"
BENCHMARK_COLLECTOR="${EIDOLON_PWNKIT_BENCHMARK_COLLECTOR:-$SCRIPT_DIR/collect-pwnkit-benchmark-sample.sh}"
BENCHMARK_CHECKER="${EIDOLON_PWNKIT_BENCHMARK_CHECKER:-$SCRIPT_DIR/check-pwnkit-benchmark-sample.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/run-pwnkit-benchmark-sample.sh [run-count] [sample-dir]

Compatibility wrapper for packaging a benchmark-capability sample produced by
an explicit benchmark executor. It has no default executor.

Do not point this wrapper at examples/m3/run-pwnkit-sample.sh. That runner
targets the Eidolon owned lab and does not provision an XBow task or exact-flag
oracle. For XBow, use pwnkit's upstream @pwnkit/benchmark xbow runner.

The raw runner writes into:
  <sample-dir>/raw-sample

The benchmark wrapper then writes:
  <sample-dir>/pwnkit-stability-sample.json

Required environment:
  EIDOLON_PWNKIT_BENCHMARK_FAMILY
  EIDOLON_PWNKIT_BENCHMARK_TASK_ID
  EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID
  EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE

Optional environment:
  EIDOLON_PWNKIT_BENCHMARK_MODEL_ID
  EIDOLON_PWNKIT_BENCHMARK_PROMPT_BUNDLE_HASH
  EIDOLON_PWNKIT_BENCHMARK_ACTION_BUDGET
  EIDOLON_PWNKIT_BENCHMARK_TOKEN_BUDGET
  EIDOLON_PWNKIT_BENCHMARK_WALL_CLOCK_BUDGET_SECONDS
  EIDOLON_PWNKIT_BENCHMARK_DEFENSE_MODE
  EIDOLON_PWNKIT_BENCHMARK_DRY_RUN
  EIDOLON_PWNKIT_BENCHMARK_RAW_RUNNER  Required executable benchmark adapter.
  EIDOLON_PWNKIT_BENCHMARK_COLLECTOR
  EIDOLON_PWNKIT_BENCHMARK_CHECKER
USAGE
}

truthy() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
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

require_env() {
  local name="$1"
  local value="${!name:-}"
  [[ -n "$value" ]] || fail "$name must not be empty"
}

write_dry_run_plan() {
  mkdir -p "$SAMPLE_DIR/raw-sample"
  {
    printf 'run_count=%s\n' "$RUN_COUNT"
    printf 'sample_dir=%s\n' "$SAMPLE_DIR"
    printf 'raw_sample_dir=%s/raw-sample\n' "$SAMPLE_DIR"
    printf 'benchmark_family=%s\n' "$EIDOLON_PWNKIT_BENCHMARK_FAMILY"
    printf 'benchmark_task_id=%s\n' "$EIDOLON_PWNKIT_BENCHMARK_TASK_ID"
    printf 'benchmark_snapshot_id=%s\n' "$EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID"
    printf 'benchmark_validation_rule=%s\n' "$EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE"
    printf 'benchmark_model_id=%s\n' "${EIDOLON_PWNKIT_BENCHMARK_MODEL_ID:-none}"
    printf 'benchmark_prompt_bundle_hash=%s\n' "${EIDOLON_PWNKIT_BENCHMARK_PROMPT_BUNDLE_HASH:-none}"
    printf 'benchmark_action_budget=%s\n' "${EIDOLON_PWNKIT_BENCHMARK_ACTION_BUDGET:-none}"
    printf 'benchmark_token_budget=%s\n' "${EIDOLON_PWNKIT_BENCHMARK_TOKEN_BUDGET:-none}"
    printf 'benchmark_wall_clock_budget_seconds=%s\n' "${EIDOLON_PWNKIT_BENCHMARK_WALL_CLOCK_BUDGET_SECONDS:-none}"
    printf 'benchmark_defense_mode=%s\n' "${EIDOLON_PWNKIT_BENCHMARK_DEFENSE_MODE:-none}"
  } > "$SAMPLE_DIR/sample-plan.txt"
  echo "dry-run sample plan: $SAMPLE_DIR/sample-plan.txt"
}

main() {
  local raw_sample_dir validation_artifact=""

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"
  require_positive_integer "run-count" "$RUN_COUNT"
  require_env EIDOLON_PWNKIT_BENCHMARK_FAMILY
  require_env EIDOLON_PWNKIT_BENCHMARK_TASK_ID
  require_env EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID
  require_env EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE
  [[ -n "$RAW_RUNNER" ]] || fail \
    "EIDOLON_PWNKIT_BENCHMARK_RAW_RUNNER is required; use pwnkit's upstream XBow runner for XBow tasks"
  if [[ "$RAW_RUNNER" == "$REPO_ROOT/examples/m3/run-pwnkit-sample.sh" ]]; then
    fail "examples/m3/run-pwnkit-sample.sh is an Eidolon owned-target runner, not an XBow benchmark executor"
  fi
  [[ -x "$RAW_RUNNER" ]] || fail "benchmark raw runner is not executable: $RAW_RUNNER"
  [[ -x "$BENCHMARK_COLLECTOR" ]] || fail "benchmark collector is not executable: $BENCHMARK_COLLECTOR"
  [[ -x "$BENCHMARK_CHECKER" ]] || fail "benchmark checker is not executable: $BENCHMARK_CHECKER"

  if truthy "$EIDOLON_PWNKIT_BENCHMARK_DRY_RUN"; then
    write_dry_run_plan
    exit 0
  fi

  raw_sample_dir="$SAMPLE_DIR/raw-sample"
  mkdir -p "$raw_sample_dir"
  "$RAW_RUNNER" "$RUN_COUNT" "$raw_sample_dir"

  if [[ -f "$raw_sample_dir/benchmark-validation.json" ]]; then
    validation_artifact="$raw_sample_dir/benchmark-validation.json"
  fi

  "$BENCHMARK_COLLECTOR" \
    "$raw_sample_dir/pwnkit-stability-sample.json" \
    ${validation_artifact:+"$validation_artifact"} \
    > "$SAMPLE_DIR/pwnkit-stability-sample.json"

  "$BENCHMARK_CHECKER" "$SAMPLE_DIR/pwnkit-stability-sample.json"
}

main "$@"
