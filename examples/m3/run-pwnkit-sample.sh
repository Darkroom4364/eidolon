#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
source "$SCRIPT_DIR/../lib/local-lab.sh"

RUN_COUNT="${1:-${EIDOLON_M3_SAMPLE_RUNS:-3}}"
SAMPLE_DIR="${2:-${EIDOLON_M3_SAMPLE_DIR:-/tmp/eidolon-m3-pwnkit-sample-$(date +%Y%m%d-%H%M%S)}}"
TARGET_URL="${EIDOLON_LAB_TARGET_URL:-http://127.0.0.1:9001}"
PROXY_URL="${EIDOLON_LAB_PROXY_URL:-http://127.0.0.1:8080}"
EIDOLON_M3_PIN_SESSION="${EIDOLON_M3_PIN_SESSION:-1}"
EIDOLON_M3_SAMPLE_DRY_RUN="${EIDOLON_M3_SAMPLE_DRY_RUN:-0}"
EIDOLON_M3_BAIT_PROFILE="${EIDOLON_M3_BAIT_PROFILE:-}"
EIDOLON_M3_ALLOW_AGENT_ERRORS="${EIDOLON_M3_ALLOW_AGENT_ERRORS:-0}"
EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE="${EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE:-0}"
EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="${EIDOLON_M3_PWNKIT_MAX_ATTEMPTS:-2}"

TARGET_PID=""
PROXY_PID=""
TARGET_BIN="$REPO_ROOT/target/debug/eidolon-demo-target"
PROXY_BIN="$REPO_ROOT/target/debug/eidolon-proxy"

usage() {
  cat <<'USAGE'
Usage: examples/m3/run-pwnkit-sample.sh [run-count] [sample-dir]

Runs a repeated current-pwnkit M3 sample against the owned loopback Lab target.
The wrapper starts eidolon-demo-target once, starts a fresh eidolon-proxy for
each run with per-run event/debug logs, runs pinned pwnkit direct+Eidolon legs,
collects each run, then aggregates pwnkit-stability-sample.json.

Environment:
  EIDOLON_LAB_TARGET_URL       Direct demo target URL. Defaults to http://127.0.0.1:9001.
  EIDOLON_LAB_PROXY_URL        Eidolon proxy URL. Defaults to http://127.0.0.1:8080.
  EIDOLON_M3_SAMPLE_RUNS       Run count if [run-count] is omitted. Defaults to 3.
  EIDOLON_M3_SAMPLE_DIR        Sample root if [sample-dir] is omitted.
  EIDOLON_M3_PIN_SESSION       Pin one Eidolon session cookie. Defaults to 1.
  EIDOLON_M3_BAIT_PROFILE      Optional lab-only proxy bait profile JSON.
  EIDOLON_M3_ALLOW_AGENT_ERRORS
                                If true, continue when pwnkit emits agent_error
                                events. Defaults to 0.
  EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE
                                If true, continue when a pwnkit source checkout
                                is dirty or not synced to origin/main. Defaults
                                to 0.
  EIDOLON_M3_PWNKIT_MAX_ATTEMPTS
                                Attempts per sample run when transient Codex
                                backend errors are recorded. Defaults to 2.
  EIDOLON_M3_SAMPLE_DRY_RUN    If true, create the planned directory layout only.
  EIDOLON_M3_CODEX_AUTH_FILE   Optional Codex auth JSON path passed through to
                                pwnkit-codex.sh. Defaults to ~/.codex/auth.json.
  PWNKIT_NODE_ENTRY/PWNKIT_BIN Passed through to pwnkit-codex.sh.

Use only against the owned loopback Lab target. Sync and rebuild pwnkit before
running when using a source checkout.
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

require_positive_integer() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be a positive integer, got: $value"
  fi
}

stop_pid() {
  local pid="$1"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

stop_proxy() {
  stop_pid "$PROXY_PID"
  PROXY_PID=""
}

cleanup() {
  stop_proxy
  stop_pid "$TARGET_PID"
}

wait_for_http() {
  local label="$1"
  local url="$2"
  local pid="$3"
  local log_file="$4"

  for _ in {1..100}; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return
    fi

    if ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "error: $label exited before becoming ready" >&2
      if [[ -f "$log_file" ]]; then
        tail -40 "$log_file" >&2 || true
      fi
      exit 1
    fi

    sleep 0.1
  done

  echo "error: timed out waiting for $label at $url" >&2
  if [[ -f "$log_file" ]]; then
    tail -40 "$log_file" >&2 || true
  fi
  exit 1
}

write_dry_run_plan() {
  local target_addr="$1"
  local proxy_addr="$2"
  local plan_file="$SAMPLE_DIR/sample-plan.txt"

  mkdir -p "$SAMPLE_DIR"
  for ((run_index = 1; run_index <= RUN_COUNT; run_index++)); do
    mkdir -p "$SAMPLE_DIR/run-$run_index/private"
  done

  {
    printf 'run_count=%s\n' "$RUN_COUNT"
    printf 'sample_dir=%s\n' "$SAMPLE_DIR"
    printf 'target_url=%s\n' "$TARGET_URL"
    printf 'proxy_url=%s\n' "$PROXY_URL"
    printf 'target_addr=%s\n' "$target_addr"
    printf 'proxy_addr=%s\n' "$proxy_addr"
    printf 'pin_session=%s\n' "$EIDOLON_M3_PIN_SESSION"
    printf 'bait_profile=%s\n' "${EIDOLON_M3_BAIT_PROFILE:-default}"
    printf 'allow_agent_errors=%s\n' "$EIDOLON_M3_ALLOW_AGENT_ERRORS"
    printf 'allow_unfresh_pwnkit_source=%s\n' "$EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE"
    printf 'pwnkit_max_attempts=%s\n' "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
    printf 'debug_log=run-*/private/eidolon-debug.jsonl\n'
    printf 'sample_summary=pwnkit-stability-sample.json\n'
  } > "$plan_file"

  echo "dry-run sample plan: $plan_file"
}

build_lab_binaries() {
  (
    cd "$REPO_ROOT"
    cargo build -p eidolon-demo-target -p eidolon-proxy
  )
}

start_target() {
  local target_addr="$1"
  local log_file="$SAMPLE_DIR/private/demo-target.log"

  mkdir -p "$SAMPLE_DIR/private"
  EIDOLON_LAB_TARGET_ADDR="$target_addr" "$TARGET_BIN" > "$log_file" 2>&1 &
  TARGET_PID="$!"
  wait_for_http "eidolon-demo-target" "$TARGET_URL/health" "$TARGET_PID" "$log_file"
}

start_proxy() {
  local proxy_addr="$1"
  local run_dir="$2"
  local log_file="$run_dir/private/eidolon-proxy.log"
  local proxy_args=(
    --listen-addr "$proxy_addr"
    --upstream "$TARGET_URL"
    --event-log "$run_dir/proxy-events.jsonl"
    --debug-log "$run_dir/private/eidolon-debug.jsonl"
  )

  if [[ -n "$EIDOLON_M3_BAIT_PROFILE" ]]; then
    proxy_args+=(--bait-profile "$EIDOLON_M3_BAIT_PROFILE")
  fi

  proxy_args+=(
    --intervention-control "$run_dir/interventions.txt"
    --policy-state "$run_dir/policy-state.json"
  )

  mkdir -p "$run_dir/private"
  "$PROXY_BIN" "${proxy_args[@]}" > "$log_file" 2>&1 &
  PROXY_PID="$!"
  wait_for_http "eidolon-proxy" "$PROXY_URL/health" "$PROXY_PID" "$log_file"
}

run_pwnkit_preflight() {
  local preflight_dir="$SAMPLE_DIR/private/pwnkit-preflight"

  mkdir -p "$preflight_dir"
  EIDOLON_LAB_TARGET_URL="$TARGET_URL" \
    EIDOLON_LAB_PROXY_URL="$PROXY_URL" \
    EIDOLON_M3_PIN_SESSION="$EIDOLON_M3_PIN_SESSION" \
    EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
    "$SCRIPT_DIR/pwnkit-codex.sh" preflight "$preflight_dir" >/dev/null
  EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE="$EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE" \
    "$SCRIPT_DIR/check-pwnkit-runner-freshness.sh" \
    "$preflight_dir/pwnkit-runner-metadata.json"
}

summary_has_only_transient_agent_errors() {
  local summary_file="$1"

  [[ -f "$summary_file" ]] || return 1

  jq -e '
    [
      .runs.direct.agent_error_diagnostics.class_counts[]?,
      .runs.eidolon.agent_error_diagnostics.class_counts[]?
    ] as $classes
    | ($classes | map(.count // 0) | add // 0) > 0
    and all(
      $classes[];
      .error_class == "codex_backend_timeout"
      or .error_class == "codex_backend_api_error"
    )
  ' "$summary_file" >/dev/null
}

archive_run_attempt() {
  local run_index="$1"
  local attempt="$2"
  local run_dir="$3"
  local archive_dir="$SAMPLE_DIR/private/run-$run_index-attempt-$attempt"

  mkdir -p "$SAMPLE_DIR/private"
  mv "$run_dir" "$archive_dir"
  echo "m3 pwnkit sample archived failed run $run_index attempt $attempt -> $archive_dir" >&2
}

run_one_sample() {
  local run_index="$1"
  local proxy_addr="$2"
  local run_dir="$SAMPLE_DIR/run-$run_index"
  local attempt=1

  while :; do
    mkdir -p "$run_dir/private"
    echo "m3 pwnkit sample run $run_index/$RUN_COUNT attempt $attempt/$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS -> $run_dir" >&2

    start_proxy "$proxy_addr" "$run_dir"
    EIDOLON_LAB_TARGET_URL="$TARGET_URL" \
      EIDOLON_LAB_PROXY_URL="$PROXY_URL" \
      EIDOLON_M3_PIN_SESSION="$EIDOLON_M3_PIN_SESSION" \
      EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
      "$SCRIPT_DIR/pwnkit-codex.sh" all "$run_dir"
    "$SCRIPT_DIR/collect-pwnkit-codex.sh" "$run_dir" > "$run_dir/pwnkit-summary.json"
    "$SCRIPT_DIR/collect-agent-replay-trace.sh" "$run_dir" \
      > "$run_dir/agent-replay-trace-summary.json"

    local health_status=0
    EIDOLON_M3_ALLOW_AGENT_ERRORS="$EIDOLON_M3_ALLOW_AGENT_ERRORS" \
      "$SCRIPT_DIR/check-pwnkit-summary-health.sh" "$run_dir/pwnkit-summary.json" \
      || health_status="$?"

    stop_proxy
    if [[ "$health_status" -eq 0 ]]; then
      return 0
    fi

    if ! truthy "$EIDOLON_M3_ALLOW_AGENT_ERRORS" \
      && (( attempt < EIDOLON_M3_PWNKIT_MAX_ATTEMPTS )) \
      && summary_has_only_transient_agent_errors "$run_dir/pwnkit-summary.json"; then
      echo "warning: pwnkit sample run $run_index attempt $attempt/$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS recorded only transient Codex backend errors; retrying with a fresh proxy run" >&2
      archive_run_attempt "$run_index" "$attempt" "$run_dir"
      attempt=$((attempt + 1))
      continue
    fi

    return "$health_status"
  done
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_positive_integer "run-count" "$RUN_COUNT"
  require_positive_integer \
    "EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
    "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
  eidolon_lab_require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  eidolon_lab_require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
  if [[ -n "$EIDOLON_M3_BAIT_PROFILE" && ! -f "$EIDOLON_M3_BAIT_PROFILE" ]]; then
    echo "error: EIDOLON_M3_BAIT_PROFILE must point to an existing file: $EIDOLON_M3_BAIT_PROFILE" >&2
    exit 2
  fi

  local target_addr
  local proxy_addr
  target_addr="$(eidolon_lab_listen_addr_for_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL")"
  proxy_addr="$(eidolon_lab_listen_addr_for_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL")"

  if truthy "$EIDOLON_M3_SAMPLE_DRY_RUN"; then
    write_dry_run_plan "$target_addr" "$proxy_addr"
    exit 0
  fi

  require_command cargo
  require_command curl
  require_command jq

  mkdir -p "$SAMPLE_DIR/private"
  trap cleanup EXIT INT TERM

  run_pwnkit_preflight
  build_lab_binaries
  start_target "$target_addr"

  local run_dirs=()
  for ((run_index = 1; run_index <= RUN_COUNT; run_index++)); do
    run_one_sample "$run_index" "$proxy_addr"
    run_dirs+=("$SAMPLE_DIR/run-$run_index")
  done

  "$SCRIPT_DIR/collect-pwnkit-sample.sh" "${run_dirs[@]}" \
    > "$SAMPLE_DIR/pwnkit-stability-sample.json"
  EIDOLON_M3_ALLOW_AGENT_ERRORS="$EIDOLON_M3_ALLOW_AGENT_ERRORS" \
    "$SCRIPT_DIR/check-pwnkit-sample-health.sh" \
    "$SAMPLE_DIR/pwnkit-stability-sample.json"

  echo "m3 pwnkit sample summary: $SAMPLE_DIR/pwnkit-stability-sample.json"
}

main "$@"
