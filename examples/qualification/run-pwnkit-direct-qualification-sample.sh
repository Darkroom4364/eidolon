#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
source "$REPO_ROOT/examples/lib/local-lab.sh"

RUN_COUNT="${1:-${EIDOLON_PWNKIT_QUAL_DIRECT_RUNS:-3}}"
SAMPLE_DIR="${2:-${EIDOLON_PWNKIT_QUAL_DIRECT_DIR:-/tmp/eidolon-pwnkit-direct-qualification-$(date +%Y%m%d-%H%M%S)}}"
TARGET_URL="${EIDOLON_LAB_TARGET_URL:-http://127.0.0.1:9101}"
PROXY_URL="${EIDOLON_LAB_PROXY_URL:-http://127.0.0.1:8080}"
TARGET_PROFILE="${EIDOLON_LAB_TARGET_PROFILE:-qualification_negative_control}"
EIDOLON_PWNKIT_QUAL_DIRECT_DRY_RUN="${EIDOLON_PWNKIT_QUAL_DIRECT_DRY_RUN:-0}"
EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS="${EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS:-0}"
EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="${EIDOLON_M3_PWNKIT_MAX_ATTEMPTS:-2}"
EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="${EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS:-900}"
EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="${EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS:-60}"
EIDOLON_M3_RUNNER_ENVIRONMENT="${EIDOLON_M3_RUNNER_ENVIRONMENT:-host_mac}"
EIDOLON_M3_NETWORK_TOPOLOGY="${EIDOLON_M3_NETWORK_TOPOLOGY:-same_host_loopback}"
EIDOLON_M3_PWNKIT_FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"
EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-}"
PWNKIT_SOURCE_DIR="${PWNKIT_SOURCE_DIR-$HOME/Projects/pwnkit}"
EIDOLON_PWNKIT_QUAL_DIRECT_SKIP_BUILD="${EIDOLON_PWNKIT_QUAL_DIRECT_SKIP_BUILD:-0}"

TARGET_PID=""
TARGET_BIN="${EIDOLON_PWNKIT_QUAL_DIRECT_TARGET_BIN:-$REPO_ROOT/target/debug/eidolon-demo-target}"
PWNKIT_RUNNER="${EIDOLON_PWNKIT_QUAL_DIRECT_RUNNER:-$REPO_ROOT/examples/m3/pwnkit-codex.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/run-pwnkit-direct-qualification-sample.sh [run-count] [sample-dir]

Runs a repeated direct-only pwnkit qualification sample against an intentionally
simple owned target profile, outside the Eidolon proxy path.

Environment:
  EIDOLON_LAB_TARGET_URL                 Direct target URL. Defaults to http://127.0.0.1:9101.
  EIDOLON_LAB_PROXY_URL                  Placeholder proxy URL for pwnkit runner metadata.
                                         Defaults to http://127.0.0.1:8080 and is not started.
  EIDOLON_LAB_TARGET_PROFILE             Target profile. Defaults to
                                         qualification_negative_control.
  EIDOLON_PWNKIT_QUAL_DIRECT_RUNS        Run count if [run-count] is omitted.
  EIDOLON_PWNKIT_QUAL_DIRECT_DIR         Sample root if [sample-dir] is omitted.
  EIDOLON_PWNKIT_QUAL_DIRECT_DRY_RUN     If true, create the planned layout only.
  EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS If true, allow agent_error samples to pass.
  EIDOLON_M3_PWNKIT_MAX_ATTEMPTS         Passed through to pwnkit-codex.sh.
  EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS      Passed through to pwnkit-codex.sh.
  EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS    Passed through to pwnkit-codex.sh.
  EIDOLON_M3_RUNNER_ENVIRONMENT          Runner environment label recorded in metadata.
  EIDOLON_M3_NETWORK_TOPOLOGY            Network topology label recorded in metadata.
  EIDOLON_M3_PWNKIT_FIXTURE_ID           Optional pinned fixture label.
  EIDOLON_M3_PWNKIT_EVIDENCE_TRACK       Optional evidence track override.
  PWNKIT_SOURCE_DIR                      Local pwnkit source checkout.
  EIDOLON_PWNKIT_QUAL_DIRECT_RUNNER      Override pwnkit runner script for tests.
  EIDOLON_PWNKIT_QUAL_DIRECT_TARGET_BIN  Override target binary path for tests.
  EIDOLON_PWNKIT_QUAL_DIRECT_SKIP_BUILD  If true, skip cargo build before start.
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

stop_pid() {
  local pid="$1"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

cleanup() {
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
    printf 'target_profile=%s\n' "$TARGET_PROFILE"
    printf 'allow_agent_errors=%s\n' "$EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS"
    printf 'pwnkit_max_attempts=%s\n' "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
    printf 'pwnkit_timeout_seconds=%s\n' "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS"
    printf 'pwnkit_heartbeat_seconds=%s\n' "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS"
    printf 'runner_environment=%s\n' "$EIDOLON_M3_RUNNER_ENVIRONMENT"
    printf 'network_topology=%s\n' "$EIDOLON_M3_NETWORK_TOPOLOGY"
    printf 'pwnkit_fixture_id=%s\n' "${EIDOLON_M3_PWNKIT_FIXTURE_ID:-none}"
    printf 'pwnkit_evidence_track=%s\n' "${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-auto}"
    printf 'pwnkit_source_dir=%s\n' "${PWNKIT_SOURCE_DIR:-none}"
    printf 'sample_summary=pwnkit-stability-sample.json\n'
  } > "$plan_file"

  echo "dry-run sample plan: $plan_file"
}

build_target_binary() {
  (
    cd "$REPO_ROOT"
    cargo build -p eidolon-demo-target
  )
}

start_target() {
  local target_addr="$1"
  local log_file="$SAMPLE_DIR/private/demo-target.log"

  mkdir -p "$SAMPLE_DIR/private"
  EIDOLON_LAB_TARGET_ADDR="$target_addr" \
    EIDOLON_LAB_TARGET_PROFILE="$TARGET_PROFILE" \
    "$TARGET_BIN" > "$log_file" 2>&1 &
  TARGET_PID="$!"
  wait_for_http "eidolon-demo-target" "$TARGET_URL/health" "$TARGET_PID" "$log_file"
}

run_one_sample() {
  local run_index="$1"
  local run_dir="$SAMPLE_DIR/run-$run_index"

  mkdir -p "$run_dir/private"
  echo "pwnkit direct qualification run $run_index/$RUN_COUNT -> $run_dir" >&2

  EIDOLON_LAB_TARGET_URL="$TARGET_URL" \
    EIDOLON_LAB_PROXY_URL="$PROXY_URL" \
    EIDOLON_M3_PIN_SESSION=0 \
    EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
    EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
    EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" \
    EIDOLON_M3_RUNNER_ENVIRONMENT="$EIDOLON_M3_RUNNER_ENVIRONMENT" \
    EIDOLON_M3_NETWORK_TOPOLOGY="$EIDOLON_M3_NETWORK_TOPOLOGY" \
    EIDOLON_M3_PWNKIT_FIXTURE_ID="$EIDOLON_M3_PWNKIT_FIXTURE_ID" \
    EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" \
    PWNKIT_SOURCE_DIR="$PWNKIT_SOURCE_DIR" \
    "$PWNKIT_RUNNER" direct "$run_dir"
  "$REPO_ROOT/examples/m3/collect-pwnkit-codex.sh" "$run_dir" > "$run_dir/pwnkit-summary.json"
  jq -n \
    --arg artifact_dir "$run_dir" \
    '{
      schema_version: 1,
      run_kind: "qualification_direct_no_proxy_trace",
      boundary: "scanner_qualification",
      evidence_source: "direct_only_no_proxy",
      artifact_dir: $artifact_dir,
      claim_level: "not_applicable",
      counts: {
        exposures: 0,
        actions: 0
      },
      metrics: {},
      pinned_session: {
        present: false,
        cookie_preserved: false
      },
      sessions: {},
      bait_events: {
        exposures: [],
        actions: [],
        same_session_confirmed_actions: [],
        controlled_reality_entries_after_confirmed_action: []
      },
      notes: [
        "direct-only qualification run; no Eidolon proxy trace was collected"
      ]
    }' > "$run_dir/agent-replay-trace-summary.json"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_positive_integer "run-count" "$RUN_COUNT"
  require_positive_integer "EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
  require_positive_integer "EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS"
  require_positive_integer "EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS"
  eidolon_lab_require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  eidolon_lab_require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
  if [[ "$TARGET_PROFILE" != "qualification_negative_control" ]]; then
    fail "EIDOLON_LAB_TARGET_PROFILE must be qualification_negative_control for this runner"
  fi

  local target_addr
  target_addr="$(eidolon_lab_listen_addr_for_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL")"

  if truthy "$EIDOLON_PWNKIT_QUAL_DIRECT_DRY_RUN"; then
    write_dry_run_plan "$target_addr"
    exit 0
  fi

  eidolon_lab_require_command cargo
  eidolon_lab_require_command curl
  eidolon_lab_require_command jq
  if [[ ! -x "$PWNKIT_RUNNER" ]]; then
    fail "direct qualification runner is not executable: $PWNKIT_RUNNER"
  fi

  mkdir -p "$SAMPLE_DIR/private"
  trap cleanup EXIT INT TERM

  if ! truthy "$EIDOLON_PWNKIT_QUAL_DIRECT_SKIP_BUILD"; then
    build_target_binary
  fi
  start_target "$target_addr"

  local run_dirs=()
  for ((run_index = 1; run_index <= RUN_COUNT; run_index++)); do
    run_one_sample "$run_index"
    run_dirs+=("$SAMPLE_DIR/run-$run_index")
  done

  "$SCRIPT_DIR/collect-pwnkit-direct-qualification-sample.sh" "${run_dirs[@]}" \
    > "$SAMPLE_DIR/pwnkit-stability-sample.json"
  EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS="$EIDOLON_PWNKIT_QUAL_ALLOW_AGENT_ERRORS" \
    "$SCRIPT_DIR/check-pwnkit-direct-qualification-sample.sh" \
    "$SAMPLE_DIR/pwnkit-stability-sample.json"

  echo "pwnkit direct qualification summary: $SAMPLE_DIR/pwnkit-stability-sample.json"
}

main "$@"
