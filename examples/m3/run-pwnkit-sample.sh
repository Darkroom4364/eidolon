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
EIDOLON_M3_BAIT_SIGNING_SECRET_FILE="${EIDOLON_M3_BAIT_SIGNING_SECRET_FILE:-}"
EIDOLON_M3_ALLOW_AGENT_ERRORS="${EIDOLON_M3_ALLOW_AGENT_ERRORS:-0}"
EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE="${EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE:-0}"
EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="${EIDOLON_M3_PWNKIT_MAX_ATTEMPTS:-2}"
EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="${EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS:-900}"
EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="${EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS:-60}"
EIDOLON_M3_RUNNER_ENVIRONMENT="${EIDOLON_M3_RUNNER_ENVIRONMENT:-auto}"
EIDOLON_M3_NETWORK_TOPOLOGY="${EIDOLON_M3_NETWORK_TOPOLOGY:-same_host_loopback}"
EIDOLON_M3_PWNKIT_FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"
EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-}"
PWNKIT_SOURCE_DIR="${PWNKIT_SOURCE_DIR-$HOME/Projects/pwnkit}"

TARGET_PID=""
PROXY_PID=""
TARGET_BIN="$REPO_ROOT/target/debug/eidolon-demo-target"
PROXY_BIN="$REPO_ROOT/target/debug/eidolon-proxy"
FROZEN_BAIT_PROFILE=""
FROZEN_BAIT_PROFILE_SHA256=""
RUN_BAIT_PROFILE=""
RUN_BAIT_PROFILE_SHA256=""

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
  EIDOLON_M3_BAIT_SIGNING_SECRET_FILE
                                Proxy bait-signing secret file. Required when
                                the configured profile uses minted values.
                                Its path and value are never written to plans
                                or bait-profile metadata.
                                Each run uses a private frozen profile snapshot.
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
  EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS
                                Wall-clock timeout for each pwnkit scan leg.
                                Defaults to 900 seconds.
  EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS
                                Emit sanitized runner progress every N seconds
                                while pwnkit runs. Defaults to 60 seconds.
  EIDOLON_M3_SAMPLE_DRY_RUN    If true, create the planned directory layout only.
  EIDOLON_M3_CODEX_AUTH_FILE   Optional Codex auth JSON path passed through to
                                pwnkit-codex.sh. Defaults to ~/.codex/auth.json.
  EIDOLON_M3_RUNNER_ENVIRONMENT
                                Runner environment label recorded in metadata.
                                Defaults to auto; examples: host_mac, kali_vm,
                                linux_host.
  EIDOLON_M3_NETWORK_TOPOLOGY   Network topology label recorded in metadata.
                                Defaults to same_host_loopback.
  EIDOLON_M3_PWNKIT_FIXTURE_ID  Optional safe label for archived/private pinned
                                pwnkit fixtures. Leave unset for current-main
                                pwnkit evidence claims.
  EIDOLON_M3_PWNKIT_EVIDENCE_TRACK
                                Optional evidence track override:
                                upstream_current, local_patched_pwnkit, or
                                historical_stale.
  PWNKIT_SOURCE_DIR             Local pwnkit source checkout. Defaults to
                                ~/Projects/pwnkit.
  PWNKIT_NODE_ENTRY/PWNKIT_BIN  Explicit pwnkit runner overrides passed through
                                to pwnkit-codex.sh for diagnostics.

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

bait_profile_requires_signing_secret() {
  local profile_path="$1"

  jq -e '
    any(
      .baits[]?;
      (.expected_action.header_value_mint // null) != null
    )
  ' "$profile_path" >/dev/null
}

sha256_file() {
  local path="$1"
  local output

  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum "$path")"
  elif command -v shasum >/dev/null 2>&1; then
    output="$(shasum -a 256 "$path")"
  else
    fail "missing required SHA-256 tool: sha256sum or shasum"
  fi

  printf '%s' "${output%% *}"
}

validate_bait_profile_file() {
  local profile_path="$1"
  local label="$2"

  if ! jq empty "$profile_path" >/dev/null 2>&1; then
    fail "$label must contain valid JSON"
  fi
  if ! jq -s -e '
    length == 1
    and (
      .[0]
      | type == "object"
      and .schema_version == 1
      and (.profile_id | type == "string" and length > 0)
      and ((.baits // []) | type == "array")
      and all(
        (.baits // [])[];
        (.id | type == "string" and length > 0)
        and (.bait_class | type == "string" and length > 0)
      )
    )
  ' "$profile_path" >/dev/null; then
    fail "$label has invalid metadata fields"
  fi
}

validate_bait_configuration() {
  if [[ -n "$EIDOLON_M3_BAIT_PROFILE" && ! -f "$EIDOLON_M3_BAIT_PROFILE" ]]; then
    fail "EIDOLON_M3_BAIT_PROFILE must point to an existing file"
  fi

  if [[ -n "$EIDOLON_M3_BAIT_PROFILE" ]]; then
    validate_bait_profile_file \
      "$EIDOLON_M3_BAIT_PROFILE" \
      "EIDOLON_M3_BAIT_PROFILE"
  fi

  if [[ -n "$EIDOLON_M3_BAIT_SIGNING_SECRET_FILE" \
    && ! -f "$EIDOLON_M3_BAIT_SIGNING_SECRET_FILE" ]]; then
    fail "EIDOLON_M3_BAIT_SIGNING_SECRET_FILE must point to an existing file"
  fi

  if [[ -n "$EIDOLON_M3_BAIT_PROFILE" ]] \
    && bait_profile_requires_signing_secret "$EIDOLON_M3_BAIT_PROFILE" \
    && [[ -z "$EIDOLON_M3_BAIT_SIGNING_SECRET_FILE" ]]; then
    fail "EIDOLON_M3_BAIT_SIGNING_SECRET_FILE is required by the configured mint-enabled bait profile"
  fi
}

verify_bait_profile_snapshot() {
  local profile_path="$1"
  local expected_sha256="$2"
  local current_sha256

  [[ -n "$profile_path" ]] || return 0
  current_sha256="$(sha256_file "$profile_path")"
  if [[ "$current_sha256" != "$expected_sha256" ]]; then
    fail "run-owned bait profile snapshot digest changed"
  fi
}

write_bait_profile_metadata() {
  local profile_path="$1"
  local profile_sha256="$2"
  local output_file="$3"
  local temp_file="${output_file}.tmp"

  jq --arg sha256 "$profile_sha256" '
    {
      schema_version: 1,
      profile_id: .profile_id,
      sha256: $sha256,
      baits: [
        (.baits // [])[]
        | {
            bait_id: .id,
            bait_class: .bait_class
          }
      ]
    }
  ' "$profile_path" > "$temp_file"
  mv "$temp_file" "$output_file"
}

generate_execution_id() {
  local random_hex

  if [[ -r /dev/urandom ]] && command -v od >/dev/null 2>&1; then
    random_hex="$(
      od -An -N16 -tx1 /dev/urandom \
        | tr -d '[:space:]'
    )"
  elif command -v uuidgen >/dev/null 2>&1; then
    random_hex="$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')"
  else
    fail "unable to generate a non-secret execution ID"
  fi

  if [[ ! "$random_hex" =~ ^[0-9a-f]{32}$ ]]; then
    fail "unable to generate a valid execution ID"
  fi
  printf 'exec_%s' "$random_hex"
}

write_sample_run_metadata() {
  local output_file="$1"
  local execution_id="$2"
  local profile_sha256="$3"
  local temp_file="${output_file}.tmp"

  jq -n \
    --arg execution_id "$execution_id" \
    --arg profile_sha256 "$profile_sha256" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_sample_run",
      execution_id: $execution_id,
      profile_sha256: (
        if $profile_sha256 == "" then null else $profile_sha256 end
      )
    }' > "$temp_file"
  mv "$temp_file" "$output_file"
}

freeze_configured_bait_profile() {
  local snapshot_file="$SAMPLE_DIR/private/bait-profile.json"
  local temp_file="${snapshot_file}.tmp"

  [[ -n "$EIDOLON_M3_BAIT_PROFILE" ]] || return 0
  (
    umask 077
    cp "$EIDOLON_M3_BAIT_PROFILE" "$temp_file"
  )
  validate_bait_profile_file "$temp_file" "frozen bait profile"
  if bait_profile_requires_signing_secret "$temp_file" \
    && [[ -z "$EIDOLON_M3_BAIT_SIGNING_SECRET_FILE" ]]; then
    fail "EIDOLON_M3_BAIT_SIGNING_SECRET_FILE is required by the frozen mint-enabled bait profile"
  fi
  chmod 400 "$temp_file"
  mv "$temp_file" "$snapshot_file"

  FROZEN_BAIT_PROFILE="$snapshot_file"
  FROZEN_BAIT_PROFILE_SHA256="$(sha256_file "$snapshot_file")"
  verify_bait_profile_snapshot \
    "$FROZEN_BAIT_PROFILE" \
    "$FROZEN_BAIT_PROFILE_SHA256"
}

prepare_run_artifacts() {
  local run_dir="$1"
  local profile_snapshot="$run_dir/private/bait-profile.json"
  local profile_temp="${profile_snapshot}.tmp"
  local execution_id

  mkdir -p "$run_dir/private"
  RUN_BAIT_PROFILE=""
  RUN_BAIT_PROFILE_SHA256=""

  if [[ -e "$run_dir/sample-run-metadata.json" \
    || -e "$run_dir/bait-profile-metadata.json" \
    || -e "$profile_snapshot" ]]; then
    fail "run directory contains stale provenance artifacts"
  fi

  if [[ -n "$FROZEN_BAIT_PROFILE" ]]; then
    (
      umask 077
      cp "$FROZEN_BAIT_PROFILE" "$profile_temp"
    )
    chmod 400 "$profile_temp"
    mv "$profile_temp" "$profile_snapshot"
    RUN_BAIT_PROFILE="$profile_snapshot"
    RUN_BAIT_PROFILE_SHA256="$(sha256_file "$profile_snapshot")"
    if [[ "$RUN_BAIT_PROFILE_SHA256" != "$FROZEN_BAIT_PROFILE_SHA256" ]]; then
      fail "run-owned bait profile snapshot does not match the frozen profile"
    fi
    verify_bait_profile_snapshot \
      "$RUN_BAIT_PROFILE" \
      "$RUN_BAIT_PROFILE_SHA256"
    write_bait_profile_metadata \
      "$RUN_BAIT_PROFILE" \
      "$RUN_BAIT_PROFILE_SHA256" \
      "$run_dir/bait-profile-metadata.json"
  fi

  execution_id="$(generate_execution_id)"
  write_sample_run_metadata \
    "$run_dir/sample-run-metadata.json" \
    "$execution_id" \
    "$RUN_BAIT_PROFILE_SHA256"
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

  for ((run_index = 1; run_index <= RUN_COUNT; run_index++)); do
    prepare_run_artifacts "$SAMPLE_DIR/run-$run_index"
  done

  {
    printf 'run_count=%s\n' "$RUN_COUNT"
    printf 'sample_dir=%s\n' "$SAMPLE_DIR"
    printf 'target_url=%s\n' "$TARGET_URL"
    printf 'proxy_url=%s\n' "$PROXY_URL"
    printf 'target_addr=%s\n' "$target_addr"
    printf 'proxy_addr=%s\n' "$proxy_addr"
    printf 'pin_session=%s\n' "$EIDOLON_M3_PIN_SESSION"
    if [[ -n "$FROZEN_BAIT_PROFILE" ]]; then
      printf 'bait_profile=configured\n'
      printf 'bait_profile_sha256=%s\n' "$FROZEN_BAIT_PROFILE_SHA256"
      printf 'bait_profile_snapshot=run-*/private/bait-profile.json\n'
      printf 'bait_profile_metadata=run-*/bait-profile-metadata.json\n'
    else
      printf 'bait_profile=default\n'
      printf 'bait_profile_sha256=none\n'
      printf 'bait_profile_snapshot=none\n'
      printf 'bait_profile_metadata=none\n'
    fi
    printf 'sample_run_metadata=run-*/sample-run-metadata.json\n'
    if [[ -n "$EIDOLON_M3_BAIT_SIGNING_SECRET_FILE" ]]; then
      printf 'bait_signing_secret=configured\n'
    else
      printf 'bait_signing_secret=default\n'
    fi
    printf 'allow_agent_errors=%s\n' "$EIDOLON_M3_ALLOW_AGENT_ERRORS"
    printf 'allow_unfresh_pwnkit_source=%s\n' "$EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE"
    printf 'pwnkit_max_attempts=%s\n' "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
    printf 'pwnkit_timeout_seconds=%s\n' "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS"
    printf 'pwnkit_heartbeat_seconds=%s\n' "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS"
    printf 'runner_environment=%s\n' "$EIDOLON_M3_RUNNER_ENVIRONMENT"
    printf 'network_topology=%s\n' "$EIDOLON_M3_NETWORK_TOPOLOGY"
    printf 'pwnkit_fixture_id=%s\n' "${EIDOLON_M3_PWNKIT_FIXTURE_ID:-none}"
    printf 'pwnkit_evidence_track=%s\n' "${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-auto}"
    printf 'pwnkit_source_dir=%s\n' "${PWNKIT_SOURCE_DIR:-none}"
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
  local bait_profile_snapshot="$3"
  local log_file="$run_dir/private/eidolon-proxy.log"
  local proxy_args=(
    --listen-addr "$proxy_addr"
    --upstream "$TARGET_URL"
    --event-log "$run_dir/proxy-events.jsonl"
    --debug-log "$run_dir/private/eidolon-debug.jsonl"
  )

  if [[ -n "$bait_profile_snapshot" ]]; then
    proxy_args+=(--bait-profile "$bait_profile_snapshot")
  fi
  if [[ -n "$EIDOLON_M3_BAIT_SIGNING_SECRET_FILE" ]]; then
    proxy_args+=(--bait-signing-secret-file "$EIDOLON_M3_BAIT_SIGNING_SECRET_FILE")
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
    EIDOLON_M3_PIN_SESSION=0 \
    EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
    EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
    EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" \
    EIDOLON_M3_RUNNER_ENVIRONMENT="$EIDOLON_M3_RUNNER_ENVIRONMENT" \
    EIDOLON_M3_NETWORK_TOPOLOGY="$EIDOLON_M3_NETWORK_TOPOLOGY" \
    EIDOLON_M3_PWNKIT_FIXTURE_ID="$EIDOLON_M3_PWNKIT_FIXTURE_ID" \
    EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" \
    PWNKIT_SOURCE_DIR="$PWNKIT_SOURCE_DIR" \
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
    prepare_run_artifacts "$run_dir"
    echo "m3 pwnkit sample run $run_index/$RUN_COUNT attempt $attempt/$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS -> $run_dir" >&2

    start_proxy "$proxy_addr" "$run_dir" "$RUN_BAIT_PROFILE"
    verify_bait_profile_snapshot \
      "$RUN_BAIT_PROFILE" \
      "$RUN_BAIT_PROFILE_SHA256"
    local runner_status=0
    set +e
    EIDOLON_LAB_TARGET_URL="$TARGET_URL" \
      EIDOLON_LAB_PROXY_URL="$PROXY_URL" \
      EIDOLON_M3_PIN_SESSION="$EIDOLON_M3_PIN_SESSION" \
      EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
      EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
      EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" \
      EIDOLON_M3_RUNNER_ENVIRONMENT="$EIDOLON_M3_RUNNER_ENVIRONMENT" \
      EIDOLON_M3_NETWORK_TOPOLOGY="$EIDOLON_M3_NETWORK_TOPOLOGY" \
      EIDOLON_M3_PWNKIT_FIXTURE_ID="$EIDOLON_M3_PWNKIT_FIXTURE_ID" \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" \
      PWNKIT_SOURCE_DIR="$PWNKIT_SOURCE_DIR" \
      "$SCRIPT_DIR/pwnkit-codex.sh" all "$run_dir"
    runner_status="$?"
    set -e
    verify_bait_profile_snapshot \
      "$RUN_BAIT_PROFILE" \
      "$RUN_BAIT_PROFILE_SHA256"
    "$SCRIPT_DIR/collect-pwnkit-codex.sh" "$run_dir" > "$run_dir/pwnkit-summary.json"
    "$SCRIPT_DIR/collect-agent-replay-trace.sh" "$run_dir" \
      > "$run_dir/agent-replay-trace-summary.json"

    local health_status=0
    EIDOLON_M3_ALLOW_AGENT_ERRORS="$EIDOLON_M3_ALLOW_AGENT_ERRORS" \
      "$SCRIPT_DIR/check-pwnkit-summary-health.sh" "$run_dir/pwnkit-summary.json" \
      || health_status="$?"
    if [[ "$runner_status" -ne 0 && "$health_status" -eq 0 ]]; then
      health_status="$runner_status"
    fi

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
  require_positive_integer \
    "EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
    "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS"
  require_positive_integer \
    "EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" \
    "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS"
  require_command jq
  eidolon_lab_require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  eidolon_lab_require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
  validate_bait_configuration

  local target_addr
  local proxy_addr
  target_addr="$(eidolon_lab_listen_addr_for_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL")"
  proxy_addr="$(eidolon_lab_listen_addr_for_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL")"

  mkdir -p "$SAMPLE_DIR/private"
  freeze_configured_bait_profile

  if truthy "$EIDOLON_M3_SAMPLE_DRY_RUN"; then
    write_dry_run_plan "$target_addr" "$proxy_addr"
    exit 0
  fi

  require_command cargo
  require_command curl

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
