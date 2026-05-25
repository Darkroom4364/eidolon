#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/../lib/local-lab.sh"

MODE="${1:-all}"
BASE_URL="${EIDOLON_LAB_BASE_URL:-${EIDOLON_LAB_TARGET_URL:-http://127.0.0.1:9001}}"
BASE_URL="${BASE_URL%/}"

usage() {
  cat <<'USAGE'
Usage: examples/baselines/defense-modes.sh [all|no-defense|static-token|static-honeypot|waf-style-block]

Runs small comparison baselines against the same loopback Eidolon Lab target
and emits JSONL for examples/metrics/collect-baselines.sh.

Environment:
  EIDOLON_LAB_BASE_URL    URL to replay against. Defaults to http://127.0.0.1:9001.

The URL must be loopback. Public or third-party targets are rejected.
USAGE
}

json_line() {
  local baseline_mode="$1"
  local traffic_kind="$2"
  local method="$3"
  local path="$4"
  local status="$5"
  local target_requested="$6"
  local bait_exposed="$7"
  local bait_action="$8"
  local blocked="$9"
  local real_surface="${10}"
  local after_decision="${11}"

  jq -cn \
    --arg baseline_mode "$baseline_mode" \
    --arg traffic_kind "$traffic_kind" \
    --arg method "$method" \
    --arg path "$path" \
    --argjson status "$status" \
    --argjson target_requested "$target_requested" \
    --argjson bait_exposed "$bait_exposed" \
    --argjson bait_action "$bait_action" \
    --argjson blocked "$blocked" \
    --argjson real_surface "$real_surface" \
    --argjson after_decision "$after_decision" \
    --argjson elapsed_seconds "$SECONDS" \
    '{
      run_kind: "defense_baseline",
      baseline_mode: $baseline_mode,
      traffic_kind: $traffic_kind,
      method: $method,
      path: $path,
      status: $status,
      target_requested: $target_requested,
      bait_exposed: $bait_exposed,
      bait_action: $bait_action,
      blocked: $blocked,
      real_surface: $real_surface,
      after_decision: $after_decision,
      elapsed_seconds: $elapsed_seconds
    }'
}

request_target() {
  local baseline_mode="$1"
  local traffic_kind="$2"
  local method="$3"
  local path="$4"
  local bait_exposed="$5"
  local bait_action="$6"
  local real_surface="$7"
  local after_decision="$8"
  local extra_header="${9:-}"
  local user_agent="eidolon-lab-defense-baseline/0.1"
  local status

  if [[ "$method" == "POST" ]]; then
    local args=(
      -sS
      -o /dev/null
      -w '%{http_code}'
      -X "$method"
      -A "$user_agent"
      -H 'Accept: application/json'
      -H 'Content-Type: application/json'
      --data '{"source":"defense-baseline","mode":"synthetic"}'
    )

    if [[ -n "$extra_header" ]]; then
      args+=(-H "$extra_header")
    fi

    status="$(curl "${args[@]}" "$BASE_URL$path")"
  else
    status="$(
      curl -sS -o /dev/null -w '%{http_code}' \
        -X "$method" \
        -A "$user_agent" \
        -H 'Accept: text/html,application/json;q=0.9,*/*;q=0.8' \
        "$BASE_URL$path"
    )"
  fi

  json_line \
    "$baseline_mode" \
    "$traffic_kind" \
    "$method" \
    "$path" \
    "$status" \
    true \
    "$bait_exposed" \
    "$bait_action" \
    false \
    "$real_surface" \
    "$after_decision"
}

blocked_request() {
  local baseline_mode="$1"
  local method="$2"
  local path="$3"

  json_line \
    "$baseline_mode" \
    "follow-probe" \
    "$method" \
    "$path" \
    403 \
    false \
    false \
    false \
    true \
    false \
    false
}

run_common_surface() {
  local baseline_mode="$1"
  local exposes_bait="$2"

  request_target "$baseline_mode" "surface" "GET" "/docs" "$exposes_bait" false true false
  request_target "$baseline_mode" "surface" "GET" "/openapi.json" false false true false
  request_target "$baseline_mode" "normal" "GET" "/api/v1/projects" false false true false
}

run_no_defense() {
  run_common_surface "no-defense" false
  request_target "no-defense" "follow-probe" "POST" "/api/v2/import/reconcile" false false false false
  request_target "no-defense" "post-decision" "GET" "/api/v1/projects/alpha" false false true true
}

run_static_token() {
  run_common_surface "static-token" true
  request_target \
    "static-token" \
    "follow-probe" \
    "POST" \
    "/api/v2/import/reconcile" \
    false \
    true \
    false \
    false \
    "X-Eidolon-Lab-Clue: static-token"
  request_target "static-token" "post-decision" "GET" "/api/v1/projects/alpha" false false true true
}

run_static_honeypot() {
  run_common_surface "static-honeypot" true
  request_target "static-honeypot" "follow-probe" "POST" "/api/v2/import/reconcile" false true false false
  request_target "static-honeypot" "post-decision" "GET" "/api/v1/projects/alpha" false false true true
}

run_waf_style_block() {
  run_common_surface "waf-style-block" false
  blocked_request "waf-style-block" "POST" "/api/v2/import/reconcile"
}

main() {
  if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
    usage
    exit 0
  fi

  eidolon_lab_require_command jq
  eidolon_lab_require_loopback_url "EIDOLON_LAB_BASE_URL" "$BASE_URL"

  case "$MODE" in
    all)
      run_no_defense
      run_static_token
      run_static_honeypot
      run_waf_style_block
      ;;
    no-defense)
      run_no_defense
      ;;
    static-token)
      run_static_token
      ;;
    static-honeypot)
      run_static_honeypot
      ;;
    waf-style-block)
      run_waf_style_block
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
