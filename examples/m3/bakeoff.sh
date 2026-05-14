#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all}"
TARGET_URL="${EIDOLON_LAB_TARGET_URL:-http://127.0.0.1:9001}"
PROXY_URL="${EIDOLON_LAB_PROXY_URL:-http://127.0.0.1:8080}"
RUNNER_KIND="${EIDOLON_M3_RUNNER_KIND:-scripted-probe}"
TARGET_URL="${TARGET_URL%/}"
PROXY_URL="${PROXY_URL%/}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/bakeoff.sh [all|no-defense|static-token|static-honeypot|waf-style-block|eidolon-mvp]

Runs the deterministic M3 scripted bakeoff matrix against loopback Lab surfaces
and emits JSONL for examples/m3/collect-bakeoff.sh.

Environment:
  EIDOLON_LAB_TARGET_URL   Direct owned demo target URL. Defaults to http://127.0.0.1:9001.
  EIDOLON_LAB_PROXY_URL    Eidolon proxy URL. Defaults to http://127.0.0.1:8080.
  EIDOLON_M3_RUNNER_KIND   Runner label. Defaults to scripted-probe.

The target and proxy URLs must be loopback. This runner compares Eidolon boundary
behavior, not agent capability or offensive solve rate.
USAGE
}

require_loopback_url() {
  local name="$1"
  local url="$2"

  if [[ "$url" != http://* ]]; then
    echo "error: $name must be an http loopback URL, got: $url" >&2
    exit 2
  fi

  local rest="${url#http://}"
  if [[ "$rest" == */* ]]; then
    echo "error: $name must not include a path, got: $url" >&2
    exit 2
  fi

  local authority="$rest"
  local host
  if [[ "$authority" == \[*\]* ]]; then
    host="${authority%%]*}"
    host="${host#[}"
  else
    host="${authority%%:*}"
  fi

  if [[ "$host" == "localhost" || "$host" == "::1" || "$host" =~ ^127(\.[0-9]{1,3}){3}$ ]]; then
    return
  fi

  echo "error: $name must be an http loopback URL, got: $url" >&2
  exit 2
}

json_line() {
  local defense_mode="$1"
  local base_url_kind="$2"
  local bait_class="$3"
  local step="$4"
  local method="$5"
  local path="$6"
  local status="$7"
  local request_sent="$8"
  local bait_exposed="$9"
  local bait_action="${10}"
  local blocked="${11}"
  local real_surface="${12}"
  local after_decision="${13}"
  local protected_upstream_reached="${14}"
  local false_positive="${15}"

  printf '{"schema_version":0,"run_kind":"m3_bakeoff","defense_mode":"%s","runner_kind":"%s","base_url_kind":"%s","bait_class":"%s","step":"%s","method":"%s","path":"%s","status":%s,"request_sent":%s,"bait_exposed":%s,"bait_action":%s,"blocked":%s,"real_surface":%s,"after_decision":%s,"protected_upstream_reached":%s,"false_positive":%s,"elapsed_seconds":%s}\n' \
    "$defense_mode" \
    "$RUNNER_KIND" \
    "$base_url_kind" \
    "$bait_class" \
    "$step" \
    "$method" \
    "$path" \
    "$status" \
    "$request_sent" \
    "$bait_exposed" \
    "$bait_action" \
    "$blocked" \
    "$real_surface" \
    "$after_decision" \
    "$protected_upstream_reached" \
    "$false_positive" \
    "$SECONDS"
}

curl_get() {
  local base_url="$1"
  local path="$2"
  local cookie_jar="$3"

  curl -sS -o /dev/null -w '%{http_code}' \
    -A "eidolon-m3-${RUNNER_KIND}/0.1" \
    -H 'Accept: text/html,application/json,application/javascript;q=0.9,*/*;q=0.8' \
    -b "$cookie_jar" \
    -c "$cookie_jar" \
    "$base_url$path"
}

curl_post() {
  local base_url="$1"
  local path="$2"
  local cookie_jar="$3"
  local header_name="$4"
  local header_value="$5"
  local status
  local args=(
    -sS
    -o /dev/null
    -w '%{http_code}'
    -X POST
    -A "eidolon-m3-${RUNNER_KIND}/0.1"
    -H 'Accept: application/json'
    -H 'Content-Type: application/json'
    -b "$cookie_jar"
    -c "$cookie_jar"
    --data '{"source":"m3-bakeoff","mode":"synthetic"}'
  )

  if [[ -n "$header_name" ]]; then
    args+=(-H "$header_name: $header_value")
  fi

  status="$(curl "${args[@]}" "$base_url$path")"
  printf '%s' "$status"
}

scenario() {
  local defense_mode="$1"
  local bait_class="$2"
  local surface_path="$3"
  local header_name="$4"
  local header_value="$5"
  local base_url="$TARGET_URL"
  local base_url_kind="direct_target"
  local cookie_jar
  local exposure_path="/docs"
  local action_header_name=""
  local action_header_value=""
  local exposure_is_bait=false
  local action_is_bait=false
  local blocked_action=false
  local send_action=true
  local action_status

  cookie_jar="$(mktemp "${TMPDIR:-/tmp}/eidolon-m3-cookies.XXXXXX")"

  case "$defense_mode" in
    no-defense)
      ;;
    static-token)
      exposure_is_bait=true
      action_is_bait=true
      action_header_name="X-Eidolon-Lab-Clue"
      action_header_value="static-token"
      ;;
    static-honeypot)
      exposure_is_bait=true
      action_is_bait=true
      ;;
    waf-style-block)
      blocked_action=true
      send_action=false
      ;;
    eidolon-mvp)
      base_url="$PROXY_URL"
      base_url_kind="proxy"
      exposure_path="$surface_path"
      exposure_is_bait=true
      action_is_bait=true
      action_header_name="$header_name"
      action_header_value="$header_value"
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac

  local exposure_status
  exposure_status="$(curl_get "$base_url" "$exposure_path" "$cookie_jar")"
  json_line "$defense_mode" "$base_url_kind" "$bait_class" "exposure" "GET" "$exposure_path" "$exposure_status" true "$exposure_is_bait" false false false false false false

  if [[ "$send_action" == true ]]; then
    action_status="$(curl_post "$base_url" "/api/v2/import/reconcile" "$cookie_jar" "$action_header_name" "$action_header_value")"
    json_line "$defense_mode" "$base_url_kind" "$bait_class" "action" "POST" "/api/v2/import/reconcile" "$action_status" true false "$action_is_bait" false false false false false
  else
    json_line "$defense_mode" "$base_url_kind" "$bait_class" "action" "POST" "/api/v2/import/reconcile" 403 false false false "$blocked_action" false false false false
  fi

  if [[ "$defense_mode" == "waf-style-block" ]]; then
    json_line "$defense_mode" "$base_url_kind" "$bait_class" "post_decision" "GET" "/api/v1/projects/alpha" 0 false false false false true true false false
  else
    local real_status
    local protected_upstream_reached=true
    if [[ "$defense_mode" == "eidolon-mvp" ]]; then
      protected_upstream_reached=false
    fi
    real_status="$(curl_get "$base_url" "/api/v1/projects/alpha" "$cookie_jar")"
    json_line "$defense_mode" "$base_url_kind" "$bait_class" "post_decision" "GET" "/api/v1/projects/alpha" "$real_status" true false false false true true "$protected_upstream_reached" false
  fi

  rm -f "$cookie_jar"
}

run_mode() {
  local defense_mode="$1"

  scenario "$defense_mode" "docs" "/docs/legacy-import" "X-Migration-Trace" "rel_2025_04_b7f2"
  scenario "$defense_mode" "open_api" "/openapi.json" "X-OpenAPI-Trace" "openapi_2026_05_f3a1"
  scenario "$defense_mode" "hidden_route" "/internal/legacy-import-checklist" "X-Hidden-Route-Trace" "hidden_route_2026_05_d91c"
  scenario "$defense_mode" "fake_credential_token" "/docs/service-token" "X-Api-Key" "eidolon_lab_token_2026_05_7e2a"
  scenario "$defense_mode" "js_discovered_route" "/assets/import-helper.js" "X-Import-Worker" "worker_2026_05_c19b"
}

main() {
  if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
    usage
    exit 0
  fi

  require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"

  case "$MODE" in
    all)
      run_mode "no-defense"
      run_mode "static-token"
      run_mode "static-honeypot"
      run_mode "waf-style-block"
      run_mode "eidolon-mvp"
      ;;
    no-defense|static-token|static-honeypot|waf-style-block|eidolon-mvp)
      run_mode "$MODE"
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
