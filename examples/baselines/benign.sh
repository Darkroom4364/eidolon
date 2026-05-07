#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all}"
BASE_URL="${EIDOLON_LAB_BASE_URL:-${EIDOLON_LAB_TARGET_URL:-http://127.0.0.1:9001}}"
BASE_URL="${BASE_URL%/}"

usage() {
  cat <<'USAGE'
Usage: examples/baselines/benign.sh [all|curl-like|browser-like|crawler-like]

Runs benign local-only traffic against the Eidolon Lab demo target or a
loopback Eidolon proxy in front of it.

Environment:
  EIDOLON_LAB_BASE_URL    URL to replay against. Defaults to http://127.0.0.1:9001.

The URL must be loopback. Public or third-party targets are rejected.
USAGE
}

require_loopback_url() {
  if [[ "$BASE_URL" != http://* ]]; then
    echo "error: EIDOLON_LAB_BASE_URL must be an http loopback URL, got: $BASE_URL" >&2
    exit 2
  fi

  local rest="${BASE_URL#http://}"
  if [[ "$rest" == */* ]]; then
    echo "error: EIDOLON_LAB_BASE_URL must not include a path, got: $BASE_URL" >&2
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

  echo "error: EIDOLON_LAB_BASE_URL must be an http loopback URL, got: $BASE_URL" >&2
  exit 2
}

json_line() {
  local mode="$1"
  local method="$2"
  local path="$3"
  local status="$4"

  printf '{"mode":"%s","method":"%s","path":"%s","status":%s}\n' \
    "$mode" "$method" "$path" "$status"
}

request() {
  local mode="$1"
  local method="$2"
  local path="$3"
  local user_agent="$4"
  local status

  if [[ "$method" == "POST" ]]; then
    status="$(
      curl -sS -o /dev/null -w '%{http_code}' \
        -X "$method" \
        -A "$user_agent" \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/json' \
        --data '{"source":"benign-baseline","mode":"synthetic"}' \
        "$BASE_URL$path"
    )"
  else
    status="$(
      curl -sS -o /dev/null -w '%{http_code}' \
        -X "$method" \
        -A "$user_agent" \
        -H 'Accept: text/html,application/json;q=0.9,*/*;q=0.8' \
        "$BASE_URL$path"
    )"
  fi

  json_line "$mode" "$method" "$path" "$status"
}

run_curl_like() {
  local ua="eidolon-lab-curl-baseline/0.1"
  request "curl-like" "GET" "/health" "$ua"
  request "curl-like" "GET" "/api/v1/projects" "$ua"
  request "curl-like" "GET" "/api/v1/projects/alpha" "$ua"
  request "curl-like" "POST" "/api/v1/imports" "$ua"
}

run_browser_like() {
  local ua="Mozilla/5.0 EidolonLabBrowserBaseline/0.1"
  request "browser-like" "GET" "/" "$ua"
  request "browser-like" "GET" "/docs" "$ua"
  request "browser-like" "GET" "/openapi.json" "$ua"
  request "browser-like" "GET" "/api/v1/projects" "$ua"
  request "browser-like" "GET" "/api/v1/projects/bravo" "$ua"
}

run_crawler_like() {
  local ua="eidolon-lab-crawler-baseline/0.1"
  request "crawler-like" "GET" "/" "$ua"
  request "crawler-like" "GET" "/docs" "$ua"
  request "crawler-like" "GET" "/openapi.json" "$ua"
  request "crawler-like" "GET" "/api/v1/projects" "$ua"
  request "crawler-like" "GET" "/api/v1/imports/demo-import-1" "$ua"
}

main() {
  if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
    usage
    exit 0
  fi

  require_loopback_url

  case "$MODE" in
    all)
      run_curl_like
      run_browser_like
      run_crawler_like
      ;;
    curl-like)
      run_curl_like
      ;;
    browser-like)
      run_browser_like
      ;;
    crawler-like)
      run_crawler_like
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
