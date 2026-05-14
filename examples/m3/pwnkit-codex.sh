#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all}"
ARTIFACT_DIR="${2:-${EIDOLON_M3_ARTIFACT_DIR:-/tmp/eidolon-m3-pwnkit-$(date +%Y%m%d-%H%M%S)}}"
TARGET_URL="${EIDOLON_LAB_TARGET_URL:-http://127.0.0.1:9001}"
PROXY_URL="${EIDOLON_LAB_PROXY_URL:-http://127.0.0.1:8080}"
PWNKIT_DEPTH="${PWNKIT_DEPTH:-quick}"
PWNKIT_MODE="${PWNKIT_MODE:-web}"
PWNKIT_RUNTIME="${PWNKIT_RUNTIME:-codex}"
PWNKIT_RATE_LIMIT="${PWNKIT_RATE_LIMIT:-2}"
PWNKIT_FEATURE_CODEX_LIVE_TARGETS="${PWNKIT_FEATURE_CODEX_LIVE_TARGETS:-1}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/pwnkit-codex.sh [all|eidolon|direct] [artifact-dir]

Runs an authorized local pwnkit Codex scan against the Eidolon proxy and/or the
direct demo target. The demo target and proxy must already be running.

Environment:
  EIDOLON_LAB_TARGET_URL    Direct demo target URL. Defaults to http://127.0.0.1:9001.
  EIDOLON_LAB_PROXY_URL     Eidolon proxy URL. Defaults to http://127.0.0.1:8080.
  EIDOLON_M3_ARTIFACT_DIR   Artifact directory if [artifact-dir] is omitted.
  PWNKIT_NODE_ENTRY         Path to a built pwnkit dist/pwnkit.js entrypoint.
  PWNKIT_BIN                pwnkit command name when PWNKIT_NODE_ENTRY is unset.
  PWNKIT_DEPTH              pwnkit depth. Defaults to quick.
  PWNKIT_MODE               pwnkit mode. Defaults to web.
  PWNKIT_RUNTIME            pwnkit runtime. Defaults to codex.
  PWNKIT_RATE_LIMIT         pwnkit --rate-limit value. Defaults to 2.

For source checkouts, either set PWNKIT_NODE_ENTRY or keep a built checkout at
~/Projects/pwnkit/dist/pwnkit.js.

Some pwnkit builds exit nonzero after writing a valid JSON report with findings.
This runner keeps those reports and continues; missing or invalid reports remain
fatal.
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

resolve_pwnkit_command() {
  if [[ -n "${PWNKIT_NODE_ENTRY:-}" ]]; then
    if [[ ! -f "$PWNKIT_NODE_ENTRY" ]]; then
      echo "error: PWNKIT_NODE_ENTRY does not exist: $PWNKIT_NODE_ENTRY" >&2
      exit 2
    fi
    PWNKIT_COMMAND=(node "$PWNKIT_NODE_ENTRY")
    return
  fi

  if [[ -n "${PWNKIT_BIN:-}" ]]; then
    if ! command -v "$PWNKIT_BIN" >/dev/null 2>&1; then
      echo "error: PWNKIT_BIN command not found: $PWNKIT_BIN" >&2
      exit 2
    fi
    PWNKIT_COMMAND=("$PWNKIT_BIN")
    return
  fi

  if [[ -f "$HOME/Projects/pwnkit/dist/pwnkit.js" ]]; then
    PWNKIT_COMMAND=(node "$HOME/Projects/pwnkit/dist/pwnkit.js")
    return
  fi

  if command -v pwnkit >/dev/null 2>&1; then
    PWNKIT_COMMAND=(pwnkit)
    return
  fi

  if command -v pwnkit-cli >/dev/null 2>&1; then
    PWNKIT_COMMAND=(pwnkit-cli)
    return
  fi

  echo "error: could not find pwnkit; set PWNKIT_NODE_ENTRY or PWNKIT_BIN" >&2
  exit 2
}

valid_pwnkit_report() {
  local report_file="$1"

  if [[ ! -s "$report_file" ]]; then
    return 1
  fi

  if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to validate nonzero pwnkit reports" >&2
    return 1
  fi

  jq -e 'type == "object" and (.findings | type == "array")' "$report_file" >/dev/null
}

has_findings() {
  local report_file="$1"
  jq -e '(.findings // []) | length > 0' "$report_file" >/dev/null
}

finding_count() {
  local report_file="$1"
  jq -r '(.findings // []) | length' "$report_file"
}

run_scan() {
  local label="$1"
  local url="$2"
  local output_json="$ARTIFACT_DIR/pwnkit-$label.json"
  local output_db="$ARTIFACT_DIR/pwnkit-$label.db"
  local output_stderr="$ARTIFACT_DIR/pwnkit-$label.stderr.log"

  echo "m3 pwnkit $label -> $url" >&2

  set +e
  PWNKIT_FEATURE_CODEX_LIVE_TARGETS="$PWNKIT_FEATURE_CODEX_LIVE_TARGETS" \
  PWNKIT_NO_UPDATE_CHECK=1 \
    "${PWNKIT_COMMAND[@]}" scan \
      --target "$url" \
      --mode "$PWNKIT_MODE" \
      --depth "$PWNKIT_DEPTH" \
      --runtime "$PWNKIT_RUNTIME" \
      --format json \
      --db-path "$output_db" \
      --rate-limit "$PWNKIT_RATE_LIMIT" \
      --verbose \
      > "$output_json" \
      2> "$output_stderr"
  local exit_code=$?
  set -e

  if [[ "$exit_code" -eq 0 ]]; then
    if valid_pwnkit_report "$output_json"; then
      return 0
    fi

    echo "error: pwnkit $label exited 0 without a valid report; see $output_json" \
      >&2
    return 2
  fi

  if valid_pwnkit_report "$output_json" && has_findings "$output_json"; then
    echo "warning: pwnkit $label exited $exit_code after writing a valid report with $(finding_count "$output_json") findings; continuing" \
      >&2
    return 0
  fi

  if valid_pwnkit_report "$output_json"; then
    echo "error: pwnkit $label exited $exit_code with a valid report but no findings; see $output_stderr" \
      >&2
    return "$exit_code"
  fi

  echo "error: pwnkit $label exited $exit_code without a valid report; see $output_stderr" \
    >&2
  return "$exit_code"
}

main() {
  if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
    usage
    exit 0
  fi

  require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
  mkdir -p "$ARTIFACT_DIR"
  printf '%s\n' "$ARTIFACT_DIR" > "$ARTIFACT_DIR/artifact-dir.txt"

  declare -a PWNKIT_COMMAND
  resolve_pwnkit_command

  case "$MODE" in
    all)
      run_scan "eidolon" "$PROXY_URL"
      run_scan "direct" "$TARGET_URL"
      ;;
    eidolon)
      run_scan "eidolon" "$PROXY_URL"
      ;;
    direct)
      run_scan "direct" "$TARGET_URL"
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac

  echo "artifacts: $ARTIFACT_DIR" >&2
}

main "$@"
