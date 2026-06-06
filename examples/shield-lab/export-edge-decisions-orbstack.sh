#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
EDGE_EXPORT_BIN="${EIDOLON_EDGE_EXPORT_BIN:-}"
FORMAT="json"
SESSION_ID=""
WEBHOOK_URL=""
OUTPUT_PATH=""

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/export-edge-decisions-orbstack.sh [OPTIONS]

Builds live Eidolon edge decision exports from the OrbStack Shield lab event log.

Options:
  --format json|ndjson   Output format. Defaults to json.
  --session <UUID>       Export only one session. Defaults to all sessions with request_seen events.
  --webhook-url <URL>    POST each export to this webhook as application/json.
  --output <PATH>        Write exports to a file instead of stdout.
  -h, --help             Show this help text.

Environment:
  KUBECTL_BIN                   kubectl command override.
  CURL_BIN                      curl command override.
  EIDOLON_SHIELD_LOCAL_STATE_DIR
                                Read events.jsonl from a local fixture directory
                                instead of the live cluster.
  EIDOLON_EDGE_EXPORT_BIN       Explicit eidolon-edge-export executable path.
                                Defaults to target/debug/eidolon-edge-export if
                                present, otherwise cargo run -q -p eidolon-trace
                                --bin eidolon-edge-export --.

The script reads /var/lib/eidolon/events.jsonl from the live proxy deployment,
generates one EidolonEdgeDecisionExport per session, and optionally POSTs each
JSON document to a webhook or SIEM receiver.
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

kubectl_cmd() {
  "$KUBECTL_BIN" "$@"
}

curl_cmd() {
  "$CURL_BIN" "$@"
}

read_proxy_state_file() {
  local basename="$1"

  if [[ -n "$LOCAL_STATE_DIR" ]]; then
    cat "$LOCAL_STATE_DIR/$basename"
    return
  fi

  kubectl_cmd -n shield-system exec deploy/eidolon-shield-proxy -- sh -lc "cat /var/lib/eidolon/$basename"
}

run_edge_export() {
  if [[ -n "$EDGE_EXPORT_BIN" ]]; then
    "$EDGE_EXPORT_BIN" "$@"
    return
  fi

  if [[ -x "$REPO_ROOT/target/debug/eidolon-edge-export" ]]; then
    "$REPO_ROOT/target/debug/eidolon-edge-export" "$@"
    return
  fi

  cargo run -q -p eidolon-trace --bin eidolon-edge-export -- "$@"
}

collect_session_ids() {
  local events_file="$1"

  if [[ -n "$SESSION_ID" ]]; then
    printf '%s\n' "$SESSION_ID"
    return
  fi

  jq -r '
    select(.kind.type == "request_seen")
    | .session_id
  ' "$events_file" | sort -u
}

write_output() {
  local rendered="$1"

  if [[ -n "$OUTPUT_PATH" ]]; then
    printf '%s\n' "$rendered" > "$OUTPUT_PATH"
  else
    printf '%s\n' "$rendered"
  fi
}

post_webhook() {
  local ndjson_file="$1"

  [[ -n "$WEBHOOK_URL" ]] || return 0

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    curl_cmd -fsS \
      -H 'content-type: application/json' \
      --data "$line" \
      "$WEBHOOK_URL" >/dev/null
  done < "$ndjson_file"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      [[ $# -ge 2 ]] || fail "missing value for --format"
      FORMAT="$2"
      shift 2
      ;;
    --session)
      [[ $# -ge 2 ]] || fail "missing value for --session"
      SESSION_ID="$2"
      shift 2
      ;;
    --webhook-url)
      [[ $# -ge 2 ]] || fail "missing value for --webhook-url"
      WEBHOOK_URL="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || fail "missing value for --output"
      OUTPUT_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

case "$FORMAT" in
  json|ndjson)
    ;;
  *)
    fail "format must be json or ndjson"
    ;;
esac

require_command jq
if [[ -z "$LOCAL_STATE_DIR" ]]; then
  require_command "$KUBECTL_BIN"
fi
if [[ -n "$WEBHOOK_URL" ]]; then
  require_command "$CURL_BIN"
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-edge-decisions.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

events_file="$tmp_dir/events.jsonl"
read_proxy_state_file events.jsonl > "$events_file"
if [[ ! -s "$events_file" ]]; then
  fail "proxy event log is empty"
fi

session_file="$tmp_dir/sessions.txt"
collect_session_ids "$events_file" > "$session_file"
if [[ ! -s "$session_file" ]]; then
  fail "proxy event log contains no request_seen sessions to export"
fi

ndjson_file="$tmp_dir/edge-exports.ndjson"
while IFS= read -r session; do
  [[ -n "$session" ]] || continue
  run_edge_export --events "$events_file" --session "$session" >> "$ndjson_file"
done < "$session_file"

if [[ ! -s "$ndjson_file" ]]; then
  fail "no edge decision exports were produced"
fi

post_webhook "$ndjson_file"

if [[ "$FORMAT" == "ndjson" ]]; then
  write_output "$(cat "$ndjson_file")"
  exit 0
fi

write_output "$(jq -s '.' "$ndjson_file")"
