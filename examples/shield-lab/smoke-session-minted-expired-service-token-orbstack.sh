#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPORT_SCRIPT="${EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT:-$SCRIPT_DIR/export-edge-decisions-orbstack.sh}"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
EDGE_EXPORT_BIN="${EIDOLON_EDGE_EXPORT_BIN:-}"
SESSION_ID="${EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_SERVICE_TOKEN_SESSION_ID:-}"
EXPECTED_BAIT_ID="${EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_SERVICE_TOKEN_BAIT_ID:-fake_service_token}"
EXPECTED_PATH="${EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_SERVICE_TOKEN_ACTION_PATH:-/api/v2/import/reconcile}"
EXPECTED_HEADER_NAME="${EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_SERVICE_TOKEN_HEADER_NAME:-X-Api-Key}"
EXPECTED_PREFIX="${EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_SERVICE_TOKEN_HEADER_PREFIX:-svc}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-session-minted-expired-service-token-orbstack.sh

Validates that an already-observed expired session-minted service-token action
was held Eidolon-owned (fail closed) and exported as `expired_session_value`.

This script reads the proxy event log either from the live OrbStack cluster or
from `EIDOLON_SHIELD_LOCAL_STATE_DIR`, then verifies both the raw event and the
edge-decision export for one session.

Required environment:
  EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_SERVICE_TOKEN_SESSION_ID
    Session UUID to validate.
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

read_proxy_state_file() {
  local basename="$1"

  if [[ -n "$LOCAL_STATE_DIR" ]]; then
    cat "$LOCAL_STATE_DIR/$basename"
    return
  fi

  kubectl_cmd -n shield-system exec deploy/eidolon-shield-proxy -- sh -lc "cat /var/lib/eidolon/$basename"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command "$KUBECTL_BIN"
require_command jq
require_command mktemp
[[ -n "$SESSION_ID" ]] || fail "EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_SERVICE_TOKEN_SESSION_ID is required"

context="$(kubectl_cmd config current-context)"
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  fail "expected kubectl current-context to be ${EXPECTED_CONTEXT}, got: ${context}"
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-session-minted-expired-service-token.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

events_file="$tmp_dir/events.jsonl"
edge_export_file="$tmp_dir/edge-export.json"
read_proxy_state_file events.jsonl > "$events_file"

action_event_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" \
    --arg bait_id "$EXPECTED_BAIT_ID" \
    --arg path "$EXPECTED_PATH" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "bait_action_observed"
          and .kind.bait_id == $bait_id
          and (.kind.path // "") == $path
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_ID} had no bait_action_observed event for ${EXPECTED_BAIT_ID}"

jq -e \
  --arg header_name "$EXPECTED_HEADER_NAME" \
  --arg prefix "$EXPECTED_PREFIX" '
    .policy_state == "observe"
    and .kind.exposure_id != null
    and .kind.method == "POST"
    and .kind.header_value_mint.header_name == $header_name
    and .kind.header_value_mint.kind == "session_hmac_sha256_v1"
    and .kind.header_value_mint.prefix == $prefix
    and .kind.header_value_mint_status == "expired_session_value"
  ' <<<"$action_event_json" >/dev/null \
  || fail "session ${SESSION_ID} action event did not record the expected expired minted-proof outcome"

request_seen_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" \
    --arg path "$EXPECTED_PATH" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "request_seen"
          and (.kind.path // "") == $path
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_ID} had no request_seen event for ${EXPECTED_PATH}"

jq -e '
    .policy_state == "observe"
    and .kind.routing_decision == "eidolon_owned"
  ' <<<"$request_seen_json" >/dev/null \
  || fail "session ${SESSION_ID} expired minted proof was not held Eidolon-owned (fail closed)"

jq -e -s \
  --arg session_id "$SESSION_ID" '
    map(
      select(
        .session_id == $session_id
        and .kind.type == "policy_changed"
        and .kind.to == "controlled_reality"
      )
    )
    | length == 0
  ' "$events_file" >/dev/null \
  || fail "session ${SESSION_ID} unexpectedly moved into controlled reality"

EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
  EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
  KUBECTL_BIN="$KUBECTL_BIN" \
  "$EXPORT_SCRIPT" \
  --session "$SESSION_ID" \
  --format json > "$edge_export_file"

jq -e \
  --arg session_id "$SESSION_ID" \
  --arg bait_id "$EXPECTED_BAIT_ID" \
  --arg header_name "$EXPECTED_HEADER_NAME" \
  --arg prefix "$EXPECTED_PREFIX" \
  --arg path "$EXPECTED_PATH" '
    length == 1
    and .[0].session_id == $session_id
    and .[0].request.method == "POST"
    and .[0].request.path == $path
    and .[0].policy.state == "observe"
    and .[0].policy.routing_decision == "eidolon_owned"
    and .[0].evidence.latest_bait_header_value_mint == {
      "bait_id": $bait_id,
      "header_name": $header_name,
      "kind": "session_hmac_sha256_v1",
      "prefix": $prefix,
      "status": "expired_session_value"
    }
  ' "$edge_export_file" >/dev/null \
  || fail "session ${SESSION_ID} edge export did not preserve the expected expired minted-proof outcome"

echo "session-minted expired service-token smoke ok: session ${SESSION_ID} was held Eidolon-owned (fail closed) and exported expired_session_value without containment"
