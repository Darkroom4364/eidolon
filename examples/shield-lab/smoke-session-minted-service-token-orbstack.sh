#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPORT_SCRIPT="${EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT:-$SCRIPT_DIR/export-edge-decisions-orbstack.sh}"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
EDGE_EXPORT_BIN="${EIDOLON_EDGE_EXPORT_BIN:-}"
SURFACE_PATH="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_SURFACE_PATH:-/docs/service-token}"
ACTION_PATH="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_ACTION_PATH:-/api/v2/import/reconcile}"
EXPECTED_BAIT_ID="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_BAIT_ID:-fake_service_token}"
HEADER_NAME="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_HEADER_NAME:-X-Api-Key}"
HEADER_PREFIX="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_HEADER_PREFIX:-svc}"
MINTED_VALUE_PATTERN="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_VALUE_PATTERN:-svc_[0-9a-f]+}"
LEGACY_STATIC_MARKER="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_LEGACY_STATIC_MARKER:-eidolon_lab_token_2026_05_7e2a}"
REPLAY_EXPECTED_HTTP_CODE="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_REPLAY_EXPECTED_HTTP_CODE:-403}"
SESSION_A="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_SESSION_A:-}"
SESSION_B="${EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_SESSION_B:-}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-session-minted-service-token-orbstack.sh

Performs a live OrbStack smoke check for the default session-minted service-
token bait. It fetches the baited surface twice in one session and once in a
different session, proves the minted header value is stable only within a
session, rejects a cross-session replay of the minted value, sends the exact
same-session bait-derived action, and verifies the safe mint audit metadata
through the edge-decision export.
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

resolve_edge_export_bin() {
  if [[ -n "$EDGE_EXPORT_BIN" ]]; then
    return
  fi

  EDGE_EXPORT_BIN="$tmp_dir/eidolon-edge-export-current"
  cat > "$EDGE_EXPORT_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cargo run -q -p eidolon-trace --bin eidolon-edge-export -- "$@"
SH
  chmod +x "$EDGE_EXPORT_BIN"
}

extract_minted_value() {
  local file="$1"
  local value

  value="$(grep -Eo "$MINTED_VALUE_PATTERN" "$file" | head -n 1 || true)"
  [[ -n "$value" ]] || fail "could not extract a minted service-token value from $file"
  printf '%s' "$value"
}

mint_session_cookie() {
  local headers value

  headers="$(curl_cmd -fsS -D - -o /dev/null "${edge_url}/")" \
    || fail "could not mint an eidolon_session cookie from ${edge_url}/"
  value="$(
    printf '%s\n' "$headers" \
      | tr -d '\r' \
      | sed -n 's/^[Ss]et-[Cc]ookie:[[:space:]]*eidolon_session=\([^;[:space:]]*\).*$/\1/p' \
      | head -n 1
  )"
  [[ -n "$value" ]] || fail "shield edge did not issue an eidolon_session cookie"
  printf '%s' "$value"
}

resolve_session_cookie() {
  local current_value="$1"

  if [[ -n "$current_value" ]]; then
    printf '%s' "$current_value"
    return
  fi

  mint_session_cookie
}

session_uuid_from_cookie_value() {
  local value="$1"

  if [[ "$value" == v1.*.*.*.* ]]; then
    printf '%s' "$value" | cut -d. -f4
    return
  fi

  printf '%s' "$value"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command "$KUBECTL_BIN"
require_command "$CURL_BIN"
require_command jq
require_command mktemp
require_command awk
require_command grep
require_command sed
require_command cut

context="$(kubectl_cmd config current-context)"
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  fail "expected kubectl current-context to be ${EXPECTED_CONTEXT}, got: ${context}"
fi

edge_svc_json="$(kubectl_cmd -n shield-system get svc eidolon-shield-edge -o json)"
edge_node_port="$(jq -r '.spec.ports[] | select(.name == "http") | (.nodePort // empty)' <<<"$edge_svc_json")"
[[ -n "$edge_node_port" ]] || fail "shield edge service has no http NodePort"
edge_url="http://${EDGE_HOST}:${edge_node_port}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-session-minted-service-token.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin
SESSION_A_COOKIE="$(resolve_session_cookie "$SESSION_A")"
SESSION_A="$(session_uuid_from_cookie_value "$SESSION_A_COOKIE")"
SESSION_B_COOKIE="$(resolve_session_cookie "$SESSION_B")"
SESSION_B="$(session_uuid_from_cookie_value "$SESSION_B_COOKIE")"

a1_headers="$tmp_dir/a1.headers"
a1_body="$tmp_dir/a1.body"
a2_headers="$tmp_dir/a2.headers"
a2_body="$tmp_dir/a2.body"
b1_headers="$tmp_dir/b1.headers"
b1_body="$tmp_dir/b1.body"
action_headers="$tmp_dir/action.headers"
action_body="$tmp_dir/action.body"
replay_headers="$tmp_dir/replay.headers"
replay_body="$tmp_dir/replay.body"
events_file="$tmp_dir/events.jsonl"
edge_export_a_file="$tmp_dir/edge-export-a.json"
edge_export_b_file="$tmp_dir/edge-export-b.json"

curl_cmd -fsS \
  -D "$a1_headers" \
  -o "$a1_body" \
  -H "Cookie: eidolon_session=${SESSION_A_COOKIE}" \
  "${edge_url}${SURFACE_PATH}"

curl_cmd -fsS \
  -D "$a2_headers" \
  -o "$a2_body" \
  -H "Cookie: eidolon_session=${SESSION_A_COOKIE}" \
  "${edge_url}${SURFACE_PATH}"

curl_cmd -fsS \
  -D "$b1_headers" \
  -o "$b1_body" \
  -H "Cookie: eidolon_session=${SESSION_B_COOKIE}" \
  "${edge_url}${SURFACE_PATH}"

for body in "$a1_body" "$a2_body" "$b1_body"; do
  if grep -Fq "$LEGACY_STATIC_MARKER" "$body"; then
    fail "service-token bait surface still exposed the legacy static token marker"
  fi
done

value_a1="$(extract_minted_value "$a1_body")"
value_a2="$(extract_minted_value "$a2_body")"
value_b1="$(extract_minted_value "$b1_body")"

[[ "$value_a1" == "$value_a2" ]] \
  || fail "same-session service-token bait was not stable across repeated exposure"
[[ "$value_a1" != "$value_b1" ]] \
  || fail "different-session service-token bait did not mint a distinct header value"

curl_cmd -sS \
  -X POST \
  -D "$replay_headers" \
  -o "$replay_body" \
  -H "Cookie: eidolon_session=${SESSION_B_COOKIE}" \
  -H "${HEADER_NAME}: ${value_a1}" \
  "${edge_url}${ACTION_PATH}"

replay_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$replay_headers")"
[[ "$replay_http_code" == "$REPLAY_EXPECTED_HTTP_CODE" ]] \
  || fail "expected HTTP ${REPLAY_EXPECTED_HTTP_CODE} from the cross-session replay, got: ${replay_http_code:-none}"
if grep -Fq '"write_committed":false' "$replay_body"; then
  fail "cross-session replay unexpectedly received the controlled-reality bait action body"
fi

curl_cmd -sS \
  -X POST \
  -D "$action_headers" \
  -o "$action_body" \
  -H "Cookie: eidolon_session=${SESSION_A_COOKIE}" \
  -H "${HEADER_NAME}: ${value_a1}" \
  "${edge_url}${ACTION_PATH}"

action_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$action_headers")"
[[ "$action_http_code" == "202" ]] \
  || fail "expected HTTP 202 from the same-session exact minted bait action, got: ${action_http_code:-none}"
grep -Fq '"write_committed":false' "$action_body" \
  || fail "same-session exact minted bait action did not receive the expected controlled-reality body"

read_proxy_state_file events.jsonl > "$events_file"

exposure_a_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_A" \
    --arg bait_id "$EXPECTED_BAIT_ID" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "bait_exposed"
          and .kind.bait_id == $bait_id
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_A} had no bait_exposed event for ${EXPECTED_BAIT_ID}"

exposure_b_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_B" \
    --arg bait_id "$EXPECTED_BAIT_ID" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "bait_exposed"
          and .kind.bait_id == $bait_id
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_B} had no bait_exposed event for ${EXPECTED_BAIT_ID}"

exposure_a_id="$(jq -r '.kind.exposure_id // empty' <<<"$exposure_a_json")"
exposure_b_id="$(jq -r '.kind.exposure_id // empty' <<<"$exposure_b_json")"
[[ -n "$exposure_a_id" ]] || fail "session ${SESSION_A} bait exposure had no exposure id"
[[ -n "$exposure_b_id" ]] || fail "session ${SESSION_B} bait exposure had no exposure id"

jq -e \
  --arg surface "$SURFACE_PATH" \
  --arg header_name "$HEADER_NAME" \
  --arg prefix "$HEADER_PREFIX" '
    .kind.surface == $surface
    and .kind.header_value_mint.header_name == $header_name
    and .kind.header_value_mint.kind == "session_hmac_sha256_v1"
    and .kind.header_value_mint.prefix == $prefix
  ' <<<"$exposure_a_json" >/dev/null \
  || fail "session ${SESSION_A} bait exposure did not preserve the expected mint audit metadata"

jq -e \
  --arg surface "$SURFACE_PATH" \
  --arg header_name "$HEADER_NAME" \
  --arg prefix "$HEADER_PREFIX" '
    .kind.surface == $surface
    and .kind.header_value_mint.header_name == $header_name
    and .kind.header_value_mint.kind == "session_hmac_sha256_v1"
    and .kind.header_value_mint.prefix == $prefix
  ' <<<"$exposure_b_json" >/dev/null \
  || fail "session ${SESSION_B} bait exposure did not preserve the expected mint audit metadata"

replay_action_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_B" \
    --arg bait_id "$EXPECTED_BAIT_ID" \
    --arg path "$ACTION_PATH" '
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
)" || fail "session ${SESSION_B} had no bait_action_observed event for the cross-session replay"

jq -e \
  --arg header_name "$HEADER_NAME" \
  --arg prefix "$HEADER_PREFIX" '
    .policy_state == "observe"
    and .kind.exposure_id == null
    and .kind.method == "POST"
    and .kind.header_value_mint.header_name == $header_name
    and .kind.header_value_mint.kind == "session_hmac_sha256_v1"
    and .kind.header_value_mint.prefix == $prefix
  ' <<<"$replay_action_json" >/dev/null \
  || fail "session ${SESSION_B} replay action did not stay uncorrelated with the expected mint audit metadata"

replay_request_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_B" \
    --arg path "$ACTION_PATH" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "request_seen"
          and (.kind.path // "") == $path
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_B} had no request_seen event for the cross-session replay"

jq -e '
    .policy_state == "observe"
    and .kind.routing_decision == "eidolon_owned"
  ' <<<"$replay_request_json" >/dev/null \
  || fail "session ${SESSION_B} replay request was not held Eidolon-owned (fail closed)"

jq -e -s \
  --arg session_id "$SESSION_B" '
    map(
      select(
        .session_id == $session_id
        and .kind.type == "policy_changed"
        and .kind.to == "controlled_reality"
      )
    )
    | length == 0
  ' "$events_file" >/dev/null \
  || fail "session ${SESSION_B} replay unexpectedly moved into controlled reality"

action_event_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_A" \
    --arg bait_id "$EXPECTED_BAIT_ID" \
    --arg path "$ACTION_PATH" '
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
)" || fail "session ${SESSION_A} had no bait_action_observed event for ${EXPECTED_BAIT_ID}"

jq -e \
  --arg exposure_id "$exposure_a_id" \
  --arg header_name "$HEADER_NAME" \
  --arg prefix "$HEADER_PREFIX" '
    .kind.exposure_id == $exposure_id
    and .kind.method == "POST"
    and .kind.header_value_mint.header_name == $header_name
    and .kind.header_value_mint.kind == "session_hmac_sha256_v1"
    and .kind.header_value_mint.prefix == $prefix
  ' <<<"$action_event_json" >/dev/null \
  || fail "session ${SESSION_A} bait action did not preserve the expected same-session mint audit metadata"

policy_changed_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_A" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "policy_changed"
          and .kind.from == "observe"
          and .kind.to == "controlled_reality"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_A} had no observe -> controlled_reality transition after the minted bait action"

jq -e \
  --arg reason_substring "confirmed bait-derived action moved session into controlled reality" '
    (.kind.reason // "") | contains($reason_substring)
  ' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${SESSION_A} controlled-reality transition reason did not match the exact minted bait action path"

  EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
  EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
  KUBECTL_BIN="$KUBECTL_BIN" \
  "$EXPORT_SCRIPT" \
  --session "$SESSION_A" \
  --format json > "$edge_export_a_file"

EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
  EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
  KUBECTL_BIN="$KUBECTL_BIN" \
  "$EXPORT_SCRIPT" \
  --session "$SESSION_B" \
  --format json > "$edge_export_b_file"

jq -e \
  --arg session_id "$SESSION_A" \
  --arg path "$ACTION_PATH" \
  --arg bait_id "$EXPECTED_BAIT_ID" \
  --arg header_name "$HEADER_NAME" \
  --arg prefix "$HEADER_PREFIX" '
    length == 1
    and .[0].session_id == $session_id
    and .[0].request.method == "POST"
    and .[0].request.path == $path
    and .[0].policy.state == "controlled_reality"
    and .[0].policy.routing_decision == "controlled_reality"
    and .[0].edge_recommendation.action == "preserve_eidolon_routing"
    and (.[0].edge_recommendation.reason_codes // []) == ["eidolon_runtime_enforcement", "controlled_reality"]
    and (.[0].evidence.bait_header_value_mints // []) == [
      {
        "bait_id": $bait_id,
        "header_name": $header_name,
        "kind": "session_hmac_sha256_v1",
        "prefix": $prefix
      }
    ]
  ' "$edge_export_a_file" >/dev/null \
  || fail "session ${SESSION_A} edge export did not preserve the expected minted bait audit metadata"

jq -e \
  --arg session_id "$SESSION_A" \
  --arg bait_id "$EXPECTED_BAIT_ID" \
  --arg header_name "$HEADER_NAME" \
  --arg prefix "$HEADER_PREFIX" '
    .[0].evidence.latest_bait_header_value_mint == {
      "bait_id": $bait_id,
      "header_name": $header_name,
      "kind": "session_hmac_sha256_v1",
      "prefix": $prefix,
      "status": "matched_session_value"
    }
  ' "$edge_export_a_file" >/dev/null \
  || fail "session ${SESSION_A} edge export did not record a matched session-minted header outcome"

jq -e \
  --arg session_id "$SESSION_B" \
  --arg path "$ACTION_PATH" \
  --arg bait_id "$EXPECTED_BAIT_ID" \
  --arg header_name "$HEADER_NAME" \
  --arg prefix "$HEADER_PREFIX" '
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
      "status": "session_value_mismatch"
    }
  ' "$edge_export_b_file" >/dev/null \
  || fail "session ${SESSION_B} edge export did not record a mismatched session-minted header outcome"

if grep -Fq "$value_a1" "$events_file" \
  || grep -Fq "$value_a1" "$edge_export_a_file" \
  || grep -Fq "$value_a1" "$edge_export_b_file"; then
  fail "minted value from session ${SESSION_A} leaked into event or export artifacts"
fi
if grep -Fq "$value_b1" "$events_file" \
  || grep -Fq "$value_b1" "$edge_export_a_file" \
  || grep -Fq "$value_b1" "$edge_export_b_file"; then
  fail "minted value from session ${SESSION_B} leaked into event or export artifacts"
fi

echo "session-minted service-token smoke ok: session ${SESSION_A} stayed stable, session ${SESSION_B} differed, cross-session replay stayed uncorrelated, and safe mint audit metadata exported without leaking values"
