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
SESSION_ID="${EIDOLON_SHIELD_HIDDEN_ROUTE_CONTROLLED_REALITY_SESSION_ID:-}"
SURFACE_PATH="${EIDOLON_SHIELD_HIDDEN_ROUTE_CONTROLLED_REALITY_SURFACE_PATH:-/customer/import-recovery-checklist}"
ACTION_PATH="${EIDOLON_SHIELD_HIDDEN_ROUTE_CONTROLLED_REALITY_ACTION_PATH:-/api/v2/import/reconcile}"
EXPECTED_BAIT_ID="${EIDOLON_SHIELD_HIDDEN_ROUTE_CONTROLLED_REALITY_BAIT_ID:-hidden_route_trace}"
EXPECTED_HEADER_NAME="${EIDOLON_SHIELD_HIDDEN_ROUTE_CONTROLLED_REALITY_HEADER_NAME:-X-Hidden-Route-Trace}"
EXPECTED_HEADER_VALUE="${EIDOLON_SHIELD_HIDDEN_ROUTE_CONTROLLED_REALITY_HEADER_VALUE:-hidden_route_2026_05_d91c}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-hidden-route-controlled-reality-orbstack.sh

Performs a live OrbStack smoke check for the default hidden-route bait. It
fetches the baited recovery checklist, extracts the static header instruction,
replays the exact same-session action, and verifies correlated bait evidence
plus controlled-reality export semantics on a second non-OpenAPI bait class.
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

resolve_session_id() {
  local current_value="$1"

  if [[ -n "$current_value" ]]; then
    printf '%s' "$current_value"
    return
  fi

  uuidgen | tr '[:upper:]' '[:lower:]'
}

extract_hidden_route_value() {
  local file="$1"
  local value

  value="$(
    awk -v header_name="$EXPECTED_HEADER_NAME" '
      {
        needle = "`" header_name ": ";
        start = index($0, needle);
        if (start == 0) {
          next;
        }
        value = substr($0, start + length(needle));
        end = index(value, "`");
        if (end == 0) {
          next;
        }
        print substr(value, 1, end - 1);
        exit;
      }
    ' "$file"
  )"
  [[ -n "$value" ]] || fail "could not extract hidden-route header value from $file"
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
if [[ -z "$SESSION_ID" ]]; then
  require_command uuidgen
fi

context="$(kubectl_cmd config current-context)"
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  fail "expected kubectl current-context to be ${EXPECTED_CONTEXT}, got: ${context}"
fi

edge_svc_json="$(kubectl_cmd -n shield-system get svc eidolon-shield-edge -o json)"
edge_node_port="$(jq -r '.spec.ports[] | select(.name == "http") | (.nodePort // empty)' <<<"$edge_svc_json")"
[[ -n "$edge_node_port" ]] || fail "shield edge service has no http NodePort"
edge_url="http://${EDGE_HOST}:${edge_node_port}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-hidden-route-controlled-reality.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
SESSION_ID="$(resolve_session_id "$SESSION_ID")"

surface_headers="$tmp_dir/surface.headers"
surface_body="$tmp_dir/surface.md"
action_headers="$tmp_dir/action.headers"
action_body="$tmp_dir/action.body"
events_file="$tmp_dir/events.jsonl"
edge_export_file="$tmp_dir/edge-export.json"

curl_cmd -fsS \
  -D "$surface_headers" \
  -o "$surface_body" \
  -H "Cookie: eidolon_session=${SESSION_ID}" \
  "${edge_url}${SURFACE_PATH}"

surface_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$surface_headers")"
[[ "$surface_http_code" == "200" ]] || fail "expected HTTP 200 for hidden-route surface, got: ${surface_http_code:-none}"

header_value="$(extract_hidden_route_value "$surface_body")"
[[ "$header_value" == "$EXPECTED_HEADER_VALUE" ]] \
  || fail "expected hidden-route header value ${EXPECTED_HEADER_VALUE}, got: ${header_value}"
grep -Fq "POST ${ACTION_PATH}" "$surface_body" \
  || fail "hidden-route surface did not preserve the expected action path"

curl_cmd -sS \
  -X POST \
  -D "$action_headers" \
  -o "$action_body" \
  -H "Cookie: eidolon_session=${SESSION_ID}" \
  -H "${EXPECTED_HEADER_NAME}: ${header_value}" \
  "${edge_url}${ACTION_PATH}"

action_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$action_headers")"
[[ "$action_http_code" == "202" ]] \
  || fail "expected HTTP 202 from the same-session hidden-route bait action, got: ${action_http_code:-none}"
grep -Fq '"write_committed":false' "$action_body" \
  || fail "same-session hidden-route bait action did not receive the expected controlled-reality body"

read_proxy_state_file events.jsonl > "$events_file"

exposure_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" \
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
)" || fail "session ${SESSION_ID} had no bait_exposed event for ${EXPECTED_BAIT_ID}"

action_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" \
    --arg bait_id "$EXPECTED_BAIT_ID" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "bait_action_observed"
          and .kind.bait_id == $bait_id
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_ID} had no bait_action_observed event for ${EXPECTED_BAIT_ID}"

exposure_id="$(jq -r '.kind.exposure_id // empty' <<<"$exposure_json")"
[[ -n "$exposure_id" ]] || fail "session ${SESSION_ID} bait exposure had no exposure id"

jq -e \
  --arg surface "$SURFACE_PATH" '
    .kind.surface == $surface
    and (.kind.header_value_mint // null) == null
  ' <<<"$exposure_json" >/dev/null \
  || fail "session ${SESSION_ID} hidden-route exposure did not preserve the expected static exposure semantics"

jq -e \
  --arg method "POST" \
  --arg path "$ACTION_PATH" \
  --arg exposure_id "$exposure_id" '
    .kind.method == $method
    and .kind.path == $path
    and .kind.exposure_id == $exposure_id
    and (.kind.header_value_mint // null) == null
    and (.kind.header_value_mint_status // null) == null
  ' <<<"$action_json" >/dev/null \
  || fail "session ${SESSION_ID} hidden-route bait action did not preserve the expected correlated static-bait semantics"

policy_changed_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" '
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
)" || fail "session ${SESSION_ID} had no observe -> controlled_reality policy transition"

jq -e '
  (.kind.reason // "") | contains("confirmed bait-derived action moved session into controlled reality")
' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${SESSION_ID} did not preserve the expected controlled-reality transition reason"

controlled_entry_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "controlled_reality_entered"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_ID} had no controlled_reality_entered event"

jq -e '.policy_state == "controlled_reality"' <<<"$controlled_entry_json" >/dev/null \
  || fail "session ${SESSION_ID} controlled_reality_entered event did not preserve controlled_reality state"

EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
  EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
  KUBECTL_BIN="$KUBECTL_BIN" \
  "$EXPORT_SCRIPT" \
  --session "$SESSION_ID" \
  --format json > "$edge_export_file"

jq -e \
  --arg session_id "$SESSION_ID" \
  --arg path "$ACTION_PATH" '
    (if type == "array" then . else [.] end) as $exports
    | ($exports | length) == 1
    and $exports[0].session_id == $session_id
    and $exports[0].request.method == "POST"
    and $exports[0].request.path == $path
    and $exports[0].policy.state == "controlled_reality"
    and $exports[0].policy.routing_decision == "controlled_reality"
    and (($exports[0].evidence.latest_bait_header_value_mint // null) == null)
    and (($exports[0].edge_recommendation.reason_codes // []) | index("controlled_reality")) != null
  ' "$edge_export_file" >/dev/null \
  || fail "edge export did not preserve the expected hidden-route controlled-reality semantics"

echo "hidden-route controlled reality smoke ok: session ${SESSION_ID} exposed ${EXPECTED_BAIT_ID}, replayed the same-session recovery header, and entered controlled reality without mint-specific audit fields"
