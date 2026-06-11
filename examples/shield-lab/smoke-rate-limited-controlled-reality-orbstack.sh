#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPORT_SCRIPT="${EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT:-$SCRIPT_DIR/export-edge-decisions-orbstack.sh}"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
TRUSTED_INGRESS_SECRET_NAME="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
TRUSTED_INGRESS_SECRET_KEY="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
EDGE_EXPORT_BIN="${EIDOLON_EDGE_EXPORT_BIN:-}"
PROMOTION_PATH="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_PROMOTION_PATH:-/docs?topic=imports}"
PROMOTION_PATH_PREFIX="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_PROMOTION_PATH_PREFIX:-/docs}"
ACTION_PATH="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_ACTION_PATH:-/api/v2/import/reconcile}"
ACTION_PATH_PREFIX="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_ACTION_PATH_PREFIX:-/api/v2/import/reconcile}"
EXPECTED_BAIT_MARKER="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_BAIT_MARKER:-X-Migration-Trace: rel_2025_04_b7f2}"
EXPECTED_BAIT_ID="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_BAIT_ID:-rel_2025_04_b7f2}"
NEAR_MISS_HEADER_NAME="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_HEADER_NAME:-X-Migration-Trace}"
NEAR_MISS_HEADER_VALUE="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_NEAR_MISS_HEADER_VALUE:-wrong}"
EXACT_HEADER_VALUE="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_EXACT_HEADER_VALUE:-rel_2025_04_b7f2}"
EXPECTED_RETRY_AFTER="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_RETRY_AFTER:-30}"
ACTOR_KIND="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_ACTOR_KIND:-agentic_browser}"
VENDOR_SCORE="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_VENDOR_SCORE:-12}"
VENDOR_SCORE_KIND="${EIDOLON_SHIELD_RATE_LIMITED_CONTROLLED_REALITY_VENDOR_SCORE_KIND:-automation_likelihood_inverse}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-rate-limited-controlled-reality-orbstack.sh

Performs a live OrbStack smoke check for the first rate-limited-to-controlled-
reality slice. It promotes one session into suspicious from the authenticated
docs surface, sends one wrong-header decoy action near miss to move the session
into rate_limited, sends the exact same-session bait-derived action, verifies
that Eidolon moved the session into controlled_reality, and checks the same
session through edge export.
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

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command "$KUBECTL_BIN"
require_command "$CURL_BIN"
require_command jq
require_command base64
require_command mktemp
require_command awk
require_command grep

context="$(kubectl_cmd config current-context)"
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  fail "expected kubectl current-context to be ${EXPECTED_CONTEXT}, got: ${context}"
fi

edge_svc_json="$(kubectl_cmd -n shield-system get svc eidolon-shield-edge -o json)"
edge_node_port="$(jq -r '.spec.ports[] | select(.name == "http") | (.nodePort // empty)' <<<"$edge_svc_json")"
[[ -n "$edge_node_port" ]] || fail "shield edge service has no http NodePort"
edge_url="http://${EDGE_HOST}:${edge_node_port}"

secret_json="$(kubectl_cmd -n shield-system get secret "$TRUSTED_INGRESS_SECRET_NAME" -o json)"
transport_auth_secret="$(jq -r --arg key "$TRUSTED_INGRESS_SECRET_KEY" '.data[$key] // empty' <<<"$secret_json" | base64 --decode)"
[[ -n "$transport_auth_secret" ]] || fail "trusted ingress secret key ${TRUSTED_INGRESS_SECRET_KEY} is empty"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-rate-limited-controlled-reality-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin

cookie_jar="$tmp_dir/cookies.txt"
promotion_headers="$tmp_dir/promotion.headers"
promotion_body="$tmp_dir/promotion.body"
near_miss_headers="$tmp_dir/near-miss.headers"
near_miss_body="$tmp_dir/near-miss.body"
action_headers="$tmp_dir/action.headers"
action_body="$tmp_dir/action.body"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"
edge_export_file="$tmp_dir/edge-export.json"

curl_cmd -fsS \
  -c "$cookie_jar" \
  -D "$promotion_headers" \
  -o "$promotion_body" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${PROMOTION_PATH}"

promotion_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$promotion_headers")"
[[ "$promotion_http_code" == "200" ]] || fail "expected HTTP 200 from rate-limited controlled-reality promotion request, got: ${promotion_http_code:-none}"
grep -Fq "$EXPECTED_BAIT_MARKER" "$promotion_body" \
  || fail "rate-limited controlled-reality promotion request did not receive the expected baited promotion surface"

curl_cmd -sS \
  -X POST \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$near_miss_headers" \
  -o "$near_miss_body" \
  -H "${NEAR_MISS_HEADER_NAME}: ${NEAR_MISS_HEADER_VALUE}" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${ACTION_PATH}"

near_miss_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$near_miss_headers")"
[[ "$near_miss_http_code" == "429" ]] || fail "expected HTTP 429 from rate-limited controlled-reality near-miss request, got: ${near_miss_http_code:-none}"
retry_after="$(awk 'BEGIN{IGNORECASE=1} tolower($1) == "retry-after:" {gsub("\r", "", $2); print $2}' "$near_miss_headers" | tail -n 1)"
[[ "$retry_after" == "$EXPECTED_RETRY_AFTER" ]] \
  || fail "expected Retry-After ${EXPECTED_RETRY_AFTER} from rate-limited controlled-reality near-miss request, got: ${retry_after:-none}"

curl_cmd -sS \
  -X POST \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$action_headers" \
  -o "$action_body" \
  -H "${NEAR_MISS_HEADER_NAME}: ${EXACT_HEADER_VALUE}" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${ACTION_PATH}"

action_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$action_headers")"
[[ "$action_http_code" == "202" ]] || fail "expected HTTP 202 from rate-limited controlled-reality exact action request, got: ${action_http_code:-none}"
grep -Fq '"write_committed":false' "$action_body" \
  || fail "rate-limited controlled-reality exact action request did not receive the expected controlled-reality response body"

read_proxy_state_file events.jsonl > "$events_file"

action_request_json="$(
  jq -c -e -s \
    --arg path_prefix "$ACTION_PATH_PREFIX" \
    --arg actor_kind "$ACTOR_KIND" \
    --arg score_kind "$VENDOR_SCORE_KIND" \
    --argjson vendor_score "$VENDOR_SCORE" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
          and (.kind.ingress_identity.source // "none") == "none"
          and (.kind.ingress_identity.trust_tier // "none") == "none"
          and (.kind.ingress_signals.actor_kind // "") == $actor_kind
          and (.kind.ingress_signals.vendor_score // -1) == $vendor_score
          and (.kind.ingress_signals.vendor_score_kind // "") == $score_kind
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the rate-limited controlled-reality exact action request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$action_request_json")"
[[ -n "$session_id" ]] || fail "matching rate-limited controlled-reality action request had no session id"

jq -e '
  .policy_state == "rate_limited"
  and .kind.routing_decision == "eidolon_owned"
' <<<"$action_request_json" >/dev/null \
  || fail "matching rate-limited controlled-reality action request did not preserve the intercepted exact-match request routing"

controlled_transition_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "policy_changed"
          and .kind.from == "rate_limited"
          and .kind.to == "controlled_reality"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no rate_limited -> controlled_reality policy transition event"

jq -e \
  --arg reason_substring "confirmed bait-derived action moved session into controlled reality" '
    (.kind.reason // "") | contains($reason_substring)
  ' <<<"$controlled_transition_json" >/dev/null \
  || fail "session ${session_id} controlled-reality transition reason did not match the confirmed bait-action path"

bait_actions_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" \
    --arg path "$ACTION_PATH_PREFIX" \
    --arg bait_id "$EXPECTED_BAIT_ID" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "bait_action_observed"
          and .kind.bait_id == $bait_id
          and (.kind.path // "") == $path
        )
      )
    ' "$events_file"
)" || fail "session ${session_id} had no bait action observations on the rate-limited controlled-reality ladder"

jq -e '
  length >= 2
  and .[-1].policy_state == "rate_limited"
  and .[-1].kind.exposure_id != null
  and .[-1].kind.method == "POST"
' <<<"$bait_actions_json" >/dev/null \
  || fail "session ${session_id} did not preserve the matched same-session bait evidence before entering controlled reality"

controlled_entry_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "controlled_reality_entered"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no controlled_reality_entered event"

jq -e '.policy_state == "controlled_reality"' <<<"$controlled_entry_json" >/dev/null \
  || fail "session ${session_id} controlled_reality_entered event did not preserve controlled_reality state"

controlled_response_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "response_served"
          and .policy_state == "controlled_reality"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no controlled-reality response event"

jq -e '
  .kind.status == 202
  and .kind.routing_decision == "controlled_reality"
' <<<"$controlled_response_json" >/dev/null \
  || fail "session ${session_id} controlled-reality response did not preserve the expected containment decision"

read_proxy_state_file debug.jsonl > "$debug_file"

action_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "bait_action_observed"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no bait_action_observed debug record"

jq -e '
  .fields.matched_prior_exposure == true
  and .fields.prior_same_bait_exposure == true
' <<<"$action_debug_json" >/dev/null \
  || fail "session ${session_id} exact bait action debug record did not preserve the matched same-session evidence"

controlled_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "controlled_reality_action_selected"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no controlled_reality_action_selected debug record"

jq -e '
  .fields.depth == 1
  and .fields.action.type == "controlled_reality"
' <<<"$controlled_debug_json" >/dev/null \
  || fail "session ${session_id} did not enter controlled reality at the first action depth"

EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
  EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
  KUBECTL_BIN="$KUBECTL_BIN" \
  "$EXPORT_SCRIPT" \
  --session "$session_id" \
  --format json > "$edge_export_file"

jq -e '
  (if type == "array" then . else [.] end) as $exports
  | ($exports | length) == 1
  and $exports[0].request.path == "/api/v2/import/reconcile"
  and $exports[0].policy.state == "controlled_reality"
  and $exports[0].policy.routing_decision == "controlled_reality"
  and $exports[0].edge_recommendation.action == "preserve_eidolon_routing"
  and (($exports[0].edge_recommendation.reason_codes // []) | index("eidolon_runtime_enforcement")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("controlled_reality")) != null
' "$edge_export_file" >/dev/null \
  || fail "edge export did not preserve the new rate-limited controlled-reality runtime decision"

printf 'rate-limited-controlled-reality smoke ok: session=%s contained_after_exact_match=true\n' "$session_id"
