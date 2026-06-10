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
PROMOTION_PATH="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_PROMOTION_PATH:-/openapi.json?eidolon_surface=legacy-import}"
PROMOTION_PATH_PREFIX="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_PROMOTION_PATH_PREFIX:-/openapi.json}"
RATE_LIMIT_PATH="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_RATE_LIMIT_PATH:-/docs}"
BLOCKED_PATH="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_BLOCKED_PATH:-/docs}"
EXPECTED_BAIT_MARKER="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_BAIT_MARKER:-X-OpenAPI-Trace}"
EXPECTED_BAIT_PATH_MARKER="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_BAIT_PATH_MARKER:-/api/v2/import/reconcile}"
EXPECTED_RETRY_AFTER="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_RETRY_AFTER:-30}"
ACTOR_KIND="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_ACTOR_KIND:-agentic_browser}"
VENDOR_SCORE="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_VENDOR_SCORE:-35}"
VENDOR_SCORE_KIND="${EIDOLON_SHIELD_RATE_LIMITED_RECON_BLOCKED_VENDOR_SCORE_KIND:-automation_likelihood_inverse}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-rate-limited-recon-blocked-orbstack.sh

Performs a live OrbStack smoke check for the first recon-driven
rate-limited-to-blocked slice. It promotes one session into suspicious from a
legacy-query OpenAPI discovery request, sends a same-session top-level docs
request to move the session into rate_limited from weighted recon churn, sends
another top-level discovery request, verifies that Eidolon moves the session
into blocked, and checks the same session through edge export.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-rate-limited-recon-blocked-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin

cookie_jar="$tmp_dir/cookies.txt"
promotion_headers="$tmp_dir/promotion.headers"
promotion_body="$tmp_dir/promotion.body"
rate_limit_headers="$tmp_dir/rate-limit.headers"
rate_limit_body="$tmp_dir/rate-limit.body"
blocked_headers="$tmp_dir/blocked.headers"
blocked_body="$tmp_dir/blocked.body"
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
[[ "$promotion_http_code" == "200" ]] || fail "expected HTTP 200 from recon-blocked promotion request, got: ${promotion_http_code:-none}"
grep -Fq "$EXPECTED_BAIT_MARKER" "$promotion_body" \
  || fail "recon-blocked promotion request did not receive the owned OpenAPI bait surface"
grep -Fq "$EXPECTED_BAIT_PATH_MARKER" "$promotion_body" \
  || fail "recon-blocked promotion request did not include the baited reconcile path"

curl_cmd -sS \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$rate_limit_headers" \
  -o "$rate_limit_body" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${RATE_LIMIT_PATH}"

rate_limit_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$rate_limit_headers")"
[[ "$rate_limit_http_code" == "429" ]] || fail "expected HTTP 429 from recon-blocked rate-limit request, got: ${rate_limit_http_code:-none}"
retry_after="$(awk 'BEGIN{IGNORECASE=1} tolower($1) == "retry-after:" {gsub("\r", "", $2); print $2}' "$rate_limit_headers" | tail -n 1)"
[[ "$retry_after" == "$EXPECTED_RETRY_AFTER" ]] \
  || fail "expected Retry-After ${EXPECTED_RETRY_AFTER} from recon-blocked rate-limit request, got: ${retry_after:-none}"

curl_cmd -sS \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$blocked_headers" \
  -o "$blocked_body" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${BLOCKED_PATH}"

blocked_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$blocked_headers")"
[[ "$blocked_http_code" == "403" ]] || fail "expected HTTP 403 from recon-blocked retry request, got: ${blocked_http_code:-none}"

read_proxy_state_file events.jsonl > "$events_file"

blocked_request_json="$(
  jq -c -e -s \
    --arg path "$BLOCKED_PATH" \
    --arg actor_kind "$ACTOR_KIND" \
    --arg score_kind "$VENDOR_SCORE_KIND" \
    --argjson vendor_score "$VENDOR_SCORE" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "") == $path
          and (.kind.ingress_identity.source // "none") == "none"
          and (.kind.ingress_identity.trust_tier // "none") == "none"
          and (.kind.ingress_signals.actor_kind // "") == $actor_kind
          and (.kind.ingress_signals.vendor_score // -1) == $vendor_score
          and (.kind.ingress_signals.vendor_score_kind // "") == $score_kind
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the recon-blocked retry request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$blocked_request_json")"
[[ -n "$session_id" ]] || fail "matching recon-blocked retry request had no session id"

jq -e '
  .policy_state == "blocked"
  and .kind.routing_decision == "eidolon_owned"
  and .kind.discovery_recon_score.repeated_discovery_score == 2
  and .kind.discovery_recon_score.query_score == 1
  and .kind.discovery_recon_score.legacy_openapi_query_score == 2
  and .kind.discovery_recon_score.total == 5
  and .kind.discovery_recon_score.threshold == 5
' <<<"$blocked_request_json" >/dev/null \
  || fail "matching recon-blocked retry request did not preserve the expected blocked decision or weighted recon state"

blocked_transition_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "policy_changed"
          and .kind.from == "rate_limited"
          and .kind.to == "blocked"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no rate_limited -> blocked policy transition event"

jq -e '
  ((.kind.reason // "") | contains("rate-limited discovery recon retry moved session to blocked"))
  and ((.kind.reason // "") | contains("path=/docs"))
  and ((.kind.reason // "") | contains("discovery_requests=3"))
  and ((.kind.reason // "") | contains("distinct_surfaces=2"))
  and ((.kind.reason // "") | contains("query_seen=true"))
  and ((.kind.reason // "") | contains("legacy_openapi_query_seen=true"))
  and ((.kind.reason // "") | contains("repeated_discovery_score=2"))
  and ((.kind.reason // "") | contains("query_score=1"))
  and ((.kind.reason // "") | contains("legacy_openapi_query_score=2"))
  and ((.kind.reason // "") | contains("recon_score=5"))
  and ((.kind.reason // "") | contains("recon_block_threshold=5"))
' <<<"$blocked_transition_json" >/dev/null \
  || fail "session ${session_id} blocked transition reason did not preserve the expected repeated recon facts"

blocked_response_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "response_served"
          and .policy_state == "blocked"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no blocked response event"

jq -e '
  .kind.status == 403
  and .kind.routing_decision == "eidolon_owned"
' <<<"$blocked_response_json" >/dev/null \
  || fail "session ${session_id} blocked response did not preserve the expected Eidolon-owned enforcement"

read_proxy_state_file debug.jsonl > "$debug_file"
request_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "request_received"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no request_received debug record"

jq -e '
  .fields.policy_state == "blocked"
  and .fields.path == "/docs"
  and .fields.query_present == false
  and .fields.discovery_request_count == 3
  and .fields.discovery_query_seen == true
  and .fields.discovery_legacy_openapi_query_seen == true
  and .fields.discovery_surface_fanout.distinct_surfaces == 2
  and .fields.discovery_recon_score.repeated_discovery_score == 2
  and .fields.discovery_recon_score.query_score == 1
  and .fields.discovery_recon_score.legacy_openapi_query_score == 2
  and .fields.discovery_recon_score.total == 5
  and .fields.discovery_recon_score.threshold == 5
' <<<"$request_debug_json" >/dev/null \
  || fail "session ${session_id} did not preserve the expected blocked recon debug state"

surface_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no surface_action_selected debug record"

jq -e '
  .fields.policy_state == "blocked"
  and .fields.policy_routing_decision == "eidolon_owned"
  and .fields.surface_action.type == "eidolon_owned"
  and .fields.policy_reason == "rate-limited discovery recon retry moved session to blocked: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=3 distinct_surfaces=2 query_seen=true legacy_openapi_query_seen=true linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false detection_count=0 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=2 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 detection_score=0 recon_score=5 recon_block_threshold=5"
' <<<"$surface_debug_json" >/dev/null \
  || fail "session ${session_id} did not keep the blocked recon retry reason on the Eidolon-owned enforcement path"

EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
  EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
  KUBECTL_BIN="$KUBECTL_BIN" \
  "$EXPORT_SCRIPT" \
  --session "$session_id" \
  --format json > "$edge_export_file"

jq -e '
  (if type == "array" then . else [.] end) as $exports
  | ($exports | length) == 1
  and $exports[0].request.path == "/docs"
  and $exports[0].policy.state == "blocked"
  and $exports[0].policy.routing_decision == "eidolon_owned"
  and ($exports[0].policy.reason | contains("rate-limited discovery recon retry moved session to blocked"))
  and $exports[0].discovery_recon_score.repeated_discovery_score == 2
  and $exports[0].discovery_recon_score.query_score == 1
  and $exports[0].discovery_recon_score.legacy_openapi_query_score == 2
  and $exports[0].discovery_recon_score.total == 5
  and $exports[0].discovery_recon_score.threshold == 5
  and $exports[0].edge_recommendation.action == "preserve_eidolon_routing"
  and (($exports[0].edge_recommendation.reason_codes // []) | index("eidolon_runtime_enforcement")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("eidolon_owned")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("pre_containment_persistence")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("discovery_recon_retry")) != null
' "$edge_export_file" >/dev/null \
  || fail "edge export did not preserve the new recon-blocked runtime decision"

printf 'rate-limited-recon-blocked smoke ok: session=%s blocked_after_recon_retry=true\n' "$session_id"
