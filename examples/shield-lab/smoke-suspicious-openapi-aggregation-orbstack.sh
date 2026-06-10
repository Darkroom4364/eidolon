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
PROMOTION_PATH="${EIDOLON_SHIELD_SUSPICIOUS_OPENAPI_AGGREGATION_PATH:-/openapi.json?eidolon_surface=legacy-import}"
PROMOTION_PATH_PREFIX="${EIDOLON_SHIELD_SUSPICIOUS_OPENAPI_AGGREGATION_PATH_PREFIX:-/openapi.json}"
EXPECTED_BAIT_MARKER="${EIDOLON_SHIELD_SUSPICIOUS_OPENAPI_AGGREGATION_BAIT_MARKER:-X-OpenAPI-Trace}"
EXPECTED_BAIT_PATH_MARKER="${EIDOLON_SHIELD_SUSPICIOUS_OPENAPI_AGGREGATION_PATH_MARKER:-/api/v2/import/reconcile}"
ACTOR_KIND="${EIDOLON_SHIELD_SUSPICIOUS_OPENAPI_AGGREGATION_ACTOR_KIND:-agentic_browser}"
VENDOR_SCORE="${EIDOLON_SHIELD_SUSPICIOUS_OPENAPI_AGGREGATION_VENDOR_SCORE:-35}"
VENDOR_SCORE_KIND="${EIDOLON_SHIELD_SUSPICIOUS_OPENAPI_AGGREGATION_VENDOR_SCORE_KIND:-automation_likelihood_inverse}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-suspicious-openapi-aggregation-orbstack.sh

Performs a live OrbStack smoke check for the target-side aggregated OpenAPI
promotion path. It sends one transport-authenticated medium-score legacy-query
OpenAPI discovery request, verifies that Eidolon promoted the session from
observe to suspicious through multi-signal aggregation, confirms the response
became an Eidolon-owned OpenAPI bait surface, and checks that the same session
exports with ingress advisory signals in the edge-decision contract.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-openapi-aggregation-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin

headers_file="$tmp_dir/response.headers"
body_file="$tmp_dir/response.body"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"
edge_export_file="$tmp_dir/edge-export.json"

curl_cmd -fsS \
  -D "$headers_file" \
  -o "$body_file" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${PROMOTION_PATH}"

http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$headers_file")"
[[ "$http_code" == "200" ]] || fail "expected HTTP 200 from suspicious-openapi-aggregation smoke request, got: ${http_code:-none}"
grep -Fq "$EXPECTED_BAIT_MARKER" "$body_file" \
  || fail "suspicious-openapi-aggregation smoke request did not receive the owned OpenAPI bait surface"
grep -Fq "$EXPECTED_BAIT_PATH_MARKER" "$body_file" \
  || fail "suspicious-openapi-aggregation smoke request did not include the baited reconcile path"

read_proxy_state_file events.jsonl > "$events_file"
request_event_json="$(
  jq -c -e -s \
    --arg path_prefix "$PROMOTION_PATH_PREFIX" \
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
)" || fail "could not find the suspicious-openapi-aggregation request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$request_event_json")"
[[ -n "$session_id" ]] || fail "matching suspicious-openapi-aggregation request had no session id"

jq -e '.policy_state == "suspicious"' <<<"$request_event_json" >/dev/null \
  || fail "matching suspicious-openapi-aggregation request did not persist a suspicious policy state"

policy_changed_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "policy_changed"
          and .kind.from == "observe"
          and .kind.to == "suspicious"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no observe -> suspicious policy transition event"

jq -e \
  --arg reason_substring "multi-signal discovery recon aggregation promoted request to suspicious" '
    (.kind.reason // "") | contains($reason_substring)
  ' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${session_id} suspicious transition reason did not match the aggregated OpenAPI promotion path"

jq -e \
  --argjson vendor_score "$VENDOR_SCORE" '
    ((.kind.reason // "") | contains("vendor_score=\($vendor_score)"))
    and ((.kind.reason // "") | contains("discovery_requests=1"))
    and ((.kind.reason // "") | contains("query_seen=true"))
    and ((.kind.reason // "") | contains("legacy_openapi_query_seen=true"))
    and ((.kind.reason // "") | contains("detection_count=0"))
    and ((.kind.reason // "") | contains("legacy_openapi_query_score=2"))
    and ((.kind.reason // "") | contains("recon_score=3"))
  ' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${session_id} suspicious transition reason did not preserve the expected aggregated OpenAPI facts"

read_proxy_state_file debug.jsonl > "$debug_file"
request_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "request_received"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no request_received debug record"

jq -e '
  .fields.policy_state == "suspicious"
  and .fields.path == "/openapi.json"
  and .fields.query_present == true
  and .fields.discovery_request_count == 1
  and .fields.discovery_query_seen == true
  and .fields.discovery_legacy_openapi_query_seen == true
' <<<"$request_debug_json" >/dev/null \
  || fail "session ${session_id} did not preserve the expected aggregated OpenAPI debug state"

surface_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no surface_action_selected debug record"

jq -e '
  .fields.policy_state == "suspicious"
  and .fields.controller_surface_action.type == "rewritten_upstream"
  and .fields.candidate_surface_action.type == "eidolon_owned"
  and .fields.surface_action.type == "eidolon_owned"
  and .fields.trusted_ingress_softened_surface == false
' <<<"$surface_debug_json" >/dev/null \
  || fail "session ${session_id} did not keep the stronger suspicious OpenAPI shaping"

bait_exposed_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "bait_exposed"
          and .kind.bait_id == "openapi_reconcile_trace"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} did not record a suspicious owned OpenAPI bait exposure"

jq -e '.kind.surface == "/openapi.json"' <<<"$bait_exposed_json" >/dev/null \
  || fail "session ${session_id} suspicious owned OpenAPI exposure was not recorded on /openapi.json"

EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
  EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
  KUBECTL_BIN="$KUBECTL_BIN" \
  "$EXPORT_SCRIPT" \
  --session "$session_id" \
  --format json > "$edge_export_file"

jq -e \
  --arg session_id "$session_id" \
  --arg actor_kind "$ACTOR_KIND" \
  --arg score_kind "$VENDOR_SCORE_KIND" \
  --argjson vendor_score "$VENDOR_SCORE" '
    length == 1
    and .[0].session_id == $session_id
    and .[0].policy.state == "suspicious"
    and .[0].policy.routing_decision == "eidolon_owned"
    and .[0].ingress_signals.actor_kind == $actor_kind
    and .[0].ingress_signals.vendor_score == $vendor_score
    and .[0].ingress_signals.vendor_score_kind == $score_kind
    and .[0].edge_recommendation.action == "preserve_eidolon_routing"
    and (.[0].edge_recommendation.reason_codes // []) == ["eidolon_runtime_enforcement", "eidolon_owned"]
  ' "$edge_export_file" >/dev/null \
  || fail "session ${session_id} edge export did not preserve the suspicious aggregated OpenAPI result"

echo "suspicious-openapi-aggregation smoke ok: session ${session_id} promoted to suspicious, served owned OpenAPI bait, and exported aggregated OpenAPI signals"
