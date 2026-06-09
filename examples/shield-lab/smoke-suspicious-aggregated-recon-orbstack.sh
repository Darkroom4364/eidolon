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
FIRST_REQUEST_PATH="${EIDOLON_SHIELD_SUSPICIOUS_AGGREGATED_RECON_FIRST_PATH:-/docs?topic=imports}"
SECOND_REQUEST_PATH="${EIDOLON_SHIELD_SUSPICIOUS_AGGREGATED_RECON_SECOND_PATH:-/docs}"
REQUEST_PATH_PREFIX="${EIDOLON_SHIELD_SUSPICIOUS_AGGREGATED_RECON_PATH_PREFIX:-/docs}"
FIRST_BAIT_MARKER="${EIDOLON_SHIELD_SUSPICIOUS_AGGREGATED_RECON_FIRST_BAIT_MARKER:-/docs/legacy-import}"
SECOND_BAIT_MARKER="${EIDOLON_SHIELD_SUSPICIOUS_AGGREGATED_RECON_SECOND_BAIT_MARKER:-X-Migration-Trace: rel_2025_04_b7f2}"
ACTOR_KIND="${EIDOLON_SHIELD_SUSPICIOUS_AGGREGATED_RECON_ACTOR_KIND:-agentic_browser}"
VENDOR_SCORE="${EIDOLON_SHIELD_SUSPICIOUS_AGGREGATED_RECON_VENDOR_SCORE:-35}"
VENDOR_SCORE_KIND="${EIDOLON_SHIELD_SUSPICIOUS_AGGREGATED_RECON_VENDOR_SCORE_KIND:-automation_likelihood_inverse}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-suspicious-aggregated-recon-orbstack.sh

Performs a live OrbStack smoke check for the first weaker aggregated
observe-to-suspicious path. It sends two same-session transport-authenticated
medium-score discovery requests, verifies that the first query-bearing request
stayed in observe, confirms that the second same-session discovery request was
promoted to suspicious through multi-signal aggregation, and checks the same
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-aggregated-recon-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin

cookie_jar="$tmp_dir/cookies.txt"
first_headers="$tmp_dir/first.headers"
first_body="$tmp_dir/first.body"
second_headers="$tmp_dir/second.headers"
second_body="$tmp_dir/second.body"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"
edge_export_file="$tmp_dir/edge-export.json"

curl_cmd -fsS \
  -c "$cookie_jar" \
  -D "$first_headers" \
  -o "$first_body" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${FIRST_REQUEST_PATH}"

curl_cmd -fsS \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$second_headers" \
  -o "$second_body" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${SECOND_REQUEST_PATH}"

first_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$first_headers")"
[[ "$first_http_code" == "200" ]] || fail "expected HTTP 200 from first aggregated recon request, got: ${first_http_code:-none}"
grep -Fq "$FIRST_BAIT_MARKER" "$first_body" \
  || fail "first aggregated recon request did not receive the expected observe discovery surface"

second_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$second_headers")"
[[ "$second_http_code" == "200" ]] || fail "expected HTTP 200 from second aggregated recon request, got: ${second_http_code:-none}"
grep -Fq "$SECOND_BAIT_MARKER" "$second_body" \
  || fail "second aggregated recon request did not receive the stronger suspicious discovery surface"

read_proxy_state_file events.jsonl > "$events_file"
request_events_json="$(
  jq -c -e -s \
    --arg path_prefix "$REQUEST_PATH_PREFIX" \
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
      | .[-2:]
    ' "$events_file"
)" || fail "could not find the aggregated recon requests in the proxy event log"

jq -e '
  length == 2
  and .[0].session_id == .[1].session_id
  and .[0].policy_state == "observe"
  and .[0].kind.routing_decision == "protected_upstream"
  and .[1].policy_state == "suspicious"
  and .[1].kind.routing_decision == "eidolon_owned"
' <<<"$request_events_json" >/dev/null \
  || fail "aggregated recon request sequence did not preserve observe then suspicious"

session_id="$(jq -r '.[1].session_id // empty' <<<"$request_events_json")"
[[ -n "$session_id" ]] || fail "matching aggregated recon requests had no session id"

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
  || fail "session ${session_id} suspicious transition reason did not match the aggregated recon path"

jq -e \
  --argjson vendor_score "$VENDOR_SCORE" '
    (.kind.reason // "") | contains("vendor_score=\($vendor_score)")
  ' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${session_id} suspicious transition reason did not preserve the medium advisory score"

jq -e '
    (.kind.reason // "") | contains("query_seen=true")
  ' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${session_id} suspicious transition reason did not preserve the query-bearing recon signal"

read_proxy_state_file debug.jsonl > "$debug_file"
request_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "request_received"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no request_received debug record"

jq -e '
  .fields.discovery_request_count == 2
  and .fields.discovery_query_seen == true
  and .fields.query_present == false
  and .fields.discovery_surface_fanout.distinct_surfaces == 1
' <<<"$request_debug_json" >/dev/null \
  || fail "session ${session_id} did not preserve the expected aggregated recon debug state"

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
  || fail "session ${session_id} did not preserve the stronger suspicious discovery shaping"

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
  || fail "session ${session_id} edge export did not preserve the aggregated recon suspicious result"

echo "suspicious-aggregated-recon smoke ok: session ${session_id} promoted on medium-score discovery plus query-bearing recon"
