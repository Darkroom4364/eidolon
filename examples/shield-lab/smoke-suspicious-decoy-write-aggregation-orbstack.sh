#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
TRUSTED_INGRESS_SECRET_NAME="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
TRUSTED_INGRESS_SECRET_KEY="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
PROMOTION_PATH="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_PROMOTION_PATH:-/docs?topic=imports}"
PROMOTION_PATH_PREFIX="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_PROMOTION_PATH_PREFIX:-/docs}"
PROBE_PATH="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_PROBE_PATH:-/api/v2/import/reconcile}"
EXPECTED_PROMOTION_MARKER="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_PROMOTION_MARKER:-/docs/legacy-import}"
EXPECTED_PROBE_STATUS="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_PROBE_STATUS:-404}"
ACTOR_KIND="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_ACTOR_KIND:-agentic_browser}"
VENDOR_SCORE="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_VENDOR_SCORE:-35}"
VENDOR_SCORE_KIND="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_VENDOR_SCORE_KIND:-automation_likelihood_inverse}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-suspicious-decoy-write-aggregation-orbstack.sh

Performs a live OrbStack smoke check for the blind decoy-write recon
contributor. It sends one transport-authenticated medium-score query-bearing
docs request, follows with a same-session POST to the decoy reconcile path
without any bait header, verifies that Eidolon promotes the second request to
suspicious through weighted recon, and confirms that the probe does not create
bait_action_observed evidence.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-decoy-write-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

cookie_jar="$tmp_dir/cookies.txt"
promotion_headers="$tmp_dir/promotion.headers"
promotion_body="$tmp_dir/promotion.body"
probe_headers="$tmp_dir/probe.headers"
probe_body="$tmp_dir/probe.body"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"

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
[[ "$promotion_http_code" == "200" ]] || fail "expected HTTP 200 from suspicious-decoy-write promotion request, got: ${promotion_http_code:-none}"
grep -Fq "$EXPECTED_PROMOTION_MARKER" "$promotion_body" \
  || fail "suspicious-decoy-write promotion request did not receive the expected observe discovery surface"

curl_cmd -sS \
  -X POST \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$probe_headers" \
  -o "$probe_body" \
  -H "Content-Type: application/json" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${PROBE_PATH}"

probe_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$probe_headers")"
[[ "$probe_http_code" == "$EXPECTED_PROBE_STATUS" ]] \
  || fail "expected HTTP ${EXPECTED_PROBE_STATUS} from suspicious-decoy-write probe request, got: ${probe_http_code:-none}"

read_proxy_state_file events.jsonl > "$events_file"

probe_request_json="$(
  jq -c -e -s \
    --arg path "$PROBE_PATH" \
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
)" || fail "could not find the suspicious-decoy-write probe request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$probe_request_json")"
[[ -n "$session_id" ]] || fail "matching suspicious-decoy-write probe request had no session id"

jq -e '
  .policy_state == "suspicious"
  and .kind.routing_decision == "protected_upstream"
  and .kind.discovery_recon_score.query_score == 1
  and .kind.discovery_recon_score.decoy_write_probe_score == 2
  and .kind.discovery_recon_score.total == 3
  and .kind.discovery_recon_score.threshold == 3
' <<<"$probe_request_json" >/dev/null \
  || fail "suspicious-decoy-write probe request did not preserve the expected suspicious weighted recon state"

promotion_request_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" \
    --arg path_prefix "$PROMOTION_PATH_PREFIX" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
        )
      )
      | first
    ' "$events_file"
)" || fail "could not find the suspicious-decoy-write promotion request for session ${session_id}"

jq -e '
  .policy_state == "observe"
  and .kind.routing_decision == "protected_upstream"
' <<<"$promotion_request_json" >/dev/null \
  || fail "suspicious-decoy-write promotion request did not stay in observe before the probe"

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
  --argjson vendor_score "$VENDOR_SCORE" '
    ((.kind.reason // "") | contains("multi-signal discovery recon aggregation promoted request to suspicious"))
    and ((.kind.reason // "") | contains("path=/api/v2/import/reconcile"))
    and ((.kind.reason // "") | contains("vendor_score=\($vendor_score)"))
    and ((.kind.reason // "") | contains("query_seen=true"))
    and ((.kind.reason // "") | contains("decoy_write_probe_seen=true"))
    and ((.kind.reason // "") | contains("decoy_write_probe_score=2"))
    and ((.kind.reason // "") | contains("recon_score=3"))
    and ((.kind.reason // "") | contains("recon_threshold=3"))
  ' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${session_id} suspicious transition reason did not preserve the blind decoy-write recon facts"

jq -e -s \
  --arg session_id "$session_id" \
  --arg path "$PROBE_PATH" '
    map(
      select(
        .session_id == $session_id
        and .kind.type == "bait_action_observed"
        and (.kind.path // "") == $path
      )
    )
    | length == 0
  ' "$events_file" >/dev/null \
  || fail "session ${session_id} blind decoy-write probe incorrectly created bait_action_observed evidence"

read_proxy_state_file debug.jsonl > "$debug_file"

request_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .event == "request_received"
          and (.fields.path // "") == "/api/v2/import/reconcile"
        )
      )
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no request_received debug record for the blind decoy-write probe"

jq -e '
  .fields.discovery_request_count == 1
  and .fields.discovery_query_seen == true
  and .fields.discovery_decoy_write_probe_seen == true
  and .fields.discovery_recon_score.decoy_write_probe_score == 2
  and .fields.discovery_recon_score.total == 3
' <<<"$request_debug_json" >/dev/null \
  || fail "session ${session_id} did not preserve the expected blind decoy-write debug state"

printf 'suspicious-decoy-write smoke ok: session %s promoted without bait attribution\n' "$session_id"
