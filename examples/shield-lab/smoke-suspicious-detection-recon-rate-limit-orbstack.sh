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
PROMOTION_PATH="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_PROMOTION_PATH:-/docs?topic=imports}"
PROMOTION_PATH_PREFIX="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_PROMOTION_PATH_PREFIX:-/docs}"
FOLLOW_UP_PATH="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_FOLLOW_UP_PATH:-/docs}"
EXPECTED_BAIT_MARKER="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_BAIT_MARKER:-X-Migration-Trace: rel_2025_04_b7f2}"
EXPECTED_RETRY_AFTER="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_RETRY_AFTER:-30}"
ACTOR_KIND="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_ACTOR_KIND:-agentic_browser}"
VENDOR_SCORE="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_VENDOR_SCORE:-35}"
VENDOR_SCORE_KIND="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_VENDOR_SCORE_KIND:-automation_likelihood_inverse}"
DETECTION_IDS="${EIDOLON_SHIELD_SUSPICIOUS_DETECTION_RECON_RATE_LIMIT_DETECTION_IDS:-3355446,445566}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-suspicious-detection-recon-rate-limit-orbstack.sh

Performs a live OrbStack smoke check for the higher-threshold advisory-assisted
discovery recon path. It sends one transport-authenticated, medium-score,
query-bearing discovery request with detection IDs to move the session into
suspicious, follows with a same-session top-level /docs request, verifies that
Eidolon moves the session into rate_limited from the weighted recon score, and
checks that the same session exports both the advisory detections and the
structured pre-containment persistence class.
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

detection_ids_json="$(jq -Rc 'split(",") | map(gsub("^ +| +$"; "")) | map(select(length > 0))' <<<"$DETECTION_IDS")"
[[ "$detection_ids_json" != "[]" ]] || fail "detection id list must not be empty"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-detection-recon-rate-limit-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin

cookie_jar="$tmp_dir/cookies.txt"
promotion_headers="$tmp_dir/promotion.headers"
promotion_body="$tmp_dir/promotion.body"
follow_up_headers="$tmp_dir/follow-up.headers"
follow_up_body="$tmp_dir/follow-up.body"
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
  -H "X-Eidolon-Ingress-Detection-Ids: ${DETECTION_IDS}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${PROMOTION_PATH}"

promotion_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$promotion_headers")"
[[ "$promotion_http_code" == "200" ]] || fail "expected HTTP 200 from suspicious-detection-recon-rate-limit promotion request, got: ${promotion_http_code:-none}"
grep -Fq "$EXPECTED_BAIT_MARKER" "$promotion_body" \
  || fail "suspicious-detection-recon-rate-limit promotion request did not receive the baited discovery surface"

curl_cmd -sS \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$follow_up_headers" \
  -o "$follow_up_body" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Detection-Ids: ${DETECTION_IDS}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${FOLLOW_UP_PATH}"

follow_up_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$follow_up_headers")"
[[ "$follow_up_http_code" == "429" ]] || fail "expected HTTP 429 from suspicious-detection-recon-rate-limit follow-up request, got: ${follow_up_http_code:-none}"
retry_after="$(awk 'BEGIN{IGNORECASE=1} tolower($1) == "retry-after:" {gsub("\r", "", $2); print $2}' "$follow_up_headers" | tail -n 1)"
[[ "$retry_after" == "$EXPECTED_RETRY_AFTER" ]] \
  || fail "expected Retry-After ${EXPECTED_RETRY_AFTER} from suspicious-detection-recon-rate-limit follow-up request, got: ${retry_after:-none}"

read_proxy_state_file events.jsonl > "$events_file"

follow_up_request_json="$(
  jq -c -e -s \
    --arg path "$FOLLOW_UP_PATH" \
    --arg actor_kind "$ACTOR_KIND" \
    --arg score_kind "$VENDOR_SCORE_KIND" \
    --argjson vendor_score "$VENDOR_SCORE" \
    --argjson detection_ids "$detection_ids_json" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "") == $path
          and (.kind.ingress_identity.source // "none") == "none"
          and (.kind.ingress_identity.trust_tier // "none") == "none"
          and (.kind.ingress_signals.actor_kind // "") == $actor_kind
          and (.kind.ingress_signals.vendor_score // -1) == $vendor_score
          and (.kind.ingress_signals.vendor_score_kind // "") == $score_kind
          and ((.kind.ingress_signals.detection_ids // []) == $detection_ids)
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the suspicious-detection-recon-rate-limit follow-up request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$follow_up_request_json")"
[[ -n "$session_id" ]] || fail "matching suspicious-detection-recon-rate-limit follow-up request had no session id"

jq -e '
  .policy_state == "rate_limited"
  and .kind.routing_decision == "rate_limited"
' <<<"$follow_up_request_json" >/dev/null \
  || fail "matching suspicious-detection-recon-rate-limit follow-up request did not persist the rate-limited decision"

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
)" || fail "could not find the suspicious-detection-recon-rate-limit promotion request for session ${session_id}"

jq -e '
  .policy_state == "suspicious"
  and .kind.routing_decision == "eidolon_owned"
  and .kind.discovery_recon_score.query_score == 1
  and .kind.discovery_recon_score.detection_score == 2
  and .kind.discovery_recon_score.total == 3
  and .kind.discovery_recon_score.threshold == 3
' <<<"$promotion_request_json" >/dev/null \
  || fail "suspicious-detection-recon-rate-limit promotion request did not preserve the expected suspicious detection-backed aggregation state"

policy_changed_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "policy_changed"
          and .kind.from == "suspicious"
          and .kind.to == "rate_limited"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no suspicious -> rate_limited policy transition event"

jq -e \
  --argjson vendor_score "$VENDOR_SCORE" '
    ((.kind.reason // "") | contains("suspicious discovery recon persistence moved session to rate limited"))
    and ((.kind.reason // "") | contains("path=/docs"))
    and ((.kind.reason // "") | contains("vendor_score=\($vendor_score)"))
    and ((.kind.reason // "") | contains("discovery_requests=2"))
    and ((.kind.reason // "") | contains("query_seen=true"))
    and ((.kind.reason // "") | contains("detection_count=2"))
    and ((.kind.reason // "") | contains("repeated_discovery_score=2"))
    and ((.kind.reason // "") | contains("query_score=1"))
    and ((.kind.reason // "") | contains("detection_score=2"))
    and ((.kind.reason // "") | contains("recon_score=5"))
    and ((.kind.reason // "") | contains("recon_rate_limit_threshold=5"))
    and .kind.persistence.pre_containment_persistence_class == "discovery_recon"
  ' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${session_id} rate-limited transition reason did not preserve the expected weighted detection-backed recon facts"

rate_limit_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "rate_limit_applied"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no rate_limit_applied event"

jq -e '.policy_state == "rate_limited"' <<<"$rate_limit_json" >/dev/null \
  || fail "session ${session_id} rate_limit_applied event did not preserve rate_limited state"

read_proxy_state_file debug.jsonl > "$debug_file"
request_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "request_received"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no request_received debug record"

jq -e \
  --argjson detection_ids "$detection_ids_json" '
  .fields.policy_state == "rate_limited"
  and .fields.path == "/docs"
  and .fields.query_present == false
  and .fields.discovery_request_count == 2
  and .fields.discovery_query_seen == true
  and ((.fields.ingress_signals.detection_ids // []) == $detection_ids)
  and .fields.discovery_recon_score.repeated_discovery_score == 2
  and .fields.discovery_recon_score.query_score == 1
  and .fields.discovery_recon_score.detection_score == 2
  and .fields.discovery_recon_score.total == 5
  and .fields.discovery_recon_score.threshold == 5
' <<<"$request_debug_json" >/dev/null \
  || fail "session ${session_id} did not preserve the expected weighted detection-backed recon debug state"

surface_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no surface_action_selected debug record"

jq -e '
  .fields.policy_state == "rate_limited"
  and .fields.surface_action.type == "rate_limited"
' <<<"$surface_debug_json" >/dev/null \
  || fail "session ${session_id} did not keep the weighted detection-backed follow-up on the rate-limited action path"

EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
  EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
  KUBECTL_BIN="$KUBECTL_BIN" \
  "$EXPORT_SCRIPT" \
  --session "$session_id" \
  --format json > "$edge_export_file"

jq -e \
  --argjson detection_ids "$detection_ids_json" '
  (if type == "array" then . else [.] end) as $exports
  | ($exports | length) == 1
  and $exports[0].request.path == "/docs"
  and $exports[0].policy.state == "rate_limited"
  and $exports[0].policy.routing_decision == "rate_limited"
  and $exports[0].policy.pre_containment_persistence_class == "discovery_recon"
  and (($exports[0].ingress_signals.detection_ids // []) == $detection_ids)
  and $exports[0].discovery_recon_score.repeated_discovery_score == 2
  and $exports[0].discovery_recon_score.query_score == 1
  and $exports[0].discovery_recon_score.detection_score == 2
  and $exports[0].discovery_recon_score.total == 5
  and $exports[0].discovery_recon_score.threshold == 5
  and $exports[0].edge_recommendation.action == "preserve_eidolon_routing"
  and (($exports[0].edge_recommendation.reason_codes // []) | index("eidolon_runtime_enforcement")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("rate_limited")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("pre_containment_persistence")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("discovery_recon")) != null
' "$edge_export_file" >/dev/null \
  || fail "edge export did not preserve the new suspicious-detection-recon-rate-limit runtime decision"

printf 'suspicious-detection-recon-rate-limit smoke ok: session=%s retry_after=%s recon_score=5 detection_score=2\n' "$session_id" "$retry_after"
