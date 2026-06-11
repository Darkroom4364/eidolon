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
PROMOTION_PATH="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_PROMOTION_PATH:-/docs?topic=imports}"
PROMOTION_PATH_PREFIX="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_PROMOTION_PATH_PREFIX:-/docs}"
PROBE_PATH="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_PROBE_PATH:-/api/v2/import/reconcile}"
RATE_LIMIT_PATH="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_RATE_LIMIT_PATH:-/docs}"
BLOCKED_PATH="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_BLOCKED_PATH:-/docs}"
EXPECTED_PROMOTION_MARKER="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_PROMOTION_MARKER:-/docs/legacy-import}"
EXPECTED_PROBE_STATUS="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_PROBE_STATUS:-404}"
EXPECTED_RETRY_AFTER="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_RETRY_AFTER:-30}"
ACTOR_KIND="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_ACTOR_KIND:-agentic_browser}"
VENDOR_SCORE="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_VENDOR_SCORE:-35}"
VENDOR_SCORE_KIND="${EIDOLON_SHIELD_RATE_LIMITED_DECOY_WRITE_RECON_BLOCKED_VENDOR_SCORE_KIND:-automation_likelihood_inverse}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-rate-limited-decoy-write-recon-blocked-orbstack.sh

Performs a live OrbStack smoke check for the recon-driven rate-limited-to-blocked
path that uses the blind decoy-write contributor. It sends one query-bearing
docs request, follows with a same-session POST to the decoy reconcile path
without any bait header so the session becomes suspicious without bait
attribution, sends a top-level /docs follow-up to move the session into
rate_limited from the weighted recon score, then repeats that top-level
discovery request and verifies that Eidolon moves the session into blocked.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-rate-limited-decoy-write-recon-blocked-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin

cookie_jar="$tmp_dir/cookies.txt"
promotion_headers="$tmp_dir/promotion.headers"
promotion_body="$tmp_dir/promotion.body"
probe_headers="$tmp_dir/probe.headers"
probe_body="$tmp_dir/probe.body"
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
[[ "$promotion_http_code" == "200" ]] || fail "expected HTTP 200 from decoy-write-recon-blocked promotion request, got: ${promotion_http_code:-none}"
grep -Fq "$EXPECTED_PROMOTION_MARKER" "$promotion_body" \
  || fail "decoy-write-recon-blocked promotion request did not receive the expected observe discovery surface"

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
  || fail "expected HTTP ${EXPECTED_PROBE_STATUS} from decoy-write-recon-blocked probe request, got: ${probe_http_code:-none}"

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
[[ "$rate_limit_http_code" == "429" ]] || fail "expected HTTP 429 from decoy-write-recon-blocked rate-limit request, got: ${rate_limit_http_code:-none}"
retry_after="$(awk 'BEGIN{IGNORECASE=1} tolower($1) == "retry-after:" {gsub("\r", "", $2); print $2}' "$rate_limit_headers" | tail -n 1)"
[[ "$retry_after" == "$EXPECTED_RETRY_AFTER" ]] \
  || fail "expected Retry-After ${EXPECTED_RETRY_AFTER} from decoy-write-recon-blocked rate-limit request, got: ${retry_after:-none}"

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
[[ "$blocked_http_code" == "403" ]] || fail "expected HTTP 403 from decoy-write-recon-blocked retry request, got: ${blocked_http_code:-none}"

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
)" || fail "could not find the decoy-write-recon-blocked probe request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$probe_request_json")"
[[ -n "$session_id" ]] || fail "matching decoy-write-recon-blocked probe request had no session id"

jq -e '
  .policy_state == "suspicious"
  and .kind.routing_decision == "protected_upstream"
  and .kind.discovery_recon_score.query_score == 1
  and .kind.discovery_recon_score.decoy_write_probe_score == 2
  and .kind.discovery_recon_score.total == 3
  and .kind.discovery_recon_score.threshold == 3
' <<<"$probe_request_json" >/dev/null \
  || fail "decoy-write-recon-blocked probe request did not preserve the expected suspicious weighted recon state"

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
)" || fail "could not find the decoy-write-recon-blocked retry request in the proxy event log"

jq -e \
  --arg session_id "$session_id" '
  .session_id == $session_id
  and .policy_state == "blocked"
  and .kind.routing_decision == "eidolon_owned"
  and .kind.discovery_recon_score.repeated_discovery_score == 2
  and .kind.discovery_recon_score.query_score == 1
  and .kind.discovery_recon_score.decoy_write_probe_score == 2
  and .kind.discovery_recon_score.total == 5
  and .kind.discovery_recon_score.threshold == 5
' <<<"$blocked_request_json" >/dev/null \
  || fail "matching decoy-write-recon-blocked retry request did not preserve the expected blocked weighted recon state"

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

jq -e \
  --argjson vendor_score "$VENDOR_SCORE" '
  ((.kind.reason // "") | contains("rate-limited discovery recon retry moved session to blocked"))
  and ((.kind.reason // "") | contains("path=/docs"))
  and ((.kind.reason // "") | contains("vendor_score=\($vendor_score)"))
  and ((.kind.reason // "") | contains("discovery_requests=3"))
  and ((.kind.reason // "") | contains("distinct_surfaces=1"))
  and ((.kind.reason // "") | contains("query_seen=true"))
  and ((.kind.reason // "") | contains("decoy_write_probe_seen=true"))
  and ((.kind.reason // "") | contains("repeated_discovery_score=2"))
  and ((.kind.reason // "") | contains("query_score=1"))
  and ((.kind.reason // "") | contains("decoy_write_probe_score=2"))
  and ((.kind.reason // "") | contains("recon_score=5"))
  and ((.kind.reason // "") | contains("recon_block_threshold=5"))
' <<<"$blocked_transition_json" >/dev/null \
  || fail "session ${session_id} blocked transition reason did not preserve the expected decoy-write weighted recon facts"

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
  and .fields.discovery_decoy_write_probe_seen == true
  and .fields.discovery_surface_fanout.distinct_surfaces == 1
  and .fields.discovery_recon_score.repeated_discovery_score == 2
  and .fields.discovery_recon_score.query_score == 1
  and .fields.discovery_recon_score.decoy_write_probe_score == 2
  and .fields.discovery_recon_score.total == 5
  and .fields.discovery_recon_score.threshold == 5
' <<<"$request_debug_json" >/dev/null \
  || fail "session ${session_id} did not preserve the expected decoy-write weighted recon blocked debug state"

surface_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no surface_action_selected debug record"

jq -e '
  .fields.policy_state == "blocked"
  and .fields.surface_action.type == "eidolon_owned"
  and ((.fields.policy_reason // "") | contains("rate-limited discovery recon retry moved session to blocked"))
  and ((.fields.policy_reason // "") | contains("decoy_write_probe_seen=true"))
  and ((.fields.policy_reason // "") | contains("decoy_write_probe_score=2"))
' <<<"$surface_debug_json" >/dev/null \
  || fail "session ${session_id} did not keep the decoy-write weighted recon retry on the blocked action path"

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
  and $exports[0].discovery_recon_score.repeated_discovery_score == 2
  and $exports[0].discovery_recon_score.query_score == 1
  and $exports[0].discovery_recon_score.decoy_write_probe_score == 2
  and $exports[0].discovery_recon_score.total == 5
  and $exports[0].discovery_recon_score.threshold == 5
  and $exports[0].edge_recommendation.action == "preserve_eidolon_routing"
  and (($exports[0].edge_recommendation.reason_codes // []) | index("eidolon_runtime_enforcement")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("eidolon_owned")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("pre_containment_persistence")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("discovery_recon_retry")) != null
' "$edge_export_file" >/dev/null \
  || fail "edge export did not preserve the new decoy-write-recon-blocked runtime decision"

printf 'rate-limited-decoy-write-recon-blocked smoke ok: session=%s retry_after=%s recon_score=5\n' "$session_id" "$retry_after"
