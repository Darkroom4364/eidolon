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
PROMOTION_PATH="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_PROMOTION_PATH:-/docs?topic=imports}"
PROMOTION_PATH_PREFIX="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_PROMOTION_PATH_PREFIX:-/docs}"
PROBE_PATH="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_PROBE_PATH:-/api/v2/import/reconcile}"
FOLLOW_UP_PATH="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_FOLLOW_UP_PATH:-/docs}"
EXPECTED_PROMOTION_MARKER="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_PROMOTION_MARKER:-/docs/legacy-import}"
EXPECTED_PROBE_STATUS="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_PROBE_STATUS:-404}"
EXPECTED_RETRY_AFTER="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_RETRY_AFTER:-30}"
ACTOR_KIND="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_ACTOR_KIND:-agentic_browser}"
VENDOR_SCORE="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_VENDOR_SCORE:-35}"
VENDOR_SCORE_KIND="${EIDOLON_SHIELD_SUSPICIOUS_DECOY_WRITE_REPEAT_BONUS_VENDOR_SCORE_KIND:-automation_likelihood_inverse}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-suspicious-decoy-write-repeat-bonus-orbstack.sh

Performs a live OrbStack smoke check for the capped repeated blind decoy-write
recon contributor. It sends one query-bearing docs request, follows with two
same-session POSTs to the decoy reconcile path without any bait header, verifies
that the second blind probe raises the decoy-write recon component while still
avoiding bait attribution, and then confirms that a later top-level /docs
follow-up is rate-limited at the stronger weighted recon score.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-decoy-write-repeat-bonus-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin

cookie_jar="$tmp_dir/cookies.txt"
promotion_headers="$tmp_dir/promotion.headers"
promotion_body="$tmp_dir/promotion.body"
first_probe_headers="$tmp_dir/first-probe.headers"
first_probe_body="$tmp_dir/first-probe.body"
second_probe_headers="$tmp_dir/second-probe.headers"
second_probe_body="$tmp_dir/second-probe.body"
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
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${PROMOTION_PATH}"

promotion_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$promotion_headers")"
[[ "$promotion_http_code" == "200" ]] || fail "expected HTTP 200 from suspicious-decoy-write-repeat-bonus promotion request, got: ${promotion_http_code:-none}"
grep -Fq "$EXPECTED_PROMOTION_MARKER" "$promotion_body" \
  || fail "suspicious-decoy-write-repeat-bonus promotion request did not receive the expected observe discovery surface"

curl_cmd -sS \
  -X POST \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$first_probe_headers" \
  -o "$first_probe_body" \
  -H "Content-Type: application/json" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${PROBE_PATH}"

first_probe_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$first_probe_headers")"
[[ "$first_probe_http_code" == "$EXPECTED_PROBE_STATUS" ]] \
  || fail "expected HTTP ${EXPECTED_PROBE_STATUS} from first suspicious-decoy-write-repeat-bonus probe, got: ${first_probe_http_code:-none}"

curl_cmd -sS \
  -X POST \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$second_probe_headers" \
  -o "$second_probe_body" \
  -H "Content-Type: application/json" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${PROBE_PATH}"

second_probe_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$second_probe_headers")"
[[ "$second_probe_http_code" == "$EXPECTED_PROBE_STATUS" ]] \
  || fail "expected HTTP ${EXPECTED_PROBE_STATUS} from second suspicious-decoy-write-repeat-bonus probe, got: ${second_probe_http_code:-none}"

curl_cmd -sS \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$follow_up_headers" \
  -o "$follow_up_body" \
  -H "X-Eidolon-Ingress-Actor-Kind: ${ACTOR_KIND}" \
  -H "X-Eidolon-Ingress-Vendor-Score: ${VENDOR_SCORE}" \
  -H "X-Eidolon-Ingress-Vendor-Score-Kind: ${VENDOR_SCORE_KIND}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${FOLLOW_UP_PATH}"

follow_up_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$follow_up_headers")"
[[ "$follow_up_http_code" == "429" ]] || fail "expected HTTP 429 from suspicious-decoy-write-repeat-bonus follow-up request, got: ${follow_up_http_code:-none}"
retry_after="$(awk 'BEGIN{IGNORECASE=1} tolower($1) == "retry-after:" {gsub("\r", "", $2); print $2}' "$follow_up_headers" | tail -n 1)"
[[ "$retry_after" == "$EXPECTED_RETRY_AFTER" ]] \
  || fail "expected Retry-After ${EXPECTED_RETRY_AFTER} from suspicious-decoy-write-repeat-bonus follow-up request, got: ${retry_after:-none}"

read_proxy_state_file events.jsonl > "$events_file"
read_proxy_state_file debug.jsonl > "$debug_file"

second_probe_request_json="$(
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
)" || fail "could not find the second suspicious-decoy-write-repeat-bonus probe request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$second_probe_request_json")"
[[ -n "$session_id" ]] || fail "matching suspicious-decoy-write-repeat-bonus probe request had no session id"

jq -e '
  .policy_state == "suspicious"
  and .kind.routing_decision == "protected_upstream"
  and .kind.discovery_recon_score.query_score == 1
  and .kind.discovery_recon_score.decoy_write_probe_score == 3
  and .kind.discovery_recon_score.total == 4
  and .kind.discovery_recon_score.threshold == 3
' <<<"$second_probe_request_json" >/dev/null \
  || fail "second suspicious-decoy-write-repeat-bonus probe request did not preserve the capped weighted recon state"

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
  || fail "session ${session_id} repeated blind decoy-write probes incorrectly created bait_action_observed evidence"

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
)" || fail "could not find the suspicious-decoy-write-repeat-bonus promotion request for session ${session_id}"

jq -e '
  .policy_state == "observe"
  and .kind.routing_decision == "protected_upstream"
' <<<"$promotion_request_json" >/dev/null \
  || fail "suspicious-decoy-write-repeat-bonus promotion request did not stay in observe before the blind probes"

suspicious_policy_changed_json="$(
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
    and ((.kind.reason // "") | contains("decoy_write_probe_count=1"))
    and ((.kind.reason // "") | contains("decoy_write_probe_score=2"))
    and ((.kind.reason // "") | contains("recon_score=3"))
    and ((.kind.reason // "") | contains("recon_threshold=3"))
  ' <<<"$suspicious_policy_changed_json" >/dev/null \
  || fail "session ${session_id} suspicious transition reason did not preserve the first blind decoy-write recon facts"

rate_limit_request_json="$(
  jq -c -e -s \
    --arg path "$FOLLOW_UP_PATH" \
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
)" || fail "could not find the suspicious-decoy-write-repeat-bonus follow-up request in the proxy event log"

jq -e '
  .session_id == $session_id
' --arg session_id "$session_id" <<<"$rate_limit_request_json" >/dev/null

jq -e '
  .policy_state == "rate_limited"
  and .kind.routing_decision == "rate_limited"
  and .kind.discovery_recon_score.repeated_discovery_score == 2
  and .kind.discovery_recon_score.query_score == 1
  and .kind.discovery_recon_score.decoy_write_probe_score == 3
  and .kind.discovery_recon_score.total == 6
  and .kind.discovery_recon_score.threshold == 5
' <<<"$rate_limit_request_json" >/dev/null \
  || fail "matching suspicious-decoy-write-repeat-bonus follow-up request did not preserve the stronger rate-limited weighted recon state"

rate_limit_policy_changed_json="$(
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
    and ((.kind.reason // "") | contains("query_seen=true"))
    and ((.kind.reason // "") | contains("decoy_write_probe_seen=true"))
    and ((.kind.reason // "") | contains("decoy_write_probe_count=2"))
    and ((.kind.reason // "") | contains("decoy_write_probe_score=3"))
    and ((.kind.reason // "") | contains("recon_score=6"))
    and ((.kind.reason // "") | contains("recon_rate_limit_threshold=5"))
  ' <<<"$rate_limit_policy_changed_json" >/dev/null \
  || fail "session ${session_id} rate-limit transition reason did not preserve the repeated blind decoy-write recon facts"

second_probe_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" \
    --arg path "$PROBE_PATH" '
      map(
        select(
          .event == "request_received"
          and .session_id == $session_id
          and (.fields.path // "") == $path
        )
      )
      | last
    ' "$debug_file"
)" || fail "could not find the second suspicious-decoy-write-repeat-bonus probe debug event"

jq -e '
  (.fields.discovery_decoy_write_probe_seen // false) == true
  and (.fields.discovery_decoy_write_probe_count // -1) == 2
  and (.fields.discovery_recon_score.decoy_write_probe_score // -1) == 3
  and (.fields.discovery_recon_score.total // -1) == 4
' <<<"$second_probe_debug_json" >/dev/null \
  || fail "second suspicious-decoy-write-repeat-bonus probe debug event did not preserve the capped count"

follow_up_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" \
    --arg path "$FOLLOW_UP_PATH" '
      map(
        select(
          .event == "request_received"
          and .session_id == $session_id
          and (.fields.path // "") == $path
        )
      )
      | last
    ' "$debug_file"
)" || fail "could not find the suspicious-decoy-write-repeat-bonus follow-up debug event"

jq -e '
  (.fields.policy_state // "") == "rate_limited"
  and (.fields.discovery_decoy_write_probe_count // -1) == 2
  and (.fields.discovery_recon_score.decoy_write_probe_score // -1) == 3
  and (.fields.discovery_recon_score.total // -1) == 6
  and (.fields.discovery_recon_score.threshold // -1) == 5
' <<<"$follow_up_debug_json" >/dev/null \
  || fail "suspicious-decoy-write-repeat-bonus follow-up debug event did not preserve the stronger rate-limited recon facts"

bash "$EXPORT_SCRIPT" \
  --format ndjson \
  --session "$session_id" \
  --output "$edge_export_file" >/dev/null

jq -e '
  .session_id == $session_id
  and .policy.state == "rate_limited"
  and .policy.routing_decision == "rate_limited"
  and .discovery_recon_score.repeated_discovery_score == 2
  and .discovery_recon_score.query_score == 1
  and .discovery_recon_score.decoy_write_probe_score == 3
  and .discovery_recon_score.total == 6
  and .discovery_recon_score.threshold == 5
' --arg session_id "$session_id" "$edge_export_file" >/dev/null \
  || fail "suspicious-decoy-write-repeat-bonus edge export did not preserve the stronger recon score"

printf 'suspicious-decoy-write-repeat-bonus smoke ok: session=%s repeat_probe_count=2 recon_score=6\n' "$session_id"
