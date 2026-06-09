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
EXPOSURE_PATH="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_EXPOSURE_PATH:-/docs/legacy-import}"
ACTION_PATH="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_ACTION_PATH:-/api/v2/import/reconcile}"
ACTION_PATH_PREFIX="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_ACTION_PATH_PREFIX:-/api/v2/import/reconcile}"
EXPECTED_BAIT_MARKER="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_BAIT_MARKER:-X-Migration-Trace: rel_2025_04_b7f2}"
EXACT_HEADER_NAME="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_HEADER_NAME:-X-Migration-Trace}"
EXACT_HEADER_VALUE="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_HEADER_VALUE:-rel_2025_04_b7f2}"
EXPECTED_RETRY_AFTER="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_RETRY_AFTER:-30}"
WARMUP_CONTROLLED_REQUESTS="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_WARMUP_REQUESTS:-3}"
EXPECTED_BLOCK_DEPTH="${EIDOLON_SHIELD_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_DEPTH:-6}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-controlled-reality-depth-limit-blocked-orbstack.sh

Performs a live OrbStack smoke check for the controlled-branch depth-limit
blocked path. It exposes one docs bait surface, performs the exact same-session
decoy action to enter controlled_reality, keeps probing the controlled branch
until Eidolon first rate-limits and then blocks the session, and verifies the
same session through edge export.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-controlled-reality-depth-limit-blocked-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
resolve_edge_export_bin

cookie_jar="$tmp_dir/cookies.txt"
exposure_headers="$tmp_dir/exposure.headers"
exposure_body="$tmp_dir/exposure.body"
entry_headers="$tmp_dir/entry.headers"
entry_body="$tmp_dir/entry.body"
probe_headers="$tmp_dir/probe.headers"
probe_body="$tmp_dir/probe.body"
throttle_headers="$tmp_dir/throttle.headers"
throttle_body="$tmp_dir/throttle.body"
blocked_headers="$tmp_dir/blocked.headers"
blocked_body="$tmp_dir/blocked.body"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"
edge_export_file="$tmp_dir/edge-export.json"

curl_cmd -fsS \
  -c "$cookie_jar" \
  -D "$exposure_headers" \
  -o "$exposure_body" \
  "${edge_url}${EXPOSURE_PATH}"

exposure_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$exposure_headers")"
[[ "$exposure_http_code" == "200" ]] || fail "expected HTTP 200 from controlled-reality depth-limit exposure request, got: ${exposure_http_code:-none}"
grep -Fq "$EXPECTED_BAIT_MARKER" "$exposure_body" \
  || fail "controlled-reality depth-limit exposure request did not receive the expected baited surface"

curl_cmd -sS \
  -X POST \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$entry_headers" \
  -o "$entry_body" \
  -H "${EXACT_HEADER_NAME}: ${EXACT_HEADER_VALUE}" \
  "${edge_url}${ACTION_PATH}"

entry_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$entry_headers")"
[[ "$entry_http_code" == "202" ]] || fail "expected HTTP 202 from controlled-reality entry request, got: ${entry_http_code:-none}"
grep -Fq '"write_committed":false' "$entry_body" \
  || fail "controlled-reality entry request did not receive the expected synthetic write response"

for ((i = 0; i < WARMUP_CONTROLLED_REQUESTS; i += 1)); do
  curl_cmd -sS \
    -b "$cookie_jar" \
    -c "$cookie_jar" \
    -D "$probe_headers" \
    -o "$probe_body" \
    "${edge_url}${ACTION_PATH}"

  probe_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$probe_headers")"
  [[ "$probe_http_code" == "200" ]] || fail "expected HTTP 200 from controlled-reality warmup request $((i + 1)), got: ${probe_http_code:-none}"
  grep -Fq '"synthetic":true' "$probe_body" \
    || fail "controlled-reality warmup request $((i + 1)) did not stay on the synthetic branch"
done

curl_cmd -sS \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$throttle_headers" \
  -o "$throttle_body" \
  "${edge_url}${ACTION_PATH}"

throttle_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$throttle_headers")"
[[ "$throttle_http_code" == "429" ]] || fail "expected HTTP 429 from controlled-reality throttle request, got: ${throttle_http_code:-none}"
retry_after="$(awk 'BEGIN{IGNORECASE=1} tolower($1) == "retry-after:" {gsub("\r", "", $2); print $2}' "$throttle_headers" | tail -n 1)"
[[ "$retry_after" == "$EXPECTED_RETRY_AFTER" ]] \
  || fail "expected Retry-After ${EXPECTED_RETRY_AFTER} from controlled-reality throttle request, got: ${retry_after:-none}"

curl_cmd -sS \
  -b "$cookie_jar" \
  -c "$cookie_jar" \
  -D "$blocked_headers" \
  -o "$blocked_body" \
  "${edge_url}${ACTION_PATH}"

blocked_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$blocked_headers")"
[[ "$blocked_http_code" == "403" ]] || fail "expected HTTP 403 from controlled-reality blocked request, got: ${blocked_http_code:-none}"

read_proxy_state_file events.jsonl > "$events_file"

blocked_request_json="$(
  jq -c -e -s \
    --arg path_prefix "$ACTION_PATH_PREFIX" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the controlled-reality blocked request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$blocked_request_json")"
[[ -n "$session_id" ]] || fail "matching controlled-reality blocked request had no session id"

jq -e '
  .policy_state == "blocked"
  and .kind.routing_decision == "eidolon_owned"
' <<<"$blocked_request_json" >/dev/null \
  || fail "matching controlled-reality blocked request did not persist the blocked decision"

controlled_entry_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "controlled_reality_entered"
        )
      )
      | first
    ' "$events_file"
)" || fail "session ${session_id} had no controlled_reality_entered event"

jq -e '.policy_state == "controlled_reality"' <<<"$controlled_entry_json" >/dev/null \
  || fail "session ${session_id} did not enter controlled_reality before the blocked step"

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
)" || fail "session ${session_id} had no controlled-reality rate-limit event"

jq -e '.policy_state == "controlled_reality"' <<<"$rate_limit_json" >/dev/null \
  || fail "session ${session_id} did not keep controlled_reality state on the first depth-limit throttle"

blocked_transition_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "policy_changed"
          and .kind.from == "controlled_reality"
          and .kind.to == "blocked"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${session_id} had no controlled_reality -> blocked policy transition event"

jq -e \
  --arg reason_substring "controlled-reality probe continued after depth-limit throttle and moved session to blocked" '
    (.kind.reason // "") | contains($reason_substring)
  ' <<<"$blocked_transition_json" >/dev/null \
  || fail "session ${session_id} blocked transition reason did not match the depth-limit persistence path"

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
  || fail "session ${session_id} blocked response did not preserve the expected Eidolon-owned hard fail"

read_proxy_state_file debug.jsonl > "$debug_file"

controlled_debug_json="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "controlled_reality_action_selected"))
      | last
    ' "$debug_file"
)" || fail "session ${session_id} had no controlled_reality_action_selected debug record"

jq -e \
  --argjson expected_depth "$EXPECTED_BLOCK_DEPTH" '
    .fields.depth == $expected_depth
    and .fields.action.type == "eidolon_owned"
    and .fields.transition.to == "blocked"
  ' <<<"$controlled_debug_json" >/dev/null \
  || fail "session ${session_id} did not record the blocked controlled-reality transition at the expected action depth"

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
' <<<"$surface_debug_json" >/dev/null \
  || fail "session ${session_id} did not preserve the blocked surface action selection in debug output"

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
  and $exports[0].policy.state == "blocked"
  and $exports[0].policy.routing_decision == "eidolon_owned"
  and $exports[0].edge_recommendation.action == "preserve_eidolon_routing"
  and (($exports[0].edge_recommendation.reason_codes // []) | index("eidolon_runtime_enforcement")) != null
  and (($exports[0].edge_recommendation.reason_codes // []) | index("eidolon_owned")) != null
' "$edge_export_file" >/dev/null \
  || fail "edge export did not preserve the controlled-reality depth-limit blocked runtime decision"

printf 'controlled-reality-depth-limit-blocked smoke ok: session=%s blocked_after_depth_limit_persistence=true\n' "$session_id"
