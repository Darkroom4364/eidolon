#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-suspicious-openapi-rate-limit-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-openapi-rate-limit-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f","observed_at":"2026-06-09T13:00:01Z","source":"proxy","policy_state":"suspicious","kind":{"type":"request_seen","method":"GET","path":"/openapi.json","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":12,"vendor_score_kind":"automation_likelihood_inverse"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f","observed_at":"2026-06-09T13:00:01Z","source":"surface_controller","policy_state":"suspicious","kind":{"type":"bait_exposed","bait_id":"openapi_reconcile_trace","exposure_id":"exp-5678","surface":"/openapi.json"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f","observed_at":"2026-06-09T13:00:02Z","source":"bait_engine","policy_state":"suspicious","kind":{"type":"bait_action_observed","bait_id":"openapi_reconcile_trace","exposure_id":null,"method":"POST","path":"/api/v2/import/reconcile"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f","observed_at":"2026-06-09T13:00:02Z","source":"policy_router","policy_state":"rate_limited","kind":{"type":"policy_changed","from":"suspicious","to":"rate_limited","reason":"suspicious same-bait near miss after exposure moved session to rate limited: path=/api/v2/import/reconcile bait_id=openapi_reconcile_trace"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f","observed_at":"2026-06-09T13:00:02Z","source":"proxy","policy_state":"rate_limited","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":12,"vendor_score_kind":"automation_likelihood_inverse"},"routing_decision":"rate_limited"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f","observed_at":"2026-06-09T13:00:02Z","source":"policy_router","policy_state":"rate_limited","kind":{"type":"rate_limit_applied","reason":"suspicious same-bait near miss after exposure moved session to rate limited: path=/api/v2/import/reconcile bait_id=openapi_reconcile_trace"}}
{"schema_version":2,"id":"77777777-7777-7777-7777-777777777777","session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f","observed_at":"2026-06-09T13:00:02Z","source":"proxy","policy_state":"rate_limited","kind":{"type":"response_served","status":429,"routing_decision":"rate_limited"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"surface_action_selected","fields":{"controller_surface_action":{"plan":"openapi_paths","type":"rewritten_upstream"},"candidate_surface_action":{"response_body_len":523,"response_status":200,"type":"eidolon_owned"},"policy_reason":"suspicious policy observes only and forwards to the protected upstream","policy_routing_decision":"protected_upstream","policy_state":"suspicious","surface_action":{"response_body_len":523,"response_status":200,"type":"eidolon_owned"},"surface_requested_intervention":true,"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781000401000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f"}
{"event":"surface_action_selected","fields":{"controller_surface_action":{"type":"protected_upstream"},"candidate_surface_action":{"type":"protected_upstream"},"policy_reason":"suspicious policy observes only and forwards to the protected upstream","policy_routing_decision":"protected_upstream","policy_state":"suspicious","surface_action":{"type":"protected_upstream"},"surface_requested_intervention":false,"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781000402000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f"}
{"event":"bait_action_near_miss","fields":{"bait_id":"openapi_reconcile_trace","method":"POST","path":"/api/v2/import/reconcile","prior_same_bait_exposure":true,"query_present":false},"observed_at_unix_ms":1781000402001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f"}
{"event":"bait_action_observed","fields":{"bait_id":"openapi_reconcile_trace","method":"POST","path":"/api/v2/import/reconcile","matched_prior_exposure":false,"prior_same_bait_exposure":true,"exposure_id":null,"query_present":false},"observed_at_unix_ms":1781000402002,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f"}
JSONL
}

make_stub_bins() {
  local dir="$1"

  cat > "$dir/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  "config current-context")
    printf 'orbstack\n'
    ;;
  "-n shield-system get svc eidolon-shield-edge -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-edge"},"spec":{"ports":[{"name":"http","nodePort":31080}]}}
JSON
    ;;
  "-n shield-system get secret eidolon-trusted-ingress -o json")
    cat <<'JSON'
{"data":{"transport-auth.txt":"c2VjcmV0LXZhbHVl"}}
JSON
    ;;
  *)
    echo "unexpected kubectl invocation: $*" >&2
    exit 1
    ;;
esac
SH

  cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

count_file="$(dirname "$0")/curl.count"
request_count=0
if [[ -f "$count_file" ]]; then
  request_count="$(cat "$count_file")"
fi
request_count="$((request_count + 1))"
printf '%s' "$request_count" > "$count_file"

cookie_read=""
cookie_write=""
headers_file=""
body_file=""
request_url=""
method="GET"
actor_kind=""
vendor_score=""
vendor_score_kind=""
transport_auth=""
trace_header=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -X)
      method="$2"
      shift 2
      ;;
    -b)
      cookie_read="$2"
      shift 2
      ;;
    -c)
      cookie_write="$2"
      shift 2
      ;;
    -D)
      headers_file="$2"
      shift 2
      ;;
    -o)
      body_file="$2"
      shift 2
      ;;
    -H)
      case "$2" in
        X-Eidolon-Ingress-Actor-Kind:*)
          actor_kind="${2#X-Eidolon-Ingress-Actor-Kind: }"
          ;;
        X-Eidolon-Ingress-Vendor-Score:*)
          vendor_score="${2#X-Eidolon-Ingress-Vendor-Score: }"
          ;;
        X-Eidolon-Ingress-Vendor-Score-Kind:*)
          vendor_score_kind="${2#X-Eidolon-Ingress-Vendor-Score-Kind: }"
          ;;
        X-Eidolon-Ingress-Transport-Auth:*)
          transport_auth="${2#X-Eidolon-Ingress-Transport-Auth: }"
          ;;
        X-OpenAPI-Trace:*)
          trace_header="${2#X-OpenAPI-Trace: }"
          ;;
      esac
      shift 2
      ;;
    http://*)
      request_url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

[[ "$actor_kind" == "agentic_browser" ]]
[[ "$vendor_score" == "12" ]]
[[ "$vendor_score_kind" == "automation_likelihood_inverse" ]]
[[ "$transport_auth" == "secret-value" ]]

case "$request_count" in
  1)
    [[ "$method" == "GET" ]]
    [[ -n "$cookie_write" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/openapi.json" ]]
    printf '# Netscape HTTP Cookie File\n' > "$cookie_write"
    printf 'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'JSON'
{"openapi":"3.0.3","info":{"title":"Customer import recovery schema","version":"0.0.0-eidolon"},"paths":{"/api/v2/import/reconcile":{"post":{"parameters":[{"name":"X-OpenAPI-Trace","schema":{"example":"openapi_reconcile_trace"}}]}}}}
JSON
    ;;
  2)
    [[ "$method" == "POST" ]]
    [[ -n "$cookie_read" ]]
    [[ -f "$cookie_read" ]]
    [[ -n "$cookie_write" ]]
    [[ "$trace_header" == "wrong" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/api/v2/import/reconcile" ]]
    printf 'HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\ncontent-type: text/plain\r\n\r\n' > "$headers_file"
    printf 'rate limited by eidolon\n' > "$body_file"
    ;;
  *)
    echo "unexpected curl invocation count: $request_count" >&2
    exit 1
    ;;
esac
SH

  cat > "$dir/edge-export" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

events=""
session=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --events)
      events="$2"
      shift 2
      ;;
    --session)
      session="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

[[ -f "$events" ]]
[[ "$session" == "3f9c6d5a-b534-4a62-a420-4885c48bd76f" ]]

cat <<'JSON'
{"contract_version":"2026-06-05.v1","observed_at":"2026-06-09T13:00:02Z","session_id":"3f9c6d5a-b534-4a62-a420-4885c48bd76f","request":{"method":"POST","path":"/api/v2/import/reconcile"},"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":12,"vendor_score_kind":"automation_likelihood_inverse"},"policy":{"state":"rate_limited","routing_decision":"rate_limited","reason":"latest request routing decision"},"evidence":{"event_schema_version":2,"event_ids":["55555555-5555-5555-5555-555555555555","77777777-7777-7777-7777-777777777777"],"bundle_ref":"session:3f9c6d5a-b534-4a62-a420-4885c48bd76f"},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","rate_limited"]}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_verifies_suspicious_openapi_rate_limit_and_export() {
  local temp_dir
  local state_dir
  local output

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$SMOKE_SCRIPT"
  )"

  rg -q 'suspicious-rate-limit smoke ok:' <<<"$output"
  rg -q '3f9c6d5a-b534-4a62-a420-4885c48bd76f' <<<"$output"
}

test_smoke_script_verifies_suspicious_openapi_rate_limit_and_export

printf 'shield-lab suspicious openapi rate limit smoke checks passed\n'
