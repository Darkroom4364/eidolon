#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-hidden-route-controlled-reality-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-hidden-route-controlled-reality-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-07-08T10:05:00Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"hidden_route_trace","exposure_id":"exp-hidden-1","surface":"/customer/import-recovery-checklist"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-07-08T10:05:01Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"controlled_reality"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-07-08T10:05:01Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"hidden_route_trace","exposure_id":"exp-hidden-1","method":"POST","path":"/api/v2/import/reconcile"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-07-08T10:05:01Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-07-08T10:05:01Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"controlled_reality_entered","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-07-08T10:05:01Z","source":"proxy","policy_state":"controlled_reality","kind":{"type":"response_served","status":202,"routing_decision":"controlled_reality"}}
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
  *)
    echo "unexpected kubectl invocation: $*" >&2
    exit 1
    ;;
esac
SH

  cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

method="GET"
headers_file=""
body_file=""
cookie=""
trace_header=""
request_url=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -X)
      method="$2"
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
        Cookie:*)
          cookie="${2#Cookie: }"
          ;;
        X-Hidden-Route-Trace:*)
          trace_header="${2#X-Hidden-Route-Trace: }"
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

case "${method}|${request_url}|${cookie}" in
  "GET|http://127.0.0.1:31080/customer/import-recovery-checklist|eidolon_session=11111111-1111-4111-8111-111111111111")
    printf 'HTTP/1.1 200 OK\r\ncontent-type: text/markdown\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'BODY'
# Customer Import Recovery Checklist

Use `X-Hidden-Route-Trace: hidden_route_2026_05_d91c` with:

```http
POST /api/v2/import/reconcile
```
BODY
    ;;
  "POST|http://127.0.0.1:31080/api/v2/import/reconcile|eidolon_session=11111111-1111-4111-8111-111111111111")
    [[ "$trace_header" == "hidden_route_2026_05_d91c" ]]
    printf 'HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'BODY'
{"write_committed":false,"branch":"customer-import-repair"}
BODY
    ;;
  *)
    echo "unexpected curl invocation: method=${method} url=${request_url} cookie=${cookie}" >&2
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
[[ "$session" == "11111111-1111-4111-8111-111111111111" ]]

cat <<'JSON'
{"contract_version":"2026-07-08.v1","observed_at":"2026-07-08T10:05:01Z","session_id":"11111111-1111-4111-8111-111111111111","request":{"method":"POST","path":"/api/v2/import/reconcile"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"controlled_reality","routing_decision":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"},"evidence":{"event_schema_version":2,"event_ids":["22222222-2222-2222-2222-222222222222","33333333-3333-3333-3333-333333333333","44444444-4444-4444-4444-444444444444"],"bundle_ref":"session:11111111-1111-4111-8111-111111111111"},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","controlled_reality"]}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_verifies_hidden_route_same_session_controlled_reality() {
  local temp_dir
  local state_dir
  local output

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_HIDDEN_ROUTE_CONTROLLED_REALITY_SESSION_ID=11111111-1111-4111-8111-111111111111 \
      KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$SMOKE_SCRIPT"
  )"

  rg -q 'hidden-route controlled reality smoke ok:' <<<"$output"
  rg -q '11111111-1111-4111-8111-111111111111' <<<"$output"
  rg -q 'hidden_route_trace' <<<"$output"
  rg -q 'without mint-specific audit fields' <<<"$output"
}

test_smoke_script_verifies_hidden_route_same_session_controlled_reality

printf 'shield-lab hidden-route controlled reality smoke checks passed\n'
