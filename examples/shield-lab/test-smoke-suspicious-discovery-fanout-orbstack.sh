#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-suspicious-discovery-fanout-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-discovery-fanout-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838","observed_at":"2026-06-09T10:00:01Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838","observed_at":"2026-06-09T10:00:02Z","source":"policy_router","policy_state":"suspicious","kind":{"type":"policy_changed","from":"observe","to":"suspicious","reason":"session recon discovery-surface fanout promoted request to suspicious: path=/openapi.json distinct_surfaces=2 surfaces=/docs,/openapi.json"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838","observed_at":"2026-06-09T10:00:02Z","source":"proxy","policy_state":"suspicious","kind":{"type":"request_seen","method":"GET","path":"/openapi.json","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838","observed_at":"2026-06-09T10:00:02Z","source":"surface_controller","policy_state":"suspicious","kind":{"type":"bait_exposed","bait_id":"openapi_reconcile_trace","exposure_id":"exp-5678","surface":"/openapi.json"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838","observed_at":"2026-06-09T10:00:02Z","source":"policy_router","policy_state":"suspicious","kind":{"type":"policy_decision","routing_decision":"eidolon_owned","reason":"surface controller served eidolon-owned response"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838","observed_at":"2026-06-09T10:00:02Z","source":"proxy","policy_state":"suspicious","kind":{"type":"response_served","status":200,"routing_decision":"eidolon_owned"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"request_received","fields":{"policy_state":"suspicious","discovery_surface_fanout":{"docs_seen":true,"openapi_seen":true,"distinct_surfaces":2}},"observed_at_unix_ms":1780989602000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838"}
{"event":"surface_action_selected","fields":{"controller_surface_action":{"plan":"openapi_paths","type":"rewritten_upstream"},"candidate_surface_action":{"response_body_len":523,"response_status":200,"type":"eidolon_owned"},"policy_reason":"suspicious policy observes only and forwards to the protected upstream","policy_routing_decision":"protected_upstream","policy_state":"suspicious","surface_action":{"response_body_len":523,"response_status":200,"type":"eidolon_owned"},"surface_requested_intervention":true,"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1780989602001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838"}
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

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    http://*)
      request_url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

case "$request_count" in
  1)
    [[ -n "$cookie_write" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/docs?topic=imports" ]]
    printf '# Netscape HTTP Cookie File\n' > "$cookie_write"
    printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'HTML'
<!doctype html><html><body><a href="/docs/legacy-import">legacy import</a></body></html>
HTML
    ;;
  2)
    [[ -n "$cookie_read" ]]
    [[ -f "$cookie_read" ]]
    [[ -n "$cookie_write" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/openapi.json" ]]
    printf 'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'JSON'
{"openapi":"3.0.3","info":{"title":"Customer import recovery schema","version":"0.0.0-eidolon"},"paths":{"/api/v2/import/reconcile":{"post":{"parameters":[{"name":"X-OpenAPI-Trace","schema":{"example":"openapi_reconcile_trace"}}]}}}}
JSON
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
[[ "$session" == "6dca4a85-4c4d-4628-9baa-12cbc7788838" ]]

cat <<'JSON'
{"contract_version":"2026-06-05.v1","observed_at":"2026-06-09T10:00:02Z","session_id":"6dca4a85-4c4d-4628-9baa-12cbc7788838","request":{"method":"GET","path":"/openapi.json"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"suspicious","routing_decision":"eidolon_owned","reason":"latest request routing decision"},"evidence":{"event_schema_version":2,"event_ids":["33333333-3333-3333-3333-333333333333","66666666-6666-6666-6666-666666666666"],"bundle_ref":"session:6dca4a85-4c4d-4628-9baa-12cbc7788838"},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","eidolon_owned"]}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_verifies_discovery_fanout_promotion_and_export() {
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

  rg -q 'suspicious-discovery-fanout smoke ok:' <<<"$output"
  rg -q '6dca4a85-4c4d-4628-9baa-12cbc7788838' <<<"$output"
}

test_smoke_script_verifies_discovery_fanout_promotion_and_export

printf 'shield-lab suspicious discovery fanout smoke checks passed\n'
