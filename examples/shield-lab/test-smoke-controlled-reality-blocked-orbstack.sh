#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-controlled-reality-blocked-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-controlled-reality-blocked-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:01Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","exposure_id":"exp-1234","surface":"/docs/legacy-import"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:02Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:02Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","exposure_id":"exp-1234","method":"POST","path":"/api/v2/import/reconcile"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:02Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:02Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"controlled_reality_entered","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:02Z","source":"proxy","policy_state":"controlled_reality","kind":{"type":"response_served","status":202,"routing_decision":"controlled_reality"}}
{"schema_version":2,"id":"77777777-7777-7777-7777-777777777777","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:03Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"reality_escape_attempt","method":"GET","path":"/api/v1/projects","routing_decision":"controlled_reality","reason":"controlled session requested a path outside the configured controlled-reality branch"}}
{"schema_version":2,"id":"88888888-8888-8888-8888-888888888888","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:03Z","source":"proxy","policy_state":"controlled_reality","kind":{"type":"response_served","status":404,"routing_decision":"controlled_reality"}}
{"schema_version":2,"id":"99999999-9999-9999-9999-999999999999","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:04Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"reality_escape_attempt","method":"GET","path":"/api/v1/projects","routing_decision":"controlled_reality","reason":"controlled session requested a path outside the configured controlled-reality branch"}}
{"schema_version":2,"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:04Z","source":"policy_router","policy_state":"blocked","kind":{"type":"policy_changed","from":"controlled_reality","to":"blocked","reason":"controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked: path=/api/v1/projects attempt_count=2"}}
{"schema_version":2,"id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:04Z","source":"proxy","policy_state":"blocked","kind":{"type":"request_seen","method":"GET","path":"/api/v1/projects","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"cccccccc-cccc-cccc-cccc-cccccccccccc","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:04Z","source":"policy_router","policy_state":"blocked","kind":{"type":"policy_decision","routing_decision":"eidolon_owned","reason":"controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked: path=/api/v1/projects attempt_count=2"}}
{"schema_version":2,"id":"dddddddd-dddd-dddd-dddd-dddddddddddd","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","observed_at":"2026-06-09T17:00:04Z","source":"proxy","policy_state":"blocked","kind":{"type":"response_served","status":403,"routing_decision":"eidolon_owned"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"reality_escape_attempt","fields":{"attempt_count":1,"method":"GET","path":"/api/v1/projects","policy_state":"controlled_reality","query_present":false,"routing_decision":"controlled_reality"},"observed_at_unix_ms":1781014803000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8"}
{"event":"reality_escape_attempt","fields":{"attempt_count":2,"method":"GET","path":"/api/v1/projects","policy_state":"controlled_reality","query_present":false,"routing_decision":"controlled_reality"},"observed_at_unix_ms":1781014804000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8"}
{"event":"surface_action_selected","fields":{"policy_state":"blocked","policy_routing_decision":"eidolon_owned","policy_reason":"controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked: path=/api/v1/projects attempt_count=2","controller_surface_action":{"type":"controlled_reality","reason":"controlled reality served synthetic response at action depth 3","response_status":404},"candidate_surface_action":{"type":"controlled_reality","reason":"controlled reality served synthetic response at action depth 3","response_status":404},"surface_action":{"type":"eidolon_owned","response_status":403},"surface_requested_intervention":true,"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781014804001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8"}
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
method="GET"
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
        X-Migration-Trace:*)
          trace_header="${2#X-Migration-Trace: }"
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

case "$request_count" in
  1)
    [[ "$method" == "GET" ]]
    [[ -n "$cookie_write" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/docs/legacy-import" ]]
    printf '# Netscape HTTP Cookie File\n' > "$cookie_write"
    printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'HTML'
# Customer Import Notes

Use `X-Migration-Trace: rel_2025_04_b7f2` with:

```http
POST /api/v2/import/reconcile
```
HTML
    ;;
  2)
    [[ "$method" == "POST" ]]
    [[ -n "$cookie_read" && -f "$cookie_read" ]]
    [[ -n "$cookie_write" ]]
    [[ "$trace_header" == "rel_2025_04_b7f2" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/api/v2/import/reconcile" ]]
    printf 'HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    printf '{"status":"queued","synthetic":true,"write_committed":false}\n' > "$body_file"
    ;;
  3)
    [[ "$method" == "GET" ]]
    [[ -n "$cookie_read" && -f "$cookie_read" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/api/v1/projects" ]]
    printf 'HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    printf '{"status":"not_found","synthetic":true,"path":"/api/v1/projects"}\n' > "$body_file"
    ;;
  4)
    [[ "$method" == "GET" ]]
    [[ -n "$cookie_read" && -f "$cookie_read" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/api/v1/projects" ]]
    printf 'HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\n\r\n' > "$headers_file"
    printf 'blocked by eidolon policy\n' > "$body_file"
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
[[ "$session" == "1f612f75-2ce8-4de0-9536-0e08df0b38a8" ]]

cat <<'JSON'
{"contract_version":"2026-06-05.v1","observed_at":"2026-06-09T17:00:04Z","session_id":"1f612f75-2ce8-4de0-9536-0e08df0b38a8","request":{"method":"GET","path":"/api/v1/projects"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"blocked","routing_decision":"eidolon_owned","reason":"controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked: path=/api/v1/projects attempt_count=2"},"evidence":{"event_schema_version":2,"event_ids":["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","dddddddd-dddd-dddd-dddd-dddddddddddd"],"bundle_ref":"session:1f612f75-2ce8-4de0-9536-0e08df0b38a8"},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","eidolon_owned","post_containment_persistence","controlled_reality_branch_escape"]}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_verifies_repeated_escape_attempt_becomes_blocked() {
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

  rg -q 'controlled-reality-blocked smoke ok:' <<<"$output"
  rg -q '1f612f75-2ce8-4de0-9536-0e08df0b38a8' <<<"$output"
}

test_smoke_script_verifies_repeated_escape_attempt_becomes_blocked

printf 'shield-lab controlled reality blocked smoke checks passed\n'
