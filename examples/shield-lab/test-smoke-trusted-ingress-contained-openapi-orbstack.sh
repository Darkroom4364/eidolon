#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-trusted-ingress-contained-openapi-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-contained-openapi-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-13T08:00:00Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"local_allowlist","trust_tier":"allowlisted","label":"docs-crawler"},"trusted_ingress_soften_match":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"request_path_softened":true},"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-13T08:00:01Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/openapi.json","safe_headers":[],"ingress_identity":{"source":"local_allowlist","trust_tier":"allowlisted","label":"docs-crawler"},"trusted_ingress_soften_match":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"request_path_softened":false},"routing_decision":"rewritten_upstream"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-13T08:00:01Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"openapi_reconcile_trace","exposure_id":"exp-openapi","surface":"/openapi.json","header_value_mint":{"header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"}}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-13T08:00:02Z","source":"proxy","policy_state":"suspicious","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-13T08:00:02Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"openapi_reconcile_trace","exposure_id":"exp-openapi","method":"POST","path":"/api/v2/import/reconcile","header_value_mint":{"header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"},"header_value_mint_status":"matched_session_value"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-13T08:00:02Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"77777777-7777-7777-7777-777777777777","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-13T08:00:02Z","source":"proxy","policy_state":"controlled_reality","kind":{"type":"response_served","status":202,"routing_decision":"controlled_reality"}}
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
trusted_actor=""
user_agent=""
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
        X-Eidolon-Trusted-Actor:*)
          trusted_actor="${2#X-Eidolon-Trusted-Actor: }"
          ;;
        User-Agent:*)
          user_agent="${2#User-Agent: }"
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

[[ "$cookie" == "eidolon_session=11111111-1111-4111-8111-111111111111" ]]
[[ "$trusted_actor" == "docs-crawler" ]]
[[ "$user_agent" == "eidolon-docs-crawler/1.0" ]]

case "${method}|${request_url}" in
  "GET|http://127.0.0.1:31080/docs?topic=imports")
    printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'HTML'
<html><body><a href="/docs/legacy-import">legacy import notes</a></body></html>
HTML
    ;;
  "GET|http://127.0.0.1:31080/openapi.json")
    printf 'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'JSON'
{"openapi":"3.0.3","paths":{"/api/v2/import/reconcile":{"post":{"parameters":[{"name":"X-OpenAPI-Trace","schema":{"example":"oapi_8d1c3e5add241c2b77c72180"}}]}}}}
JSON
    ;;
  "POST|http://127.0.0.1:31080/api/v2/import/reconcile")
    [[ "$trace_header" == "oapi_8d1c3e5add241c2b77c72180" ]]
    printf 'HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'JSON'
{"write_committed":false,"branch":"customer-import-repair"}
JSON
    ;;
  *)
    echo "unexpected curl invocation: method=${method} url=${request_url}" >&2
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
{"contract_version":"2026-06-13.v1","observed_at":"2026-06-13T08:00:02Z","session_id":"11111111-1111-4111-8111-111111111111","request":{"method":"POST","path":"/api/v2/import/reconcile"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"controlled_reality","routing_decision":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"},"evidence":{"event_schema_version":2,"event_ids":["44444444-4444-4444-4444-444444444444","55555555-5555-5555-5555-555555555555","66666666-6666-6666-6666-666666666666"],"bundle_ref":"session:11111111-1111-4111-8111-111111111111","bait_header_value_mints":[{"bait_id":"openapi_reconcile_trace","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"}],"latest_bait_header_value_mint":{"bait_id":"openapi_reconcile_trace","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi","status":"matched_session_value"}},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","controlled_reality"]}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_proves_trusted_softening_does_not_bypass_containment() {
  local temp_dir
  local state_dir
  local output

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_TRUSTED_CONTAINMENT_SESSION_ID=11111111-1111-4111-8111-111111111111 \
      KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$SMOKE_SCRIPT"
  )"

  rg -q 'trusted-ingress containment smoke ok:' <<<"$output"
  rg -q '11111111-1111-4111-8111-111111111111' <<<"$output"
  rg -q 'softened /docs' <<<"$output"
  rg -q 'entered controlled reality' <<<"$output"
}

test_smoke_script_proves_trusted_softening_does_not_bypass_containment

printf 'shield-lab trusted ingress containment smoke checks passed\n'
