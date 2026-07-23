#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-session-minted-service-token-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-session-minted-service-token-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-11T18:35:00Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"fake_service_token","exposure_id":"exp-a1","surface":"/docs/service-token","header_value_mint":{"header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-11T18:35:01Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"fake_service_token","exposure_id":"exp-a2","surface":"/docs/service-token","header_value_mint":{"header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"22222222-2222-4222-8222-222222222222","observed_at":"2026-06-11T18:35:02Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"fake_service_token","exposure_id":"exp-b1","surface":"/docs/service-token","header_value_mint":{"header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"22222222-2222-4222-8222-222222222222","observed_at":"2026-06-11T18:35:02Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"22222222-2222-4222-8222-222222222222","observed_at":"2026-06-11T18:35:02Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"fake_service_token","exposure_id":null,"method":"POST","path":"/api/v2/import/reconcile","header_value_mint":{"header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-11T18:35:03Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"controlled_reality"}}
{"schema_version":2,"id":"77777777-7777-7777-7777-777777777777","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-11T18:35:03Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"fake_service_token","exposure_id":"exp-a2","method":"POST","path":"/api/v2/import/reconcile","header_value_mint":{"header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}}}
{"schema_version":2,"id":"88888888-8888-8888-8888-888888888888","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-11T18:35:03Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"99999999-9999-9999-9999-999999999999","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-11T18:35:03Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"controlled_reality_entered","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-11T18:35:03Z","source":"proxy","policy_state":"controlled_reality","kind":{"type":"response_served","status":202,"routing_decision":"controlled_reality"}}
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
api_key=""
request_url=""
proof_cache_control="${EIDOLON_TEST_PROOF_CACHE_CONTROL:-No-Store, PRIVATE}"
proof_etag="${EIDOLON_TEST_PROOF_ETAG:-}"
proof_last_modified="${EIDOLON_TEST_PROOF_LAST_MODIFIED:-}"
printf -v fixture_tag_a '%024d' 0
printf -v fixture_tag_b '%024d' 1
session_a_value="svc_w5ac7f6_${fixture_tag_a}"
session_b_value="svc_w5ac7f6_${fixture_tag_b}"

write_proof_headers() {
  printf 'HTTP/1.1 200 OK\r\ncontent-type: text/markdown\r\nCache-Control: %s\r\n' \
    "$proof_cache_control" > "$headers_file"
  if [[ -n "$proof_etag" ]]; then
    printf 'ETag: %s\r\n' "$proof_etag" >> "$headers_file"
  fi
  if [[ -n "$proof_last_modified" ]]; then
    printf 'Last-Modified: %s\r\n' "$proof_last_modified" >> "$headers_file"
  fi
  printf '\r\n' >> "$headers_file"
}

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
        X-Api-Key:*)
          api_key="${2#X-Api-Key: }"
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
  "GET|http://127.0.0.1:31080/docs/service-token|eidolon_session=11111111-1111-4111-8111-111111111111")
    write_proof_headers
    printf '# Customer Service Token\n\nUse `%s: %s` with:\n\n```http\nPOST /api/v2/import/reconcile\n```\n' \
      "X-Api-Key" "$session_a_value" > "$body_file"
    ;;
  "GET|http://127.0.0.1:31080/docs/service-token|eidolon_session=22222222-2222-4222-8222-222222222222")
    write_proof_headers
    printf '# Customer Service Token\n\nUse `%s: %s` with:\n\n```http\nPOST /api/v2/import/reconcile\n```\n' \
      "X-Api-Key" "$session_b_value" > "$body_file"
    ;;
  "POST|http://127.0.0.1:31080/api/v2/import/reconcile|eidolon_session=11111111-1111-4111-8111-111111111111")
    [[ "$api_key" == "$session_a_value" ]]
    printf 'HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'BODY'
{"write_committed":false,"branch":"customer-import-repair"}
BODY
    ;;
  "POST|http://127.0.0.1:31080/api/v2/import/reconcile|eidolon_session=22222222-2222-4222-8222-222222222222")
    [[ "$api_key" == "$session_a_value" ]]
    printf 'HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'BODY'
{"status":"blocked","synthetic":true,"reason":"configured unsafe bait action failed closed","path":"/api/v2/import/reconcile"}
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
case "$session" in
  "11111111-1111-4111-8111-111111111111")
    cat <<'JSON'
{"contract_version":"2026-06-05.v1","observed_at":"2026-06-11T18:35:03Z","session_id":"11111111-1111-4111-8111-111111111111","request":{"method":"POST","path":"/api/v2/import/reconcile"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"controlled_reality","routing_decision":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"},"evidence":{"event_schema_version":2,"event_ids":["66666666-6666-6666-6666-666666666666","77777777-7777-7777-7777-777777777777","88888888-8888-8888-8888-888888888888"],"bundle_ref":"session:11111111-1111-4111-8111-111111111111","bait_header_value_mints":[{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"latest_bait_header_value_mint":{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc","status":"matched_session_value"}},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","controlled_reality"]}}
JSON
    ;;
  "22222222-2222-4222-8222-222222222222")
    cat <<'JSON'
{"contract_version":"2026-06-05.v1","observed_at":"2026-06-11T18:35:02Z","session_id":"22222222-2222-4222-8222-222222222222","request":{"method":"POST","path":"/api/v2/import/reconcile"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"observe","routing_decision":"eidolon_owned","reason":"configured unsafe bait action failed closed after proof rejection"},"evidence":{"event_schema_version":2,"event_ids":["44444444-4444-4444-4444-444444444444","55555555-5555-5555-5555-555555555555"],"bundle_ref":"session:22222222-2222-4222-8222-222222222222","bait_header_value_mints":[{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"latest_bait_header_value_mint":{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc","status":"session_value_mismatch"}},"edge_recommendation":{"action":"observe","reason_codes":["eidolon_owned"]}}
JSON
    ;;
  *)
    echo "unexpected session for edge-export stub: $session" >&2
    exit 1
    ;;
esac
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_verifies_default_session_minted_service_token() {
  local temp_dir
  local state_dir
  local output

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_SESSION_A=11111111-1111-4111-8111-111111111111 \
      EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_SESSION_B=22222222-2222-4222-8222-222222222222 \
      KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$SMOKE_SCRIPT"
  )"

  rg -q 'session-minted service-token smoke ok:' <<<"$output"
  rg -q '11111111-1111-4111-8111-111111111111' <<<"$output"
  rg -q '22222222-2222-4222-8222-222222222222' <<<"$output"
  rg -q 'cross-session replay stayed uncorrelated' <<<"$output"
}

assert_smoke_rejects_cache_headers() {
  local cache_control="$1"
  local etag="$2"
  local last_modified="$3"
  local expected="$4"
  local temp_dir
  local state_dir
  local output

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  if output="$(
    EIDOLON_TEST_PROOF_CACHE_CONTROL="$cache_control" \
      EIDOLON_TEST_PROOF_ETAG="$etag" \
      EIDOLON_TEST_PROOF_LAST_MODIFIED="$last_modified" \
      EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_SESSION_A=11111111-1111-4111-8111-111111111111 \
      EIDOLON_SHIELD_SESSION_MINTED_SERVICE_TOKEN_SESSION_B=22222222-2222-4222-8222-222222222222 \
      KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$SMOKE_SCRIPT" 2>&1
  )"; then
    echo "expected service-token smoke to reject unsafe proof cache headers" >&2
    exit 1
  fi

  rg -q "$expected" <<<"$output"
}

test_smoke_script_verifies_default_session_minted_service_token
assert_smoke_rejects_cache_headers \
  'private' \
  '' \
  '' \
  'missing Cache-Control directive no-store'
assert_smoke_rejects_cache_headers \
  'no-store' \
  '' \
  '' \
  'missing Cache-Control directive private'
assert_smoke_rejects_cache_headers \
  'private, no-store=3600' \
  '' \
  '' \
  'missing Cache-Control directive no-store'
assert_smoke_rejects_cache_headers \
  'private=1, no-store' \
  '' \
  '' \
  'missing Cache-Control directive private'
assert_smoke_rejects_cache_headers \
  'private, no-store' \
  '"stale-proof"' \
  '' \
  'exposed a stale ETag or Last-Modified validator'
assert_smoke_rejects_cache_headers \
  'private, no-store' \
  '' \
  'Wed, 22 Jul 2026 10:00:00 GMT' \
  'exposed a stale ETag or Last-Modified validator'

printf 'shield-lab session-minted service-token smoke checks passed\n'
