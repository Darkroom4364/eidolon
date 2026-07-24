#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-session-minted-legacy-import-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-session-minted-legacy-import-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","request_id":"10000000-0000-4000-8000-000000000001","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-12T09:20:00Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","bait_class":"docs","exposure_id":"exp-a1","surface":"/docs/legacy-import","header_value_mint":{"header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"}}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","request_id":"10000000-0000-4000-8000-000000000002","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-12T09:20:01Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","bait_class":"docs","exposure_id":"exp-a2","surface":"/docs/legacy-import","header_value_mint":{"header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"}}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","request_id":"10000000-0000-4000-8000-000000000003","session_id":"22222222-2222-4222-8222-222222222222","observed_at":"2026-06-12T09:20:02Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","bait_class":"docs","exposure_id":"exp-b1","surface":"/docs/legacy-import","header_value_mint":{"header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"}}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","request_id":"20000000-0000-4000-8000-000000000001","session_id":"22222222-2222-4222-8222-222222222222","observed_at":"2026-06-12T09:20:02Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","request_id":"20000000-0000-4000-8000-000000000001","session_id":"22222222-2222-4222-8222-222222222222","observed_at":"2026-06-12T09:20:02Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","bait_class":"docs","exposure_id":null,"method":"POST","path":"/api/v2/import/reconcile","header_value_mint":{"header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},"header_value_mint_status":"session_value_mismatch"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","request_id":"20000000-0000-4000-8000-000000000001","session_id":"22222222-2222-4222-8222-222222222222","observed_at":"2026-06-12T09:20:02Z","source":"proxy","policy_state":"observe","kind":{"type":"response_served","status":403,"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"77777777-7777-7777-7777-777777777777","request_id":"30000000-0000-4000-8000-000000000001","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-12T09:20:03Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"88888888-8888-8888-8888-888888888888","request_id":"30000000-0000-4000-8000-000000000001","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-12T09:20:03Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","bait_class":"docs","exposure_id":"exp-a2","method":"POST","path":"/api/v2/import/reconcile","header_value_mint":{"header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},"header_value_mint_status":"matched_session_value"}}
{"schema_version":2,"id":"99999999-9999-9999-9999-999999999999","request_id":"30000000-0000-4000-8000-000000000001","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-12T09:20:03Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","request_id":"30000000-0000-4000-8000-000000000001","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-12T09:20:03Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"controlled_reality_entered","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","request_id":"30000000-0000-4000-8000-000000000001","session_id":"11111111-1111-4111-8111-111111111111","observed_at":"2026-06-12T09:20:03Z","source":"proxy","policy_state":"controlled_reality","kind":{"type":"response_served","status":202,"routing_decision":"controlled_reality"}}
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
proof_cache_control="${EIDOLON_TEST_PROOF_CACHE_CONTROL:-No-Store, PRIVATE}"
proof_etag="${EIDOLON_TEST_PROOF_ETAG:-}"
proof_last_modified="${EIDOLON_TEST_PROOF_LAST_MODIFIED:-}"

write_proof_headers() {
  local output_file="$1"

  {
    printf 'HTTP/1.1 200 OK\r\n'
    printf 'content-type: text/markdown\r\n'
    printf 'Cache-Control: %s\r\n' "$proof_cache_control"
    if [[ -n "$proof_etag" ]]; then
      printf 'ETag: %s\r\n' "$proof_etag"
    fi
    if [[ -n "$proof_last_modified" ]]; then
      printf 'Last-Modified: %s\r\n' "$proof_last_modified"
    fi
    printf '\r\n'
  } > "$output_file"
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

case "${method}|${request_url}|${cookie}" in
  "GET|http://127.0.0.1:31080/docs/legacy-import|eidolon_session=11111111-1111-4111-8111-111111111111")
    write_proof_headers "$headers_file"
    cat > "$body_file" <<'BODY'
# Variant Customer Import Notes

Use `X-Migration-Trace: mig_w5ac7f6_8d1c3e5add241c2b77c72180` with:

```http
POST /api/v2/import/reconcile
```
BODY
    ;;
  "GET|http://127.0.0.1:31080/docs/legacy-import|eidolon_session=22222222-2222-4222-8222-222222222222")
    write_proof_headers "$headers_file"
    cat > "$body_file" <<'BODY'
# Variant Customer Import Notes

Use `X-Migration-Trace: mig_w5ac7f6_37dfde370fb3c688eaeb145c` with:

```http
POST /api/v2/import/reconcile
```
BODY
    ;;
  "POST|http://127.0.0.1:31080/api/v2/import/reconcile|eidolon_session=11111111-1111-4111-8111-111111111111")
    [[ "$trace_header" == "mig_w5ac7f6_8d1c3e5add241c2b77c72180" ]]
    printf 'HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'BODY'
{"write_committed":false,"branch":"customer-import-repair"}
BODY
    ;;
  "POST|http://127.0.0.1:31080/api/v2/import/reconcile|eidolon_session=22222222-2222-4222-8222-222222222222")
    [[ "$trace_header" == "mig_w5ac7f6_8d1c3e5add241c2b77c72180" ]]
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

  chmod +x "$dir/kubectl" "$dir/curl"
}

test_smoke_script_verifies_default_session_minted_legacy_import_bait() {
  local output

  output="$(run_smoke_fixture 'No-Store, PRIVATE' '' '')"

  rg -q 'session-minted legacy-import smoke ok:' <<<"$output"
  rg -q '11111111-1111-4111-8111-111111111111' <<<"$output"
  rg -q '22222222-2222-4222-8222-222222222222' <<<"$output"
  rg -q 'cross-session replay stayed uncorrelated' <<<"$output"
}

run_smoke_fixture() {
  local cache_control="$1"
  local etag="$2"
  local last_modified="$3"
  local temp_dir
  local state_dir

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  EIDOLON_TEST_PROOF_CACHE_CONTROL="$cache_control" \
    EIDOLON_TEST_PROOF_ETAG="$etag" \
    EIDOLON_TEST_PROOF_LAST_MODIFIED="$last_modified" \
    EIDOLON_SHIELD_SESSION_MINTED_LEGACY_IMPORT_SESSION_A=11111111-1111-4111-8111-111111111111 \
    EIDOLON_SHIELD_SESSION_MINTED_LEGACY_IMPORT_SESSION_B=22222222-2222-4222-8222-222222222222 \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    "$SMOKE_SCRIPT"
}

assert_smoke_rejected() {
  local cache_control="$1"
  local etag="$2"
  local last_modified="$3"
  local expected_message="$4"
  local label="$5"
  local output

  if output="$(run_smoke_fixture "$cache_control" "$etag" "$last_modified" 2>&1)"; then
    echo "expected legacy-import smoke to reject $label" >&2
    exit 1
  fi

  rg -q "$expected_message" <<<"$output"
}

test_smoke_script_rejects_missing_private() {
  assert_smoke_rejected \
    'no-store' \
    '' \
    '' \
    'missing bare Cache-Control directive private' \
    'a proof response without private'
}

test_smoke_script_rejects_missing_no_store() {
  assert_smoke_rejected \
    'private' \
    '' \
    '' \
    'missing bare Cache-Control directive no-store' \
    'a proof response without no-store'
}

test_smoke_script_rejects_directive_arguments() {
  assert_smoke_rejected \
    'private=1, no-store' \
    '' \
    '' \
    'missing bare Cache-Control directive private' \
    'a private directive with an argument'
  assert_smoke_rejected \
    'private, no-store=3600' \
    '' \
    '' \
    'missing bare Cache-Control directive no-store' \
    'a no-store directive with an argument'
}

test_smoke_script_rejects_stale_validators() {
  assert_smoke_rejected \
    'private, no-store' \
    '"stale-proof"' \
    '' \
    'exposed a stale ETag or Last-Modified validator' \
    'a proof response with ETag'
  assert_smoke_rejected \
    'private, no-store' \
    '' \
    'Wed, 22 Jul 2026 10:00:00 GMT' \
    'exposed a stale ETag or Last-Modified validator' \
    'a proof response with Last-Modified'
}

test_smoke_script_verifies_default_session_minted_legacy_import_bait
test_smoke_script_rejects_missing_private
test_smoke_script_rejects_missing_no_store
test_smoke_script_rejects_directive_arguments
test_smoke_script_rejects_stale_validators

printf 'shield-lab session-minted legacy-import smoke checks passed\n'
