#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-trusted-ingress-expired-claim-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-ingress-expired-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","observed_at":"2026-06-13T19:00:01Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/openapi.json","safe_headers":[],"ingress_identity":{"source":"signed_agent","trust_tier":"weakly_asserted","label":"expired-orbstack-smoke","expires_at":"2000-01-01T00:00:00Z"},"authenticated_ingress_rule_rejection":{"label":"expired-orbstack-smoke","source":"signed_agent","trust_tier":"signed_attested","expires_at":"2000-01-01T00:00:00Z","methods":["GET"],"path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"verified_categories":["AI Assistant"],"reason":"expired"},"routing_decision":"protected_upstream"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"request_received","fields":{"authenticated_ingress_rule_rejection":{"label":"expired-orbstack-smoke","reason":"expired"}},"observed_at_unix_ms":1781290801000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
{"event":"surface_action_selected","fields":{"candidate_surface_action":{"type":"rewritten_upstream"},"surface_action":{"type":"rewritten_upstream"},"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781290801001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
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
{"metadata":{"name":"eidolon-trusted-ingress"},"data":{"transport-auth.txt":"ZWRnZS1zZWNyZXQ="}}
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

headers_file=""
body_file=""
request_url=""

while [[ $# -gt 0 ]]; do
  case "$1" in
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

[[ "$request_url" == "http://127.0.0.1:31080/openapi.json" ]]
printf 'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"
cat > "$body_file" <<'JSON'
{"paths":{"/api/v2/import/reconcile":{"post":{}},"/api/v1/imports":{"post":{}}}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl"
}

test_smoke_script_proves_expired_claim_degrades_and_stays_baited() {
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
      "$SMOKE_SCRIPT"
  )"

  rg -q 'trusted-ingress expired-claim smoke ok:' <<<"$output"
  rg -q 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' <<<"$output"
}

test_smoke_script_proves_expired_claim_degrades_and_stays_baited

printf 'shield-lab trusted ingress expired claim smoke checks passed\n'
