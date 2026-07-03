#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-trusted-ingress-explicit-rule-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-explicit-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","observed_at":"2026-06-18T10:00:01Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"signed_agent","trust_tier":"signed_attested","label":"docs-signed-agent"},"trusted_ingress_soften_match":{"label":"docs-signed-agent","source":"signed_agent","trust_tier":"signed_attested","methods":["GET"],"path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"verified_categories":["AI Assistant"],"request_path_softened":true},"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","observed_at":"2026-06-18T10:00:02Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"signed_agent","trust_tier":"weakly_asserted","label":"wrong-signed-agent"},"authenticated_ingress_rule_rejection":{"label":"docs-signed-agent","source":"signed_agent","trust_tier":"signed_attested","methods":["GET"],"path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"verified_categories":["AI Assistant"],"reason":"label_mismatch"},"routing_decision":"rewritten_upstream"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"request_received","fields":{},"observed_at_unix_ms":1781776801000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
{"event":"surface_action_selected","fields":{"candidate_surface_action":{"type":"rewritten_upstream"},"surface_action":{"type":"protected_upstream"},"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_local_soften_path_prefixes":["/docs"],"trusted_ingress_softened_surface":true,"trusted_ingress_softening_reason":"trusted ingress identity suppressed bait surface intervention before runtime suspicion was established"},"observed_at_unix_ms":1781776801001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
{"event":"request_received","fields":{"authenticated_ingress_rule_rejection":{"label":"docs-signed-agent","reason":"label_mismatch"}},"observed_at_unix_ms":1781776802000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
{"event":"surface_action_selected","fields":{"candidate_surface_action":{"type":"rewritten_upstream"},"surface_action":{"type":"rewritten_upstream"},"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_local_soften_path_prefixes":[],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781776802001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
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
identity_label=""
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
    -H)
      case "$2" in
        X-Eidolon-Ingress-Identity-Label:*)
          identity_label="${2#X-Eidolon-Ingress-Identity-Label: }"
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

[[ "$request_url" == "http://127.0.0.1:31080/docs?topic=imports" ]]
printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n' > "$headers_file"

case "$identity_label" in
  "docs-signed-agent")
    cat > "$body_file" <<'HTML'
<!doctype html><html><body><main>softened docs</main></body></html>
HTML
    ;;
  "wrong-signed-agent")
    cat > "$body_file" <<'HTML'
<!doctype html><html><body><main><a href="/docs/legacy-import">baited docs</a></main></body></html>
HTML
    ;;
  *)
    echo "unexpected explicit-rule label: $identity_label" >&2
    exit 1
    ;;
esac
SH

  chmod +x "$dir/kubectl" "$dir/curl"
}

test_smoke_script_verifies_authenticated_explicit_rule_and_downgrade() {
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

  rg -q 'trusted-ingress explicit-rule smoke ok:' <<<"$output"
  rg -q 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' <<<"$output"
  rg -q 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' <<<"$output"
}

test_smoke_script_verifies_authenticated_explicit_rule_and_downgrade

printf 'shield-lab trusted ingress explicit-rule smoke checks passed\n'
