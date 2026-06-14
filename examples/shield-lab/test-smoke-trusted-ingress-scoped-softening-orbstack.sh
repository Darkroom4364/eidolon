#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-trusted-ingress-scoped-softening-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-scope-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","observed_at":"2026-06-12T20:00:01Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"local_allowlist","trust_tier":"allowlisted","label":"docs-crawler"},"trusted_ingress_soften_match":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"request_path_softened":true},"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","observed_at":"2026-06-12T20:00:02Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/openapi.json","safe_headers":[],"ingress_identity":{"source":"local_allowlist","trust_tier":"allowlisted","label":"docs-crawler"},"trusted_ingress_soften_match":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"request_path_softened":false},"routing_decision":"rewritten_upstream"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"surface_action_selected","fields":{"candidate_surface_action":{"type":"rewritten_upstream"},"surface_action":{"type":"protected_upstream"},"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_local_soften_path_prefixes":["/docs"],"trusted_ingress_softened_surface":true,"trusted_ingress_softening_reason":"trusted ingress identity suppressed bait surface intervention before runtime suspicion was established"},"observed_at_unix_ms":1781284801001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
{"event":"surface_action_selected","fields":{"candidate_surface_action":{"type":"rewritten_upstream"},"surface_action":{"type":"rewritten_upstream"},"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_local_soften_path_prefixes":["/docs"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781284802001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
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

headers_file=""
body_file=""
trusted_actor=""
user_agent=""
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
        X-Eidolon-Trusted-Actor:*)
          trusted_actor="${2#X-Eidolon-Trusted-Actor: }"
          ;;
        User-Agent:*)
          user_agent="${2#User-Agent: }"
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

[[ "$trusted_actor" == "docs-crawler" ]]
[[ "$user_agent" == "eidolon-docs-crawler/1.0" ]]
printf 'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n' > "$headers_file"

case "$request_url" in
  "http://127.0.0.1:31080/docs?topic=imports")
    cat > "$body_file" <<'HTML'
<html><body><a href="/docs/legacy-import">legacy import notes</a></body></html>
HTML
    ;;
  "http://127.0.0.1:31080/openapi.json")
    cat > "$body_file" <<'JSON'
{"paths":{"/api/v2/import/reconcile":{"post":{}},"/api/v1/imports":{"post":{}}}}
JSON
    ;;
  *)
    echo "unexpected trusted-scope request: $request_url" >&2
    exit 1
    ;;
esac
SH

  chmod +x "$dir/kubectl" "$dir/curl"
}

test_smoke_script_verifies_scoped_local_softening() {
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

  rg -q 'trusted-ingress scoped softening smoke ok:' <<<"$output"
  rg -q 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' <<<"$output"
  rg -q 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' <<<"$output"
}

test_smoke_script_verifies_scoped_local_softening

printf 'shield-lab trusted ingress scoped softening smoke checks passed\n'
