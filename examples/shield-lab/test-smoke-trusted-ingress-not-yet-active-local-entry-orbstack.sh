#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-trusted-ingress-not-yet-active-local-entry-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-not-yet-active-entry-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","observed_at":"2026-06-14T08:12:01Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"local_ingress_trust_scope_rejection":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","not_before":"2999-01-01T00:00:00Z","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"reason":"not_yet_active"},"routing_decision":"rewritten_upstream"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"surface_action_selected","fields":{"candidate_surface_action":{"type":"rewritten_upstream"},"surface_action":{"type":"rewritten_upstream"},"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_local_soften_path_prefixes":[],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781463121001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
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
[[ "$request_url" == "http://127.0.0.1:31080/docs?topic=imports" ]]
printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n' > "$headers_file"
cat > "$body_file" <<'HTML'
<html><body>X-Migration-Trace: mig_fixture_value</body></html>
HTML
SH

  chmod +x "$dir/kubectl" "$dir/curl"
}

test_smoke_script_proves_not_yet_active_local_allowlist_keeps_docs_baited() {
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

  rg -q 'trusted-ingress not-yet-active-local-entry smoke ok:' <<<"$output"
  rg -q 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' <<<"$output"
}

test_smoke_script_proves_not_yet_active_local_allowlist_keeps_docs_baited

printf 'shield-lab trusted ingress not-yet-active local entry smoke checks passed\n'
