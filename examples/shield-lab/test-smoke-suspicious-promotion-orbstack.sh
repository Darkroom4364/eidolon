#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-suspicious-promotion-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-promotion-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"8c1c53ad-d352-4db6-b812-a93cc7950761","observed_at":"2026-06-07T14:54:37.546301637Z","source":"policy_router","policy_state":"suspicious","kind":{"type":"policy_changed","from":"observe","to":"suspicious","reason":"authenticated ingress advisory signals promoted discovery request to suspicious: path=/docs actor_kind=agentic_browser vendor_score=12 kind=automation_likelihood_inverse"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"8c1c53ad-d352-4db6-b812-a93cc7950761","observed_at":"2026-06-07T14:54:37.546362804Z","source":"proxy","policy_state":"suspicious","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":12,"vendor_score_kind":"automation_likelihood_inverse"},"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"8c1c53ad-d352-4db6-b812-a93cc7950761","observed_at":"2026-06-07T14:54:37.547781103Z","source":"policy_router","policy_state":"suspicious","kind":{"type":"policy_decision","routing_decision":"rewritten_upstream","reason":"surface controller rewrote upstream response"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"8c1c53ad-d352-4db6-b812-a93cc7950761","observed_at":"2026-06-07T14:54:37.547788353Z","source":"proxy","policy_state":"suspicious","kind":{"type":"response_served","status":200,"routing_decision":"rewritten_upstream"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"surface_action_selected","fields":{"candidate_surface_action":{"plan":"html","type":"rewritten_upstream"},"policy_reason":"suspicious policy observes only and forwards to the protected upstream","policy_routing_decision":"protected_upstream","policy_state":"suspicious","surface_action":{"plan":"html","type":"rewritten_upstream"},"surface_requested_intervention":true,"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1780844077546,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"8c1c53ad-d352-4db6-b812-a93cc7950761"}
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
{"data":{"transport-auth.txt":"c2VjcmV0LXZhbHVl"}}
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
actor_kind=""
vendor_score=""
vendor_score_kind=""
transport_auth=""
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
        X-Eidolon-Ingress-Actor-Kind:*)
          actor_kind="${2#X-Eidolon-Ingress-Actor-Kind: }"
          ;;
        X-Eidolon-Ingress-Vendor-Score:*)
          vendor_score="${2#X-Eidolon-Ingress-Vendor-Score: }"
          ;;
        X-Eidolon-Ingress-Vendor-Score-Kind:*)
          vendor_score_kind="${2#X-Eidolon-Ingress-Vendor-Score-Kind: }"
          ;;
        X-Eidolon-Ingress-Transport-Auth:*)
          transport_auth="${2#X-Eidolon-Ingress-Transport-Auth: }"
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

[[ "$actor_kind" == "agentic_browser" ]]
[[ "$vendor_score" == "12" ]]
[[ "$vendor_score_kind" == "automation_likelihood_inverse" ]]
[[ "$transport_auth" == "secret-value" ]]
[[ "$request_url" == "http://127.0.0.1:31080/docs?topic=imports" ]]

printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n' > "$headers_file"
cat > "$body_file" <<'HTML'
<!doctype html>
<html><body><main><a href="/docs/legacy-import">legacy import</a></main></body></html>
HTML
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
[[ "$session" == "8c1c53ad-d352-4db6-b812-a93cc7950761" ]]

cat <<'JSON'
{"contract_version":"2026-06-05.v1","observed_at":"2026-06-07T14:54:37.546362804Z","session_id":"8c1c53ad-d352-4db6-b812-a93cc7950761","request":{"method":"GET","path":"/docs?topic=<redacted>"},"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":12,"vendor_score_kind":"automation_likelihood_inverse"},"policy":{"state":"suspicious","routing_decision":"rewritten_upstream","reason":"latest request routing decision"},"evidence":{"event_schema_version":2,"event_ids":["22222222-2222-2222-2222-222222222222","44444444-4444-4444-4444-444444444444"],"bundle_ref":"session:8c1c53ad-d352-4db6-b812-a93cc7950761"},"edge_recommendation":{"action":"observe","reason_codes":["suspicious_session"]}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_verifies_suspicious_promotion_and_export() {
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

  rg -q 'suspicious-promotion smoke ok:' <<<"$output"
  rg -q '8c1c53ad-d352-4db6-b812-a93cc7950761' <<<"$output"
}

test_smoke_script_verifies_suspicious_promotion_and_export

printf 'shield-lab suspicious promotion smoke checks passed\n'
