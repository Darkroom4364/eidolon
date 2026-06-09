#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-suspicious-detection-aggregation-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-detection-aggregation-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"9b78852f-3266-45fc-9f22-b5d2d5607020","observed_at":"2026-06-09T21:00:01Z","source":"policy_router","policy_state":"suspicious","kind":{"type":"policy_changed","from":"observe","to":"suspicious","reason":"multi-signal discovery recon aggregation promoted request to suspicious: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=1 distinct_surfaces=1 query_seen=true detection_count=2 weak_signals=2"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"9b78852f-3266-45fc-9f22-b5d2d5607020","observed_at":"2026-06-09T21:00:01Z","source":"proxy","policy_state":"suspicious","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":35,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["3355446","445566"]},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"9b78852f-3266-45fc-9f22-b5d2d5607020","observed_at":"2026-06-09T21:00:01Z","source":"surface_controller","policy_state":"suspicious","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","exposure_id":"exp-1234","surface":"/docs"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"9b78852f-3266-45fc-9f22-b5d2d5607020","observed_at":"2026-06-09T21:00:01Z","source":"policy_router","policy_state":"suspicious","kind":{"type":"policy_decision","routing_decision":"eidolon_owned","reason":"surface controller served eidolon-owned response"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"9b78852f-3266-45fc-9f22-b5d2d5607020","observed_at":"2026-06-09T21:00:01Z","source":"proxy","policy_state":"suspicious","kind":{"type":"response_served","status":200,"routing_decision":"eidolon_owned"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"request_received","fields":{"client_peer":"127.0.0.1:50500","method":"GET","target_form":"origin","path":"/docs","query_present":true,"http_version":"HTTP/1.1","body_len":0,"header_count":7,"safe_headers":[],"session_source":"generated","ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":35,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["3355446","445566"]},"discovery_surface_fanout":{"docs_seen":true,"openapi_seen":false,"distinct_surfaces":1},"discovery_request_count":1,"discovery_query_seen":true,"policy_state":"suspicious","intervention_mode":"enabled"},"observed_at_unix_ms":1781038801000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"9b78852f-3266-45fc-9f22-b5d2d5607020"}
{"event":"surface_action_selected","fields":{"controller_surface_action":{"plan":"html","type":"rewritten_upstream"},"candidate_surface_action":{"status":200,"type":"eidolon_owned"},"policy_reason":"suspicious policy observes only and forwards to the protected upstream","policy_routing_decision":"protected_upstream","policy_state":"suspicious","surface_action":{"status":200,"type":"eidolon_owned"},"surface_requested_intervention":true,"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781038801001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"9b78852f-3266-45fc-9f22-b5d2d5607020"}
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
detection_ids=""
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
        X-Eidolon-Ingress-Detection-Ids:*)
          detection_ids="${2#X-Eidolon-Ingress-Detection-Ids: }"
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
[[ "$vendor_score" == "35" ]]
[[ "$vendor_score_kind" == "automation_likelihood_inverse" ]]
[[ "$detection_ids" == "3355446,445566" ]]
[[ "$transport_auth" == "secret-value" ]]
[[ "$request_url" == "http://127.0.0.1:31080/docs?topic=imports" ]]

printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n' > "$headers_file"
cat > "$body_file" <<'HTML'
# Customer Import Notes

Use `X-Migration-Trace: rel_2025_04_b7f2` with:

```http
POST /api/v2/import/reconcile
```
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
[[ "$session" == "9b78852f-3266-45fc-9f22-b5d2d5607020" ]]

cat <<'JSON'
{"contract_version":"2026-06-05.v1","observed_at":"2026-06-09T21:00:01Z","session_id":"9b78852f-3266-45fc-9f22-b5d2d5607020","request":{"method":"GET","path":"/docs?topic=<redacted>"},"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":35,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["3355446","445566"]},"policy":{"state":"suspicious","routing_decision":"eidolon_owned","reason":"surface controller served eidolon-owned response"},"evidence":{"event_schema_version":2,"event_ids":["22222222-2222-2222-2222-222222222222","55555555-5555-5555-5555-555555555555"],"bundle_ref":"session:9b78852f-3266-45fc-9f22-b5d2d5607020"},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","eidolon_owned"]}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_verifies_detection_aggregation_promotion_and_export() {
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

  rg -q 'suspicious-detection-aggregation smoke ok:' <<<"$output"
  rg -q '9b78852f-3266-45fc-9f22-b5d2d5607020' <<<"$output"
}

test_smoke_script_verifies_detection_aggregation_promotion_and_export

printf 'shield-lab suspicious detection aggregation smoke checks passed\n'
