#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-suspicious-detection-recon-rate-limit-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-suspicious-detection-recon-rate-limit-smoke-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","observed_at":"2026-06-11T13:30:01Z","source":"policy_router","policy_state":"suspicious","kind":{"type":"policy_changed","from":"observe","to":"suspicious","reason":"multi-signal discovery recon aggregation promoted request to suspicious: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=1 distinct_surfaces=1 query_seen=true legacy_openapi_query_seen=false linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=2 repeated_discovery_score=0 query_score=1 legacy_openapi_query_score=0 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=2 recon_score=3 recon_threshold=3"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","observed_at":"2026-06-11T13:30:01Z","source":"proxy","policy_state":"suspicious","kind":{"type":"request_seen","method":"GET","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":35,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["3355446","445566"]},"discovery_recon_score":{"query_score":1,"detection_score":2,"total":3,"threshold":3},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","observed_at":"2026-06-11T13:30:01Z","source":"surface_controller","policy_state":"suspicious","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","exposure_id":"exp-1234","surface":"/docs"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","observed_at":"2026-06-11T13:30:01Z","source":"policy_router","policy_state":"suspicious","kind":{"type":"policy_decision","routing_decision":"eidolon_owned","reason":"surface controller served eidolon-owned response"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","observed_at":"2026-06-11T13:30:01Z","source":"proxy","policy_state":"suspicious","kind":{"type":"response_served","status":200,"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","persistence":{"pre_containment_persistence_class":"discovery_recon"},"observed_at":"2026-06-11T13:30:02Z","source":"policy_router","policy_state":"rate_limited","kind":{"type":"policy_changed","from":"suspicious","to":"rate_limited","reason":"suspicious discovery recon persistence moved session to rate limited: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=2 distinct_surfaces=1 query_seen=true legacy_openapi_query_seen=false linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=2 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=0 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=2 recon_score=5 recon_rate_limit_threshold=5"}}
{"schema_version":2,"id":"77777777-7777-7777-7777-777777777777","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","observed_at":"2026-06-11T13:30:02Z","source":"proxy","policy_state":"rate_limited","kind":{"type":"request_seen","method":"GET","path":"/docs","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":35,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["3355446","445566"]},"discovery_recon_score":{"repeated_discovery_score":2,"query_score":1,"detection_score":2,"total":5,"threshold":5},"routing_decision":"rate_limited"}}
{"schema_version":2,"id":"88888888-8888-8888-8888-888888888888","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","persistence":{"pre_containment_persistence_class":"discovery_recon"},"observed_at":"2026-06-11T13:30:02Z","source":"policy_router","policy_state":"rate_limited","kind":{"type":"rate_limit_applied","reason":"suspicious discovery recon persistence moved session to rate limited: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=2 distinct_surfaces=1 query_seen=true legacy_openapi_query_seen=false linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=2 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=0 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=2 recon_score=5 recon_rate_limit_threshold=5"}}
{"schema_version":2,"id":"99999999-9999-9999-9999-999999999999","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","observed_at":"2026-06-11T13:30:02Z","source":"proxy","policy_state":"rate_limited","kind":{"type":"response_served","status":429,"routing_decision":"rate_limited"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"request_received","fields":{"client_peer":"127.0.0.1:50500","method":"GET","target_form":"origin","path":"/docs","query_present":true,"http_version":"HTTP/1.1","body_len":0,"header_count":7,"safe_headers":[],"session_source":"generated","ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":35,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["3355446","445566"]},"discovery_surface_fanout":{"docs_seen":true,"openapi_seen":false,"distinct_surfaces":1},"discovery_request_count":1,"discovery_query_seen":true,"discovery_legacy_openapi_query_seen":false,"discovery_linked_bait_surface_seen":false,"discovery_linked_bait_surface_classes":0,"discovery_decoy_write_probe_seen":false,"discovery_decoy_write_probe_count":0,"discovery_decoy_write_probe_path_classes":0,"discovery_recon_score":{"query_score":1,"detection_score":2,"total":3,"threshold":3},"policy_state":"suspicious","intervention_mode":"enabled"},"observed_at_unix_ms":1781184601000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b"}
{"event":"surface_action_selected","fields":{"controller_surface_action":{"plan":"html","type":"rewritten_upstream"},"candidate_surface_action":{"status":200,"type":"eidolon_owned"},"policy_reason":"surface controller served eidolon-owned response","policy_routing_decision":"eidolon_owned","policy_state":"suspicious","surface_action":{"status":200,"type":"eidolon_owned"},"surface_requested_intervention":true,"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781184601001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b"}
{"event":"request_received","fields":{"client_peer":"127.0.0.1:50500","method":"GET","target_form":"origin","path":"/docs","query_present":false,"http_version":"HTTP/1.1","body_len":0,"header_count":7,"safe_headers":[],"session_source":"cookie","ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":35,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["3355446","445566"]},"discovery_surface_fanout":{"docs_seen":true,"openapi_seen":false,"distinct_surfaces":1},"discovery_request_count":2,"discovery_query_seen":true,"discovery_legacy_openapi_query_seen":false,"discovery_linked_bait_surface_seen":false,"discovery_linked_bait_surface_classes":0,"discovery_decoy_write_probe_seen":false,"discovery_decoy_write_probe_count":0,"discovery_decoy_write_probe_path_classes":0,"discovery_recon_score":{"repeated_discovery_score":2,"query_score":1,"detection_score":2,"total":5,"threshold":5},"policy_state":"rate_limited","intervention_mode":"enabled"},"observed_at_unix_ms":1781184602000,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b"}
{"event":"surface_action_selected","fields":{"controller_surface_action":{"type":"protected_upstream"},"candidate_surface_action":{"type":"protected_upstream"},"policy_reason":"suspicious policy observes only and forwards to the protected upstream","policy_routing_decision":"protected_upstream","policy_state":"rate_limited","surface_action":{"type":"rate_limited"},"surface_requested_intervention":false,"trusted_bait_soften_path_prefixes":["/docs","/openapi.json"],"trusted_ingress_softened_surface":false,"trusted_ingress_softening_reason":null},"observed_at_unix_ms":1781184602001,"run_kind":"eidolon_proxy_debug","schema_version":1,"session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b"}
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
actor_kind=""
vendor_score=""
vendor_score_kind=""
detection_ids=""
transport_auth=""

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

case "$request_count" in
  1)
    [[ "$method" == "GET" ]]
    [[ -n "$cookie_write" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/docs?topic=imports" ]]
    printf '# Netscape HTTP Cookie File\n' > "$cookie_write"
    printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n' > "$headers_file"
    cat > "$body_file" <<'HTML'
# Customer Import Notes

Use `X-Migration-Trace: mig_w5ac7f6_8d1c3e5add241c2b77c72180` with:

```http
POST /api/v2/import/reconcile
```
HTML
    ;;
  2)
    [[ "$method" == "GET" ]]
    [[ -n "$cookie_read" ]]
    [[ -f "$cookie_read" ]]
    [[ -n "$cookie_write" ]]
    [[ "$request_url" == "http://127.0.0.1:31080/docs" ]]
    printf 'HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\ncontent-type: text/plain\r\n\r\n' > "$headers_file"
    printf 'rate limited by eidolon\n' > "$body_file"
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
[[ "$session" == "b91b8d86-56ae-4631-b19f-b84b9954039b" ]]

cat <<'JSON'
{"contract_version":"2026-06-05.v1","observed_at":"2026-06-11T13:30:02Z","session_id":"b91b8d86-56ae-4631-b19f-b84b9954039b","request":{"method":"GET","path":"/docs"},"ingress_identity":{"source":"none","trust_tier":"none"},"ingress_signals":{"actor_kind":"agentic_browser","vendor_score":35,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["3355446","445566"]},"discovery_recon_score":{"repeated_discovery_score":2,"query_score":1,"detection_score":2,"total":5,"threshold":5},"policy":{"state":"rate_limited","routing_decision":"rate_limited","reason":"latest request routing decision","pre_containment_persistence_class":"discovery_recon"},"evidence":{"event_schema_version":2,"event_ids":["77777777-7777-7777-7777-777777777777","99999999-9999-9999-9999-999999999999"],"bundle_ref":"session:b91b8d86-56ae-4631-b19f-b84b9954039b"},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","rate_limited","pre_containment_persistence","discovery_recon"]}}
JSON
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/edge-export"
}

test_smoke_script_verifies_suspicious_detection_recon_rate_limit_and_export() {
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

  rg -q 'suspicious-detection-recon-rate-limit smoke ok:' <<<"$output"
  rg -q 'b91b8d86-56ae-4631-b19f-b84b9954039b' <<<"$output"
  rg -q 'detection_score=2' <<<"$output"
}

test_smoke_script_verifies_suspicious_detection_recon_rate_limit_and_export

printf 'shield-lab suspicious detection recon rate-limit smoke checks passed\n'
