#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPORT_SCRIPT="$SCRIPT_DIR/export-orbstack-evidence.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-export-test.XXXXXX"
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
  "-n shield-system get deploy eidolon-shield-proxy -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-proxy"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"args":["--owned-cluster-lab","--ingress-transport-auth-secret-file","/var/run/secrets/eidolon-trusted-ingress/transport-auth.txt","--bait-signing-secret-file","/var/run/secrets/eidolon-bait-signing/signing-secret.txt"]}]}}},"status":{"readyReplicas":1,"availableReplicas":1}}
JSON
    ;;
  "-n shield-system get pods -l app.kubernetes.io/name=eidolon-shield-proxy -o json")
    cat <<'JSON'
{"items":[{"metadata":{"name":"eidolon-shield-proxy-abc"},"status":{"containerStatuses":[{"imageID":"docker://sha256:proxy"}]}}]}
JSON
    ;;
  "-n shield-targets get deploy eidolon-owned-demo-target -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-owned-demo-target"},"spec":{"replicas":2},"status":{"readyReplicas":2,"availableReplicas":2}}
JSON
    ;;
  "-n shield-targets get pods -l app.kubernetes.io/name=eidolon-owned-demo-target -o json")
    cat <<'JSON'
{"items":[{"metadata":{"name":"eidolon-owned-demo-target-a"},"status":{"containerStatuses":[{"imageID":"docker://sha256:target"}]}}]}
JSON
    ;;
  "-n shield-system get svc eidolon-shield-edge -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-edge"},"spec":{"type":"NodePort","ports":[{"name":"http","port":80,"nodePort":31080}]}}
JSON
    ;;
  "-n shield-targets get svc eidolon-owned-demo-target-edge -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-owned-demo-target-edge"},"spec":{"type":"NodePort","ports":[{"name":"http","port":80,"nodePort":31081}]}}
JSON
    ;;
  "-n shield-system get pvc eidolon-shield-proxy-state -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-proxy-state"},"spec":{"storageClassName":"local-path","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}},"status":{"phase":"Bound","capacity":{"storage":"1Gi"},"accessModes":["ReadWriteOnce"]}}
JSON
    ;;
  "-n shield-system get configmap eidolon-shield-bait-profile -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-bait-profile"},"data":{"bait-profile.json":"{\"profile_id\":\"orbstack_default_m3_catalog\",\"baits\":[{\"id\":\"rel_2025_04_b7f2\",\"surface\":\"/docs/legacy-import\",\"surface_kind\":\"docs\",\"expected_action\":{\"header_name\":\"X-Migration-Trace\",\"header_value_mint\":{\"kind\":\"session_hmac_sha256_v1\",\"prefix\":\"mig\"}}},{\"id\":\"openapi_reconcile_trace\",\"surface\":\"/openapi.json\",\"surface_kind\":\"open_api\",\"expected_action\":{\"header_name\":\"X-OpenAPI-Trace\",\"header_value_mint\":{\"kind\":\"session_hmac_sha256_v1\",\"prefix\":\"oapi\"}}},{\"id\":\"fake_service_token\",\"surface\":\"/docs/service-token\",\"surface_kind\":\"token\",\"expected_action\":{\"header_name\":\"X-Api-Key\",\"header_value_mint\":{\"kind\":\"session_hmac_sha256_v1\",\"prefix\":\"svc\"}}}]}"}}
JSON
    ;;
  "-n shield-system get configmap eidolon-shield-ingress-trust-config -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-ingress-trust-config"},"data":{"ingress-trust.json":"{\"schema_version\":1,\"entries\":[{\"label\":\"docs-crawler\",\"source\":\"local_allowlist\",\"trust_tier\":\"allowlisted\",\"expires_at\":\"2999-06-05T12:00:00Z\",\"methods\":[\"GET\"],\"path_prefixes\":[\"/docs\",\"/openapi.json\"],\"bait_soften_path_prefixes\":[\"/docs\"],\"user_agent_substrings\":[\"eidolon-docs-crawler\"],\"hosts\":[\"127.0.0.1\",\"localhost\"],\"source_cidrs\":[\"192.168.194.1/32\"],\"required_headers\":[{\"name\":\"X-Eidolon-Trusted-Actor\",\"value\":\"docs-crawler\"}]}]}"}}
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
if [[ "$*" == *"%{http_code}"* ]]; then
  printf '200'
  exit 0
fi
echo "unexpected curl invocation: $*" >&2
exit 1
SH

  cat > "$dir/export-edge-decisions.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

output=""
session=""
min_coverage=""
latest_mint_outcome=""
local_trust_rejection_label=""
local_trust_rejection_reason=""
local_trust_rejection_history_label=""
local_trust_rejection_history_reason=""
trusted_soften_label=""
trusted_soften_path_softened=""
trusted_soften_history_label=""
trusted_soften_history_path_softened=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    --session)
      session="$2"
      shift 2
      ;;
    --min-polymorphic-coverage)
      min_coverage="$2"
      shift 2
      ;;
    --latest-mint-outcome)
      latest_mint_outcome="$2"
      shift 2
      ;;
    --local-trust-rejection-label)
      local_trust_rejection_label="$2"
      shift 2
      ;;
    --local-trust-rejection-reason)
      local_trust_rejection_reason="$2"
      shift 2
      ;;
    --local-trust-rejection-history-label)
      local_trust_rejection_history_label="$2"
      shift 2
      ;;
    --local-trust-rejection-history-reason)
      local_trust_rejection_history_reason="$2"
      shift 2
      ;;
    --trusted-soften-label)
      trusted_soften_label="$2"
      shift 2
      ;;
    --trusted-soften-path-softened)
      trusted_soften_path_softened="$2"
      shift 2
      ;;
    --trusted-soften-history-label)
      trusted_soften_history_label="$2"
      shift 2
      ;;
    --trusted-soften-history-path-softened)
      trusted_soften_history_path_softened="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

selected='{"contract_version":"2026-06-12.v1","observed_at":"2026-06-04T00:00:00Z","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","request":{"method":"GET","path":"/openapi.json?token=secret"},"ingress_identity":{"source":"local_allowlist","trust_tier":"allowlisted","label":"docs-crawler"},"trusted_ingress_soften_match":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"request_path_softened":false},"ingress_signals":{"actor_kind":"assistant","vendor_score":42,"vendor_score_kind":"automation_likelihood_inverse","detection_ids":["det-123"]},"discovery_recon_score":{"query_score":1,"detection_score":2,"total":3,"threshold":3},"policy":{"state":"suspicious","routing_decision":"protected_upstream","reason":"aggregated recon signals moved session to suspicious"},"evidence":{"event_schema_version":2,"event_ids":["11111111-1111-1111-1111-111111111111"],"bundle_ref":"session:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","trusted_ingress_soften_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"saw_request_path_softened":true,"saw_request_path_unsoftened":true}],"bait_header_value_mints":[{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"latest_bait_header_value_mint":{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc","status":"matched_session_value"}},"edge_recommendation":{"action":"observe","reason_codes":["suspicious_session"]},"deployment_context":{"bait_profile_id":"orbstack_default_m3_catalog","polymorphic_baits":[{"bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","surface_kind":"docs","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},{"bait_id":"openapi_reconcile_trace","surface":"/openapi.json","surface_kind":"open_api","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"},{"bait_id":"fake_service_token","surface":"/docs/service-token","surface_kind":"token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"trusted_ingress_soften_scopes":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","expires_at":"2999-06-05T12:00:00Z","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"]}]}}'
selected_array="[$selected]"
rejected='{"contract_version":"2026-06-12.v1","observed_at":"2026-06-04T00:00:01Z","session_id":"dddddddd-dddd-dddd-dddd-dddddddddddd","request":{"method":"GET","path":"/docs?token=secret"},"ingress_identity":{"source":"none","trust_tier":"none"},"local_ingress_trust_scope_rejection":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","reason":"host_mismatch","expires_at":"2999-06-05T12:00:00Z","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["api.internal.example"],"source_cidrs":["192.168.194.1/32"]},"policy":{"state":"observe","routing_decision":"protected_upstream","reason":"request remained observable after trusted ingress scope rejection"},"evidence":{"event_schema_version":2,"event_ids":["44444444-4444-4444-4444-444444444444"],"bundle_ref":"session:dddddddd-dddd-dddd-dddd-dddddddddddd","trusted_ingress_soften_histories":[]},"edge_recommendation":{"action":"observe","reason_codes":["trusted_ingress_scope_rejection"]},"deployment_context":{"bait_profile_id":"orbstack_default_m3_catalog","polymorphic_baits":[{"bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","surface_kind":"docs","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},{"bait_id":"openapi_reconcile_trace","surface":"/openapi.json","surface_kind":"open_api","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"},{"bait_id":"fake_service_token","surface":"/docs/service-token","surface_kind":"token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"trusted_ingress_soften_scopes":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","expires_at":"2999-06-05T12:00:00Z","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"]}]}}'
rejected_array="[$rejected]"
all_sessions='[{"contract_version":"2026-06-12.v1","observed_at":"2026-06-04T00:00:02Z","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","request":{"method":"POST","path":"/api/v2/import/reconcile?token=secret"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"controlled_reality","routing_decision":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"},"evidence":{"event_schema_version":2,"event_ids":["33333333-3333-3333-3333-333333333333"],"bundle_ref":"session:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","local_ingress_trust_scope_rejection_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["docs.invalid.eidolon"],"source_cidrs":["192.168.194.1/32"],"reasons":["host_mismatch"]}],"trusted_ingress_soften_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"saw_request_path_softened":true,"saw_request_path_unsoftened":true}]},"edge_recommendation":{"action":"preserve_eidolon_routing","reason_codes":["eidolon_runtime_enforcement","controlled_reality"]},"deployment_context":{"bait_profile_id":"orbstack_default_m3_catalog","polymorphic_baits":[{"bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","surface_kind":"docs","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},{"bait_id":"openapi_reconcile_trace","surface":"/openapi.json","surface_kind":"open_api","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"},{"bait_id":"fake_service_token","surface":"/docs/service-token","surface_kind":"token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"trusted_ingress_soften_scopes":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","expires_at":"2999-06-05T12:00:00Z","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"]}]}},'"$rejected"','"$selected"']'

if [[ -n "$session" ]]; then
  case "$session" in
    aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa)
      rendered="$selected"
      ;;
    dddddddd-dddd-dddd-dddd-dddddddddddd)
      rendered="$rejected"
      ;;
    *)
      echo "unexpected session: $session" >&2
      exit 1
      ;;
  esac
else
  rendered="$all_sessions"
fi

if [[ -n "$min_coverage" ]]; then
  case "$min_coverage" in
    1)
      rendered="$selected_array"
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$latest_mint_outcome" ]]; then
  case "$latest_mint_outcome" in
    matched_session_value)
      rendered="$selected_array"
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$local_trust_rejection_label" ]]; then
  case "$local_trust_rejection_label" in
    docs-crawler)
      rendered="$rejected_array"
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$local_trust_rejection_reason" ]]; then
  case "$local_trust_rejection_reason" in
    host_mismatch)
      rendered="$rejected_array"
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$local_trust_rejection_history_label" ]]; then
  case "$local_trust_rejection_history_label" in
    docs-crawler)
      rendered='[{"contract_version":"2026-06-12.v1","observed_at":"2026-06-04T00:00:02Z","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","request":{"method":"POST","path":"/api/v2/import/reconcile?token=secret"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"controlled_reality","routing_decision":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"},"evidence":{"event_schema_version":2,"event_ids":["33333333-3333-3333-3333-333333333333"],"bundle_ref":"session:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","local_ingress_trust_scope_rejection_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["docs.invalid.eidolon"],"source_cidrs":["192.168.194.1/32"],"reasons":["host_mismatch"]}],"trusted_ingress_soften_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"saw_request_path_softened":true,"saw_request_path_unsoftened":true}]},"edge_recommendation":{"action":"preserve_eidolon_routing","reason_codes":["eidolon_runtime_enforcement","controlled_reality"]},"deployment_context":{"bait_profile_id":"orbstack_default_m3_catalog","polymorphic_baits":[{"bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","surface_kind":"docs","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},{"bait_id":"openapi_reconcile_trace","surface":"/openapi.json","surface_kind":"open_api","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"},{"bait_id":"fake_service_token","surface":"/docs/service-token","surface_kind":"token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"trusted_ingress_soften_scopes":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","expires_at":"2999-06-05T12:00:00Z","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"]}]}}]'
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$local_trust_rejection_history_reason" ]]; then
  case "$local_trust_rejection_history_reason" in
    host_mismatch)
      rendered='[{"contract_version":"2026-06-12.v1","observed_at":"2026-06-04T00:00:02Z","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","request":{"method":"POST","path":"/api/v2/import/reconcile?token=secret"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"controlled_reality","routing_decision":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"},"evidence":{"event_schema_version":2,"event_ids":["33333333-3333-3333-3333-333333333333"],"bundle_ref":"session:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","local_ingress_trust_scope_rejection_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["docs.invalid.eidolon"],"source_cidrs":["192.168.194.1/32"],"reasons":["host_mismatch"]}],"trusted_ingress_soften_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"saw_request_path_softened":true,"saw_request_path_unsoftened":true}]},"edge_recommendation":{"action":"preserve_eidolon_routing","reason_codes":["eidolon_runtime_enforcement","controlled_reality"]},"deployment_context":{"bait_profile_id":"orbstack_default_m3_catalog","polymorphic_baits":[{"bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","surface_kind":"docs","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},{"bait_id":"openapi_reconcile_trace","surface":"/openapi.json","surface_kind":"open_api","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"},{"bait_id":"fake_service_token","surface":"/docs/service-token","surface_kind":"token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"trusted_ingress_soften_scopes":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","expires_at":"2999-06-05T12:00:00Z","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"]}]}}]'
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$trusted_soften_label" ]]; then
  case "$trusted_soften_label" in
    docs-crawler)
      rendered="$selected_array"
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$trusted_soften_path_softened" ]]; then
  case "$trusted_soften_path_softened" in
    false)
      rendered="$selected_array"
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$trusted_soften_history_label" ]]; then
  case "$trusted_soften_history_label" in
    docs-crawler)
      rendered="$selected_array"
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$trusted_soften_history_path_softened" ]]; then
  case "$trusted_soften_history_path_softened" in
    false)
      rendered='[{"contract_version":"2026-06-12.v1","observed_at":"2026-06-04T00:00:02Z","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","request":{"method":"POST","path":"/api/v2/import/reconcile?token=secret"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"controlled_reality","routing_decision":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"},"evidence":{"event_schema_version":2,"event_ids":["33333333-3333-3333-3333-333333333333"],"bundle_ref":"session:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","trusted_ingress_soften_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"],"saw_request_path_softened":true,"saw_request_path_unsoftened":true}]},"edge_recommendation":{"action":"preserve_eidolon_routing","reason_codes":["eidolon_runtime_enforcement","controlled_reality"]},"deployment_context":{"bait_profile_id":"orbstack_default_m3_catalog","polymorphic_baits":[{"bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","surface_kind":"docs","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},{"bait_id":"openapi_reconcile_trace","surface":"/openapi.json","surface_kind":"open_api","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"},{"bait_id":"fake_service_token","surface":"/docs/service-token","surface_kind":"token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"trusted_ingress_soften_scopes":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","expires_at":"2999-06-05T12:00:00Z","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"user_agent_substrings":["eidolon-docs-crawler"],"hosts":["127.0.0.1","localhost"],"source_cidrs":["192.168.194.1/32"]}]}}]'
      ;;
    *)
      rendered='[]'
      ;;
  esac
fi

if [[ -n "$output" ]]; then
  printf '%s\n' "$rendered" > "$output"
else
  printf '%s\n' "$rendered"
fi
SH

  chmod +x "$dir/kubectl" "$dir/curl" "$dir/export-edge-decisions.sh"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-04T00:00:00Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/openapi.json?token=secret","safe_headers":[],"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-04T00:00:01Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"openapi_reconcile_trace","exposure_id":"exp-1234","surface":"/openapi.json?eidolon_surface=secret"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"proxy_started","fields":{"listen_addr":"0.0.0.0:9102","upstream":"http://eidolon-owned-demo-target.shield-targets.svc.cluster.local:9101"},"observed_at_unix_ms":1780521426739,"run_kind":"eidolon_proxy_debug","session_id":null}
{"event":"request_received","fields":{"client_peer":"192.168.194.1:48090","path":"/api/v2/import/reconcile?token=secret"},"observed_at_unix_ms":1780521426740,"run_kind":"eidolon_proxy_debug","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
JSONL

  cat > "$dir/policy-state.json" <<'JSON'
{
  "schema_version": 1,
  "sessions": [
    {
      "session_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "policy_state": "controlled_reality",
      "controlled_reality_depth": 1
    }
  ]
}
JSON
}

test_export_bundle_redacts_sensitive_values() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    "$EXPORT_SCRIPT" \
    --session aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
    "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]]
  [[ -f "$bundle_dir/cluster-status.json" ]]
  [[ -f "$bundle_dir/edge-session-index.md" ]]
  [[ -f "$bundle_dir/events.redacted.jsonl" ]]
  [[ -f "$bundle_dir/debug.redacted.jsonl" ]]
  [[ -f "$bundle_dir/policy-state.redacted.json" ]]
  [[ -f "$bundle_dir/selected-session-edge-summary.md" ]]
  [[ -f "$bundle_dir/SHA256SUMS" ]]

  ! rg -q 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa|11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|secret|192.168.194.1:48090|http://eidolon-owned-demo-target' "$bundle_dir"

  jq -e '
    .edge.url == "http://127.0.0.1:31080"
    and .proxy_state.status == "Bound"
    and .bait_profile.profile_id == "orbstack_default_m3_catalog"
    and (.bait_profile.polymorphic_baits | length) == 3
    and (.ingress_trust.trusted_soften_scopes | length) == 1
    and .ingress_trust.trusted_soften_scopes[0].label == "docs-crawler"
    and .ingress_trust.trusted_soften_scopes[0].expires_at == "2999-06-05T12:00:00Z"
    and .ingress_trust.trusted_soften_scopes[0].user_agent_substrings == ["eidolon-docs-crawler"]
    and .ingress_trust.trusted_soften_scopes[0].hosts == ["127.0.0.1", "localhost"]
    and .ingress_trust.trusted_soften_scopes[0].source_cidrs == ["192.168.194.1/32"]
  ' "$bundle_dir/cluster-status.json" >/dev/null

  jq -e '
    .sessions == [
      {
        session_id: "<redacted>",
        policy_state: "controlled_reality",
        controlled_reality_depth: 1
      }
    ]
  ' "$bundle_dir/policy-state.redacted.json" >/dev/null

  rg -q 'events.redacted.jsonl' "$bundle_dir/SHA256SUMS"
  rg -q 'debug.redacted.jsonl' "$bundle_dir/SHA256SUMS"
  rg -q 'policy-state.redacted.json' "$bundle_dir/SHA256SUMS"
  rg -q 'Redacted event log lines: `2`' "$bundle_dir/README.md"
  rg -q 'Direct target URL: `http://127.0.0.1:31081` \(HTTP `200`\)' "$bundle_dir/README.md"
  rg -q 'Bait profile: `orbstack_default_m3_catalog`' "$bundle_dir/README.md"
  rg -q 'Active polymorphic bait surfaces: `3`' "$bundle_dir/README.md"
  rg -q 'Trusted ingress soften scopes: `1`' "$bundle_dir/README.md"
  rg -q 'edge-session-index.md' "$bundle_dir/README.md"
  rg -q 'selected-session-edge-summary.md' "$bundle_dir/README.md"
  rg -q '`/docs/legacy-import` -> `X-Migration-Trace` \(`mig`, `session_hmac_sha256_v1`, bait id `rel_2025_04_b7f2`\)' "$bundle_dir/README.md"
  rg -q '`/openapi.json` -> `X-OpenAPI-Trace` \(`oapi`, `session_hmac_sha256_v1`, bait id `openapi_reconcile_trace`\)' "$bundle_dir/README.md"
  rg -q '`/docs/service-token` -> `X-Api-Key` \(`svc`, `session_hmac_sha256_v1`, bait id `fake_service_token`\)' "$bundle_dir/README.md"
  rg -q '## Active Trusted Ingress Softening' "$bundle_dir/README.md"
  rg -q '`docs-crawler`: soften `/docs`; match `/docs`, `/openapi.json`; ua `eidolon-docs-crawler`; host `127.0.0.1`, `localhost`; source `192.168.194.1/32`; expires `2999-06-05T12:00:00Z`; identity `local_allowlist` / `allowlisted`' "$bundle_dir/README.md"
  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `3`' "$bundle_dir/edge-session-index.md"
  rg -q 'Local Trust Rejection' "$bundle_dir/edge-session-index.md"
  rg -q 'Trusted Soften Context' "$bundle_dir/edge-session-index.md"
  rg -q 'Minted Coverage' "$bundle_dir/edge-session-index.md"
  rg -q 'Latest Mint Outcome' "$bundle_dir/edge-session-index.md"
  rg -q '<redacted-1>' "$bundle_dir/edge-session-index.md"
  rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
  rg -q '<redacted-3>' "$bundle_dir/edge-session-index.md"
  rg -q '`controlled_reality`' "$bundle_dir/edge-session-index.md"
  rg -q '`suspicious`' "$bundle_dir/edge-session-index.md"
  rg -q '`observe`' "$bundle_dir/edge-session-index.md"
  rg -q 'X-Api-Key' "$bundle_dir/edge-session-index.md"
  rg -q '`matched_session_value` via `X-Api-Key`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \(`host_mismatch`\)' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \[`host_mismatch`; ua `eidolon-docs-crawler`; host `docs.invalid.eidolon`, source `192.168.194.1/32`\]' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \(soften `/docs`; ua `eidolon-docs-crawler`; host `127.0.0.1`, `localhost`; path softened `false`\)' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \[softened `true`, unsoftened `true`, ua `eidolon-docs-crawler`, host `127.0.0.1`, `localhost`, source `192.168.194.1/32`\]' "$bundle_dir/edge-session-index.md"
  rg -q '`1/3`' "$bundle_dir/edge-session-index.md"
  rg -q '`0/3`' "$bundle_dir/edge-session-index.md"
  rg -q '^# Eidolon Edge Session Summary$' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Session: `<redacted>`' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Request: `GET /openapi.json\?<redacted>`' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'det-123' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'fake_service_token' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Latest minted outcome: `matched_session_value` via `X-Api-Key` \[prefix `svc`, bait `fake_service_token`\]' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Coverage: `1/3` active session-minted baits observed' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Observed active minted baits: `fake_service_token`' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Remaining active minted baits: `rel_2025_04_b7f2`, `openapi_reconcile_trace`' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Trusted soften match: `docs-crawler` \(`local_allowlist` / `allowlisted`\)' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Trusted soften scope: soften `/docs`; match `/docs`, `/openapi.json`; ua `eidolon-docs-crawler`; host `127.0.0.1`, `localhost`; source `192.168.194.1/32`; request path softened `false`' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Trusted soften history: `docs-crawler` \[softened `true`, unsoftened `true`, ua `eidolon-docs-crawler`, host `127.0.0.1`, `localhost`, source `192.168.194.1/32`\]' "$bundle_dir/selected-session-edge-summary.md"
  rg -q '/docs/legacy-import' "$bundle_dir/selected-session-edge-summary.md"
  rg -q '/docs/service-token' "$bundle_dir/selected-session-edge-summary.md"
  rg -q '## Active Trusted Ingress Softening' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Scope `docs-crawler`: soften `/docs`; match `/docs`, `/openapi.json`; ua `eidolon-docs-crawler`; host `127.0.0.1`, `localhost`; source `192.168.194.1/32`; expires `2999-06-05T12:00:00Z`; identity `local_allowlist` / `allowlisted`' "$bundle_dir/selected-session-edge-summary.md"
}

test_export_bundle_renders_selected_session_local_trust_rejection() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    "$EXPORT_SCRIPT" \
    --session dddddddd-dddd-dddd-dddd-dddddddddddd \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Summary$' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Local trust scope rejection: `docs-crawler` \(`host_mismatch`\)' "$bundle_dir/selected-session-edge-summary.md"
  rg -q 'Rejected local trust scope: soften `/docs`; match `/docs`, `/openapi.json`; ua `eidolon-docs-crawler`; host `api.internal.example`; source `192.168.194.1/32`; expires `2999-06-05T12:00:00Z`' "$bundle_dir/selected-session-edge-summary.md"
}

test_export_refuses_non_empty_bundle_dir() {
  local temp_dir
  local state_dir
  local bundle_dir
  local output
  local status=0
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir" "$bundle_dir"
  printf 'existing\n' > "$bundle_dir/existing.txt"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      "$EXPORT_SCRIPT" "$bundle_dir" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'bundle directory must be empty' <<<"$output"
}

test_export_bundle_filters_edge_index_by_min_polymorphic_coverage() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE=1 \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '<redacted-1>' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
  rg -q '`matched_session_value` via `X-Api-Key`' "$bundle_dir/edge-session-index.md"
  rg -q '`1/3`' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_latest_mint_outcome() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_LATEST_MINT_OUTCOME=matched_session_value \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '<redacted-1>' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
  rg -q 'Latest Mint Outcome' "$bundle_dir/edge-session-index.md"
  rg -q '`matched_session_value` via `X-Api-Key`' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_local_trust_rejection_label() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_LABEL=docs-crawler \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \(`host_mismatch`\)' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_local_trust_rejection_reason() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON=host_mismatch \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \(`host_mismatch`\)' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_local_trust_rejection_history_label() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_LABEL=docs-crawler \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \[`host_mismatch`; ua `eidolon-docs-crawler`; host `docs.invalid.eidolon`, source `192.168.194.1/32`\]' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_local_trust_rejection_history_reason() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON=host_mismatch \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \[`host_mismatch`; ua `eidolon-docs-crawler`; host `docs.invalid.eidolon`, source `192.168.194.1/32`\]' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_trusted_soften_label() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_LABEL=docs-crawler \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \(soften `/docs`; ua `eidolon-docs-crawler`; host `127.0.0.1`, `localhost`; path softened `false`\)' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_trusted_soften_path_softened() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED=false \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \(soften `/docs`; ua `eidolon-docs-crawler`; host `127.0.0.1`, `localhost`; path softened `false`\)' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_trusted_soften_history_label() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_LABEL=docs-crawler \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \(soften `/docs`; ua `eidolon-docs-crawler`; host `127.0.0.1`, `localhost`; path softened `false`\)' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_filters_edge_index_by_trusted_soften_history_path_softened() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT="$temp_dir/export-edge-decisions.sh" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED=false \
    "$EXPORT_SCRIPT" \
    "$bundle_dir" >/dev/null

  rg -q '^# Eidolon Edge Session Index$' "$bundle_dir/edge-session-index.md"
  rg -q 'Exported sessions: `1`' "$bundle_dir/edge-session-index.md"
  rg -q '`docs-crawler` \[softened `true`, unsoftened `true`, ua `eidolon-docs-crawler`, host `127.0.0.1`, `localhost`, source `192.168.194.1/32`\]' "$bundle_dir/edge-session-index.md"
  ! rg -q '<redacted-2>' "$bundle_dir/edge-session-index.md"
}

test_export_bundle_redacts_sensitive_values
test_export_bundle_renders_selected_session_local_trust_rejection
test_export_refuses_non_empty_bundle_dir
test_export_bundle_filters_edge_index_by_min_polymorphic_coverage
test_export_bundle_filters_edge_index_by_latest_mint_outcome
test_export_bundle_filters_edge_index_by_local_trust_rejection_label
test_export_bundle_filters_edge_index_by_local_trust_rejection_reason
test_export_bundle_filters_edge_index_by_local_trust_rejection_history_label
test_export_bundle_filters_edge_index_by_local_trust_rejection_history_reason
test_export_bundle_filters_edge_index_by_trusted_soften_label
test_export_bundle_filters_edge_index_by_trusted_soften_path_softened
test_export_bundle_filters_edge_index_by_trusted_soften_history_label
test_export_bundle_filters_edge_index_by_trusted_soften_history_path_softened

printf 'shield-lab export checks passed\n'
