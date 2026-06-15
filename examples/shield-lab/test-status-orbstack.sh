#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
STATUS_SCRIPT="$SCRIPT_DIR/status-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-status-test.XXXXXX"
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
{"items":[
  {"metadata":{"name":"eidolon-owned-demo-target-a"},"status":{"containerStatuses":[{"imageID":"docker://sha256:target-a"}]}},
  {"metadata":{"name":"eidolon-owned-demo-target-b"},"status":{"containerStatuses":[{"imageID":"docker://sha256:target-b"}]}}
]}
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

  chmod +x "$dir/kubectl" "$dir/curl"
}

test_json_status_reports_edge_and_pvc() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .context == "orbstack"
      and .edge.url == "http://127.0.0.1:31080"
      and .edge.http_status == 200
      and .edge.reachable == true
      and .direct_target_edge.url == "http://127.0.0.1:31081"
      and .direct_target_edge.http_status == 200
      and .direct_target_edge.reachable == true
      and .proxy.ready_replicas == 1
      and .proxy.trusted_ingress_transport_auth_enabled == true
      and .proxy.bait_signing_enabled == true
      and .target.ready_replicas == 2
      and .proxy_state.status == "Bound"
      and .proxy_state.storage_class == "local-path"
      and .bait_profile.profile_id == "orbstack_default_m3_catalog"
      and (.bait_profile.polymorphic_baits | length) == 3
      and .bait_profile.polymorphic_baits[0].bait_id == "rel_2025_04_b7f2"
      and .bait_profile.polymorphic_baits[0].prefix == "mig"
      and .bait_profile.polymorphic_baits[1].bait_id == "openapi_reconcile_trace"
      and .bait_profile.polymorphic_baits[1].prefix == "oapi"
      and .bait_profile.polymorphic_baits[2].bait_id == "fake_service_token"
      and .bait_profile.polymorphic_baits[2].prefix == "svc"
      and .ingress_trust.configmap_name == "eidolon-shield-ingress-trust-config"
      and (.ingress_trust.trusted_soften_scopes | length) == 1
      and .ingress_trust.trusted_soften_scopes[0].label == "docs-crawler"
      and .ingress_trust.trusted_soften_scopes[0].source == "local_allowlist"
      and .ingress_trust.trusted_soften_scopes[0].trust_tier == "allowlisted"
      and .ingress_trust.trusted_soften_scopes[0].expires_at == "2999-06-05T12:00:00Z"
      and .ingress_trust.trusted_soften_scopes[0].path_prefixes == ["/docs", "/openapi.json"]
      and .ingress_trust.trusted_soften_scopes[0].bait_soften_path_prefixes == ["/docs"]
      and .ingress_trust.trusted_soften_scopes[0].user_agent_substrings == ["eidolon-docs-crawler"]
      and .ingress_trust.trusted_soften_scopes[0].hosts == ["127.0.0.1", "localhost"]
      and .ingress_trust.trusted_soften_scopes[0].source_cidrs == ["192.168.194.1/32"]
      and .ingress_trust.trusted_soften_scopes[0].required_header_names == ["X-Eidolon-Trusted-Actor"]
    ' >/dev/null
}

test_human_status_mentions_running_components() {
  local temp_dir
  local output
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      "$STATUS_SCRIPT"
  )"

  rg -q '^OrbStack Shield lab status$' <<<"$output"
  rg -q 'edge: http://127.0.0.1:31080 \(HTTP 200, type=NodePort\)' <<<"$output"
  rg -q 'direct-target: http://127.0.0.1:31081 \(HTTP 200, type=NodePort\)' <<<"$output"
  rg -q 'proxy: 1/1 ready' <<<"$output"
  rg -q 'trusted-ingress: transport-auth enabled' <<<"$output"
  rg -q 'trusted-soften-scopes: docs-crawler -> /docs \(match /docs, /openapi.json; ua eidolon-docs-crawler; host 127.0.0.1, localhost; source 192.168.194.1/32; headers X-Eidolon-Trusted-Actor; expires 2999-06-05T12:00:00Z\)' <<<"$output"
  rg -q 'bait-signing: enabled' <<<"$output"
  rg -q 'polymorphic-baits: /docs/legacy-import -> X-Migration-Trace \[mig\], /openapi.json -> X-OpenAPI-Trace \[oapi\], /docs/service-token -> X-Api-Key \[svc\]' <<<"$output"
  rg -q 'target: 2/2 ready' <<<"$output"
  rg -q 'proxy-state: Bound 1Gi \(local-path\)' <<<"$output"
}

test_json_status_reports_unreachable_edge_without_failing() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  cat > "$temp_dir/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exit 7
SH
  chmod +x "$temp_dir/curl"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .edge.url == "http://127.0.0.1:31080"
      and .edge.reachable == false
      and .edge.http_status == null
      and .direct_target_edge.url == "http://127.0.0.1:31081"
      and .direct_target_edge.reachable == false
      and .direct_target_edge.http_status == null
    ' >/dev/null
}

test_json_status_reports_edge_and_pvc
test_human_status_mentions_running_components
test_json_status_reports_unreachable_edge_without_failing

printf 'shield-lab status checks passed\n'
