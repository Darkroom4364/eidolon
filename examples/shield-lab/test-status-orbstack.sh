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

fixture="${EIDOLON_STATUS_FIXTURE:-healthy}"

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
  "-n shield-system exec eidolon-shield-proxy-abc -- df -Pk /var/lib/eidolon")
    case "$fixture" in
      unavailable|mixed_degraded_unavailable)
        exit 1
        ;;
      malformed_df)
        printf 'not valid df output\n'
        ;;
      disk_pressure)
        printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
        printf '/dev/disk1 1024 942 82 92%% /var/lib/eidolon\n'
        ;;
      *)
        printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
        printf '/dev/disk1 1024 102 922 10%% /var/lib/eidolon\n'
        ;;
    esac
    ;;
  "-n shield-system logs eidolon-shield-proxy-abc")
    case "$fixture" in
      unavailable)
        exit 1
        ;;
      persistence_failure|mixed_degraded_unavailable)
        printf 'eidolon persistence failure: event log: fixture write failed\n'
        ;;
      persistence_failure_before_last_500)
        printf 'eidolon persistence failure: event log: old fixture write failed\n'
        for line_number in {1..501}; do
          printf 'normal proxy log line %s\n' "$line_number"
        done
        ;;
      reconstruction_degraded|reconstruction_log_only)
        printf 'eidolon startup: ignoring crash-torn event log tail at line 7\n'
        ;;
      tail_repaired)
        printf 'eidolon log tail repair: repaired crash-torn event log tail\n'
        ;;
      *)
        printf 'eidolon proxy started\n'
        ;;
    esac
    ;;
  "-n shield-system exec eidolon-shield-proxy-abc -- tail -n 1000 /var/lib/eidolon/debug.jsonl")
    case "$fixture" in
      unavailable|reconstruction_log_only|mixed_degraded_unavailable)
        exit 1
        ;;
      reconstruction_degraded)
        cat <<'JSONL'
{"event":"proxy_started","fields":{"restored_bait_exposure_torn_tail_line":7,"restored_consumed_bait_proof_torn_tail_line":null}}
JSONL
        ;;
      tail_repaired)
        cat <<'JSONL'
{"event":"proxy_started","fields":{"event_log_tail_repair":{"outcome":"truncated"},"debug_log_tail_repair":{"outcome":"appended_newline"}}}
JSONL
        ;;
      migration_quarantine_active)
        cat <<'JSONL'
{"event":"proxy_started","fields":{"consumed_proof_migration_quarantine_until":null}}
{"event":"proxy_started","fields":{"consumed_proof_migration_quarantine_until":4102444800,"event_log_tail_repair":{"outcome":"not_needed"},"debug_log_tail_repair":{"outcome":"not_needed"}}}
JSONL
        ;;
      *)
        cat <<'JSONL'
{"event":"proxy_started","fields":{"restored_bait_exposure_torn_tail_line":null,"restored_consumed_bait_proof_torn_tail_line":null,"event_log_tail_repair":{"outcome":"not_needed"},"debug_log_tail_repair":{"outcome":"not_needed"}}}
JSONL
        ;;
    esac
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
      and .ingress_trust.trusted_soften_scopes[0].methods == ["GET"]
      and .ingress_trust.trusted_soften_scopes[0].path_prefixes == ["/docs", "/openapi.json"]
      and .ingress_trust.trusted_soften_scopes[0].bait_soften_path_prefixes == ["/docs"]
      and .ingress_trust.trusted_soften_scopes[0].user_agent_substrings == ["eidolon-docs-crawler"]
      and .ingress_trust.trusted_soften_scopes[0].hosts == ["127.0.0.1", "localhost"]
      and .ingress_trust.trusted_soften_scopes[0].source_cidrs == ["192.168.194.1/32"]
      and .ingress_trust.trusted_soften_scopes[0].required_header_names == ["X-Eidolon-Trusted-Actor"]
      and .operator_health.status == "healthy"
      and .operator_health.pod_name == "eidolon-shield-proxy-abc"
      and .operator_health.persistent_volume.status == "healthy"
      and .operator_health.persistent_volume.used_percent == 10
      and .operator_health.persistent_volume.pressure == false
      and .operator_health.persistence.status == "healthy"
      and .operator_health.persistence.failure_marker_seen == false
      and .operator_health.reconstruction.status == "healthy"
      and .operator_health.reconstruction.startup_debug_available == true
      and .operator_health.reconstruction.evidence == []
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
  rg -q 'trusted-soften-scopes: docs-crawler -> /docs \(match /docs, /openapi.json; methods GET; ua eidolon-docs-crawler; host 127.0.0.1, localhost; source 192.168.194.1/32; headers X-Eidolon-Trusted-Actor; expires 2999-06-05T12:00:00Z\)' <<<"$output"
  rg -q 'bait-signing: enabled' <<<"$output"
  rg -q 'polymorphic-baits: /docs/legacy-import -> X-Migration-Trace \[mig\], /openapi.json -> X-OpenAPI-Trace \[oapi\], /docs/service-token -> X-Api-Key \[svc\]' <<<"$output"
  rg -q 'target: 2/2 ready' <<<"$output"
  rg -q 'proxy-state: Bound 1Gi \(local-path\)' <<<"$output"
  rg -q 'operator-health: healthy \(disk=10% used, persistence=healthy, reconstruction=healthy\)' <<<"$output"
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

test_json_status_reports_disk_pressure_as_degraded() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=disk_pressure \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "degraded"
      and .operator_health.persistent_volume.status == "degraded"
      and .operator_health.persistent_volume.used_percent == 92
      and .operator_health.persistent_volume.pressure == true
      and .operator_health.persistent_volume.pressure_threshold_percent == 85
    ' >/dev/null
}

test_json_status_reports_persistence_failure_as_degraded() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=persistence_failure \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "degraded"
      and .operator_health.persistence.status == "degraded"
      and .operator_health.persistence.marker == "eidolon persistence failure:"
      and .operator_health.persistence.failure_marker_seen == true
      and .operator_health.persistence.pod_logs_available == true
    ' >/dev/null
}

test_json_status_finds_persistence_failure_before_last_500_lines() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=persistence_failure_before_last_500 \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "degraded"
      and .operator_health.persistence.status == "degraded"
      and .operator_health.persistence.failure_marker_seen == true
      and .operator_health.persistence.pod_logs_available == true
    ' >/dev/null
}

test_json_status_reports_degraded_reconstruction_evidence() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=reconstruction_degraded \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "degraded"
      and .operator_health.reconstruction.status == "degraded"
      and (
        .operator_health.reconstruction.evidence
        | any(
            .source == "startup_debug"
            and .signal == "restored_bait_exposure_torn_tail_line"
            and .value == 7
          )
      )
      and (
        .operator_health.reconstruction.evidence
        | any(.source == "pod_logs" and .signal == "torn_tail_or_repair")
      )
    ' >/dev/null
}

test_json_status_reports_active_migration_quarantine_as_degraded() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=migration_quarantine_active \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "degraded"
      and .operator_health.reconstruction.status == "degraded"
      and .operator_health.reconstruction.startup_debug_available == true
      and (
        .operator_health.reconstruction.evidence
        | any(
            .source == "startup_debug"
            and .signal == "consumed_proof_migration_quarantine_until"
            and .state == "active"
            and .value == 4102444800
          )
      )
    ' >/dev/null
}

test_json_status_reports_tail_repair_as_degraded() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=tail_repaired \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "degraded"
      and .operator_health.reconstruction.status == "degraded"
      and (
        .operator_health.reconstruction.evidence
        | any(
            .source == "startup_debug"
            and .signal == "event_log_tail_repair"
            and .value.outcome == "truncated"
          )
      )
      and (
        .operator_health.reconstruction.evidence
        | any(
            .source == "startup_debug"
            and .signal == "debug_log_tail_repair"
            and .value.outcome == "appended_newline"
          )
      )
      and (
        .operator_health.reconstruction.evidence
        | any(.source == "pod_logs" and .signal == "torn_tail_or_repair")
      )
    ' >/dev/null
}

test_json_status_uses_log_only_reconstruction_evidence() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=reconstruction_log_only \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "degraded"
      and .operator_health.reconstruction.status == "degraded"
      and .operator_health.reconstruction.startup_debug_available == false
      and .operator_health.reconstruction.evidence == [
        {
          "source": "pod_logs",
          "signal": "torn_tail_or_repair"
        }
      ]
    ' >/dev/null
}

test_json_status_reports_unavailable_health_probes() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=unavailable \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "unavailable"
      and .operator_health.persistent_volume.status == "unavailable"
      and .operator_health.persistent_volume.pressure == null
      and .operator_health.persistence.status == "unavailable"
      and .operator_health.persistence.failure_marker_seen == null
      and .operator_health.persistence.pod_logs_available == false
      and .operator_health.reconstruction.status == "unavailable"
      and .operator_health.reconstruction.startup_debug_available == false
    ' >/dev/null
}

test_json_status_reports_mixed_degraded_and_unavailable_probes() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=mixed_degraded_unavailable \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "degraded"
      and .operator_health.persistent_volume.status == "unavailable"
      and .operator_health.persistence.status == "degraded"
      and .operator_health.reconstruction.status == "unavailable"
    ' >/dev/null
}

test_json_status_reports_malformed_disk_probe_as_unavailable() {
  local temp_dir
  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  EIDOLON_STATUS_FIXTURE=malformed_df \
    KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    "$STATUS_SCRIPT" --json \
    | jq -e '
      .operator_health.status == "unavailable"
      and .operator_health.persistent_volume.status == "unavailable"
      and .operator_health.persistence.status == "healthy"
      and .operator_health.reconstruction.status == "healthy"
    ' >/dev/null
}

test_json_status_reports_edge_and_pvc
test_human_status_mentions_running_components
test_json_status_reports_unreachable_edge_without_failing
test_json_status_reports_disk_pressure_as_degraded
test_json_status_reports_persistence_failure_as_degraded
test_json_status_finds_persistence_failure_before_last_500_lines
test_json_status_reports_degraded_reconstruction_evidence
test_json_status_reports_active_migration_quarantine_as_degraded
test_json_status_reports_tail_repair_as_degraded
test_json_status_uses_log_only_reconstruction_evidence
test_json_status_reports_unavailable_health_probes
test_json_status_reports_mixed_degraded_and_unavailable_probes
test_json_status_reports_malformed_disk_probe_as_unavailable

printf 'shield-lab status checks passed\n'
