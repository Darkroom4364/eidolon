#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
DISK_PRESSURE_THRESHOLD_PERCENT=85
PERSISTENCE_FAILURE_MARKER="eidolon persistence failure:"
CURRENT_EPOCH_SECONDS="$(date -u +%s)"

JSON_OUTPUT=0

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/status-orbstack.sh [--json]

Reports the current OrbStack Shield lab status. By default this prints a compact
human-readable summary. Use --json for machine-readable output.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

kubectl_cmd() {
  "$KUBECTL_BIN" "$@"
}

curl_cmd() {
  "$CURL_BIN" "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      JSON_OUTPUT=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

require_command "$KUBECTL_BIN"
require_command "$CURL_BIN"
require_command jq

context="$(kubectl_cmd config current-context)"
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  fail "expected kubectl current-context to be ${EXPECTED_CONTEXT}, got: ${context}"
fi

proxy_deploy_json="$(kubectl_cmd -n shield-system get deploy eidolon-shield-proxy -o json)"
proxy_pods_json="$(kubectl_cmd -n shield-system get pods -l app.kubernetes.io/name=eidolon-shield-proxy -o json)"
target_deploy_json="$(kubectl_cmd -n shield-targets get deploy eidolon-owned-demo-target -o json)"
target_pods_json="$(kubectl_cmd -n shield-targets get pods -l app.kubernetes.io/name=eidolon-owned-demo-target -o json)"
edge_svc_json="$(kubectl_cmd -n shield-system get svc eidolon-shield-edge -o json)"
target_edge_svc_json="$(kubectl_cmd -n shield-targets get svc eidolon-owned-demo-target-edge -o json)"
pvc_json="$(kubectl_cmd -n shield-system get pvc eidolon-shield-proxy-state -o json)"
bait_profile_configmap_json='{}'
ingress_trust_configmap_json='{}'

if configmap_json="$(
  kubectl_cmd -n shield-system get configmap eidolon-shield-bait-profile -o json 2>/dev/null
)"; then
  bait_profile_configmap_json="$configmap_json"
fi

if configmap_json="$(
  kubectl_cmd -n shield-system get configmap eidolon-shield-ingress-trust-config -o json 2>/dev/null
)"; then
  ingress_trust_configmap_json="$configmap_json"
fi

edge_node_port="$(jq -r '.spec.ports[] | select(.name == "http") | (.nodePort // empty)' <<<"$edge_svc_json")"
edge_service_type="$(jq -r '.spec.type' <<<"$edge_svc_json")"
edge_url=""
edge_http_status=""
edge_reachable=false
target_edge_node_port="$(jq -r '.spec.ports[] | select(.name == "http") | (.nodePort // empty)' <<<"$target_edge_svc_json")"
target_edge_service_type="$(jq -r '.spec.type' <<<"$target_edge_svc_json")"
target_edge_url=""
target_edge_http_status=""
target_edge_reachable=false

if [[ -n "$edge_node_port" ]]; then
  edge_url="http://${EDGE_HOST}:${edge_node_port}"
  if edge_http_status="$(curl_cmd -sS -o /dev/null -w '%{http_code}' "${edge_url}/openapi.json" 2>/dev/null)"; then
    edge_reachable=true
  fi
fi

if [[ -n "$target_edge_node_port" ]]; then
  target_edge_url="http://${EDGE_HOST}:${target_edge_node_port}"
  if target_edge_http_status="$(curl_cmd -sS -o /dev/null -w '%{http_code}' "${target_edge_url}/openapi.json" 2>/dev/null)"; then
    target_edge_reachable=true
  fi
fi

proxy_pod_name="$(jq -r 'first((.items // [])[]?.metadata.name) // empty' <<<"$proxy_pods_json")"
disk_health_status="unavailable"
disk_total_kib=""
disk_used_kib=""
disk_available_kib=""
disk_used_percent=""
disk_pressure=null
proxy_logs_available=false
persistence_health_status="unavailable"
persistence_failure_seen=null
startup_debug_available=false
reconstruction_health_status="unavailable"
reconstruction_evidence_json='[]'
reconstruction_startup_evidence_json='[]'

if [[ -n "$proxy_pod_name" ]]; then
  if disk_output="$(
    kubectl_cmd -n shield-system exec "$proxy_pod_name" -- \
      df -Pk /var/lib/eidolon 2>/dev/null
  )"; then
    disk_metrics="$(
      awk '
        NR > 1 && NF >= 5 {
          total = $2
          used = $3
          available = $4
          percent = $5
        }
        END {
          gsub(/%/, "", percent)
          if (total ~ /^[0-9]+$/ && used ~ /^[0-9]+$/ &&
              available ~ /^[0-9]+$/ && percent ~ /^[0-9]+$/) {
            printf "%s %s %s %s", total, used, available, percent
          }
        }
      ' <<<"$disk_output"
    )"
    if [[ "$disk_metrics" =~ ^([0-9]+)\ ([0-9]+)\ ([0-9]+)\ ([0-9]+)$ ]]; then
      disk_total_kib="${BASH_REMATCH[1]}"
      disk_used_kib="${BASH_REMATCH[2]}"
      disk_available_kib="${BASH_REMATCH[3]}"
      disk_used_percent="$((10#${BASH_REMATCH[4]}))"
      disk_pressure=false
      disk_health_status="healthy"
      if (( disk_used_percent >= DISK_PRESSURE_THRESHOLD_PERCENT )); then
        disk_pressure=true
        disk_health_status="degraded"
      fi
    fi
  fi

  proxy_logs=""
  reconstruction_log_evidence_json='[]'
  if proxy_logs="$(
    kubectl_cmd -n shield-system logs "$proxy_pod_name" 2>/dev/null
  )"; then
    proxy_logs_available=true
    persistence_failure_seen=false
    persistence_health_status="healthy"
    if [[ "$proxy_logs" == *"$PERSISTENCE_FAILURE_MARKER"* ]]; then
      persistence_failure_seen=true
      persistence_health_status="degraded"
    fi

    if [[ "$proxy_logs" == *"eidolon startup: ignoring crash-torn event log tail"* ||
      "$proxy_logs" == *"eidolon startup: repaired crash-torn"* ||
      "$proxy_logs" == *"eidolon log tail repair:"* ||
      "$proxy_logs" == *"eidolon reconstruction degraded:"* ]]; then
      reconstruction_log_evidence_json='[
        {
          "source": "pod_logs",
          "signal": "torn_tail_or_repair"
        }
      ]'
    fi
  fi

  startup_debug_json=null
  if startup_debug_tail="$(
    kubectl_cmd -n shield-system exec "$proxy_pod_name" -- \
      tail -n 1000 /var/lib/eidolon/debug.jsonl 2>/dev/null
  )"; then
    startup_debug_json="$(
      jq -Rsc '
        [split("\n")[] | fromjson? | select(.event == "proxy_started")]
        | last // null
      ' <<<"$startup_debug_tail"
    )"
    if [[ "$startup_debug_json" != "null" ]]; then
      startup_debug_available=true
      reconstruction_startup_evidence_json="$(
        jq -c --argjson now_epoch "$CURRENT_EPOCH_SECONDS" '
          (.fields // {}) as $fields |
          [
            ($fields | to_entries[] |
              select(
                (
                  .key == "restored_bait_exposure_torn_tail_line"
                  or .key == "restored_consumed_bait_proof_torn_tail_line"
                )
                and .value != null
              ) |
              {
                source: "startup_debug",
                signal: .key,
                value: .value
              }),
            (
              ["event_log_tail_repair", "debug_log_tail_repair"][] as $signal |
              ($fields[$signal] // null) as $repair |
              select(
                ($repair | type) == "object"
                and (
                  $repair.outcome == "appended_newline"
                  or $repair.outcome == "truncated"
                )
              ) |
              {
                source: "startup_debug",
                signal: $signal,
                value: $repair
              }
            ),
            (
              ($fields.consumed_proof_migration_quarantine_until // null) as $until |
              select(
                ($until | type) == "number"
                and $until > $now_epoch
              ) |
              {
                source: "startup_debug",
                signal: "consumed_proof_migration_quarantine_until",
                state: "active",
                value: $until
              }
            )
          ]
        ' <<<"$startup_debug_json"
      )"
    fi
  fi

  reconstruction_evidence_json="$(
    jq -cn \
      --argjson startup "$reconstruction_startup_evidence_json" \
      --argjson logs "$reconstruction_log_evidence_json" \
      '$startup + $logs'
  )"
  if [[ "$(jq 'length' <<<"$reconstruction_evidence_json")" -gt 0 ]]; then
    reconstruction_health_status="degraded"
  elif [[ "$startup_debug_available" == true ]]; then
    reconstruction_health_status="healthy"
  fi
fi

operator_health_status="unavailable"
if [[ "$disk_health_status" == "degraded" ||
  "$persistence_health_status" == "degraded" ||
  "$reconstruction_health_status" == "degraded" ]]; then
  operator_health_status="degraded"
elif [[ "$disk_health_status" == "healthy" &&
  "$persistence_health_status" == "healthy" &&
  "$reconstruction_health_status" == "healthy" ]]; then
  operator_health_status="healthy"
fi

operator_health_json="$(jq -n \
  --arg status "$operator_health_status" \
  --arg pod_name "$proxy_pod_name" \
  --arg disk_status "$disk_health_status" \
  --arg disk_total_kib "$disk_total_kib" \
  --arg disk_used_kib "$disk_used_kib" \
  --arg disk_available_kib "$disk_available_kib" \
  --arg disk_used_percent "$disk_used_percent" \
  --argjson disk_pressure "$disk_pressure" \
  --arg persistence_status "$persistence_health_status" \
  --arg persistence_marker "$PERSISTENCE_FAILURE_MARKER" \
  --argjson persistence_failure_seen "$persistence_failure_seen" \
  --argjson proxy_logs_available "$proxy_logs_available" \
  --arg reconstruction_status "$reconstruction_health_status" \
  --argjson startup_debug_available "$startup_debug_available" \
  --argjson reconstruction_evidence "$reconstruction_evidence_json" \
  --argjson disk_pressure_threshold "$DISK_PRESSURE_THRESHOLD_PERCENT" \
  '
    {
      status: $status,
      pod_name: (if $pod_name == "" then null else $pod_name end),
      persistent_volume: {
        status: $disk_status,
        path: "/var/lib/eidolon",
        pressure_threshold_percent: $disk_pressure_threshold,
        pressure: $disk_pressure,
        total_kib: (if $disk_total_kib == "" then null else ($disk_total_kib | tonumber) end),
        used_kib: (if $disk_used_kib == "" then null else ($disk_used_kib | tonumber) end),
        available_kib: (
          if $disk_available_kib == "" then null else ($disk_available_kib | tonumber) end
        ),
        used_percent: (
          if $disk_used_percent == "" then null else ($disk_used_percent | tonumber) end
        )
      },
      persistence: {
        status: $persistence_status,
        marker: $persistence_marker,
        failure_marker_seen: $persistence_failure_seen,
        pod_logs_available: $proxy_logs_available
      },
      reconstruction: {
        status: $reconstruction_status,
        startup_debug_available: $startup_debug_available,
        evidence: $reconstruction_evidence
      }
    }
  ')"

status_json="$(jq -n \
  --arg generated_at "$(date -u +%FT%TZ)" \
  --arg context "$context" \
  --arg edge_host "$EDGE_HOST" \
  --arg edge_url "$edge_url" \
  --arg edge_http_status "$edge_http_status" \
  --arg edge_service_type "$edge_service_type" \
  --argjson edge_reachable "$edge_reachable" \
  --arg target_edge_url "$target_edge_url" \
  --arg target_edge_http_status "$target_edge_http_status" \
  --arg target_edge_service_type "$target_edge_service_type" \
  --argjson target_edge_reachable "$target_edge_reachable" \
  --argjson proxy_deploy "$proxy_deploy_json" \
  --argjson proxy_pods "$proxy_pods_json" \
  --argjson target_deploy "$target_deploy_json" \
  --argjson target_pods "$target_pods_json" \
  --argjson edge_svc "$edge_svc_json" \
  --argjson target_edge_svc "$target_edge_svc_json" \
  --argjson pvc "$pvc_json" \
  --argjson bait_profile_configmap "$bait_profile_configmap_json" \
  --argjson ingress_trust_configmap "$ingress_trust_configmap_json" \
  --argjson operator_health "$operator_health_json" \
  '
    def bait_profile_document:
      ($bait_profile_configmap.data["bait-profile.json"]? // null) as $raw
      | if ($raw | type) == "string" then
          ($raw | fromjson?)
        else
          null
        end;
    def ingress_trust_document:
      ($ingress_trust_configmap.data["ingress-trust.json"]? // null) as $raw
      | if ($raw | type) == "string" then
          ($raw | fromjson?)
        else
          null
        end;
    def polymorphic_baits:
      [
        (bait_profile_document.baits // [])[]
        | select((.expected_action.header_value_mint // null) != null)
        | {
            bait_id: .id,
            surface: .surface,
            surface_kind: .surface_kind,
            header_name: .expected_action.header_name,
            kind: .expected_action.header_value_mint.kind,
            prefix: .expected_action.header_value_mint.prefix
          }
      ];
    def trusted_soften_scopes:
      (
        [
          (ingress_trust_document.entries // [])[]
          | select(((.bait_soften_path_prefixes // []) | length) > 0)
          | {
              label: (.label // null),
              source: .source,
              trust_tier: .trust_tier,
              not_before: (.not_before // null),
              expires_at: (.expires_at // null),
              methods: (.methods // []),
              path_prefixes: (.path_prefixes // []),
              bait_soften_path_prefixes: (.bait_soften_path_prefixes // []),
              user_agent_substrings: (.user_agent_substrings // []),
              hosts: (.hosts // []),
              source_cidrs: (.source_cidrs // []),
              required_header_names: ((.required_headers // []) | map(.name)),
              verified_categories: []
            }
        ]
        +
        [
          (ingress_trust_document.authenticated_entries // [])[]
          | select(((.bait_soften_path_prefixes // []) | length) > 0)
          | {
              label: (.label // null),
              source: .source,
              trust_tier: .trust_tier,
              not_before: (.not_before // null),
              expires_at: (.expires_at // null),
              methods: (.methods // []),
              path_prefixes: (.path_prefixes // []),
              bait_soften_path_prefixes: (.bait_soften_path_prefixes // []),
              user_agent_substrings: [],
              hosts: [],
              source_cidrs: [],
              required_header_names: [],
              verified_categories: (.verified_categories // [])
            }
        ]
      );
    def authenticated_trusted_ingress_rules:
      [
        (ingress_trust_document.authenticated_entries // [])[]
        | {
            label: (.label // null),
            source: .source,
            trust_tier: .trust_tier,
            not_before: (.not_before // null),
            expires_at: (.expires_at // null),
            methods: (.methods // []),
            path_prefixes: (.path_prefixes // []),
            bait_soften_path_prefixes: (.bait_soften_path_prefixes // []),
            verified_categories: (.verified_categories // [])
          }
      ];
    {
      generated_at: $generated_at,
      context: $context,
      edge: {
        service_name: ($edge_svc.metadata.name // null),
        service_type: $edge_service_type,
        host: $edge_host,
        node_port: (($edge_svc.spec.ports[] | select(.name == "http") | .nodePort) // null),
        url: (if $edge_url == "" then null else $edge_url end),
        reachable: $edge_reachable,
        http_status: (
          if $edge_http_status == "" then
            null
          else
            ($edge_http_status | tonumber?)
          end
        )
      },
      direct_target_edge: {
        service_name: ($target_edge_svc.metadata.name // null),
        service_type: $target_edge_service_type,
        host: $edge_host,
        node_port: (($target_edge_svc.spec.ports[] | select(.name == "http") | .nodePort) // null),
        url: (if $target_edge_url == "" then null else $target_edge_url end),
        reachable: $target_edge_reachable,
        http_status: (
          if $target_edge_http_status == "" then
            null
          else
            ($target_edge_http_status | tonumber?)
          end
        )
      },
      proxy: {
        deployment_name: ($proxy_deploy.metadata.name // null),
        replicas: ($proxy_deploy.spec.replicas // 0),
        ready_replicas: ($proxy_deploy.status.readyReplicas // 0),
        available_replicas: ($proxy_deploy.status.availableReplicas // 0),
        pod_names: [($proxy_pods.items // [])[] | .metadata.name],
        image_ids: [($proxy_pods.items // [])[] | .status.containerStatuses[]?.imageID],
        trusted_ingress_transport_auth_enabled: (
          any(
            (($proxy_deploy.spec.template.spec.containers // [])[]?.args // [])[];
            . == "--ingress-transport-auth-secret-file"
          )
        ),
        bait_signing_enabled: (
          any(
            (($proxy_deploy.spec.template.spec.containers // [])[]?.args // [])[];
            . == "--bait-signing-secret-file"
          )
        ),
        pvc_claim: ($pvc.metadata.name // null)
      },
      target: {
        deployment_name: ($target_deploy.metadata.name // null),
        replicas: ($target_deploy.spec.replicas // 0),
        ready_replicas: ($target_deploy.status.readyReplicas // 0),
        available_replicas: ($target_deploy.status.availableReplicas // 0),
        pod_names: [($target_pods.items // [])[] | .metadata.name],
        image_ids: [($target_pods.items // [])[] | .status.containerStatuses[]?.imageID]
      },
      proxy_state: {
        claim_name: ($pvc.metadata.name // null),
        status: ($pvc.status.phase // null),
        storage_class: ($pvc.spec.storageClassName // null),
        requested_storage: ($pvc.spec.resources.requests.storage // null),
        bound_storage: ($pvc.status.capacity.storage // null),
        access_modes: ($pvc.status.accessModes // $pvc.spec.accessModes // [])
      },
      bait_profile: {
        configmap_name: ($bait_profile_configmap.metadata.name // null),
        profile_id: (bait_profile_document.profile_id // null),
        polymorphic_baits: polymorphic_baits
      },
      ingress_trust: {
        configmap_name: ($ingress_trust_configmap.metadata.name // null),
        authenticated_trusted_ingress_rules: authenticated_trusted_ingress_rules,
        trusted_soften_scopes: trusted_soften_scopes
      },
      operator_health: $operator_health
    }
  ')"

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
  printf '%s\n' "$status_json"
  exit 0
fi

jq -r '
  "OrbStack Shield lab status",
  "context: \(.context)",
  (
    if .edge.url == null then
      "edge: unavailable"
    else
      "edge: \(.edge.url) (" +
      (if .edge.http_status == null then "unreachable" else "HTTP \(.edge.http_status)" end) +
      ", type=\(.edge.service_type))"
    end
  ),
  (
    if .direct_target_edge.url == null then
      "direct-target: unavailable"
    else
      "direct-target: \(.direct_target_edge.url) (" +
      (if .direct_target_edge.http_status == null then "unreachable" else "HTTP \(.direct_target_edge.http_status)" end) +
      ", type=\(.direct_target_edge.service_type))"
    end
  ),
  "proxy: \(.proxy.ready_replicas)/\(.proxy.replicas) ready, pods=\(.proxy.pod_names | join(", "))",
  "trusted-ingress: transport-auth " + (if .proxy.trusted_ingress_transport_auth_enabled then "enabled" else "disabled" end),
  (
    if (.ingress_trust.authenticated_trusted_ingress_rules | length) == 0 then
      "authenticated-trusted-rules: none"
    else
      "authenticated-trusted-rules: " + (
        .ingress_trust.authenticated_trusted_ingress_rules
        | map(
            ((.label // (.source + "/" + .trust_tier)))
            + " (match "
            + (
                if (.path_prefixes | length) == 0 then
                  "all"
                else
                  (.path_prefixes | join(", "))
                end
              )
            + (
                if (.bait_soften_path_prefixes | length) == 0 then
                  "; soften none"
                else
                  "; soften " + (.bait_soften_path_prefixes | join(", "))
                end
              )
            + (
                if (.methods | length) == 0 then
                  "; methods any"
                else
                  "; methods " + (.methods | join(", "))
                end
              )
            + (
                if (.verified_categories | length) == 0 then
                  ""
                else
                  "; categories " + (.verified_categories | join(", "))
                end
              )
            + (
                if (.not_before // null) == null then
                  ""
                else
                  "; not-before " + .not_before
                end
              )
            + (
                if (.expires_at // null) == null then
                  ""
                else
                  "; expires " + .expires_at
                end
              )
            + ")"
          )
        | join(", ")
      )
    end
  ),
  (
    if (.ingress_trust.trusted_soften_scopes | length) == 0 then
      "trusted-soften-scopes: none"
    else
      "trusted-soften-scopes: " + (
        .ingress_trust.trusted_soften_scopes
        | map(
            ((.label // (.source + "/" + .trust_tier)))
            + " -> "
            + (.bait_soften_path_prefixes | join(", "))
            + " (match "
            + (
                if (.path_prefixes | length) == 0 then
                  "all"
                else
                  (.path_prefixes | join(", "))
                end
              )
            + (
                if (.methods | length) == 0 then
                  "; methods any"
                else
                  "; methods " + (.methods | join(", "))
                end
              )
            + (
                if (.verified_categories | length) == 0 then
                  ""
                else
                  "; categories " + (.verified_categories | join(", "))
                end
              )
            + (
                if (.user_agent_substrings | length) == 0 then
                  "; ua any"
                else
                  "; ua " + (.user_agent_substrings | join(", "))
                end
              )
            + (
                if (.hosts | length) == 0 then
                  "; host any"
                else
                  "; host " + (.hosts | join(", "))
                end
              )
            + (
                if (.source_cidrs | length) == 0 then
                  "; source any"
                else
                  "; source " + (.source_cidrs | join(", "))
                end
              )
            + (
                if (.required_header_names | length) == 0 then
                  "; headers any"
                else
                  "; headers " + (.required_header_names | join(", "))
                end
              )
            + (
                if (.not_before // null) == null then
                  ""
                else
                  "; not-before " + .not_before
                end
              )
            + (
                if (.expires_at // null) == null then
                  ""
                else
                  "; expires " + .expires_at
                end
              )
            + ")"
          )
        | join(", ")
      )
    end
  ),
  "bait-signing: " + (if .proxy.bait_signing_enabled then "enabled" else "disabled" end),
  (
    if (.bait_profile.polymorphic_baits | length) == 0 then
      "polymorphic-baits: none"
    else
      "polymorphic-baits: " + (
        .bait_profile.polymorphic_baits
        | map("\(.surface) -> \(.header_name) [\(.prefix)]")
        | join(", ")
      )
    end
  ),
  "target: \(.target.ready_replicas)/\(.target.replicas) ready, pods=\(.target.pod_names | join(", "))",
  "proxy-state: \(.proxy_state.status) \(.proxy_state.bound_storage // .proxy_state.requested_storage // "unknown") (\(.proxy_state.storage_class // "no-storage-class"))",
  (
    "operator-health: \(.operator_health.status) (disk=" +
    (
      if .operator_health.persistent_volume.status == "unavailable" then
        "unavailable"
      elif .operator_health.persistent_volume.pressure then
        "\(.operator_health.persistent_volume.used_percent)% pressure"
      else
        "\(.operator_health.persistent_volume.used_percent)% used"
      end
    ) +
    ", persistence=\(.operator_health.persistence.status)" +
    ", reconstruction=\(.operator_health.reconstruction.status))"
  )
' <<<"$status_json"
