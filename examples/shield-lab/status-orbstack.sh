#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"

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

if configmap_json="$(
  kubectl_cmd -n shield-system get configmap eidolon-shield-bait-profile -o json 2>/dev/null
)"; then
  bait_profile_configmap_json="$configmap_json"
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
  '
    def bait_profile_document:
      ($bait_profile_configmap.data["bait-profile.json"]? // null) as $raw
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
      }
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
  "proxy-state: \(.proxy_state.status) \(.proxy_state.bound_storage // .proxy_state.requested_storage // "unknown") (\(.proxy_state.storage_class // "no-storage-class"))"
' <<<"$status_json"
