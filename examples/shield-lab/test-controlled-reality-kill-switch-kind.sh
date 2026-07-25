#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
KILL_SWITCH_SCRIPT="$SCRIPT_DIR/controlled-reality-kill-switch-kind.sh"

new_fixture() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-kill-switch-fixture.XXXXXX"
}

write_proxy() {
  local dir="$1"
  local replicas="${2:-1}"
  local remote="${3:-true}"

  if [[ "$remote" == "true" ]]; then
    args='[
      "--controlled-reality-backend-addr",
      "renderer.example:9103",
      "--controlled-reality-backend-auth-secret-file",
      "/secret"
    ]'
  else
    args='[]'
  fi

  jq -n \
    --argjson replicas "$replicas" \
    --argjson args "$args" \
    '{
      spec: {
        replicas: $replicas,
        template: {
          spec: {
            containers: [{
              name: "shield-proxy",
              args: $args
            }]
          }
        }
      }
    }' >"$dir/proxy-deployment.json"
}

write_renderer() {
  local dir="$1"
  local desired="$2"
  local available="$3"
  local annotations="$4"

  jq -n \
    --argjson desired "$desired" \
    --argjson available "$available" \
    --argjson annotations "$annotations" \
    '{
      metadata: {annotations: $annotations},
      spec: {replicas: $desired},
      status: {availableReplicas: $available}
    }' >"$dir/renderer-deployment.json"
}

write_runtime_shape() {
  local dir="$1"
  local pod_count="$2"
  local endpoint_count="$3"

  jq -n --argjson count "$pod_count" \
    '{items: [range(0; $count) | {metadata: {name: ("renderer-" + tostring)}}]}' \
    >"$dir/renderer-pods.json"
  jq -n --argjson count "$endpoint_count" '
    {
      items: [{
        endpoints: [
          range(0; $count)
          | {addresses: [("10.0.0." + ((. + 10) | tostring))]}
        ]
      }]
    }
  ' >"$dir/renderer-endpointslices.json"
}

expect_state() {
  local dir="$1"
  local expected="$2"

  "$KILL_SWITCH_SCRIPT" --validate-fixture "$dir" \
    | jq -e --arg state "$expected" '.state == $state' >/dev/null
}

expect_failure() {
  local dir="$1"

  if "$KILL_SWITCH_SCRIPT" --validate-fixture "$dir" >/dev/null 2>&1; then
    echo "fixture unexpectedly passed: $dir" >&2
    exit 1
  fi
}

fixtures=()
trap 'rm -rf "${fixtures[@]:-}"' EXIT

enabled="$(new_fixture)"
fixtures+=("$enabled")
write_proxy "$enabled"
write_renderer "$enabled" 1 1 '{}'
write_runtime_shape "$enabled" 1 1
expect_state "$enabled" enabled

disabled="$(new_fixture)"
fixtures+=("$disabled")
write_proxy "$disabled"
write_renderer "$disabled" 0 0 '{
  "shield.eidolon.dev/kill-switch-state": "disabled",
  "shield.eidolon.dev/kill-switch-restore-replicas": "1",
  "shield.eidolon.dev/kill-switch-disabled-at": "2026-07-24T19:00:00Z",
  "shield.eidolon.dev/kill-switch-proxy-drained-at": "2026-07-24T19:00:01Z"
}'
write_runtime_shape "$disabled" 0 0
"$KILL_SWITCH_SCRIPT" --validate-fixture "$disabled" \
  | jq -e '
      .state == "disabled"
      and .restore_replicas == 1
      and .proxy_drained == true
    ' >/dev/null

manual_outage="$(new_fixture)"
fixtures+=("$manual_outage")
write_proxy "$manual_outage"
write_renderer "$manual_outage" 0 0 '{}'
write_runtime_shape "$manual_outage" 0 0
expect_state "$manual_outage" unmanaged_outage

stale_endpoint="$(new_fixture)"
fixtures+=("$stale_endpoint")
cp -R "$disabled/." "$stale_endpoint/"
write_runtime_shape "$stale_endpoint" 0 1
expect_state "$stale_endpoint" transitioning

stale_pod="$(new_fixture)"
fixtures+=("$stale_pod")
cp -R "$disabled/." "$stale_pod/"
write_runtime_shape "$stale_pod" 1 0
expect_state "$stale_pod" transitioning

stale_available="$(new_fixture)"
fixtures+=("$stale_available")
cp -R "$disabled/." "$stale_available/"
jq '.status.availableReplicas = 1' \
  "$stale_available/renderer-deployment.json" \
  >"$stale_available/renderer-deployment.next.json"
mv "$stale_available/renderer-deployment.next.json" \
  "$stale_available/renderer-deployment.json"
expect_state "$stale_available" transitioning

missing_restore="$(new_fixture)"
fixtures+=("$missing_restore")
cp -R "$disabled/." "$missing_restore/"
jq 'del(.metadata.annotations["shield.eidolon.dev/kill-switch-restore-replicas"])' \
  "$missing_restore/renderer-deployment.json" \
  >"$missing_restore/renderer-deployment.next.json"
mv "$missing_restore/renderer-deployment.next.json" \
  "$missing_restore/renderer-deployment.json"
expect_state "$missing_restore" unmanaged_outage

missing_drain="$(new_fixture)"
fixtures+=("$missing_drain")
cp -R "$disabled/." "$missing_drain/"
jq 'del(.metadata.annotations["shield.eidolon.dev/kill-switch-proxy-drained-at"])' \
  "$missing_drain/renderer-deployment.json" \
  >"$missing_drain/renderer-deployment.next.json"
mv "$missing_drain/renderer-deployment.next.json" \
  "$missing_drain/renderer-deployment.json"
expect_state "$missing_drain" unmanaged_outage

local_renderer="$(new_fixture)"
fixtures+=("$local_renderer")
cp -R "$enabled/." "$local_renderer/"
write_proxy "$local_renderer" 1 false
expect_failure "$local_renderer"

multiple_proxies="$(new_fixture)"
fixtures+=("$multiple_proxies")
cp -R "$enabled/." "$multiple_proxies/"
write_proxy "$multiple_proxies" 2 true
expect_failure "$multiple_proxies"

"$KILL_SWITCH_SCRIPT" --help | grep -Fq 'acknowledges only'
echo "kind controlled-reality kill-switch fixture tests ok"
