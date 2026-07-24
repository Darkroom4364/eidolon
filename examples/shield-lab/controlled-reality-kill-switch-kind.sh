#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_KIND_CONTEXT:-kind-eidolon-shield}"
WAIT_ATTEMPTS="${EIDOLON_SHIELD_KIND_KILL_SWITCH_WAIT_ATTEMPTS:-120}"

RENDERER_NAMESPACE="shield-controlled-reality"
RENDERER_DEPLOYMENT="eidolon-controlled-reality"
RENDERER_LABEL="app.kubernetes.io/name=eidolon-controlled-reality"
RENDERER_SERVICE="eidolon-controlled-reality"
PROXY_NAMESPACE="shield-system"
PROXY_DEPLOYMENT="eidolon-shield-proxy"

STATE_ANNOTATION="shield.eidolon.dev/kill-switch-state"
RESTORE_ANNOTATION="shield.eidolon.dev/kill-switch-restore-replicas"
DISABLED_AT_ANNOTATION="shield.eidolon.dev/kill-switch-disabled-at"
PROXY_DRAINED_AT_ANNOTATION="shield.eidolon.dev/kill-switch-proxy-drained-at"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/controlled-reality-kill-switch-kind.sh disable
       examples/shield-lab/controlled-reality-kill-switch-kind.sh enable
       examples/shield-lab/controlled-reality-kill-switch-kind.sh status
       examples/shield-lab/controlled-reality-kill-switch-kind.sh --validate-fixture DIR

Disables every kind controlled-reality renderer replica and acknowledges only
after renderer Pods/endpoints are gone and the single remote-mode proxy has
restarted. All commands emit JSON.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 \
    || fail "missing required tool: $command_name"
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing fixture file: $path"
}

proxy_is_remote_singleton() {
  local proxy_json="$1"
  local backend_flag_count
  local proxy_replicas
  local secret_flag_count

  proxy_replicas="$(jq -r '.spec.replicas // 0' <<<"$proxy_json")"
  backend_flag_count="$(
    jq '
      [
        .spec.template.spec.containers[]?.args[]?
        | select(. == "--controlled-reality-backend-addr")
      ]
      | length
    ' <<<"$proxy_json"
  )"
  secret_flag_count="$(
    jq '
      [
        .spec.template.spec.containers[]?.args[]?
        | select(. == "--controlled-reality-backend-auth-secret-file")
      ]
      | length
    ' <<<"$proxy_json"
  )"

  [[ "$proxy_replicas" == "1" && "$backend_flag_count" == "1" \
    && "$secret_flag_count" == "1" ]]
}

status_from_json() {
  local renderer_json="$1"
  local pods_json="$2"
  local endpoints_json="$3"
  local proxy_json="$4"
  local annotation_state
  local available_replicas
  local desired_replicas
  local drained_at
  local endpoint_address_count
  local pod_count
  local proxy_drained=false
  local restore_replicas
  local restore_json
  local state

  proxy_is_remote_singleton "$proxy_json" \
    || fail "kill switch requires exactly one proxy replica configured for the authenticated remote renderer"

  desired_replicas="$(jq -r '.spec.replicas // 0' <<<"$renderer_json")"
  available_replicas="$(jq -r '.status.availableReplicas // 0' <<<"$renderer_json")"
  pod_count="$(jq '.items | length' <<<"$pods_json")"
  endpoint_address_count="$(
    jq '[.items[].endpoints[]?.addresses[]?] | length' <<<"$endpoints_json"
  )"
  annotation_state="$(
    jq -r --arg key "$STATE_ANNOTATION" \
      '.metadata.annotations[$key] // ""' <<<"$renderer_json"
  )"
  restore_replicas="$(
    jq -r --arg key "$RESTORE_ANNOTATION" \
      '.metadata.annotations[$key] // ""' <<<"$renderer_json"
  )"
  drained_at="$(
    jq -r --arg key "$PROXY_DRAINED_AT_ANNOTATION" \
      '.metadata.annotations[$key] // ""' <<<"$renderer_json"
  )"

  if [[ -n "$drained_at" && "$drained_at" != "pending" ]]; then
    proxy_drained=true
  fi

  if [[ "$desired_replicas" == "0" && "$available_replicas" == "0" \
    && "$pod_count" == "0" \
    && "$endpoint_address_count" == "0" ]]
  then
    if [[ "$annotation_state" == "disabled" \
      && "$restore_replicas" =~ ^[1-9][0-9]*$ \
      && "$proxy_drained" == "true" ]]
    then
      state="disabled"
    else
      state="unmanaged_outage"
    fi
  elif [[ "$desired_replicas" =~ ^[1-9][0-9]*$ \
    && "$available_replicas" == "$desired_replicas" \
    && "$pod_count" -ge "$desired_replicas" \
    && "$endpoint_address_count" -ge "$desired_replicas" \
    && ( -z "$annotation_state" || "$annotation_state" == "enabled" ) ]]
  then
    state="enabled"
  else
    state="transitioning"
  fi

  if [[ "$restore_replicas" =~ ^[1-9][0-9]*$ ]]; then
    restore_json="$restore_replicas"
  else
    restore_json=null
  fi

  jq -n \
    --arg state "$state" \
    --argjson desired_replicas "$desired_replicas" \
    --argjson available_replicas "$available_replicas" \
    --argjson pod_count "$pod_count" \
    --argjson endpoint_address_count "$endpoint_address_count" \
    --argjson restore_replicas "$restore_json" \
    --argjson proxy_drained "$proxy_drained" \
    '{
      schema_version: 1,
      state: $state,
      desired_replicas: $desired_replicas,
      available_replicas: $available_replicas,
      pod_count: $pod_count,
      endpoint_address_count: $endpoint_address_count,
      restore_replicas: $restore_replicas,
      proxy_drained: $proxy_drained
    }'
}

cluster_snapshot() {
  local renderer_json
  local pods_json
  local endpoints_json
  local proxy_json

  renderer_json="$(
    "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get \
      "deployment/$RENDERER_DEPLOYMENT" -o json
  )"
  pods_json="$(
    "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get pods \
      -l "$RENDERER_LABEL" -o json
  )"
  endpoints_json="$(
    "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get endpointslice \
      -l "kubernetes.io/service-name=$RENDERER_SERVICE" -o json
  )"
  proxy_json="$(
    "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get \
      "deployment/$PROXY_DEPLOYMENT" -o json
  )"

  status_from_json "$renderer_json" "$pods_json" "$endpoints_json" "$proxy_json"
}

wait_for_state() {
  local expected="$1"
  local attempt
  local status_json=""

  for attempt in $(seq 1 "$WAIT_ATTEMPTS"); do
    status_json="$(cluster_snapshot)"
    if [[ "$(jq -r '.state' <<<"$status_json")" == "$expected" ]]; then
      printf '%s\n' "$status_json"
      return
    fi
    sleep 1
  done

  printf '%s\n' "$status_json" >&2
  fail "kill switch did not reach state: $expected"
}

wait_for_renderer_drained() {
  local attempt
  local desired_replicas
  local endpoint_address_count
  local pod_count

  for attempt in $(seq 1 "$WAIT_ATTEMPTS"); do
    desired_replicas="$(
      "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get \
        "deployment/$RENDERER_DEPLOYMENT" -o jsonpath='{.spec.replicas}'
    )"
    pod_count="$(
      "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get pods \
        -l "$RENDERER_LABEL" -o json | jq '.items | length'
    )"
    endpoint_address_count="$(
      "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get endpointslice \
        -l "kubernetes.io/service-name=$RENDERER_SERVICE" -o json \
        | jq '[.items[].endpoints[]?.addresses[]?] | length'
    )"
    if [[ "$desired_replicas" == "0" && "$pod_count" == "0" \
      && "$endpoint_address_count" == "0" ]]
    then
      return
    fi
    sleep 1
  done
  fail "renderer Pods or Service endpoints did not drain"
}

disable_renderer() {
  local annotation_state
  local desired_replicas
  local now
  local renderer_json
  local restore_replicas

  renderer_json="$(
    "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get \
      "deployment/$RENDERER_DEPLOYMENT" -o json
  )"
  desired_replicas="$(jq -r '.spec.replicas // 0' <<<"$renderer_json")"
  annotation_state="$(
    jq -r --arg key "$STATE_ANNOTATION" \
      '.metadata.annotations[$key] // ""' <<<"$renderer_json"
  )"
  restore_replicas="$(
    jq -r --arg key "$RESTORE_ANNOTATION" \
      '.metadata.annotations[$key] // ""' <<<"$renderer_json"
  )"

  if [[ "$desired_replicas" =~ ^[1-9][0-9]*$ ]]; then
    restore_replicas="$desired_replicas"
    "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" annotate \
      "deployment/$RENDERER_DEPLOYMENT" \
      "$RESTORE_ANNOTATION=$restore_replicas" --overwrite >/dev/null
  elif [[ "$desired_replicas" != "0" \
    || ! "$restore_replicas" =~ ^[1-9][0-9]*$ \
    || ( "$annotation_state" != "disabling" && "$annotation_state" != "disabled" ) ]]
  then
    fail "renderer is already down without valid kill-switch restore metadata"
  fi

  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" annotate \
    "deployment/$RENDERER_DEPLOYMENT" \
    "$STATE_ANNOTATION=disabling" \
    "$PROXY_DRAINED_AT_ANNOTATION=pending" --overwrite >/dev/null
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" scale \
    "deployment/$RENDERER_DEPLOYMENT" --replicas=0 >/dev/null
  wait_for_renderer_drained

  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout restart \
    "deployment/$PROXY_DEPLOYMENT" >/dev/null
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout status \
    "deployment/$PROXY_DEPLOYMENT" --timeout=120s >/dev/null
  wait_for_renderer_drained

  now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" annotate \
    "deployment/$RENDERER_DEPLOYMENT" \
    "$STATE_ANNOTATION=disabled" \
    "$DISABLED_AT_ANNOTATION=$now" \
    "$PROXY_DRAINED_AT_ANNOTATION=$now" --overwrite >/dev/null

  wait_for_state disabled
}

enable_renderer() {
  local annotation_state
  local desired_replicas
  local renderer_json
  local restore_replicas
  local state
  local status_json

  status_json="$(cluster_snapshot)"
  state="$(jq -r '.state' <<<"$status_json")"
  if [[ "$state" == "enabled" ]]; then
    printf '%s\n' "$status_json"
    return
  fi

  renderer_json="$(
    "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get \
      "deployment/$RENDERER_DEPLOYMENT" -o json
  )"
  desired_replicas="$(jq -r '.spec.replicas // 0' <<<"$renderer_json")"
  annotation_state="$(
    jq -r --arg key "$STATE_ANNOTATION" \
      '.metadata.annotations[$key] // ""' <<<"$renderer_json"
  )"
  restore_replicas="$(
    jq -r --arg key "$RESTORE_ANNOTATION" \
      '.metadata.annotations[$key] // ""' <<<"$renderer_json"
  )"
  [[ "$restore_replicas" =~ ^[1-9][0-9]*$ \
    && ( "$desired_replicas" == "0" || "$desired_replicas" == "$restore_replicas" ) \
    && ( "$annotation_state" == "disabled" \
      || "$annotation_state" == "disabling" \
      || "$annotation_state" == "enabling" ) ]] \
    || fail "cannot enable renderer without managed kill-switch restore metadata"

  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" annotate \
    "deployment/$RENDERER_DEPLOYMENT" \
    "$STATE_ANNOTATION=enabling" --overwrite >/dev/null
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" scale \
    "deployment/$RENDERER_DEPLOYMENT" \
    --replicas="$restore_replicas" >/dev/null
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" rollout status \
    "deployment/$RENDERER_DEPLOYMENT" --timeout=120s >/dev/null
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" annotate \
    "deployment/$RENDERER_DEPLOYMENT" \
    "$STATE_ANNOTATION=enabled" \
    "$RESTORE_ANNOTATION-" \
    "$DISABLED_AT_ANNOTATION-" \
    "$PROXY_DRAINED_AT_ANNOTATION-" --overwrite >/dev/null

  wait_for_state enabled
}

validate_fixture() {
  local dir="$1"

  for file in \
    renderer-deployment.json \
    renderer-pods.json \
    renderer-endpointslices.json \
    proxy-deployment.json
  do
    require_file "$dir/$file"
  done

  status_from_json \
    "$(<"$dir/renderer-deployment.json")" \
    "$(<"$dir/renderer-pods.json")" \
    "$(<"$dir/renderer-endpointslices.json")" \
    "$(<"$dir/proxy-deployment.json")"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command jq

if [[ "${1:-}" == "--validate-fixture" ]]; then
  [[ "$#" == "2" ]] || fail "--validate-fixture requires one directory"
  validate_fixture "$2"
  exit 0
fi

[[ "$#" == "1" ]] || {
  usage >&2
  exit 2
}
[[ "$WAIT_ATTEMPTS" =~ ^[1-9][0-9]*$ ]] \
  || fail "wait attempts must be a positive integer"
require_command "$KUBECTL_BIN"
require_command date
require_command seq

context="$("$KUBECTL_BIN" config current-context)"
[[ "$context" == "$EXPECTED_CONTEXT" ]] \
  || fail "expected kubectl current-context ${EXPECTED_CONTEXT}, got: ${context}"

case "$1" in
  disable)
    proxy_json="$(
      "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get \
        "deployment/$PROXY_DEPLOYMENT" -o json
    )"
    proxy_is_remote_singleton "$proxy_json" \
      || fail "kill switch requires exactly one proxy replica configured for the authenticated remote renderer"
    disable_renderer
    ;;
  enable)
    proxy_json="$(
      "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get \
        "deployment/$PROXY_DEPLOYMENT" -o json
    )"
    proxy_is_remote_singleton "$proxy_json" \
      || fail "kill switch requires exactly one proxy replica configured for the authenticated remote renderer"
    enable_renderer
    ;;
  status)
    cluster_snapshot
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
