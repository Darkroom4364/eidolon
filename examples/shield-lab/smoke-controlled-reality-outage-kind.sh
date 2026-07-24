#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
KIND_BIN="${KIND_BIN:-kind}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_KIND_CONTEXT:-kind-eidolon-shield}"
KIND_CLUSTER_NAME="${EIDOLON_SHIELD_KIND_CLUSTER_NAME:-eidolon-shield}"
PROBE_IMAGE="${EIDOLON_SHIELD_KIND_PROBE_IMAGE:-busybox:1.37.0-musl}"
PROBE_IMAGE_DIGEST="${EIDOLON_SHIELD_KIND_PROBE_IMAGE_DIGEST:-sha256:222ad6d973c0d198014546a65cd02c5fdedcc172123c5b4c2bf0af636550bd94}"
EVIDENCE_PATH="${EIDOLON_SHIELD_KIND_OUTAGE_EVIDENCE_PATH:-/tmp/eidolon-kind-outage-evidence.json}"
OUTAGE_QUIET_SECONDS="${EIDOLON_SHIELD_KIND_OUTAGE_QUIET_SECONDS:-5}"

tmp_dir=""
target_probe_pod=""
outage_probe_pod=""
renderer_node=""
renderer_original_replicas=""
renderer_scaled_down=0
target_logs_first_line=1
target_pod=""

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-controlled-reality-outage-kind.sh
       examples/shield-lab/smoke-controlled-reality-outage-kind.sh --validate-fixture DIR

Proves a valid bait-derived action fails closed when the remote renderer is
unavailable and sends zero requests to the protected upstream.
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

require_result() {
  local file="$1"
  local label="$2"
  local expected="$3"

  grep -Fxq "${label}=${expected}" "$file" \
    || fail "expected ${label}=${expected} in ${file}"
}

result_value() {
  local file="$1"
  local label="$2"

  sed -n "s/^${label}=//p" "$file" | tail -n 1
}

target_probe_count_in_file() {
  local file="$1"
  local probe_id="$2"

  jq -R -s --arg probe_id "$probe_id" '
    [
      split("\n")[]
      | fromjson?
      | select(
          .event == "protected_upstream_probe_observed"
          and .method == "POST"
          and .route == "api_v2_import_reconcile"
          and .probe_id == $probe_id
        )
    ]
    | length
  ' "$file"
}

target_reconcile_count_in_file() {
  local file="$1"

  jq -R -s '
    [
      split("\n")[]
      | fromjson?
      | select(
          .event == "protected_upstream_probe_observed"
          and .method == "POST"
          and .route == "api_v2_import_reconcile"
        )
    ]
    | length
  ' "$file"
}

validate_evidence() {
  local dir="$1"
  local action_link
  local action_request_id
  local baseline_probe_count
  local baseline_probe_id
  local exposure_request_id
  local outage_probe_count
  local outage_probe_id
  local target_reconcile_count

  for file in \
    action.meta \
    action.body \
    proxy-events.jsonl \
    proxy-debug.jsonl \
    target-audit.log \
    target-probes.meta
  do
    [[ -f "$dir/$file" ]] || fail "missing evidence file: $dir/$file"
  done

  require_result "$dir/action.meta" action_status 503
  require_result "$dir/action.meta" cache_control "private, no-store"
  require_result "$dir/action.meta" cache_private true
  require_result "$dir/action.meta" cache_no_store true
  require_result "$dir/action.meta" eidolon_synthetic true
  jq -e '
    . == {
      status: "unavailable",
      synthetic: true,
      write_committed: false,
      message: "controlled reality renderer unavailable"
    }
  ' "$dir/action.body" >/dev/null \
    || fail "renderer outage body did not preserve fixed synthetic non-write semantics"

  baseline_probe_id="$(result_value "$dir/target-probes.meta" baseline_probe_id)"
  outage_probe_id="$(result_value "$dir/target-probes.meta" outage_probe_id)"
  [[ ${#baseline_probe_id} -le 64 \
    && "$baseline_probe_id" =~ ^shield-probe-[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] \
    || fail "baseline probe ID was missing or unsafe"
  [[ ${#outage_probe_id} -le 64 \
    && "$outage_probe_id" =~ ^shield-probe-[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] \
    || fail "outage probe ID was missing or unsafe"
  [[ "$baseline_probe_id" != "$outage_probe_id" ]] \
    || fail "baseline and outage probe IDs must differ"

  baseline_probe_count="$(
    target_probe_count_in_file "$dir/target-audit.log" "$baseline_probe_id"
  )"
  outage_probe_count="$(
    target_probe_count_in_file "$dir/target-audit.log" "$outage_probe_id"
  )"
  target_reconcile_count="$(
    target_reconcile_count_in_file "$dir/target-audit.log"
  )"
  [[ "$baseline_probe_count" == "1" ]] \
    || fail "direct baseline probe was not observed exactly once"
  [[ "$target_reconcile_count" == "1" ]] \
    || fail "unexpected protected reconcile request reached the protected upstream"
  [[ "$outage_probe_count" == "0" ]] \
    || fail "renderer outage action reached the protected upstream"

  action_link="$(
    jq -c -e -s '
      [.[] | select(
        .kind.type == "bait_exposed"
        and .kind.bait_id == "rel_2025_04_b7f2"
        and .kind.surface == "/docs/legacy-import"
      )] as $exposures
      | [.[] | select(
        .kind.type == "bait_action_observed"
        and .kind.bait_id == "rel_2025_04_b7f2"
        and .kind.path == "/api/v2/import/reconcile"
        and .kind.header_value_mint_status == "matched_session_value"
      )] as $actions
      | select(($exposures | length) == 1 and ($actions | length) == 1)
      | $exposures[0] as $exposure
      | $actions[0] as $action
      | select(
          ($exposure.request_id | type == "string")
          and ($action.request_id | type == "string")
          and $exposure.request_id != $action.request_id
          and $exposure.session_id == $action.session_id
          and $exposure.kind.exposure_id == $action.kind.exposure_id
        )
      | {
          action_request_id: $action.request_id,
          exposure_request_id: $exposure.request_id
        }
    ' "$dir/proxy-events.jsonl"
  )" || fail "outage exposure/action evidence was missing or ambiguously linked"
  action_request_id="$(jq -r '.action_request_id' <<<"$action_link")"
  exposure_request_id="$(jq -r '.exposure_request_id' <<<"$action_link")"

  jq -e -s --arg request_id "$action_request_id" '
    any(.[];
      .request_id == $request_id
      and .kind.type == "request_seen"
      and .kind.method == "POST"
      and .kind.path == "/api/v2/import/reconcile"
      and .kind.routing_decision == "eidolon_owned"
    )
    and any(.[];
      .request_id == $request_id
      and .kind.type == "policy_changed"
      and .kind.from == "observe"
      and .kind.to == "controlled_reality"
    )
    and any(.[];
      .request_id == $request_id
      and .policy_state == "controlled_reality"
      and .kind.type == "response_served"
      and .kind.status == 503
      and .kind.routing_decision == "eidolon_owned"
      and (.kind.controlled_reality // null) == null
    )
  ' "$dir/proxy-events.jsonl" >/dev/null \
    || fail "outage response did not remain request-linked and Eidolon-owned"

  jq -e -s --arg request_id "$action_request_id" '
    map(select(
      .event == "controlled_reality_backend_failed"
      and .fields.request_id == $request_id
      and .fields.reason == "connect_failed"
      and .fields.response_status == 503
      and .fields.local_fallback == false
    ))
    | length == 1
  ' "$dir/proxy-debug.jsonl" >/dev/null \
    || fail "outage failure audit was missing or not linked to the action request"

  jq -n \
    --arg verified_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg action_request_id "$action_request_id" \
    --arg baseline_probe_id "$baseline_probe_id" \
    --arg exposure_request_id "$exposure_request_id" \
    --arg outage_probe_id "$outage_probe_id" \
    '{
      schema_version: 1,
      result: "passed",
      verified_at: $verified_at,
      renderer_outage: {
        action_request_id: $action_request_id,
        exposure_request_id: $exposure_request_id,
        status: 503,
        routing_decision: "eidolon_owned",
        local_fallback: false,
        cache_policy: "private_no_store",
        write_committed: false
      },
      protected_upstream: {
        audit_detector_baselined: true,
        baseline_probe_id: $baseline_probe_id,
        baseline_requests_observed: 1,
        outage_probe_id: $outage_probe_id,
        outage_requests_observed: 0
      }
    }'
}

restore_renderer() {
  if [[ "$renderer_scaled_down" != "1" ]]; then
    return
  fi

  "$KUBECTL_BIN" -n shield-controlled-reality scale \
    deployment/eidolon-controlled-reality \
    --replicas="$renderer_original_replicas" >/dev/null
  "$KUBECTL_BIN" -n shield-controlled-reality rollout status \
    deployment/eidolon-controlled-reality --timeout=120s >/dev/null
  renderer_scaled_down=0
}

cleanup() {
  local status=$?
  local restore_status=0
  trap - EXIT INT TERM
  set +e

  restore_renderer
  restore_status=$?
  [[ "$status" != "0" || "$restore_status" == "0" ]] || status=2

  [[ -n "$target_probe_pod" ]] \
    && "$KUBECTL_BIN" -n shield-system delete pod "$target_probe_pod" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$outage_probe_pod" ]] \
    && "$KUBECTL_BIN" -n shield-system delete pod "$outage_probe_pod" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$tmp_dir" ]] && rm -rf "$tmp_dir"
  exit "$status"
}

wait_for_pod_completion() {
  local namespace="$1"
  local name="$2"
  local phase
  local attempt

  for attempt in $(seq 1 60); do
    phase="$(
      "$KUBECTL_BIN" -n "$namespace" get pod "$name" \
        -o jsonpath='{.status.phase}' 2>/dev/null || true
    )"
    case "$phase" in
      Succeeded)
        return
        ;;
      Failed)
        "$KUBECTL_BIN" -n "$namespace" logs "$name" >&2 || true
        fail "probe pod failed: ${namespace}/${name}"
        ;;
    esac
    sleep 1
  done
  fail "probe pod did not complete: ${namespace}/${name}"
}

wait_for_renderer_unavailable() {
  local endpoint_count
  local pod_count
  local attempt

  for attempt in $(seq 1 60); do
    pod_count="$(
      "$KUBECTL_BIN" -n shield-controlled-reality get pods \
        -l app.kubernetes.io/name=eidolon-controlled-reality -o json \
        | jq '.items | length'
    )"
    endpoint_count="$(
      "$KUBECTL_BIN" -n shield-controlled-reality get endpointslice \
        -l kubernetes.io/service-name=eidolon-controlled-reality -o json \
        | jq '[.items[].endpoints[]?.addresses[]?] | length'
    )"
    [[ "$pod_count" == "0" && "$endpoint_count" == "0" ]] && return
    sleep 1
  done
  fail "renderer pods or service endpoints remained after scale-down"
}

capture_target_audit() {
  local output_file="$1"

  "$KUBECTL_BIN" -n shield-targets logs "$target_pod" \
    --all-containers=true --tail=-1 \
    | tail -n "+${target_logs_first_line}" >"$output_file"
}

create_target_probe() {
  local target_ip="$1"
  local probe_id="$2"
  local probe_script

  probe_script='
    {
      printf "POST /api/v2/import/reconcile HTTP/1.1\r\n"
      printf "Host: eidolon-owned-demo-target\r\n"
      printf "X-Shield-Lab-Probe: %s\r\n" "$PROBE_ID"
      printf "Content-Length: 0\r\n"
      printf "Connection: close\r\n\r\n"
    } | nc -n -w 5 "$TARGET_IP" 9101 > /tmp/response.raw
    tr -d "\r" < /tmp/response.raw > /tmp/response
    awk "NR == 1 { print \"target_status=\" \$2 }" /tmp/response
  '

  jq -n \
    --arg name "$target_probe_pod" \
    --arg node "$renderer_node" \
    --arg image "$PROBE_IMAGE" \
    --arg target_ip "$target_ip" \
    --arg probe_id "$probe_id" \
    --arg probe_script "$probe_script" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {"app.kubernetes.io/name": "eidolon-kind-target-audit-probe"}
      },
      spec: {
        nodeName: $node,
        automountServiceAccountToken: false,
        restartPolicy: "Never",
        containers: [{
          name: "probe",
          image: $image,
          imagePullPolicy: "Never",
          command: ["sh", "-c", $probe_script],
          env: [
            {name: "TARGET_IP", value: $target_ip},
            {name: "PROBE_ID", value: $probe_id}
          ]
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

create_outage_probe() {
  local proxy_ip="$1"
  local probe_id="$2"
  local probe_script

  probe_script='
    set -eu
    {
      printf "GET /docs/legacy-import HTTP/1.1\r\n"
      printf "Host: eidolon-shield-proxy\r\n"
      printf "Connection: close\r\n\r\n"
    } | nc -n -w 5 "$PROXY_IP" 9102 > /tmp/exposure.raw
    tr -d "\r" < /tmp/exposure.raw > /tmp/exposure
    cookie="$(
      sed -n "s/^[Ss]et-[Cc]ookie:[[:space:]]*eidolon_session=\([^;[:space:]]*\).*/\1/p" \
        /tmp/exposure | head -n 1
    )"
    marker="$(grep -Eo "mig_w[0-9a-f]+_[0-9a-f]+" /tmp/exposure | head -n 1)"
    test -n "$cookie"
    test -n "$marker"
    {
      printf "POST /api/v2/import/reconcile HTTP/1.1\r\n"
      printf "Host: eidolon-shield-proxy\r\n"
      printf "Cookie: eidolon_session=%s\r\n" "$cookie"
      printf "X-Migration-Trace: %s\r\n" "$marker"
      printf "X-Shield-Lab-Probe: %s\r\n" "$PROBE_ID"
      printf "Content-Length: 0\r\n"
      printf "Connection: close\r\n\r\n"
    } | nc -n -w 5 "$PROXY_IP" 9102 > /tmp/action.raw
    tr -d "\r" < /tmp/action.raw > /tmp/action
    awk "NR == 1 { print \"action_status=\" \$2 }" /tmp/action
    cache_control="$(
      sed -n "s/^[Cc]ache-[Cc]ontrol:[[:space:]]*//p" /tmp/action | head -n 1
    )"
    printf "cache_control=%s\n" "$cache_control"
    if grep -Eiq "^Cache-Control:.*private" /tmp/action; then
      echo "cache_private=true"
    else
      echo "cache_private=false"
    fi
    if grep -Eiq "^Cache-Control:.*no-store" /tmp/action; then
      echo "cache_no_store=true"
    else
      echo "cache_no_store=false"
    fi
    if grep -Eiq "^X-Eidolon-Synthetic:[[:space:]]*true[[:space:]]*$" /tmp/action; then
      echo "eidolon_synthetic=true"
    else
      echo "eidolon_synthetic=false"
    fi
    echo "action_body_begin"
    awk "body { print } /^$/ { body = 1 }" /tmp/action
    echo "action_body_end"
  '

  jq -n \
    --arg name "$outage_probe_pod" \
    --arg node "$renderer_node" \
    --arg image "$PROBE_IMAGE" \
    --arg proxy_ip "$proxy_ip" \
    --arg probe_id "$probe_id" \
    --arg probe_script "$probe_script" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {"app.kubernetes.io/name": "eidolon-kind-outage-probe"}
      },
      spec: {
        nodeName: $node,
        automountServiceAccountToken: false,
        restartPolicy: "Never",
        containers: [{
          name: "probe",
          image: $image,
          imagePullPolicy: "Never",
          command: ["sh", "-c", $probe_script],
          env: [
            {name: "PROXY_IP", value: $proxy_ip},
            {name: "PROBE_ID", value: $probe_id}
          ]
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

capture_proxy_file_from_line() {
  local basename="$1"
  local first_line="$2"

  "$KUBECTL_BIN" -n shield-system exec deploy/eidolon-shield-proxy -- \
    tail -n "+${first_line}" "/var/lib/eidolon/${basename}"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--validate-fixture" ]]; then
  [[ "$#" == "2" ]] || fail "--validate-fixture requires one directory"
  require_command jq
  require_command grep
  validate_evidence "$2"
  exit 0
fi

[[ "$#" == "0" ]] || fail "unknown argument: $1"
[[ "$OUTAGE_QUIET_SECONDS" =~ ^[1-9][0-9]*$ ]] \
  || fail "outage quiet period must be a positive integer"

for command_name in \
  "$KUBECTL_BIN" "$KIND_BIN" "$DOCKER_BIN" jq grep sed seq date mktemp tail wc
do
  require_command "$command_name"
done

context="$("$KUBECTL_BIN" config current-context)"
[[ "$context" == "$EXPECTED_CONTEXT" ]] \
  || fail "expected kubectl current-context ${EXPECTED_CONTEXT}, got: ${context}"

"$KUBECTL_BIN" -n shield-system rollout status \
  deployment/eidolon-shield-proxy --timeout=120s >/dev/null
"$KUBECTL_BIN" -n shield-targets rollout status \
  deployment/eidolon-owned-demo-target --timeout=120s >/dev/null
"$KUBECTL_BIN" -n shield-controlled-reality rollout status \
  deployment/eidolon-controlled-reality --timeout=120s >/dev/null

"$DOCKER_BIN" image inspect \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' "$PROBE_IMAGE" \
  | grep -Fq "@${PROBE_IMAGE_DIGEST}" \
  || fail "probe image ${PROBE_IMAGE} does not match ${PROBE_IMAGE_DIGEST}"
"$KIND_BIN" load docker-image "$PROBE_IMAGE" --name "$KIND_CLUSTER_NAME" >/dev/null

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-outage.XXXXXX")"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

suffix="$(date -u +%H%M%S)-$$"
target_probe_pod="eidolon-target-audit-${suffix}"
outage_probe_pod="eidolon-outage-${suffix}"
baseline_probe_id="shield-probe-baseline-${suffix}"
outage_probe_id="shield-probe-outage-${suffix}"
printf 'baseline_probe_id=%s\noutage_probe_id=%s\n' \
  "$baseline_probe_id" "$outage_probe_id" >"$tmp_dir/target-probes.meta"

renderer_node="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod \
    -l app.kubernetes.io/name=eidolon-controlled-reality \
    -o jsonpath='{.items[0].spec.nodeName}'
)"
target_ip="$(
  "$KUBECTL_BIN" -n shield-targets get svc eidolon-owned-demo-target \
    -o jsonpath='{.spec.clusterIP}'
)"
target_pod="$(
  "$KUBECTL_BIN" -n shield-targets get pod \
    -l app.kubernetes.io/name=eidolon-owned-demo-target \
    -o jsonpath='{.items[0].metadata.name}'
)"
target_pod_uid="$(
  "$KUBECTL_BIN" -n shield-targets get pod "$target_pod" \
    -o jsonpath='{.metadata.uid}'
)"
target_restart_count="$(
  "$KUBECTL_BIN" -n shield-targets get pod "$target_pod" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}'
)"
proxy_ip="$(
  "$KUBECTL_BIN" -n shield-system get svc eidolon-shield-proxy \
    -o jsonpath='{.spec.clusterIP}'
)"
[[ -n "$renderer_node" && -n "$target_ip" && -n "$target_pod" \
  && -n "$target_pod_uid" && -n "$target_restart_count" && -n "$proxy_ip" ]] \
  || fail "could not resolve renderer node, target pod, and required ClusterIPs"
target_logs_before="$(
  "$KUBECTL_BIN" -n shield-targets logs "$target_pod" \
    --all-containers=true --tail=-1 | wc -l
)"
target_logs_first_line=$((target_logs_before + 1))

create_target_probe "$target_ip" "$baseline_probe_id"
wait_for_pod_completion shield-system "$target_probe_pod"
"$KUBECTL_BIN" -n shield-system logs "$target_probe_pod" >"$tmp_dir/target-probe.log"
require_result "$tmp_dir/target-probe.log" target_status 404

baseline_probe_count=0
for attempt in $(seq 1 20); do
  capture_target_audit "$tmp_dir/target-audit.log"
  baseline_probe_count="$(
    target_probe_count_in_file "$tmp_dir/target-audit.log" "$baseline_probe_id"
  )"
  [[ "$baseline_probe_count" == "1" ]] && break
  sleep 1
done
[[ "$baseline_probe_count" == "1" ]] \
  || fail "protected target did not emit exactly one baseline probe audit marker"

events_before="$(
  "$KUBECTL_BIN" -n shield-system exec deploy/eidolon-shield-proxy -- \
    sh -c 'wc -l < /var/lib/eidolon/events.jsonl'
)"
debug_before="$(
  "$KUBECTL_BIN" -n shield-system exec deploy/eidolon-shield-proxy -- \
    sh -c 'wc -l < /var/lib/eidolon/debug.jsonl'
)"
events_first_line=$((events_before + 1))
debug_first_line=$((debug_before + 1))

renderer_original_replicas="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get \
    deployment/eidolon-controlled-reality -o jsonpath='{.spec.replicas}'
)"
[[ "$renderer_original_replicas" =~ ^[1-9][0-9]*$ ]] \
  || fail "renderer deployment must start with at least one replica"
"$KUBECTL_BIN" -n shield-controlled-reality scale \
  deployment/eidolon-controlled-reality --replicas=0 >/dev/null
renderer_scaled_down=1
wait_for_renderer_unavailable

create_outage_probe "$proxy_ip" "$outage_probe_id"
wait_for_pod_completion shield-system "$outage_probe_pod"
"$KUBECTL_BIN" -n shield-system logs "$outage_probe_pod" >"$tmp_dir/outage-probe.log"
grep -E '^(action_status|cache_control|cache_private|cache_no_store|eidolon_synthetic)=' \
  "$tmp_dir/outage-probe.log" >"$tmp_dir/action.meta"
awk '
  /^action_body_begin$/ { body = 1; next }
  /^action_body_end$/ { body = 0 }
  body { print }
' "$tmp_dir/outage-probe.log" >"$tmp_dir/action.body"

capture_proxy_file_from_line events.jsonl "$events_first_line" \
  >"$tmp_dir/proxy-events.jsonl"
capture_proxy_file_from_line debug.jsonl "$debug_first_line" \
  >"$tmp_dir/proxy-debug.jsonl"

for _ in $(seq 1 "$OUTAGE_QUIET_SECONDS"); do
  current_target_pod="$(
    "$KUBECTL_BIN" -n shield-targets get pod \
      -l app.kubernetes.io/name=eidolon-owned-demo-target \
      -o jsonpath='{.items[0].metadata.name}'
  )"
  current_target_pod_uid="$(
    "$KUBECTL_BIN" -n shield-targets get pod "$current_target_pod" \
      -o jsonpath='{.metadata.uid}'
  )"
  current_target_restart_count="$(
    "$KUBECTL_BIN" -n shield-targets get pod "$current_target_pod" \
      -o jsonpath='{.status.containerStatuses[0].restartCount}'
  )"
  [[ "$current_target_pod" == "$target_pod" \
    && "$current_target_pod_uid" == "$target_pod_uid" \
    && "$current_target_restart_count" == "$target_restart_count" ]] \
    || fail "protected target restarted during outage proof"
  capture_target_audit "$tmp_dir/target-audit.log"
  outage_probe_count="$(
    target_probe_count_in_file "$tmp_dir/target-audit.log" "$outage_probe_id"
  )"
  [[ "$outage_probe_count" == "0" ]] \
    || fail "renderer outage action reached the protected upstream"
  sleep 1
done
capture_target_audit "$tmp_dir/target-audit.log"

restore_renderer

validate_evidence "$tmp_dir" >"$tmp_dir/validation.json"
mkdir -p "$(dirname "$EVIDENCE_PATH")"
cp "$tmp_dir/validation.json" "$EVIDENCE_PATH"
echo "kind controlled-reality outage smoke ok: ${EVIDENCE_PATH}"
