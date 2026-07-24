#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
KIND_BIN="${KIND_BIN:-kind}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_KIND_CONTEXT:-kind-eidolon-shield}"
EXPECTED_UPSTREAM_URL="${EIDOLON_SHIELD_KIND_EXPECTED_UPSTREAM_URL:-http://eidolon-owned-demo-target.shield-targets.svc.cluster.local:9101}"
KIND_CLUSTER_NAME="${EIDOLON_SHIELD_KIND_CLUSTER_NAME:-eidolon-shield}"
PROBE_IMAGE="${EIDOLON_SHIELD_KIND_PROBE_IMAGE:-busybox:1.37.0-musl}"
PROBE_IMAGE_DIGEST="${EIDOLON_SHIELD_KIND_PROBE_IMAGE_DIGEST:-sha256:222ad6d973c0d198014546a65cd02c5fdedcc172123c5b4c2bf0af636550bd94}"
EVIDENCE_PATH="${EIDOLON_SHIELD_KIND_CAPACITY_EVIDENCE_PATH:-/tmp/eidolon-kind-capacity-evidence.json}"
QUIET_SECONDS="${EIDOLON_SHIELD_KIND_CAPACITY_QUIET_SECONDS:-3}"

tmp_dir=""
stress_pod=""
baseline_pod=""
action_pod=""
renderer_args_changed=0

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-controlled-reality-capacity-kind.sh
       examples/shield-lab/smoke-controlled-reality-capacity-kind.sh --validate-fixture DIR

Proves renderer connection, audit, and replay bounds are observable, replay
saturation fails closed with HTTP 503, and no protected-upstream write occurs.
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
          and .probe_id == $probe_id
        )
    ]
    | length
  ' "$file"
}

target_write_count_in_file() {
  local file="$1"

  jq -R -s '
    [
      split("\n")[]
      | fromjson?
      | select(.event == "protected_upstream_probe_observed")
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
  local capacity_probe_count
  local capacity_probe_id
  local followup_request_id
  local target_replica_count
  local target_write_count

  for file in \
    action.log \
    probe-ids.meta \
    proxy-debug.jsonl \
    proxy-events.jsonl \
    renderer-identity.meta \
    renderer.jsonl \
    restoration.meta \
    stress.log \
    target-audit.log \
    target-identity.meta
  do
    [[ -f "$dir/$file" ]] || fail "missing evidence file: $dir/$file"
  done

  require_result "$dir/stress.log" stress_complete true
  require_result "$dir/action.log" entry_status 202
  require_result "$dir/action.log" entry_write_committed false
  require_result "$dir/action.log" followup_status 503
  require_result "$dir/action.log" followup_synthetic true
  require_result "$dir/action.log" followup_write_committed false
  require_result "$dir/renderer-identity.meta" single_replica true
  require_result "$dir/renderer-identity.meta" pod_uid_stable true
  require_result "$dir/renderer-identity.meta" restart_count_stable true
  require_result "$dir/restoration.meta" args_restored true
  require_result "$dir/restoration.meta" renderer_ready true
  require_result "$dir/target-identity.meta" pod_set_stable true
  require_result "$dir/target-identity.meta" restart_count_stable true
  require_result "$dir/target-identity.meta" upstream_verified true

  baseline_probe_id="$(result_value "$dir/probe-ids.meta" baseline_probe_id)"
  capacity_probe_id="$(result_value "$dir/probe-ids.meta" capacity_probe_id)"
  target_replica_count="$(
    result_value "$dir/probe-ids.meta" target_replica_count
  )"
  [[ "$target_replica_count" =~ ^[1-9][0-9]*$ ]] \
    || fail "target replica count was missing or invalid"
  for probe_id in "$baseline_probe_id" "$capacity_probe_id"; do
    [[ ${#probe_id} -le 64 \
      && "$probe_id" =~ ^shield-probe-[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] \
      || fail "probe ID was missing or unsafe: ${probe_id:-none}"
  done
  [[ "$baseline_probe_id" != "$capacity_probe_id" ]] \
    || fail "baseline and capacity probe IDs must differ"

  baseline_probe_count="$(
    target_probe_count_in_file "$dir/target-audit.log" "$baseline_probe_id"
  )"
  capacity_probe_count="$(
    target_probe_count_in_file "$dir/target-audit.log" "$capacity_probe_id"
  )"
  target_write_count="$(target_write_count_in_file "$dir/target-audit.log")"
  [[ "$baseline_probe_count" == "$target_replica_count" ]] \
    || fail "not every protected target replica emitted the write baseline"
  [[ "$capacity_probe_count" == "0" ]] \
    || fail "replay-saturated request reached the protected target"
  [[ "$target_write_count" == "$target_replica_count" ]] \
    || fail "an unexpected write-shaped request reached the protected target"

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
      | [.[] | select(
        .kind.type == "request_seen"
        and .kind.method == "POST"
        and .kind.path == "/api/v1/imports"
        and .kind.routing_decision == "eidolon_owned"
      )] as $followups
      | select(
          ($exposures | length) == 1
          and ($actions | length) == 1
          and ($followups | length) == 1
        )
      | $exposures[0] as $exposure
      | $actions[0] as $action
      | $followups[0] as $followup
      | select(
          ($exposure.request_id | type == "string")
          and ($action.request_id | type == "string")
          and ($followup.request_id | type == "string")
          and $exposure.request_id != $action.request_id
          and $action.request_id != $followup.request_id
          and $exposure.session_id == $action.session_id
          and $action.session_id == $followup.session_id
          and $exposure.kind.exposure_id == $action.kind.exposure_id
        )
      | {
          action_request_id: $action.request_id,
          followup_request_id: $followup.request_id
        }
    ' "$dir/proxy-events.jsonl"
  )" || fail "capacity exposure, action, and follow-up were not uniquely linked"
  action_request_id="$(jq -r '.action_request_id' <<<"$action_link")"
  followup_request_id="$(jq -r '.followup_request_id' <<<"$action_link")"

  jq -e -s --arg request_id "$followup_request_id" '
    any(.[];
      .request_id == $request_id
      and .policy_state == "controlled_reality"
      and .kind.type == "response_served"
      and .kind.status == 503
      and .kind.routing_decision == "eidolon_owned"
      and (.kind.controlled_reality // null) == null
    )
  ' "$dir/proxy-events.jsonl" >/dev/null \
    || fail "replay saturation did not produce a request-linked fail-closed response"

  jq -e -s --arg request_id "$followup_request_id" '
    map(select(
      .event == "controlled_reality_backend_failed"
      and .fields.request_id == $request_id
      and .fields.reason == "malformed_frame"
      and .fields.response_status == 503
      and .fields.local_fallback == false
    ))
    | length == 1
  ' "$dir/proxy-debug.jsonl" >/dev/null \
    || fail "proxy fail-closed backend audit was missing or ambiguous"

  jq -e -s \
    --arg action_request_id "$action_request_id" \
    --arg followup_request_id "$followup_request_id" '
    map(select(.counters != null and .limits != null)) as $records
    | select(($records | length) > 1)
    | select(all($records[];
        .schema_version == 1
        and .component == "eidolon-controlled-reality"
      ))
    | select(all($records[];
        .limits.connection_workers == 1
        and .limits.connection_queue_capacity == 1
        and .limits.audit_queue_capacity == 1
        and .limits.replay_cache_capacity == 1
      ))
    | select(
        any($records[];
          .event == "startup"
          and .counters.connection_queue_saturated_total == 0
          and .counters.audit_events_dropped_total == 0
          and .counters.replay_cache_saturated_total == 0
        )
      )
    | select(
        any($records[];
          .event == "served"
          and .request_id == $action_request_id
          and .status == 202
        )
      )
    | select(
        any($records[];
          .event == "rejected"
          and .request_id == $followup_request_id
          and .reason == "replay_cache_saturated"
        )
      )
    | select(
        ($records | map(.counters.connection_queue_saturated_total) | max) > 0
        and ($records | map(.counters.audit_events_dropped_total) | max) > 0
        and ($records | map(.counters.replay_cache_saturated_total) | max) > 0
      )
    | select(
        [
          range(1; ($records | length)) as $index
          | select(
              $records[$index].counters.connection_queue_saturated_total
                < $records[$index - 1].counters.connection_queue_saturated_total
              or $records[$index].counters.audit_events_dropped_total
                < $records[$index - 1].counters.audit_events_dropped_total
              or $records[$index].counters.replay_cache_saturated_total
                < $records[$index - 1].counters.replay_cache_saturated_total
            )
        ]
        | length == 0
      )
  ' "$dir/renderer.jsonl" >/dev/null \
    || fail "renderer limits or monotonic saturation counters were not proven"

  jq -n \
    --arg verified_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg action_request_id "$action_request_id" \
    --arg followup_request_id "$followup_request_id" \
    --arg baseline_probe_id "$baseline_probe_id" \
    --arg capacity_probe_id "$capacity_probe_id" \
    --argjson target_replica_count "$target_replica_count" \
    '{
      schema_version: 1,
      result: "passed",
      verified_at: $verified_at,
      renderer: {
        configured_limits: {
          connection_workers: 1,
          connection_queue_capacity: 1,
          audit_queue_capacity: 1,
          replay_cache_capacity: 1
        },
        connection_queue_saturated: true,
        audit_events_dropped: true,
        replay_cache_saturated: true,
        counters_monotonic: true,
        process_local: true
      },
      fail_closed: {
        action_request_id: $action_request_id,
        followup_request_id: $followup_request_id,
        followup_status: 503,
        local_fallback: false
      },
      protected_upstream: {
        replicas_audited: $target_replica_count,
        baseline_probe_id: $baseline_probe_id,
        baseline_requests_observed: $target_replica_count,
        capacity_probe_id: $capacity_probe_id,
        capacity_requests_observed: 0
      },
      deployment_restored: true
    }'
}

patch_renderer_args() {
  local args_file="$1"
  local patch

  patch="$(
    jq -c '[
      {
        op: "replace",
        path: "/spec/template/spec/containers/0/args",
        value: .
      }
    ]' "$args_file"
  )"
  "$KUBECTL_BIN" -n shield-controlled-reality patch deployment \
    eidolon-controlled-reality --type=json -p "$patch" >/dev/null
}

restore_renderer() {
  local current_args
  local original_args

  [[ "$renderer_args_changed" == "1" ]] || return
  patch_renderer_args "$tmp_dir/original-renderer-args.json"
  "$KUBECTL_BIN" -n shield-controlled-reality rollout status \
    deployment/eidolon-controlled-reality --timeout=120s >/dev/null
  current_args="$(
    "$KUBECTL_BIN" -n shield-controlled-reality get deployment \
      eidolon-controlled-reality -o json \
      | jq -c '.spec.template.spec.containers[0].args'
  )"
  original_args="$(jq -c . "$tmp_dir/original-renderer-args.json")"
  [[ "$current_args" == "$original_args" ]] \
    || fail "renderer arguments were not restored exactly"
  printf 'args_restored=true\nrenderer_ready=true\n' \
    >"$tmp_dir/restoration.meta"
  renderer_args_changed=0
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e

  for pod in "$stress_pod" "$baseline_pod" "$action_pod"; do
    [[ -n "$pod" ]] \
      && "$KUBECTL_BIN" -n shield-system delete pod "$pod" \
        --ignore-not-found --wait=false >/dev/null 2>&1
  done
  if [[ "$renderer_args_changed" == "1" && -n "$tmp_dir" ]]; then
    patch_renderer_args "$tmp_dir/original-renderer-args.json" >/dev/null 2>&1
    "$KUBECTL_BIN" -n shield-controlled-reality rollout status \
      deployment/eidolon-controlled-reality --timeout=120s >/dev/null 2>&1
  fi
  [[ -n "$tmp_dir" ]] && rm -rf "$tmp_dir"
  exit "$status"
}

wait_for_pod_completion() {
  local namespace="$1"
  local name="$2"
  local phase

  for _ in $(seq 1 90); do
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

wait_for_stress_completion() {
  for _ in $(seq 1 120); do
    if "$KUBECTL_BIN" -n shield-system logs "$stress_pod" 2>/dev/null \
      | grep -Fxq 'stress_complete=true'
    then
      return
    fi
    sleep 1
  done
  "$KUBECTL_BIN" -n shield-system logs "$stress_pod" >&2 || true
  fail "renderer stress pod did not complete its load phase"
}

wait_for_single_renderer() {
  local pods

  for _ in $(seq 1 60); do
    pods="$(
      "$KUBECTL_BIN" -n shield-controlled-reality get pods \
        -l app.kubernetes.io/name=eidolon-controlled-reality -o json \
        | jq -r '
            .items
            | map(select(
                .metadata.deletionTimestamp == null
                and .status.phase == "Running"
                and any(.status.conditions[]?;
                  .type == "Ready" and .status == "True"
                )
              ))
            | .[].metadata.name
          '
    )"
    if [[ "$(printf '%s\n' "$pods" | grep -c .)" == "1" ]]; then
      printf '%s\n' "$pods"
      return
    fi
    sleep 1
  done
  fail "capacity proof requires exactly one ready renderer pod"
}

capture_target_audit() {
  local output_file="$1"
  local pod
  local expected_uid
  local expected_restarts
  local first_line
  local pod_ip
  local current_uid
  local current_restarts
  local current_pods

  : >"$output_file"
  current_pods="$(
    "$KUBECTL_BIN" -n shield-targets get pods \
      -l app.kubernetes.io/name=eidolon-owned-demo-target \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
      | sort
  )"
  [[ "$current_pods" == "$(<"$tmp_dir/target-pods.txt")" ]] \
    || fail "protected target pod set changed during capacity proof"
  while IFS=$'\t' read -r \
    pod expected_uid expected_restarts first_line pod_ip
  do
    [[ -n "$pod" ]] || continue
    current_uid="$(
      "$KUBECTL_BIN" -n shield-targets get pod "$pod" -o jsonpath='{.metadata.uid}'
    )"
    current_restarts="$(
      "$KUBECTL_BIN" -n shield-targets get pod "$pod" \
        -o jsonpath='{.status.containerStatuses[0].restartCount}'
    )"
    [[ "$current_uid" == "$expected_uid" ]] \
      || fail "protected target pod changed during capacity proof: $pod"
    [[ "$current_restarts" == "$expected_restarts" ]] \
      || fail "protected target restarted during capacity proof: $pod"
    "$KUBECTL_BIN" -n shield-targets logs "$pod" \
      --all-containers=true --tail=-1 \
      | tail -n "+${first_line}" >>"$output_file"
  done <"$tmp_dir/target-snapshot.tsv"
}

capture_proxy_file_from_line() {
  local file="$1"
  local first_line="$2"

  "$KUBECTL_BIN" -n shield-system exec deploy/eidolon-shield-proxy -- \
    tail -n "+${first_line}" "/var/lib/eidolon/${file}"
}

create_baseline_probe() {
  local node="$1"
  local target_ips="$2"
  local probe_id="$3"
  local probe_script

  probe_script='
    set -eu
    body="{\"source\":\"capacity-baseline\",\"mode\":\"synthetic\"}"
    for target_ip in $TARGET_IPS; do
      {
        printf "POST /api/v1/imports HTTP/1.1\r\n"
        printf "Host: eidolon-owned-demo-target\r\n"
        printf "X-Shield-Lab-Probe: %s\r\n" "$PROBE_ID"
        printf "Content-Type: application/json\r\n"
        printf "Content-Length: %s\r\n" "${#body}"
        printf "Connection: close\r\n\r\n"
        printf "%s" "$body"
      } | nc -n -w 5 "$target_ip" 9101 >/dev/null
    done
  '

  jq -n \
    --arg name "$baseline_pod" \
    --arg node "$node" \
    --arg image "$PROBE_IMAGE" \
    --arg target_ips "$target_ips" \
    --arg probe_id "$probe_id" \
    --arg probe_script "$probe_script" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {"app.kubernetes.io/name": "eidolon-kind-capacity-baseline"}
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
            {name: "TARGET_IPS", value: $target_ips},
            {name: "PROBE_ID", value: $probe_id}
          ]
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

create_stress_pod() {
  local node="$1"
  local renderer_ip="$2"
  local stress_script

  stress_script='
    set -eu
    for _ in 1 2 3 4; do
      (sleep 4 | nc -n -w 6 "$RENDERER_IP" 9103 >/dev/null 2>&1 || true) &
    done
    sleep 1
    round=0
    while [ "$round" -lt 3 ]; do
      worker=0
      while [ "$worker" -lt 8 ]; do
        (
          request=0
          while [ "$request" -lt 300 ]; do
            printf "malformed\n" \
              | nc -n -w 1 "$RENDERER_IP" 9103 >/dev/null 2>&1 || true
            request=$((request + 1))
          done
        ) &
        worker=$((worker + 1))
      done
      wait || true
      round=$((round + 1))
    done
    echo "stress_complete=true"
    sleep 300
  '

  jq -n \
    --arg name "$stress_pod" \
    --arg node "$node" \
    --arg image "$PROBE_IMAGE" \
    --arg renderer_ip "$renderer_ip" \
    --arg stress_script "$stress_script" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {"app.kubernetes.io/name": "eidolon-shield-proxy"}
      },
      spec: {
        nodeName: $node,
        automountServiceAccountToken: false,
        restartPolicy: "Never",
        containers: [{
          name: "stress",
          image: $image,
          imagePullPolicy: "Never",
          command: ["sh", "-c", $stress_script],
          env: [{name: "RENDERER_IP", value: $renderer_ip}]
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

create_action_probe() {
  local node="$1"
  local proxy_ip="$2"
  local probe_id="$3"
  local action_script

  action_script='
    set -eu
    request() {
      output="$1"
      shift
      {
        "$@"
      } | nc -n -w 5 "$PROXY_IP" 9102 >"$output.raw"
      tr -d "\r" <"$output.raw" >"$output"
    }

    request /tmp/exposure \
      printf "GET /docs/legacy-import HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nConnection: close\r\n\r\n"
    cookie="$(
      sed -n "s/^[Ss]et-[Cc]ookie:[[:space:]]*eidolon_session=\([^;[:space:]]*\).*/\1/p" \
        /tmp/exposure | head -n 1
    )"
    marker="$(grep -Eo "mig_w[0-9a-f]+_[0-9a-f]+" /tmp/exposure | head -n 1)"
    test -n "$cookie"
    test -n "$marker"

    request /tmp/entry \
      printf "POST /api/v2/import/reconcile HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nX-Migration-Trace: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" \
        "$cookie" "$marker"
    awk "NR == 1 { print \"entry_status=\" \$2 }" /tmp/entry
    if grep -Fq "\"write_committed\":false" /tmp/entry; then
      echo "entry_write_committed=false"
    else
      echo "entry_write_committed=unknown"
    fi

    body="{\"source\":\"capacity-followup\",\"mode\":\"synthetic\"}"
    {
      printf "POST /api/v1/imports HTTP/1.1\r\n"
      printf "Host: eidolon-shield-proxy\r\n"
      printf "Cookie: eidolon_session=%s\r\n" "$cookie"
      printf "X-Shield-Lab-Probe: %s\r\n" "$PROBE_ID"
      printf "Content-Type: application/json\r\n"
      printf "Content-Length: %s\r\n" "${#body}"
      printf "Connection: close\r\n\r\n"
      printf "%s" "$body"
    } | nc -n -w 5 "$PROXY_IP" 9102 > /tmp/followup.raw
    tr -d "\r" < /tmp/followup.raw > /tmp/followup
    awk "NR == 1 { print \"followup_status=\" \$2 }" /tmp/followup
    if grep -Fq "\"synthetic\":true" /tmp/followup; then
      echo "followup_synthetic=true"
    else
      echo "followup_synthetic=false"
    fi
    if grep -Fq "\"write_committed\":false" /tmp/followup; then
      echo "followup_write_committed=false"
    else
      echo "followup_write_committed=unknown"
    fi
  '

  jq -n \
    --arg name "$action_pod" \
    --arg node "$node" \
    --arg image "$PROBE_IMAGE" \
    --arg proxy_ip "$proxy_ip" \
    --arg probe_id "$probe_id" \
    --arg action_script "$action_script" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {"app.kubernetes.io/name": "eidolon-kind-capacity-action"}
      },
      spec: {
        nodeName: $node,
        automountServiceAccountToken: false,
        restartPolicy: "Never",
        containers: [{
          name: "probe",
          image: $image,
          imagePullPolicy: "Never",
          command: ["sh", "-c", $action_script],
          env: [
            {name: "PROXY_IP", value: $proxy_ip},
            {name: "PROBE_ID", value: $probe_id}
          ]
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
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
[[ "$QUIET_SECONDS" =~ ^[1-9][0-9]*$ ]] \
  || fail "quiet period must be a positive integer"

for command_name in \
  "$KUBECTL_BIN" "$KIND_BIN" "$DOCKER_BIN" \
  cut date grep jq mktemp sed seq sort tail tr wc
do
  require_command "$command_name"
done

context="$("$KUBECTL_BIN" config current-context)"
[[ "$context" == "$EXPECTED_CONTEXT" ]] \
  || fail "expected kubectl current-context ${EXPECTED_CONTEXT}, got: ${context}"
"$KIND_BIN" get clusters | grep -Fxq "$KIND_CLUSTER_NAME" \
  || fail "kind cluster ${KIND_CLUSTER_NAME} is not running"

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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-capacity.XXXXXX")"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

suffix="$(date -u +%H%M%S)-$$"
stress_pod="eidolon-capacity-stress-${suffix}"
baseline_pod="eidolon-capacity-baseline-${suffix}"
action_pod="eidolon-capacity-action-${suffix}"
baseline_probe_id="shield-probe-capacity-baseline-${suffix}"
capacity_probe_id="shield-probe-capacity-action-${suffix}"

renderer_replicas="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get deployment \
    eidolon-controlled-reality -o json \
    | jq -r '[.spec.replicas, .status.replicas, .status.availableReplicas] | @tsv'
)"
[[ "$renderer_replicas" == $'1\t1\t1' ]] \
  || fail "capacity proof requires one available renderer replica"

"$KUBECTL_BIN" -n shield-controlled-reality get deployment \
  eidolon-controlled-reality -o json \
  | jq '.spec.template.spec.containers[0].args' \
  >"$tmp_dir/original-renderer-args.json"
jq -e '
  all(.[];
    . != "--connection-workers"
    and . != "--connection-queue-capacity"
    and . != "--audit-queue-capacity"
    and . != "--replay-cache-capacity"
  )
' "$tmp_dir/original-renderer-args.json" >/dev/null \
  || fail "renderer deployment already contains capacity overrides"
jq '
  . + [
      "--connection-workers", "1",
      "--connection-queue-capacity", "1",
      "--audit-queue-capacity", "1",
      "--replay-cache-capacity", "1"
    ]
' "$tmp_dir/original-renderer-args.json" >"$tmp_dir/stress-renderer-args.json"
patch_renderer_args "$tmp_dir/stress-renderer-args.json"
renderer_args_changed=1
"$KUBECTL_BIN" -n shield-controlled-reality rollout status \
  deployment/eidolon-controlled-reality --timeout=120s >/dev/null

renderer_pod="$(wait_for_single_renderer)"
renderer_uid="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.metadata.uid}'
)"
renderer_restarts="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}'
)"
renderer_ip="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.status.podIP}'
)"
node="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.spec.nodeName}'
)"
proxy_ip="$(
  "$KUBECTL_BIN" -n shield-system get pod \
    -l app.kubernetes.io/name=eidolon-shield-proxy \
    -o jsonpath='{.items[0].status.podIP}'
)"
[[ -n "$renderer_uid" && -n "$renderer_restarts" && -n "$renderer_ip" \
  && -n "$node" && -n "$proxy_ip" ]] \
  || fail "could not resolve live kind capacity inputs"

"$KUBECTL_BIN" -n shield-system get deployment eidolon-shield-proxy -o json \
  | jq -e '
      .spec.template.spec.containers[]
      | select(.name == "shield-proxy")
      | .args as $args
      | [
          range(0; $args | length) as $index
          | select($args[$index] == "--upstream")
          | $args[$index + 1]
        ] == ["$(EIDOLON_UPSTREAM_TARGET)"]
        and any(.env[];
          .name == "EIDOLON_UPSTREAM_TARGET"
          and .valueFrom.configMapKeyRef.name == "eidolon-shield-proxy-config"
          and .valueFrom.configMapKeyRef.key == "EIDOLON_UPSTREAM_TARGET"
        )
    ' >/dev/null \
  || fail "proxy upstream argument is not sourced from the expected config"
actual_upstream_url="$(
  "$KUBECTL_BIN" -n shield-system get configmap eidolon-shield-proxy-config \
    -o jsonpath='{.data.EIDOLON_UPSTREAM_TARGET}'
)"
[[ "$actual_upstream_url" == "$EXPECTED_UPSTREAM_URL" ]] \
  || fail "proxy upstream config does not match the owned target Service"

: >"$tmp_dir/target-snapshot.tsv"
"$KUBECTL_BIN" -n shield-targets get pods \
  -l app.kubernetes.io/name=eidolon-owned-demo-target \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
  | sort >"$tmp_dir/target-pods.txt"
[[ -s "$tmp_dir/target-pods.txt" ]] || fail "no protected target pods were found"
while IFS= read -r pod; do
  uid="$(
    "$KUBECTL_BIN" -n shield-targets get pod "$pod" -o jsonpath='{.metadata.uid}'
  )"
  restarts="$(
    "$KUBECTL_BIN" -n shield-targets get pod "$pod" \
      -o jsonpath='{.status.containerStatuses[0].restartCount}'
  )"
  lines="$(
    "$KUBECTL_BIN" -n shield-targets logs "$pod" \
      --all-containers=true --tail=-1 | wc -l
  )"
  pod_ip="$(
    "$KUBECTL_BIN" -n shield-targets get pod "$pod" \
      -o jsonpath='{.status.podIP}'
  )"
  [[ -n "$uid" && -n "$restarts" && -n "$pod_ip" ]] \
    || fail "protected target snapshot was incomplete: $pod"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$pod" "$uid" "$restarts" "$((lines + 1))" "$pod_ip" \
    >>"$tmp_dir/target-snapshot.tsv"
done <"$tmp_dir/target-pods.txt"
target_replica_count="$(wc -l <"$tmp_dir/target-snapshot.tsv" | tr -d ' ')"
target_ips="$(cut -f 5 "$tmp_dir/target-snapshot.tsv" | tr '\n' ' ')"
target_pod_ips_sorted="$(cut -f 5 "$tmp_dir/target-snapshot.tsv" | sort)"
target_endpoint_ips_sorted="$(
  "$KUBECTL_BIN" -n shield-targets get endpointslice \
    -l kubernetes.io/service-name=eidolon-owned-demo-target -o json \
    | jq -r '.items[].endpoints[]?.addresses[]?' \
    | sort
)"
[[ "$target_endpoint_ips_sorted" == "$target_pod_ips_sorted" ]] \
  || fail "owned target Service endpoints do not match the audited target pods"
printf 'baseline_probe_id=%s\ncapacity_probe_id=%s\ntarget_replica_count=%s\n' \
  "$baseline_probe_id" "$capacity_probe_id" "$target_replica_count" \
  >"$tmp_dir/probe-ids.meta"

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

create_baseline_probe "$node" "$target_ips" "$baseline_probe_id"
wait_for_pod_completion shield-system "$baseline_pod"

baseline_count=0
for _ in $(seq 1 20); do
  capture_target_audit "$tmp_dir/target-audit.log"
  baseline_count="$(
    target_probe_count_in_file "$tmp_dir/target-audit.log" "$baseline_probe_id"
  )"
  [[ "$baseline_count" == "$target_replica_count" ]] && break
  sleep 1
done
[[ "$baseline_count" == "$target_replica_count" ]] \
  || fail "protected target write detector baseline was not observed"

create_stress_pod "$node" "$renderer_ip"
wait_for_stress_completion
"$KUBECTL_BIN" -n shield-system logs "$stress_pod" >"$tmp_dir/stress.log"

create_action_probe "$node" "$proxy_ip" "$capacity_probe_id"
wait_for_pod_completion shield-system "$action_pod"
"$KUBECTL_BIN" -n shield-system logs "$action_pod" >"$tmp_dir/action.log"

"$KUBECTL_BIN" -n shield-system exec "$stress_pod" -- \
  sh -c 'printf "snapshot\n" | nc -n -w 3 "$RENDERER_IP" 9103 >/dev/null 2>&1 || true'
sleep "$QUIET_SECONDS"

capture_target_audit "$tmp_dir/target-audit.log"
printf 'pod_set_stable=true\nrestart_count_stable=true\nupstream_verified=true\n' \
  >"$tmp_dir/target-identity.meta"
capture_proxy_file_from_line events.jsonl "$events_first_line" \
  >"$tmp_dir/proxy-events.jsonl"
capture_proxy_file_from_line debug.jsonl "$debug_first_line" \
  >"$tmp_dir/proxy-debug.jsonl"
"$KUBECTL_BIN" -n shield-controlled-reality logs "$renderer_pod" \
  >"$tmp_dir/renderer.jsonl"

current_renderer_pods="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pods \
    -l app.kubernetes.io/name=eidolon-controlled-reality -o json \
    | jq -r '
        .items
        | map(select(
            .metadata.deletionTimestamp == null
            and .status.phase == "Running"
            and any(.status.conditions[]?;
              .type == "Ready" and .status == "True"
            )
          ))
        | .[].metadata.name
      '
)"
[[ "$current_renderer_pods" == "$renderer_pod" ]] \
  || fail "renderer pod set changed during capacity proof"
[[ "$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.metadata.uid}'
)" == "$renderer_uid" ]] || fail "renderer pod changed during capacity proof"
[[ "$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}'
)" == "$renderer_restarts" ]] || fail "renderer restarted during capacity proof"
printf 'single_replica=true\npod_uid_stable=true\nrestart_count_stable=true\n' \
  >"$tmp_dir/renderer-identity.meta"

"$KUBECTL_BIN" -n shield-system delete pod "$stress_pod" \
  --ignore-not-found --wait=false >/dev/null
stress_pod=""
restore_renderer

validate_evidence "$tmp_dir" >"$tmp_dir/validation.json"
mkdir -p "$(dirname "$EVIDENCE_PATH")"
cp "$tmp_dir/validation.json" "$EVIDENCE_PATH"
cat "$tmp_dir/validation.json"
