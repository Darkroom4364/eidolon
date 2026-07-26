#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
KIND_BIN="${KIND_BIN:-kind}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_KIND_CONTEXT:-kind-eidolon-shield}"
KIND_CLUSTER_NAME="${EIDOLON_SHIELD_KIND_CLUSTER_NAME:-eidolon-shield}"
PROBE_IMAGE="${EIDOLON_SHIELD_KIND_PROBE_IMAGE:-busybox:1.37.0-musl}"
PROBE_IMAGE_DIGEST="${EIDOLON_SHIELD_KIND_PROBE_IMAGE_DIGEST:-sha256:222ad6d973c0d198014546a65cd02c5fdedcc172123c5b4c2bf0af636550bd94}"
EVIDENCE_PATH="${EIDOLON_SHIELD_KIND_LEASE_EVIDENCE_PATH:-/tmp/eidolon-kind-lease-proof-evidence.json}"

PROXY_NAMESPACE="shield-system"
PROXY_DEPLOYMENT="eidolon-shield-proxy"
PROXY_SERVICE="eidolon-shield-proxy"
PROXY_PVC="eidolon-shield-proxy-state"
RENDERER_NAMESPACE="shield-controlled-reality"
RENDERER_DEPLOYMENT="eidolon-controlled-reality"
TARGET_NAMESPACE="shield-targets"
TARGET_SELECTOR="app.kubernetes.io/name=eidolon-owned-demo-target"
LEASE_LOCK="eidolon-overlapping-writer-lease-lock"
LEASE_ERROR_MARKER="durable state already has an active writer"

tmp_dir=""
evidence_dir=""
probe_a=""
interloper=""
lock_acquired=0
proof_complete=0

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-overlapping-writer-lease-kind.sh
       examples/shield-lab/smoke-overlapping-writer-lease-kind.sh --validate-fixture DIR

Starts a second proxy pod pinned to the same node and the same ReadWriteOnce
PVC while the supported single writer holds the durable state lease, and proves
the overlapping writer fails closed at startup, the primary writer never
restart or loses readiness, durable state files stay byte-identical, and the
protected upstream observes zero writes beyond the labelled baseline.
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

sha256_stdin() {
  shasum -a 256 | awk '{print $1}'
}

validate_evidence() {
  local dir="$1"

  for file in \
    lease-proof.json \
    flow.json \
    proxy-debug.jsonl \
    proxy-debug-added.jsonl \
    target-audit.jsonl
  do
    [[ -f "$dir/$file" ]] || fail "missing evidence file: $dir/$file"
  done

  jq -e '
    .schema_version == 1
    and (.primary.pod_uid | type == "string" and length > 0)
    and .primary.node_name == .interloper.node_name
    and .primary.restart_count_before == .primary.restart_count_after
    and .primary.ready_after == true
    and (.interloper.pod_name | type == "string" and length > 0)
    and .interloper.phase == "Failed"
    and .interloper.lease_error_observed == true
    and (.interloper.restart_count | type == "number" and . == 0)
    and (.state.events_digest_before | test("^[0-9a-f]{64}$"))
    and .state.events_digest_before == .state.events_digest_after
    and (.state.debug_lines_before | type == "number" and . >= 0)
    and (.state.debug_lines_after | type == "number")
    and (.state.debug_lines_after >= .state.debug_lines_before)
    and .state.debug_added_records_allowed == true
    and .state.policy_digest_before == .state.policy_digest_after
    and .state.proxy_started_count_before == .state.proxy_started_count_after
    and (.state.proxy_started_count_before | type == "number" and . >= 1)
  ' "$dir/lease-proof.json" >/dev/null \
    || fail "lease evidence did not prove a fail-closed overlap with stable state"

  jq -e '
    .interloper_pod_name | type == "string" and length > 0
  ' "$dir/flow.json" >/dev/null \
    || fail "flow evidence was incomplete"
  jq -e --slurpfile lease "$dir/lease-proof.json" '
    .primary_pod_uid == $lease[0].primary.pod_uid
    and .node_name == $lease[0].primary.node_name
    and .interloper_pod_name == $lease[0].interloper.pod_name
    and .statuses.interloper_failed == true
    and .statuses.primary_ready == true
    and .statuses.state_digests_unchanged == true
    and .statuses.lease_error_observed == true
    and .statuses.proxy_started_unchanged == true
    and (.baseline_probe_id | type == "string" and length > 0)
    and (.target_replica_count | type == "number" and . > 0)
  ' "$dir/flow.json" >/dev/null \
    || fail "flow evidence was inconsistent with the lease proof"

  jq -e -s --slurpfile lease "$dir/lease-proof.json" '
    $lease[0] as $l
    | [.[] | select(.event == "proxy_started")] as $starts
    | ($starts | length) == $l.state.proxy_started_count_after
  ' "$dir/proxy-debug.jsonl" >/dev/null \
    || fail "a new proxy writer started during the overlap attempt"

  jq -e -s '
    all(.[]; .event == "connection_closed_without_request")
  ' "$dir/proxy-debug-added.jsonl" >/dev/null \
    || fail "unexpected debug records were written during the overlap attempt"

  jq -e -s --slurpfile flow "$dir/flow.json" '
    $flow[0] as $f
    | length == $f.target_replica_count
    and all(.[];
      .event == "protected_upstream_probe_observed"
      and .probe_id == $f.baseline_probe_id
    )
  ' "$dir/target-audit.jsonl" >/dev/null \
    || fail "target audit was missing its baseline or observed an unexpected write"

  jq -n \
    --slurpfile lease "$dir/lease-proof.json" \
    --slurpfile flow "$dir/flow.json" \
    '{
      schema_version: 1,
      result: "passed",
      overlapping_writer_failed_closed: true,
      lease_error_observed: true,
      primary_writer_stable: true,
      durable_state_unchanged: true,
      protected_upstream_writes: 0,
      interloper_pod_name: $lease[0].interloper.pod_name,
      primary_pod_uid: $lease[0].primary.pod_uid
    }'
}

wait_for_pod_ready() {
  local namespace="$1"
  local name="$2"
  "$KUBECTL_BIN" -n "$namespace" wait \
    --for=condition=Ready "pod/$name" --timeout=120s >/dev/null
}

create_probe_pod() {
  local name="$1"

  jq -n \
    --arg name "$name" \
    --arg image "$PROBE_IMAGE" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {"app.kubernetes.io/name": "eidolon-lease-proof-probe"}
      },
      spec: {
        automountServiceAccountToken: false,
        enableServiceLinks: false,
        restartPolicy: "Never",
        terminationGracePeriodSeconds: 1,
        securityContext: {
          runAsNonRoot: true,
          runAsUser: 65532,
          runAsGroup: 65532,
          seccompProfile: {type: "RuntimeDefault"}
        },
        containers: [{
          name: "probe",
          image: $image,
          imagePullPolicy: "Never",
          command: ["sleep", "900"],
          securityContext: {
            allowPrivilegeEscalation: false,
            readOnlyRootFilesystem: true,
            capabilities: {drop: ["ALL"]}
          }
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

write_request() {
  local output="$1"
  shift
  printf "$@" >"$output"
  chmod 0600 "$output"
}

send_request() {
  local pod="$1"
  local request_file="$2"
  local response_file="$3"
  local target_ip="$4"
  local target_port="$5"

  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec -i "$pod" -- \
    nc -n -w 8 "$target_ip" "$target_port" \
    <"$request_file" >"$response_file"
  tr -d '\r' <"$response_file" >"$response_file.normalized"
  mv "$response_file.normalized" "$response_file"
  chmod 0600 "$response_file"
}

capture_target_log_positions() {
  local output="$1"
  local pod
  local lines
  local uid

  : >"$output"
  while read -r pod; do
    [[ -n "$pod" ]] || continue
    lines="$("$KUBECTL_BIN" -n "$TARGET_NAMESPACE" logs "$pod" | wc -l | tr -d ' ')"
    uid="$(
      "$KUBECTL_BIN" -n "$TARGET_NAMESPACE" get pod "$pod" \
        -o jsonpath='{.metadata.uid}'
    )"
    printf '%s\t%s\t%s\n' "$pod" "$uid" "$lines" >>"$output"
  done < <(
    "$KUBECTL_BIN" -n "$TARGET_NAMESPACE" get pods -l "$TARGET_SELECTOR" \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort
  )
  [[ -s "$output" ]] || fail "no protected target pods were found"
}

collect_target_audit() {
  local positions="$1"
  local output="$2"
  local pod
  local expected_uid
  local start_line
  local current_uid

  : >"$output"
  while IFS=$'\t' read -r pod expected_uid start_line; do
    current_uid="$(
      "$KUBECTL_BIN" -n "$TARGET_NAMESPACE" get pod "$pod" \
        -o jsonpath='{.metadata.uid}'
    )"
    [[ "$current_uid" == "$expected_uid" ]] \
      || fail "protected target pod changed during lease proof: $pod"
    "$KUBECTL_BIN" -n "$TARGET_NAMESPACE" logs "$pod" \
      | tail -n "+$((start_line + 1))" \
      | jq -R -c --arg pod "$pod" '
          fromjson?
          | select(.event == "protected_upstream_probe_observed")
          | . + {pod: $pod}
        ' >>"$output"
  done <"$positions"
}

state_digest() {
  local state_file="$1"
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- cat "$state_file" | sha256_stdin
}

debug_line_count() {
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- wc -l /var/lib/eidolon/debug.jsonl \
    | awk '{print $1}'
}

proxy_started_count() {
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- cat /var/lib/eidolon/debug.jsonl \
    | jq -s '[.[] | select(.event == "proxy_started")] | length'
}

cleanup() {
  local status=$?

  set +e
  [[ -n "$interloper" ]] \
    && "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete pod "$interloper" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$probe_a" ]] \
    && "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete pod "$probe_a" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  if (( status != 0 && proof_complete == 0 )); then
    "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout status \
      deployment/"$PROXY_DEPLOYMENT" --timeout=60s >/dev/null 2>&1 \
      || echo "warning: proxy deployment was not healthy after the failed proof" >&2
  fi
  if (( lock_acquired )) && (( status == 0 || proof_complete )); then
    "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete configmap "$LEASE_LOCK" \
      --ignore-not-found >/dev/null 2>&1
  fi
  if [[ -n "$tmp_dir" ]] && (( status == 0 || proof_complete )); then
    rm -rf "$tmp_dir"
  elif [[ -n "$tmp_dir" ]]; then
    echo "lease-proof artifacts retained at: $tmp_dir" >&2
    echo "lease lock retained: ${PROXY_NAMESPACE}/${LEASE_LOCK}" >&2
  fi
  exit "$status"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--validate-fixture" ]]; then
  [[ "$#" == "2" ]] || fail "--validate-fixture requires one directory"
  require_command jq
  validate_evidence "$2"
  exit 0
fi

[[ "$#" == "0" ]] || fail "unknown argument: $1"

for command_name in \
  "$KUBECTL_BIN" "$KIND_BIN" "$DOCKER_BIN" \
  awk chmod cut date grep head jq mkdir mktemp mv sed shasum sort tail tr wc
do
  require_command "$command_name"
done

context="$("$KUBECTL_BIN" config current-context)"
[[ "$context" == "$EXPECTED_CONTEXT" ]] \
  || fail "expected kubectl current-context ${EXPECTED_CONTEXT}, got: ${context}"

proxy_strategy="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get deployment "$PROXY_DEPLOYMENT" \
    -o jsonpath='{.spec.strategy.type}'
)"
proxy_replicas="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get deployment "$PROXY_DEPLOYMENT" \
    -o jsonpath='{.spec.replicas}'
)"
renderer_replicas="$(
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get deployment "$RENDERER_DEPLOYMENT" \
    -o jsonpath='{.spec.replicas}'
)"
[[ "$proxy_strategy" == "Recreate" ]] \
  || fail "proxy deployment must use Recreate"
[[ "$proxy_replicas" == "1" ]] \
  || fail "proxy deployment must begin with exactly one replica"
[[ "$renderer_replicas" == "1" ]] \
  || fail "renderer deployment must begin with exactly one replica"

"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout status \
  deployment/"$PROXY_DEPLOYMENT" --timeout=120s >/dev/null
"$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" rollout status \
  deployment/"$RENDERER_DEPLOYMENT" --timeout=120s >/dev/null
"$KUBECTL_BIN" -n "$TARGET_NAMESPACE" rollout status \
  deployment/eidolon-owned-demo-target --timeout=120s >/dev/null

pvc_phase="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pvc "$PROXY_PVC" \
    -o jsonpath='{.status.phase}'
)"
pvc_modes="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pvc "$PROXY_PVC" \
    -o json | jq -c '.spec.accessModes'
)"
[[ "$pvc_phase" == "Bound" && "$pvc_modes" == '["ReadWriteOnce"]' ]] \
  || fail "proxy PVC must be Bound and ReadWriteOnce"

if ! "$DOCKER_BIN" image inspect "$PROBE_IMAGE" >/dev/null 2>&1; then
  "$DOCKER_BIN" pull "$PROBE_IMAGE" >/dev/null
fi
"$DOCKER_BIN" image inspect \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' "$PROBE_IMAGE" \
  | grep -Fq "@${PROBE_IMAGE_DIGEST}" \
  || fail "probe image ${PROBE_IMAGE} does not match ${PROBE_IMAGE_DIGEST}"
"$KIND_BIN" load docker-image "$PROBE_IMAGE" --name "$KIND_CLUSTER_NAME" >/dev/null

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-lease-proof.XXXXXX")"
chmod 0700 "$tmp_dir"
evidence_dir="$tmp_dir/evidence"
mkdir -m 0700 "$evidence_dir"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_id="$(date -u +%H%M%S)-$$"
probe_a="eidolon-lease-probe-${run_id}"
interloper="eidolon-lease-interloper-${run_id}"
baseline_probe_id="shield-probe-lease-baseline-${run_id}"

if ! "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" create configmap "$LEASE_LOCK" \
  --from-literal="run-id=$run_id" >/dev/null 2>&1; then
  fail "lease lock already exists: ${PROXY_NAMESPACE}/${LEASE_LOCK}"
fi
lock_acquired=1

# Capture the primary writer's identity, node, restart count, and state facts.
primary_pod_json="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pods \
    -l app.kubernetes.io/name="$PROXY_DEPLOYMENT" -o json \
    | jq -e 'select(.items | length == 1) | .items[0]'
)"
primary_pod_uid="$(jq -r '.metadata.uid' <<<"$primary_pod_json")"
primary_node="$(jq -r '.spec.nodeName' <<<"$primary_pod_json")"
primary_restart_count_before="$(
  jq -r '[.status.containerStatuses[].restartCount] | add' <<<"$primary_pod_json"
)"
[[ -n "$primary_pod_uid" && -n "$primary_node" && "$primary_node" != "null" ]] \
  || fail "could not resolve the primary proxy pod identity"

events_digest_before="$(state_digest /var/lib/eidolon/events.jsonl)"
debug_lines_before="$(debug_line_count)"
policy_digest_before="$(state_digest /var/lib/eidolon/policy-state.json)"
started_count_before="$(proxy_started_count)"

create_probe_pod "$probe_a"
wait_for_pod_ready "$PROXY_NAMESPACE" "$probe_a"
capture_target_log_positions "$tmp_dir/target-positions.tsv"
target_replica_count="$(wc -l <"$tmp_dir/target-positions.tsv" | tr -d ' ')"

while IFS=$'\t' read -r target_pod _ _; do
  target_ip="$(
    "$KUBECTL_BIN" -n "$TARGET_NAMESPACE" get pod "$target_pod" \
      -o jsonpath='{.status.podIP}'
  )"
  write_request "$tmp_dir/baseline.request" \
    'POST /api/v2/import/reconcile HTTP/1.1\r\nHost: eidolon-owned-demo-target\r\nX-Shield-Lab-Probe: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
    "$baseline_probe_id"
  send_request "$probe_a" "$tmp_dir/baseline.request" \
    "$tmp_dir/baseline.response" "$target_ip" 9101
done <"$tmp_dir/target-positions.tsv"

# Start the overlapping writer on the same node and the same PVC.
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get deployment "$PROXY_DEPLOYMENT" -o json \
  | jq -n \
    --arg name "$interloper" \
    --arg node "$primary_node" \
    --slurpfile deployment /dev/stdin \
    '($deployment[0].spec.template.spec) as $spec
    | {
        apiVersion: "v1",
        kind: "Pod",
        metadata: {
          name: $name,
          namespace: "shield-system",
          labels: {"app.kubernetes.io/name": "eidolon-lease-interloper"}
        },
        spec: ($spec * {
          restartPolicy: "Never",
          nodeName: $node,
          terminationGracePeriodSeconds: 1
        })
      }' \
  | "$KUBECTL_BIN" apply -f - >/dev/null

interloper_phase=""
deadline=$((SECONDS + 120))
while (( SECONDS < deadline )); do
  interloper_phase="$(
    "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pod "$interloper" \
      -o jsonpath='{.status.phase}' 2>/dev/null || true
  )"
  [[ "$interloper_phase" == "Failed" || "$interloper_phase" == "Succeeded" ]] \
    && break
  sleep 2
done
[[ "$interloper_phase" == "Failed" ]] \
  || fail "overlapping writer did not fail closed (phase: ${interloper_phase:-unknown})"

interloper_logs="$("$KUBECTL_BIN" -n "$PROXY_NAMESPACE" logs "$interloper" \
  --tail=50 2>/dev/null || true)"
grep -q "$LEASE_ERROR_MARKER" <<<"$interloper_logs" \
  || fail "overlapping writer failed without the lease marker"
interloper_restart_count="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pod "$interloper" \
    -o json | jq '[.status.containerStatuses[]?.restartCount] | add // 0'
)"
[[ "$interloper_restart_count" == "0" ]] \
  || fail "overlapping writer restarted instead of failing once"

# The primary writer must be untouched: same pod, no restarts, ready, and
# every durable state file byte-identical with no new writer start.
primary_pod_json_after="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pods \
    -l app.kubernetes.io/name="$PROXY_DEPLOYMENT" -o json \
    | jq -e 'select(.items | length == 1) | .items[0]'
)"
[[ "$(jq -r '.metadata.uid' <<<"$primary_pod_json_after")" == "$primary_pod_uid" ]] \
  || fail "primary proxy pod identity changed during the overlap attempt"
primary_restart_count_after="$(
  jq -r '[.status.containerStatuses[].restartCount] | add' <<<"$primary_pod_json_after"
)"
[[ "$primary_restart_count_after" == "$primary_restart_count_before" ]] \
  || fail "primary proxy restarted during the overlap attempt"
primary_ready="$(
  jq -r '[.status.conditions[] | select(.type == "Ready") | .status] | first' \
    <<<"$primary_pod_json_after"
)"
[[ "$primary_ready" == "True" ]] \
  || fail "primary proxy lost readiness during the overlap attempt"

events_digest_after="$(state_digest /var/lib/eidolon/events.jsonl)"
debug_lines_after="$(debug_line_count)"
policy_digest_after="$(state_digest /var/lib/eidolon/policy-state.json)"
started_count_after="$(proxy_started_count)"
[[ "$events_digest_after" == "$events_digest_before" ]] \
  || fail "event log changed during the overlap attempt"
(( debug_lines_after >= debug_lines_before )) \
  || fail "debug log shrank during the overlap attempt"
# Kubelet tcpSocket probes append connection_closed_without_request records;
# anything beyond that probe-noise class means a real writer was active.
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  tail -n "+$((debug_lines_before + 1))" /var/lib/eidolon/debug.jsonl \
  >"$evidence_dir/proxy-debug-added.jsonl"
jq -e -s 'all(.[]; .event == "connection_closed_without_request")' \
  "$evidence_dir/proxy-debug-added.jsonl" >/dev/null \
  || fail "unexpected debug records were written during the overlap attempt"
[[ "$policy_digest_after" == "$policy_digest_before" ]] \
  || fail "policy state changed during the overlap attempt"
[[ "$started_count_after" == "$started_count_before" ]] \
  || fail "a new proxy writer started during the overlap attempt"

collect_target_audit "$tmp_dir/target-positions.tsv" "$evidence_dir/target-audit.jsonl"

"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  cat /var/lib/eidolon/debug.jsonl \
  | jq -c 'select(.event == "proxy_started")' \
  >"$evidence_dir/proxy-debug.jsonl"

jq -n \
  --arg pod_uid "$primary_pod_uid" \
  --arg node "$primary_node" \
  --argjson restarts_before "$primary_restart_count_before" \
  --argjson restarts_after "$primary_restart_count_after" \
  --arg interloper "$interloper" \
  --arg phase "$interloper_phase" \
  --argjson interloper_restarts "$interloper_restart_count" \
  --arg events_before "$events_digest_before" \
  --arg events_after "$events_digest_after" \
  --argjson debug_before "$debug_lines_before" \
  --argjson debug_after "$debug_lines_after" \
  --arg policy_before "$policy_digest_before" \
  --arg policy_after "$policy_digest_after" \
  --argjson started_before "$started_count_before" \
  --argjson started_after "$started_count_after" \
  '{
    schema_version: 1,
    primary: {
      pod_uid: $pod_uid,
      node_name: $node,
      restart_count_before: $restarts_before,
      restart_count_after: $restarts_after,
      ready_after: true
    },
    interloper: {
      pod_name: $interloper,
      node_name: $node,
      phase: $phase,
      lease_error_observed: true,
      restart_count: $interloper_restarts
    },
    state: {
      events_digest_before: $events_before,
      events_digest_after: $events_after,
      debug_lines_before: $debug_before,
      debug_lines_after: $debug_after,
      debug_added_records_allowed: true,
      policy_digest_before: $policy_before,
      policy_digest_after: $policy_after,
      proxy_started_count_before: $started_before,
      proxy_started_count_after: $started_after
    }
  }' >"$evidence_dir/lease-proof.json"

jq -n \
  --arg primary_pod_uid "$primary_pod_uid" \
  --arg node "$primary_node" \
  --arg interloper "$interloper" \
  --arg baseline_probe_id "$baseline_probe_id" \
  --argjson target_replica_count "$target_replica_count" \
  '{
    primary_pod_uid: $primary_pod_uid,
    node_name: $node,
    interloper_pod_name: $interloper,
    baseline_probe_id: $baseline_probe_id,
    statuses: {
      interloper_failed: true,
      primary_ready: true,
      state_digests_unchanged: true,
      lease_error_observed: true,
      proxy_started_unchanged: true
    },
    target_replica_count: $target_replica_count
  }' >"$evidence_dir/flow.json"

proof_complete=1
validate_evidence "$evidence_dir" | tee "$EVIDENCE_PATH"
chmod 0600 "$EVIDENCE_PATH"
