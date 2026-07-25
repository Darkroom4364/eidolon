#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
KIND_BIN="${KIND_BIN:-kind}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_KIND_CONTEXT:-kind-eidolon-shield}"
KIND_CLUSTER_NAME="${EIDOLON_SHIELD_KIND_CLUSTER_NAME:-eidolon-shield}"
WHISKER_LOCAL_PORT="${EIDOLON_SHIELD_KIND_WHISKER_LOCAL_PORT:-18091}"
PROBE_IMAGE="${EIDOLON_SHIELD_KIND_PROBE_IMAGE:-busybox:1.37.0-musl}"
PROBE_IMAGE_DIGEST="${EIDOLON_SHIELD_KIND_PROBE_IMAGE_DIGEST:-sha256:222ad6d973c0d198014546a65cd02c5fdedcc172123c5b4c2bf0af636550bd94}"
METADATA_IP="${EIDOLON_SHIELD_KIND_METADATA_IP:-169.254.169.254}"
INTERNET_IP="${EIDOLON_SHIELD_KIND_INTERNET_IP:-1.1.1.1}"
EVIDENCE_PATH="${EIDOLON_SHIELD_KIND_ISOLATION_EVIDENCE_PATH:-/tmp/eidolon-kind-isolation-evidence.json}"
FIXTURE_DIR=""

tmp_dir=""
whisker_forward_pid=""
renderer_node=""
metadata_alias_added=0
metadata_pod=""
positive_pod=""
baseline_pod=""
isolated_pod=""
ingress_probe_pod=""

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-controlled-reality-isolation-kind.sh
       examples/shield-lab/smoke-controlled-reality-isolation-kind.sh --validate-fixture DIR

Runs the live kind boundary proof for the remote controlled-reality renderer.
The fixture mode validates captured evidence without contacting a cluster.
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

policy_match_filter='
  def enforced_policy($name):
    any(
      .policies.enforced[]?;
      (
        .name == $name
        or ((.name // "") | endswith("." + $name))
        or .trigger.name == $name
        or ((.trigger.name // "") | endswith("." + $name))
      )
    );
'

validate_evidence() {
  local dir="$1"
  local metadata
  local flow_started_at
  local isolated_name
  local ingress_name
  local action_link
  local action_request_id
  local exposure_request_id

  for file in \
    metadata.json \
    baseline.log \
    isolated.log \
    ingress.log \
    action.status \
    action.body \
    proxy-events.jsonl \
    renderer.jsonl \
    flows.jsonl
  do
    [[ -f "$dir/$file" ]] || fail "missing evidence file: $dir/$file"
  done

  metadata="$(jq -c -e '
    select(
      (.flow_started_at | type == "string")
      and (.isolated_pod | type == "string" and length > 0)
      and (.ingress_probe_pod | type == "string" and length > 0)
    )
  ' "$dir/metadata.json")" || fail "invalid fixture metadata"
  flow_started_at="$(jq -r '.flow_started_at' <<<"$metadata")"
  isolated_name="$(jq -r '.isolated_pod' <<<"$metadata")"
  ingress_name="$(jq -r '.ingress_probe_pod' <<<"$metadata")"

  for label in target api metadata internet; do
    require_result "$dir/baseline.log" "$label" connected
    require_result "$dir/isolated.log" "$label" blocked
  done
  require_result "$dir/ingress.log" renderer blocked

  [[ "$(<"$dir/action.status")" == "202" ]] \
    || fail "controlled-reality action did not return HTTP 202"
  grep -Fq '"write_committed":false' "$dir/action.body" \
    || fail "controlled-reality action did not prove a synthetic non-write response"

  action_link="$(
    jq -c -e -s '
      [.[]
        | select(
            .kind.type == "bait_exposed"
            and .kind.bait_id == "rel_2025_04_b7f2"
            and .kind.surface == "/docs/legacy-import"
          )
      ] as $exposures
      | [.[]
          | select(
              .kind.type == "bait_action_observed"
              and .kind.bait_id == "rel_2025_04_b7f2"
              and .kind.path == "/api/v2/import/reconcile"
              and .kind.header_value_mint_status == "matched_session_value"
            )
        ] as $actions
      | select(($exposures | length) == 1 and ($actions | length) == 1)
      | $actions[0] as $action
      | $exposures[0] as $exposure
      | select(
          ($action.request_id | type == "string")
          and ($exposure.request_id | type == "string")
          and $action.request_id != $exposure.request_id
          and $action.session_id == $exposure.session_id
          and $action.kind.exposure_id == $exposure.kind.exposure_id
        )
      | {
          action_request_id: $action.request_id,
          exposure_request_id: $exposure.request_id
        }
    ' "$dir/proxy-events.jsonl"
  )" || fail "proxy exposure/action evidence was missing or ambiguously linked"
  action_request_id="$(jq -r '.action_request_id' <<<"$action_link")"
  exposure_request_id="$(jq -r '.exposure_request_id' <<<"$action_link")"

  jq -e -s --arg request_id "$action_request_id" '
    any(.[];
      .request_id == $request_id
      and .kind.type == "request_seen"
      and .kind.method == "POST"
      and .kind.path == "/api/v2/import/reconcile"
    )
    and any(.[];
      .request_id == $request_id
      and .kind.type == "policy_changed"
      and .kind.from == "observe"
      and .kind.to == "controlled_reality"
    )
    and any(.[];
      .request_id == $request_id
      and .kind.type == "response_served"
      and .kind.status == 202
      and .kind.routing_decision == "controlled_reality"
      and .kind.controlled_reality.origin_request_id == $request_id
    )
  ' "$dir/proxy-events.jsonl" >/dev/null \
    || fail "proxy events did not preserve one request-linked controlled-reality chain"

  jq -e -s --arg request_id "$action_request_id" '
    map(
      select(
        .event == "served"
        and .request_id == $request_id
        and .status == 202
      )
    )
    | length == 1
  ' "$dir/renderer.jsonl" >/dev/null \
    || fail "renderer audit did not uniquely match the proxy action request"

  jq -e -s \
    --arg started "$flow_started_at" \
    --arg source "$isolated_name" \
    "${policy_match_filter}"'
      def isolated_deny:
        .action == "Deny"
        and .source_namespace == "shield-controlled-reality"
        and .source_name == $source
        and (.end_time | fromdateiso8601) >= ($started | fromdateiso8601)
        and enforced_policy("controlled-reality-default-deny");
      any(.[]; isolated_deny and .dest_namespace == "shield-targets" and .dest_port == 9101)
      and any(.[]; isolated_deny and .dest_name == "PRIVATE NETWORK" and .dest_port == 6443)
      and any(.[]; isolated_deny and .dest_name == "PUBLIC NETWORK" and .dest_port == 80)
      and any(.[]; isolated_deny and .dest_name == "PUBLIC NETWORK" and .dest_port == 443)
    ' "$dir/flows.jsonl" >/dev/null \
    || fail "Goldmane did not record all four isolated egress denials"

  jq -e -s \
    --arg started "$flow_started_at" \
    --arg source "$ingress_name" \
    "${policy_match_filter}"'
      any(.[];
        .action == "Deny"
        and .source_namespace == "shield-system"
        and .source_name == $source
        and .dest_namespace == "shield-controlled-reality"
        and .dest_port == 9103
        and (.end_time | fromdateiso8601) >= ($started | fromdateiso8601)
        and enforced_policy("controlled-reality-default-deny")
      )
    ' "$dir/flows.jsonl" >/dev/null \
    || fail "Goldmane did not record the unauthorized renderer ingress denial"

  jq -n \
    --arg verified_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg action_request_id "$action_request_id" \
    --arg exposure_request_id "$exposure_request_id" \
    --arg isolated_pod "$isolated_name" \
    --arg ingress_probe_pod "$ingress_name" \
    '{
      schema_version: 1,
      result: "passed",
      verified_at: $verified_at,
      proxy_renderer: {
        action_request_id: $action_request_id,
        exposure_request_id: $exposure_request_id,
        status: 202,
        write_committed: false,
        renderer_audit_correlated: true
      },
      egress: {
        baseline_reachable: ["target", "api", "metadata", "internet"],
        isolated_denied: ["target", "api", "metadata", "internet"],
        source_pod: $isolated_pod,
        denied_flows_correlated: true
      },
      ingress: {
        unauthorized_renderer_access_denied: true,
        source_pod: $ingress_probe_pod,
        denied_flow_correlated: true
      }
    }'
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e

  for pid in "$whisker_forward_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1
      wait "$pid" >/dev/null 2>&1
    fi
  done

  [[ -n "$metadata_pod" ]] \
    && "$KUBECTL_BIN" -n shield-system delete pod "$metadata_pod" \
      --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1
  [[ -n "$positive_pod" ]] \
    && "$KUBECTL_BIN" -n shield-system delete pod "$positive_pod" --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$baseline_pod" ]] \
    && "$KUBECTL_BIN" -n shield-system delete pod "$baseline_pod" --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$isolated_pod" ]] \
    && "$KUBECTL_BIN" -n shield-controlled-reality delete pod "$isolated_pod" --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$ingress_probe_pod" ]] \
    && "$KUBECTL_BIN" -n shield-system delete pod "$ingress_probe_pod" --ignore-not-found --wait=false >/dev/null 2>&1

  if [[ "$metadata_alias_added" == "1" && -n "$renderer_node" ]]; then
    "$DOCKER_BIN" exec "$renderer_node" \
      ip address del "${METADATA_IP}/32" dev lo >/dev/null 2>&1
  fi

  [[ -n "$tmp_dir" ]] && rm -rf "$tmp_dir"
  exit "$status"
}

wait_for_port_forward() {
  local pid="$1"
  local url="$2"
  local log_file="$3"
  local attempt

  for attempt in $(seq 1 40); do
    kill -0 "$pid" >/dev/null 2>&1 \
      || fail "port-forward exited early: $(<"$log_file")"
    if "$CURL_BIN" -sS --max-time 1 -o /dev/null "$url" 2>/dev/null; then
      return
    fi
    sleep 0.25
  done
  fail "port-forward did not become ready: $(<"$log_file")"
}

wait_for_pod_ready() {
  local namespace="$1"
  local name="$2"
  "$KUBECTL_BIN" -n "$namespace" wait \
    --for=condition=Ready "pod/$name" --timeout=60s >/dev/null
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

create_metadata_pod() {
  jq -n \
    --arg name "$metadata_pod" \
    --arg node "$renderer_node" \
    --arg image "$PROBE_IMAGE" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {"app.kubernetes.io/name": "eidolon-kind-metadata-canary"}
      },
      spec: {
        nodeName: $node,
        hostNetwork: true,
        automountServiceAccountToken: false,
        restartPolicy: "Never",
        containers: [{
          name: "metadata",
          image: $image,
          imagePullPolicy: "Never",
          command: ["httpd", "-f", "-p", "80"]
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

create_positive_probe() {
  local proxy_ip="$1"
  local probe_script

  probe_script='
    set -eu
    {
      printf "GET /docs/legacy-import HTTP/1.1\r\n"
      printf "Host: eidolon-shield-proxy\r\n"
      printf "Connection: close\r\n\r\n"
    } | nc -n -w 5 "$PROXY_IP" 9102 > /tmp/exposure.raw
    tr -d "\r" < /tmp/exposure.raw > /tmp/exposure
    grep -Eiq "^Cache-Control:.*private" /tmp/exposure
    grep -Eiq "^Cache-Control:.*no-store" /tmp/exposure
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
      printf "Content-Length: 0\r\n"
      printf "Connection: close\r\n\r\n"
    } | nc -n -w 5 "$PROXY_IP" 9102 > /tmp/action.raw
    tr -d "\r" < /tmp/action.raw > /tmp/action
    status="$(awk "NR == 1 { print \$2 }" /tmp/action)"
    echo "action_status=$status"
    echo "action_body_begin"
    awk "body { print } /^$/ { body = 1 }" /tmp/action
    echo "action_body_end"
  '

  jq -n \
    --arg name "$positive_pod" \
    --arg node "$renderer_node" \
    --arg image "$PROBE_IMAGE" \
    --arg proxy_ip "$proxy_ip" \
    --arg probe_script "$probe_script" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {"app.kubernetes.io/name": "eidolon-kind-positive-probe"}
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
          env: [{name: "PROXY_IP", value: $proxy_ip}]
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

create_boundary_probe() {
  local namespace="$1"
  local name="$2"
  local target_ip="$3"
  local api_ip="$4"
  local renderer_ip="$5"
  local probe_kind="$6"
  local probe_script

  if [[ "$probe_kind" == "renderer" ]]; then
    probe_script='
      if nc -z -w 2 "$RENDERER_IP" 9103 >/dev/null 2>&1; then
        echo "renderer=connected"
      else
        echo "renderer=blocked"
      fi
    '
  else
    probe_script='
      probe() {
        if nc -z -w 2 "$2" "$3" >/dev/null 2>&1; then
          echo "$1=connected"
        else
          echo "$1=blocked"
        fi
      }
      probe target "$TARGET_IP" 9101
      probe api "$API_IP" 443
      probe metadata "$METADATA_IP" 80
      probe internet "$INTERNET_IP" 443
    '
  fi

  jq -n \
    --arg namespace "$namespace" \
    --arg name "$name" \
    --arg node "$renderer_node" \
    --arg image "$PROBE_IMAGE" \
    --arg target_ip "$target_ip" \
    --arg api_ip "$api_ip" \
    --arg renderer_ip "$renderer_ip" \
    --arg metadata_ip "$METADATA_IP" \
    --arg internet_ip "$INTERNET_IP" \
    --arg probe_script "$probe_script" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: $namespace,
        labels: {"app.kubernetes.io/name": "eidolon-kind-boundary-probe"}
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
            {name: "API_IP", value: $api_ip},
            {name: "RENDERER_IP", value: $renderer_ip},
            {name: "METADATA_IP", value: $metadata_ip},
            {name: "INTERNET_IP", value: $internet_ip}
          ]
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

capture_new_proxy_events() {
  local first_line="$1"
  "$KUBECTL_BIN" -n shield-system exec deploy/eidolon-shield-proxy -- \
    tail -n "+${first_line}" /var/lib/eidolon/events.jsonl
}

capture_filtered_flows() {
  local output_file="$1"
  local pipeline_status
  local curl_status
  local sed_status
  local jq_status

  set +e
  "$CURL_BIN" -sS -N --max-time 5 \
    "http://127.0.0.1:${WHISKER_LOCAL_PORT}/whisker-backend/flows?watch=true&startTimeGte=-600" \
    2>"$tmp_dir/whisker-curl.err" \
    | sed -n 's/^data: //p' \
    | jq -c \
        --arg isolated "$isolated_pod" \
        --arg ingress "$ingress_probe_pod" \
        'select(.source_name == $isolated or .source_name == $ingress)' \
        >"$output_file"
  pipeline_status=("${PIPESTATUS[@]}")
  curl_status="${pipeline_status[0]}"
  sed_status="${pipeline_status[1]}"
  jq_status="${pipeline_status[2]}"
  set -e

  [[ "$curl_status" == "0" || "$curl_status" == "28" ]] \
    || fail "Whisker flow read failed: $(<"$tmp_dir/whisker-curl.err")"
  [[ "$sed_status" == "0" && "$jq_status" == "0" ]] \
    || fail "Whisker flow response was malformed"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--validate-fixture" ]]; then
  [[ "$#" == "2" ]] || fail "--validate-fixture requires one directory"
  FIXTURE_DIR="$2"
  require_command jq
  require_command grep
  validate_evidence "$FIXTURE_DIR"
  exit 0
fi

[[ "$#" == "0" ]] || fail "unknown argument: $1"

for command_name in \
  "$KUBECTL_BIN" "$KIND_BIN" "$DOCKER_BIN" "$CURL_BIN" jq grep sed seq date mktemp
do
  require_command "$command_name"
done

context="$("$KUBECTL_BIN" config current-context)"
[[ "$context" == "$EXPECTED_CONTEXT" ]] \
  || fail "expected kubectl current-context ${EXPECTED_CONTEXT}, got: ${context}"

for component in calico goldmane whisker; do
  "$KUBECTL_BIN" wait --for=condition=Available \
    "tigerastatus/$component" --timeout=120s >/dev/null
done
"$KUBECTL_BIN" -n shield-system rollout status \
  deployment/eidolon-shield-proxy --timeout=120s >/dev/null
"$KUBECTL_BIN" -n shield-controlled-reality rollout status \
  deployment/eidolon-controlled-reality --timeout=120s >/dev/null

if ! "$DOCKER_BIN" image inspect "$PROBE_IMAGE" >/dev/null 2>&1; then
  "$DOCKER_BIN" pull "$PROBE_IMAGE" >/dev/null
fi
"$DOCKER_BIN" image inspect \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' "$PROBE_IMAGE" \
  | grep -Fq "@${PROBE_IMAGE_DIGEST}" \
  || fail "probe image ${PROBE_IMAGE} does not match ${PROBE_IMAGE_DIGEST}"
"$KIND_BIN" load docker-image "$PROBE_IMAGE" --name "$KIND_CLUSTER_NAME" >/dev/null

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-isolation.XXXXXX")"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

suffix="$(date -u +%H%M%S)-$$"
metadata_pod="eidolon-metadata-${suffix}"
positive_pod="eidolon-positive-${suffix}"
baseline_pod="eidolon-baseline-${suffix}"
isolated_pod="eidolon-isolated-${suffix}"
ingress_probe_pod="eidolon-ingress-${suffix}"

renderer_node="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod \
    -l app.kubernetes.io/name=eidolon-controlled-reality \
    -o jsonpath='{.items[0].spec.nodeName}'
)"
[[ -n "$renderer_node" ]] || fail "could not resolve the renderer node"

target_ip="$(
  "$KUBECTL_BIN" -n shield-targets get svc eidolon-owned-demo-target \
    -o jsonpath='{.spec.clusterIP}'
)"
api_ip="$(
  "$KUBECTL_BIN" -n default get svc kubernetes \
    -o jsonpath='{.spec.clusterIP}'
)"
renderer_ip="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get svc eidolon-controlled-reality \
    -o jsonpath='{.spec.clusterIP}'
)"
proxy_ip="$(
  "$KUBECTL_BIN" -n shield-system get svc eidolon-shield-proxy \
    -o jsonpath='{.spec.clusterIP}'
)"
for value in "$target_ip" "$api_ip" "$renderer_ip" "$proxy_ip"; do
  [[ -n "$value" && "$value" != "None" ]] || fail "could not resolve a required ClusterIP"
done

target_node_port="$(
  "$KUBECTL_BIN" -n shield-targets get svc eidolon-owned-demo-target \
    -o jsonpath='{.spec.ports[0].nodePort}'
)"
[[ -z "$target_node_port" ]] \
  || fail "kind target unexpectedly exposes NodePort ${target_node_port}"

if ! "$DOCKER_BIN" exec "$renderer_node" \
  ip -o address show dev lo | grep -Fq "${METADATA_IP}/32"; then
  "$DOCKER_BIN" exec "$renderer_node" \
    ip address add "${METADATA_IP}/32" dev lo
  metadata_alias_added=1
fi

create_metadata_pod
wait_for_pod_ready shield-system "$metadata_pod"

"$KUBECTL_BIN" -n calico-system port-forward \
  service/whisker "${WHISKER_LOCAL_PORT}:8081" \
  >"$tmp_dir/whisker-forward.log" 2>&1 &
whisker_forward_pid=$!
wait_for_port_forward \
  "$whisker_forward_pid" \
  "http://127.0.0.1:${WHISKER_LOCAL_PORT}/" \
  "$tmp_dir/whisker-forward.log"

events_before="$(
  "$KUBECTL_BIN" -n shield-system exec deploy/eidolon-shield-proxy -- \
    sh -c 'wc -l < /var/lib/eidolon/events.jsonl'
)"
events_first_line=$((events_before + 1))
renderer_logs_before="$(
  "$KUBECTL_BIN" -n shield-controlled-reality logs \
    deployment/eidolon-controlled-reality | wc -l | tr -d ' '
)"
renderer_first_line=$((renderer_logs_before + 1))

create_positive_probe "$proxy_ip"
wait_for_pod_completion shield-system "$positive_pod"
"$KUBECTL_BIN" -n shield-system logs "$positive_pod" >"$tmp_dir/positive.log"
sed -n 's/^action_status=//p' "$tmp_dir/positive.log" >"$tmp_dir/action.status"
awk '
  /^action_body_begin$/ { body = 1; next }
  /^action_body_end$/ { body = 0 }
  body { print }
' "$tmp_dir/positive.log" >"$tmp_dir/action.body"

capture_new_proxy_events "$events_first_line" >"$tmp_dir/proxy-events.jsonl"
"$KUBECTL_BIN" -n shield-controlled-reality logs \
  deployment/eidolon-controlled-reality \
  | tail -n "+${renderer_first_line}" \
  >"$tmp_dir/renderer.jsonl"

flow_started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
create_boundary_probe shield-system "$baseline_pod" \
  "$target_ip" "$api_ip" "$renderer_ip" boundary
wait_for_pod_completion shield-system "$baseline_pod"
"$KUBECTL_BIN" -n shield-system logs "$baseline_pod" >"$tmp_dir/baseline.log"

create_boundary_probe shield-controlled-reality "$isolated_pod" \
  "$target_ip" "$api_ip" "$renderer_ip" boundary
wait_for_pod_completion shield-controlled-reality "$isolated_pod"
"$KUBECTL_BIN" -n shield-controlled-reality logs "$isolated_pod" >"$tmp_dir/isolated.log"

create_boundary_probe shield-system "$ingress_probe_pod" \
  "$target_ip" "$api_ip" "$renderer_ip" renderer
wait_for_pod_completion shield-system "$ingress_probe_pod"
"$KUBECTL_BIN" -n shield-system logs "$ingress_probe_pod" >"$tmp_dir/ingress.log"

jq -n \
  --arg flow_started_at "$flow_started_at" \
  --arg isolated_pod "$isolated_pod" \
  --arg ingress_probe_pod "$ingress_probe_pod" \
  '{
    flow_started_at: $flow_started_at,
    isolated_pod: $isolated_pod,
    ingress_probe_pod: $ingress_probe_pod
  }' >"$tmp_dir/metadata.json"

for attempt in $(seq 1 8); do
  capture_filtered_flows "$tmp_dir/flows.jsonl"
  if (validate_evidence "$tmp_dir") >"$tmp_dir/validation.json" 2>/dev/null; then
    break
  fi
  [[ "$attempt" != "8" ]] || validate_evidence "$tmp_dir" >/dev/null
  sleep 5
done

mkdir -p "$(dirname "$EVIDENCE_PATH")"
cp "$tmp_dir/validation.json" "$EVIDENCE_PATH"
echo "kind controlled-reality isolation smoke ok: ${EVIDENCE_PATH}"
