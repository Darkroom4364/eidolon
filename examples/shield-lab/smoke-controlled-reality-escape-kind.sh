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
EVIDENCE_PATH="${EIDOLON_SHIELD_KIND_ESCAPE_EVIDENCE_PATH:-/tmp/eidolon-kind-escape-evidence.json}"
QUIET_SECONDS="${EIDOLON_SHIELD_KIND_ESCAPE_QUIET_SECONDS:-3}"

tmp_dir=""
baseline_pod=""
escape_pod=""

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-controlled-reality-escape-kind.sh
       examples/shield-lab/smoke-controlled-reality-escape-kind.sh --validate-fixture DIR

Proves repeated POST escape attempts from a controlled session stay synthetic,
become blocked, and generate zero protected-upstream write requests.
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
  local baseline_probe_id
  local escape_probe_id
  local baseline_probe_count
  local baseline_status_count
  local escape_probe_count
  local target_replica_count
  local target_write_count
  local action_link
  local escape_link
  local first_escape_request_id
  local session_id

  for file in \
    probe-ids.meta \
    target-identity.meta \
    renderer-identity.meta \
    baseline.log \
    escape.log \
    target-audit.log \
    proxy-events.jsonl \
    renderer.jsonl
  do
    [[ -f "$dir/$file" ]] || fail "missing evidence file: $dir/$file"
  done

  require_result "$dir/target-identity.meta" pod_uid_stable true
  require_result "$dir/target-identity.meta" restart_count_stable true
  require_result "$dir/target-identity.meta" upstream_verified true
  require_result "$dir/renderer-identity.meta" single_replica true
  require_result "$dir/renderer-identity.meta" pod_uid_stable true
  require_result "$dir/renderer-identity.meta" restart_count_stable true
  require_result "$dir/escape.log" entry_status 202
  require_result "$dir/escape.log" entry_write_committed false
  require_result "$dir/escape.log" first_escape_status 404
  require_result "$dir/escape.log" first_escape_synthetic true
  require_result "$dir/escape.log" second_escape_status 403

  baseline_probe_id="$(result_value "$dir/probe-ids.meta" baseline_probe_id)"
  escape_probe_id="$(result_value "$dir/probe-ids.meta" escape_probe_id)"
  target_replica_count="$(
    result_value "$dir/probe-ids.meta" target_replica_count
  )"
  [[ "$target_replica_count" =~ ^[1-9][0-9]*$ ]] \
    || fail "target replica count was missing or invalid"
  for probe_id in "$baseline_probe_id" "$escape_probe_id"; do
    [[ ${#probe_id} -le 64 \
      && "$probe_id" =~ ^shield-probe-[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] \
      || fail "probe ID was missing or unsafe: ${probe_id:-none}"
  done
  [[ "$baseline_probe_id" != "$escape_probe_id" ]] \
    || fail "baseline and escape probe IDs must differ"

  baseline_probe_count="$(
    target_probe_count_in_file "$dir/target-audit.log" "$baseline_probe_id"
  )"
  escape_probe_count="$(
    target_probe_count_in_file "$dir/target-audit.log" "$escape_probe_id"
  )"
  target_write_count="$(target_write_count_in_file "$dir/target-audit.log")"
  baseline_status_count="$(
    grep -Fxc 'target_status=202' "$dir/baseline.log" || true
  )"
  [[ "$baseline_status_count" == "$target_replica_count" ]] \
    || fail "not every target replica returned the expected baseline status"
  [[ "$baseline_probe_count" == "$target_replica_count" ]] \
    || fail "not every target replica emitted the protected-write baseline"
  [[ "$escape_probe_count" == "0" ]] \
    || fail "controlled-session escape reached a protected write route"
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
          exposure_request_id: $exposure.request_id,
          session_id: $action.session_id
        }
    ' "$dir/proxy-events.jsonl"
  )" || fail "controlled-reality entry evidence was missing or ambiguously linked"
  session_id="$(jq -r '.session_id' <<<"$action_link")"

  escape_link="$(
    jq -c -e -s --arg session_id "$session_id" '
      [.[] | select(
        .session_id == $session_id
        and .kind.type == "reality_escape_attempt"
        and .kind.method == "POST"
        and .kind.path == "/api/v1/imports"
        and .kind.routing_decision == "controlled_reality"
      )] as $escapes
      | select(
          ($escapes | length) == 2
          and ($escapes[0].request_id | type == "string")
          and ($escapes[1].request_id | type == "string")
          and $escapes[0].request_id != $escapes[1].request_id
        )
      | {
          first_request_id: $escapes[0].request_id,
          second_request_id: $escapes[1].request_id
        }
    ' "$dir/proxy-events.jsonl"
  )" || fail "POST escape attempts were missing, duplicated, or misrouted"
  first_escape_request_id="$(jq -r '.first_request_id' <<<"$escape_link")"

  jq -e -s \
    --arg session_id "$session_id" \
    --arg first_id "$first_escape_request_id" \
    --arg second_id "$(jq -r '.second_request_id' <<<"$escape_link")" '
    any(.[];
        .session_id == $session_id
        and .request_id == $first_id
        and .policy_state == "controlled_reality"
        and .kind.type == "response_served"
        and .kind.status == 404
        and .kind.routing_decision == "controlled_reality"
      )
      and any(.[];
        .session_id == $session_id
        and .request_id == $second_id
        and .kind.type == "policy_changed"
        and .kind.from == "controlled_reality"
        and .kind.to == "blocked"
        and .persistence.post_containment_persistence_kind
          == "controlled_reality_branch_escape"
      )
      and any(.[];
        .session_id == $session_id
        and .request_id == $second_id
        and .policy_state == "blocked"
        and .kind.type == "response_served"
        and .kind.status == 403
        and .kind.routing_decision == "eidolon_owned"
      )
  ' "$dir/proxy-events.jsonl" >/dev/null \
    || fail "POST escape requests did not remain request-linked, synthetic, and blocked"

  jq -e -s --arg request_id "$first_escape_request_id" '
    map(select(
      .event == "served"
      and .request_id == $request_id
      and .status == 404
    ))
    | length == 1
  ' "$dir/renderer.jsonl" >/dev/null \
    || fail "renderer audit did not uniquely match the first POST escape request"

  jq -n \
    --arg verified_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg session_id "$session_id" \
    --arg baseline_probe_id "$baseline_probe_id" \
    --arg escape_probe_id "$escape_probe_id" \
    --argjson target_replica_count "$target_replica_count" \
    '{
      schema_version: 1,
      result: "passed",
      verified_at: $verified_at,
      session_id: $session_id,
      escape: {
        method: "POST",
        path: "/api/v1/imports",
        attempts: 2,
        first_status: 404,
        second_status: 403,
        final_policy_state: "blocked"
      },
      protected_upstream: {
        audit_detector_baselined: true,
        replicas_audited: $target_replica_count,
        baseline_probe_id: $baseline_probe_id,
        baseline_requests_observed: $target_replica_count,
        escape_probe_id: $escape_probe_id,
        escape_requests_observed: 0
      }
    }'
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e

  [[ -n "$baseline_pod" ]] \
    && "$KUBECTL_BIN" -n shield-system delete pod "$baseline_pod" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$escape_pod" ]] \
    && "$KUBECTL_BIN" -n shield-system delete pod "$escape_pod" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$tmp_dir" ]] && rm -rf "$tmp_dir"
  exit "$status"
}

wait_for_pod_completion() {
  local namespace="$1"
  local name="$2"
  local phase

  for _ in $(seq 1 60); do
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
    || fail "owned target pod set changed during the escape proof"
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
      || fail "target pod changed during the escape proof: $pod"
    [[ "$current_restarts" == "$expected_restarts" ]] \
      || fail "target container restarted during the escape proof: $pod"
    "$KUBECTL_BIN" -n shield-targets logs "$pod" \
      --all-containers=true --tail=-1 \
      | tail -n "+${first_line}" >>"$output_file"
  done <"$tmp_dir/target-snapshot.tsv"
}

create_baseline_probe() {
  local node="$1"
  local target_ips="$2"
  local probe_id="$3"
  local probe_script

  probe_script='
    set -eu
    body="{\"source\":\"escape-baseline\",\"mode\":\"synthetic\"}"
    index=0
    for target_ip in $TARGET_IPS; do
      index=$((index + 1))
      {
        printf "POST /api/v1/imports HTTP/1.1\r\n"
        printf "Host: eidolon-owned-demo-target\r\n"
        printf "X-Shield-Lab-Probe: %s\r\n" "$PROBE_ID"
        printf "Content-Type: application/json\r\n"
        printf "Content-Length: %s\r\n" "${#body}"
        printf "Connection: close\r\n\r\n"
        printf "%s" "$body"
      } | nc -n -w 5 "$target_ip" 9101 > "/tmp/response-${index}.raw"
      tr -d "\r" < "/tmp/response-${index}.raw" > "/tmp/response-${index}"
      awk "NR == 1 { print \"target_status=\" \$2 }" "/tmp/response-${index}"
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
        labels: {"app.kubernetes.io/name": "eidolon-kind-escape-baseline"}
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

create_escape_probe() {
  local node="$1"
  local proxy_ip="$2"
  local probe_id="$3"
  local probe_script

  probe_script='
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

    body="{\"source\":\"escape-attempt\",\"mode\":\"synthetic\"}"
    send_escape() {
      output="$1"
      {
        printf "POST /api/v1/imports HTTP/1.1\r\n"
        printf "Host: eidolon-shield-proxy\r\n"
        printf "Cookie: eidolon_session=%s\r\n" "$cookie"
        printf "X-Shield-Lab-Probe: %s\r\n" "$PROBE_ID"
        printf "Content-Type: application/json\r\n"
        printf "Content-Length: %s\r\n" "${#body}"
        printf "Connection: close\r\n\r\n"
        printf "%s" "$body"
      } | nc -n -w 5 "$PROXY_IP" 9102 >"$output.raw"
      tr -d "\r" <"$output.raw" >"$output"
    }

    send_escape /tmp/first
    awk "NR == 1 { print \"first_escape_status=\" \$2 }" /tmp/first
    if grep -Fq "\"synthetic\":true" /tmp/first; then
      echo "first_escape_synthetic=true"
    else
      echo "first_escape_synthetic=false"
    fi

    send_escape /tmp/second
    awk "NR == 1 { print \"second_escape_status=\" \$2 }" /tmp/second
  '

  jq -n \
    --arg name "$escape_pod" \
    --arg node "$node" \
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
        labels: {"app.kubernetes.io/name": "eidolon-kind-escape-probe"}
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-escape.XXXXXX")"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

suffix="$(date -u +%H%M%S)-$$"
baseline_pod="eidolon-escape-baseline-${suffix}"
escape_pod="eidolon-escape-${suffix}"
baseline_probe_id="shield-probe-baseline-${suffix}"
escape_probe_id="shield-probe-escape-${suffix}"

renderer_replicas="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get deployment \
    eidolon-controlled-reality -o json \
    | jq -r '
        [
          .spec.replicas,
          .status.replicas,
          .status.availableReplicas
        ]
        | @tsv
      '
)"
[[ "$renderer_replicas" == $'1\t1\t1' ]] \
  || fail "escape proof requires one available renderer replica"
"$KUBECTL_BIN" -n shield-controlled-reality get pods \
  -l app.kubernetes.io/name=eidolon-controlled-reality \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
  | sort >"$tmp_dir/renderer-pods.txt"
[[ "$(wc -l <"$tmp_dir/renderer-pods.txt" | tr -d ' ')" == "1" ]] \
  || fail "escape proof requires exactly one renderer pod"
renderer_pod="$(<"$tmp_dir/renderer-pods.txt")"
node="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.spec.nodeName}'
)"
renderer_uid="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.metadata.uid}'
)"
renderer_restarts="$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}'
)"
proxy_ip="$(
  "$KUBECTL_BIN" -n shield-system get svc eidolon-shield-proxy \
    -o jsonpath='{.spec.clusterIP}'
)"
[[ -n "$node" && -n "$renderer_uid" && -n "$renderer_restarts" \
  && -n "$proxy_ip" ]] \
  || fail "could not resolve live kind probe inputs"

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
[[ -s "$tmp_dir/target-pods.txt" ]] || fail "no owned target pods were found"
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
    || fail "target pod snapshot was incomplete: $pod"
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
printf 'baseline_probe_id=%s\nescape_probe_id=%s\ntarget_replica_count=%s\n' \
  "$baseline_probe_id" "$escape_probe_id" "$target_replica_count" \
  >"$tmp_dir/probe-ids.meta"
events_before="$(
  "$KUBECTL_BIN" -n shield-system exec deploy/eidolon-shield-proxy -- \
    sh -c 'wc -l < /var/lib/eidolon/events.jsonl'
)"
events_first_line=$((events_before + 1))
renderer_logs_before="$(
  "$KUBECTL_BIN" -n shield-controlled-reality logs "$renderer_pod" \
    | wc -l | tr -d ' '
)"
renderer_first_line=$((renderer_logs_before + 1))

create_baseline_probe "$node" "$target_ips" "$baseline_probe_id"
wait_for_pod_completion shield-system "$baseline_pod"
"$KUBECTL_BIN" -n shield-system logs "$baseline_pod" >"$tmp_dir/baseline.log"

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
  || fail "protected-write audit baseline was not observed"

create_escape_probe "$node" "$proxy_ip" "$escape_probe_id"
wait_for_pod_completion shield-system "$escape_pod"
"$KUBECTL_BIN" -n shield-system logs "$escape_pod" >"$tmp_dir/escape.log"

sleep "$QUIET_SECONDS"
capture_target_audit "$tmp_dir/target-audit.log"
"$KUBECTL_BIN" -n shield-system exec deploy/eidolon-shield-proxy -- \
  tail -n "+${events_first_line}" /var/lib/eidolon/events.jsonl \
  >"$tmp_dir/proxy-events.jsonl"
"$KUBECTL_BIN" -n shield-controlled-reality logs "$renderer_pod" \
  | tail -n "+${renderer_first_line}" \
  >"$tmp_dir/renderer.jsonl"

"$KUBECTL_BIN" -n shield-controlled-reality get pods \
  -l app.kubernetes.io/name=eidolon-controlled-reality \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
  | sort >"$tmp_dir/renderer-pods-after.txt"
[[ "$(<"$tmp_dir/renderer-pods-after.txt")" == "$(<"$tmp_dir/renderer-pods.txt")" ]] \
  || fail "renderer pod set changed during the escape proof"
[[ "$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.metadata.uid}'
)" == "$renderer_uid" ]] || fail "renderer pod changed during the escape proof"
[[ "$(
  "$KUBECTL_BIN" -n shield-controlled-reality get pod "$renderer_pod" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}'
)" == "$renderer_restarts" ]] || fail "renderer restarted during the escape proof"

printf 'pod_uid_stable=true\nrestart_count_stable=true\nupstream_verified=true\n' \
  >"$tmp_dir/target-identity.meta"
printf 'single_replica=true\npod_uid_stable=true\nrestart_count_stable=true\n' \
  >"$tmp_dir/renderer-identity.meta"

validate_evidence "$tmp_dir" >"$tmp_dir/validation.json"
mkdir -p "$(dirname "$EVIDENCE_PATH")"
cp "$tmp_dir/validation.json" "$EVIDENCE_PATH"
cat "$tmp_dir/validation.json"
