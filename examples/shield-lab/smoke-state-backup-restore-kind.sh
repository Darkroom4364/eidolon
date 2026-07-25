#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
KIND_BIN="${KIND_BIN:-kind}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_KIND_CONTEXT:-kind-eidolon-shield}"
KIND_CLUSTER_NAME="${EIDOLON_SHIELD_KIND_CLUSTER_NAME:-eidolon-shield}"
PROBE_IMAGE="${EIDOLON_SHIELD_KIND_PROBE_IMAGE:-busybox:1.37.0-musl}"
PROBE_IMAGE_DIGEST="${EIDOLON_SHIELD_KIND_PROBE_IMAGE_DIGEST:-sha256:222ad6d973c0d198014546a65cd02c5fdedcc172123c5b4c2bf0af636550bd94}"
EVIDENCE_PATH="${EIDOLON_SHIELD_KIND_RECOVERY_EVIDENCE_PATH:-/tmp/eidolon-kind-state-recovery-evidence.json}"

PROXY_NAMESPACE="shield-system"
PROXY_DEPLOYMENT="eidolon-shield-proxy"
PROXY_SERVICE="eidolon-shield-proxy"
PROXY_PVC="eidolon-shield-proxy-state"
RENDERER_NAMESPACE="shield-controlled-reality"
RENDERER_DEPLOYMENT="eidolon-controlled-reality"
TARGET_NAMESPACE="shield-targets"
TARGET_SELECTOR="app.kubernetes.io/name=eidolon-owned-demo-target"
RECOVERY_LOCK="eidolon-state-recovery-lock"

tmp_dir=""
evidence_dir=""
probe_a=""
probe_b=""
helper_pod=""
helper_policy=""
lock_acquired=0
recovery_archive_ready=0
recovery_spec_ready=0
secrets_backed_up=0
secrets_mutated=0
recovery_complete=0
cleanup_recovered=0

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-state-backup-restore-kind.sh
       examples/shield-lab/smoke-state-backup-restore-kind.sh --validate-fixture DIR

Creates non-empty contained and replay-control sessions, quiesces the kind
single-writer deployment, backs up its PVC and exact key Secrets, restores into
a fresh PVC, and proves session, policy, workflow, request-link, and replay
state survived without a protected-upstream write.
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

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

http_status() {
  awk 'NR == 1 { print $2 }' "$1"
}

http_body() {
  awk 'body { print } /^$/ { body = 1 }' "$1"
}

set_cookie_count() {
  grep -Eic '^Set-Cookie:[[:space:]]*eidolon_session=' "$1" || true
}

validate_evidence() {
  local dir="$1"

  for file in \
    recovery.json \
    flow.json \
    policy-before.json \
    policy-restored.json \
    policy-after.json \
    proxy-events.jsonl \
    proxy-debug.jsonl \
    target-audit.jsonl
  do
    [[ -f "$dir/$file" ]] || fail "missing evidence file: $dir/$file"
  done

  jq -e '
    .schema_version == 1
    and .quiesced.proxy_pods == 0
    and .quiesced.proxy_ready_endpoints == 0
    and .quiesced.renderer_pods == 0
    and (.pvc.old_uid | type == "string" and length > 0)
    and (.pvc.new_uid | type == "string" and length > 0)
    and .pvc.old_uid != .pvc.new_uid
    and (.pvc.old_pv_uid | type == "string" and length > 0)
    and (.pvc.new_pv_uid | type == "string" and length > 0)
    and .pvc.old_pv_uid != .pvc.new_pv_uid
    and .pvc.phase == "Bound"
    and .pvc.access_modes == ["ReadWriteOnce"]
    and (.downtime_seconds | type == "number" and . >= 0)
    and (.state.before | length) > 0
    and (.state.before | sort_by(.path)) == (.state.restored | sort_by(.path))
    and any(.state.before[]; .path == "events.jsonl.consumed-proofs.json")
    and (.secrets.before | length) == 6
    and (.secrets.before | sort_by(.namespace, .name, .key))
      == (.secrets.restored | sort_by(.namespace, .name, .key))
    and (
      [.secrets.before[] | "\(.namespace)/\(.name):\(.key)"] | sort
    ) == ([
      "shield-controlled-reality/eidolon-controlled-reality-auth:auth-secret.txt",
      "shield-system/eidolon-bait-signing:signing-secret.txt",
      "shield-system/eidolon-controlled-reality-auth:auth-secret.txt",
      "shield-system/eidolon-session-signing:key-ring.json",
      "shield-system/eidolon-trusted-ingress:continuity-key.txt",
      "shield-system/eidolon-trusted-ingress:transport-auth.txt"
    ] | sort)
    and (
      [.secrets.before[]
       | select(.name == "eidolon-controlled-reality-auth")
       | .sha256] | unique | length
    ) == 1
  ' "$dir/recovery.json" >/dev/null \
    || fail "recovery evidence did not prove a fresh, exact recovery set"

  jq -e '
    .contained_session_id != .control_session_id
    and .exposure_request_id != .action_request_id
    and .action_request_id != .status_request_id
    and .control_seed_request_id != .replay_request_id
    and (.exposure_id | type == "string" and length > 0)
    and (.job_id | type == "string" and length > 0)
    and .status_path == ("/api/v2/import/reconcile/jobs/" + .job_id)
    and .statuses.contained_action == 202
    and .statuses.control_seed == 202
    and .statuses.replay == 403
    and .statuses.status_read == 200
    and .write_committed.contained_action == false
    and .write_committed.status_read == false
    and .post_restore_set_cookie_count == 0
    and (.target_replica_count | type == "number" and . > 0)
  ' "$dir/flow.json" >/dev/null \
    || {
      jq -c . "$dir/flow.json" >&2
      fail "recovery flow outcomes were incomplete or contradictory"
    }

  jq -e --slurpfile flow "$dir/flow.json" '
    .contained.session_id == $flow[0].contained_session_id
    and .contained.persisted == true
    and .contained.policy_state == "controlled_reality"
    and .contained.controlled_reality_depth == 1
    and .contained.controlled_reality_workflow_state == "queued"
    and .contained.controlled_reality_origin_request_id == $flow[0].action_request_id
    and .contained.controlled_reality_pending_update == null
    and .control.session_id == $flow[0].control_session_id
    and .control.persisted == false
    and .control.policy_state == "observe"
    and .control.controlled_reality_depth == 0
    and .control.controlled_reality_workflow_state == "ready"
    and .control.controlled_reality_origin_request_id == null
    and .control.controlled_reality_pending_update == null
  ' "$dir/policy-before.json" >/dev/null \
    || fail "pre-recovery policy state was not the required two-session control"

  jq -e --slurpfile before "$dir/policy-before.json" '
    . == $before[0]
  ' "$dir/policy-restored.json" >/dev/null \
    || fail "restored policy state did not exactly match the quiesced state"

  jq -e --slurpfile flow "$dir/flow.json" '
    .contained.session_id == $flow[0].contained_session_id
    and .contained.persisted == true
    and .contained.policy_state == "controlled_reality"
    and .contained.controlled_reality_workflow_state == "completed"
    and .contained.controlled_reality_origin_request_id == $flow[0].action_request_id
    and .contained.controlled_reality_pending_update == null
    and .control.session_id == $flow[0].control_session_id
    and .control.persisted == false
    and .control.policy_state == "observe"
    and .control.controlled_reality_depth == 0
    and .control.controlled_reality_workflow_state == "ready"
    and .control.controlled_reality_origin_request_id == null
    and .control.controlled_reality_pending_update == null
  ' "$dir/policy-after.json" >/dev/null \
    || fail "post-recovery policy state lost containment or changed the control"

  jq -e -s --slurpfile flow "$dir/flow.json" '
    $flow[0] as $f
    | [.[] | select(
        .session_id == $f.contained_session_id
        and .request_id == $f.exposure_request_id
        and .kind.type == "bait_exposed"
        and .kind.bait_id == "rel_2025_04_b7f2"
        and .kind.exposure_id == $f.exposure_id
      )] as $exposures
    | [.[] | select(
        .session_id == $f.contained_session_id
        and .request_id == $f.action_request_id
        and .kind.type == "bait_action_observed"
        and .kind.header_value_mint_status == "matched_session_value"
        and .kind.exposure_id == $f.exposure_id
      )] as $actions
    | [.[] | select(
        .session_id == $f.control_session_id
        and .request_id == $f.control_seed_request_id
        and .kind.type == "bait_action_observed"
        and .kind.header_value_mint_status == "matched_session_value"
        and .kind.exposure_id == null
      )] as $seeds
    | [.[] | select(
        .session_id == $f.control_session_id
        and .request_id == $f.replay_request_id
        and .kind.type == "bait_action_observed"
        and .kind.header_value_mint_status == "replay_seen"
        and .kind.exposure_id == null
      )] as $replays
    | [.[] | select(
        .session_id == $f.contained_session_id
        and .request_id == $f.action_request_id
        and .kind.type == "response_served"
        and .kind.status == 202
        and .kind.controlled_reality.kind == "job_submitted"
        and .kind.controlled_reality.origin_request_id == $f.action_request_id
        and .kind.controlled_reality.job_id == $f.job_id
      )] as $entries
    | [.[] | select(
        .session_id == $f.contained_session_id
        and .request_id == $f.status_request_id
        and .kind.type == "response_served"
        and .kind.status == 200
        and .kind.controlled_reality.kind == "status_read"
        and .kind.controlled_reality.origin_request_id == $f.action_request_id
        and .kind.controlled_reality.job_id == $f.job_id
      )] as $statuses
    | select(
        ($exposures | length) == 1
        and ($actions | length) == 1
        and ($seeds | length) == 1
        and ($replays | length) == 1
        and ($entries | length) == 1
        and ($statuses | length) == 1
      )
    | select(
        [.[] | select(
          .session_id == $f.control_session_id
          and .kind.type == "policy_changed"
        )] | length == 0
      )
  ' "$dir/proxy-events.jsonl" >/dev/null \
    || fail "event history did not uniquely preserve action and replay causality"

  jq -e -s --slurpfile flow "$dir/flow.json" '
    $flow[0] as $f
    | [.[] | select(
        .event == "session_resolved"
        and .session_id == $f.control_session_id
        and .fields.request_id == $f.replay_request_id
        and .fields.session_source == "cookie"
        and .fields.cookie_outcome == "valid"
        and .fields.key_status == "active"
      )] as $control
    | [.[] | select(
        .event == "session_resolved"
        and .session_id == $f.contained_session_id
        and .fields.request_id == $f.status_request_id
        and .fields.session_source == "cookie"
        and .fields.cookie_outcome == "valid"
        and .fields.key_status == "active"
      )] as $contained
    | ($control | length) == 1 and ($contained | length) == 1
  ' "$dir/proxy-debug.jsonl" >/dev/null \
    || fail "old cookies were not uniquely accepted under the restored active key"

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
    --slurpfile recovery "$dir/recovery.json" \
    --slurpfile flow "$dir/flow.json" \
    '{
      schema_version: 1,
      result: "passed",
      pvc_replaced: true,
      contained_session_preserved: true,
      consumed_proof_rejected_after_restore: true,
      protected_upstream_writes: 0,
      downtime_seconds: $recovery[0].downtime_seconds,
      contained_session_id: $flow[0].contained_session_id,
      control_session_id: $flow[0].control_session_id
    }'
}

wait_for_pod_ready() {
  local namespace="$1"
  local name="$2"
  "$KUBECTL_BIN" -n "$namespace" wait \
    --for=condition=Ready "pod/$name" --timeout=120s >/dev/null
}

wait_for_zero_proxy_endpoints() {
  local deadline=$((SECONDS + 120))
  local endpoint_count
  local pod_count

  while (( SECONDS < deadline )); do
    pod_count="$(
      "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pods \
        -l app.kubernetes.io/name="$PROXY_DEPLOYMENT" -o json \
        | jq '.items | length'
    )"
    endpoint_count="$(
      "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get endpointslice \
        -l kubernetes.io/service-name="$PROXY_SERVICE" -o json \
        | jq '[.items[].endpoints[]? | select(.conditions.ready == true)] | length'
    )"
    if [[ "$pod_count" == "0" && "$endpoint_count" == "0" ]]; then
      return 0
    fi
    sleep 1
  done
  fail "proxy pods or ready endpoints remained after scale-to-zero"
}

wait_for_zero_renderer_pods() {
  local deadline=$((SECONDS + 120))
  local count

  while (( SECONDS < deadline )); do
    count="$(
      "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" get pods \
        -l app.kubernetes.io/name="$RENDERER_DEPLOYMENT" -o json \
        | jq '.items | length'
    )"
    [[ "$count" == "0" ]] && return 0
    sleep 1
  done
  fail "renderer pods remained after scale-to-zero"
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
        labels: {"app.kubernetes.io/name": "eidolon-state-recovery-probe"}
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

create_helper_policy() {
  jq -n \
    --arg name "$helper_policy" \
    --arg run "$helper_policy" \
    '{
      apiVersion: "networking.k8s.io/v1",
      kind: "NetworkPolicy",
      metadata: {name: $name, namespace: "shield-system"},
      spec: {
        podSelector: {matchLabels: {"eidolon.dev/recovery-run": $run}},
        policyTypes: ["Ingress", "Egress"],
        ingress: [],
        egress: []
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
}

create_helper_pod() {
  local read_only="$1"
  local image="$2"

  jq -n \
    --arg name "$helper_pod" \
    --arg run "$helper_policy" \
    --arg image "$image" \
    --arg pvc "$PROXY_PVC" \
    --argjson read_only "$read_only" \
    '{
      apiVersion: "v1",
      kind: "Pod",
      metadata: {
        name: $name,
        namespace: "shield-system",
        labels: {
          "app.kubernetes.io/name": "eidolon-state-recovery-helper",
          "eidolon.dev/recovery-run": $run
        }
      },
      spec: {
        automountServiceAccountToken: false,
        enableServiceLinks: false,
        restartPolicy: "Never",
        activeDeadlineSeconds: 600,
        terminationGracePeriodSeconds: 1,
        securityContext: {
          runAsNonRoot: true,
          runAsUser: 65532,
          runAsGroup: 65532,
          fsGroup: 65532,
          fsGroupChangePolicy: "OnRootMismatch",
          seccompProfile: {type: "RuntimeDefault"}
        },
        containers: [{
          name: "state",
          image: $image,
          imagePullPolicy: "Never",
          command: ["/bin/sh", "-c", "sleep 600"],
          securityContext: {
            allowPrivilegeEscalation: false,
            readOnlyRootFilesystem: true,
            capabilities: {drop: ["ALL"]}
          },
          volumeMounts: [{
            name: "state",
            mountPath: "/state",
            readOnly: $read_only
          }]
        }],
        volumes: [{
          name: "state",
          persistentVolumeClaim: {claimName: $pvc}
        }]
      }
    }' | "$KUBECTL_BIN" apply -f - >/dev/null
  wait_for_pod_ready "$PROXY_NAMESPACE" "$helper_pod"
}

delete_helper_pod() {
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete pod "$helper_pod" \
    --ignore-not-found --wait=true >/dev/null
}

capture_state_manifest() {
  local output="$1"

  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec "$helper_pod" -- /bin/sh -ec '
    cd /state
    names="$(find . -mindepth 1 -maxdepth 1 -print | sed "s#^\./##" | sort)"
    for path in $names; do
      case "$path" in
        policy-state.json.lock)
          continue
          ;;
        events.jsonl|events.jsonl.exposures.json|events.jsonl.exposures.json.tmp|events.jsonl.consumed-proofs.json|events.jsonl.consumed-proofs.json.tmp|debug.jsonl|policy-state.json|policy-state.tmp|policy-state.json.continuity.json|policy-state.json.continuity.json.tmp|interventions.txt)
          ;;
        events.jsonl.*|debug.jsonl.*)
          suffix="${path#*.jsonl.}"
          case "$suffix" in
            ""|*[!0-9]*)
              echo "unsafe archive name: $path" >&2
              exit 1
              ;;
          esac
          ;;
        *)
          echo "unexpected state path: $path" >&2
          exit 1
          ;;
      esac
      [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "unsafe state path: $path" >&2
        exit 1
      }
      digest="$(sha256sum "$path" | awk "{print \$1}")"
      bytes="$(wc -c <"$path" | tr -d " ")"
      printf "%s\t%s\t%s\n" "$path" "$digest" "$bytes"
    done
  ' >"$output"
  [[ -s "$output" ]] || fail "state manifest was empty"
}

write_secret_snapshot() {
  local output_dir="$1"
  mkdir -p "$output_dir"
  chmod 0700 "$output_dir"

  snapshot_secret "$PROXY_NAMESPACE" eidolon-session-signing \
    '["key-ring.json"]' "$output_dir/session-signing.json"
  snapshot_secret "$PROXY_NAMESPACE" eidolon-trusted-ingress \
    '["transport-auth.txt","continuity-key.txt"]' "$output_dir/trusted-ingress.json"
  snapshot_secret "$PROXY_NAMESPACE" eidolon-bait-signing \
    '["signing-secret.txt"]' "$output_dir/bait-signing.json"
  snapshot_secret "$PROXY_NAMESPACE" eidolon-controlled-reality-auth \
    '["auth-secret.txt"]' "$output_dir/proxy-renderer-auth.json"
  snapshot_secret "$RENDERER_NAMESPACE" eidolon-controlled-reality-auth \
    '["auth-secret.txt"]' "$output_dir/renderer-auth.json"
}

snapshot_secret() {
  local namespace="$1"
  local name="$2"
  local expected_keys="$3"
  local output="$4"

  "$KUBECTL_BIN" -n "$namespace" get secret "$name" -o json \
    | jq -e --argjson expected "$expected_keys" '
        select((.data | keys | sort) == ($expected | sort))
        | select(all(.data[]; type == "string" and length > 0))
        | {
            apiVersion: "v1",
            kind: "Secret",
            metadata: {name: .metadata.name, namespace: .metadata.namespace},
            type: .type,
            data: .data
          }
      ' >"$output"
  [[ -s "$output" ]] || fail "Secret ${namespace}/${name} did not contain exactly the required keys"
  chmod 0600 "$output"
}

secret_digest_manifest() {
  local input_dir="$1"
  local output="$2"

  "$PYTHON_BIN" - "$input_dir" "$output" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
records = []
for path in sorted(source.glob("*.json")):
    value = json.loads(path.read_text())
    namespace = value["metadata"]["namespace"]
    name = value["metadata"]["name"]
    for key, encoded in sorted(value["data"].items()):
        raw = base64.b64decode(encoded, validate=True)
        records.append({
            "namespace": namespace,
            "name": name,
            "key": key,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        })
output.write_text(json.dumps(records, sort_keys=True, separators=(",", ":")) + "\n")
PY
}

restore_secrets() {
  local input_dir="$1"
  local file

  for resource in \
    "$PROXY_NAMESPACE/eidolon-session-signing" \
    "$PROXY_NAMESPACE/eidolon-trusted-ingress" \
    "$PROXY_NAMESPACE/eidolon-bait-signing" \
    "$PROXY_NAMESPACE/eidolon-controlled-reality-auth" \
    "$RENDERER_NAMESPACE/eidolon-controlled-reality-auth"
  do
    "$KUBECTL_BIN" -n "${resource%/*}" delete secret "${resource#*/}" \
      --ignore-not-found --wait=true >/dev/null \
      || return 1
  done
  for file in "$input_dir"/*.json; do
    "$KUBECTL_BIN" create -f "$file" >/dev/null \
      || return 1
  done
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

capture_policy_pair() {
  local output="$1"
  local contained_session="$2"
  local control_session="$3"

  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- cat /var/lib/eidolon/policy-state.json \
    | jq -e --arg contained "$contained_session" --arg control "$control_session" '
        (.sessions | map(select(.session_id == $contained)) | first) as $contained_record
        | (.sessions | map(select(.session_id == $control)) | first) as $control_record
        | select($contained_record != null)
        | {
            contained: ($contained_record + {persisted: true}),
            control: (
              ($control_record // {
                session_id: $control,
                policy_state: "observe",
                controlled_reality_depth: 0,
                controlled_reality_workflow_state: "ready",
                controlled_reality_origin_request_id: null,
                controlled_reality_pending_update: null
              }) + {persisted: ($control_record != null)}
            )
          }
      ' >"$output"
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
      || fail "protected target pod changed during recovery smoke: $pod"
    "$KUBECTL_BIN" -n "$TARGET_NAMESPACE" logs "$pod" \
      | tail -n "+$((start_line + 1))" \
      | jq -R -c --arg pod "$pod" '
          fromjson?
          | select(.event == "protected_upstream_probe_observed")
          | . + {pod: $pod}
        ' >>"$output"
  done <"$positions"
}

make_control_proof() {
  local cookie_file="$1"
  local secret_file="$2"
  local proof_file="$3"

  "$PYTHON_BIN" - "$cookie_file" "$secret_file" "$proof_file" <<'PY'
import base64
import hashlib
import hmac
import json
import pathlib
import time
import uuid
import sys

cookie = pathlib.Path(sys.argv[1]).read_text().strip()
secret_resource = json.loads(pathlib.Path(sys.argv[2]).read_text())
secret = base64.b64decode(
    secret_resource["data"]["signing-secret.txt"], validate=True
).decode().strip().encode()
parts = cookie.split(".")
if len(parts) != 5:
    raise SystemExit("unexpected session cookie shape")
session = uuid.UUID(parts[3]).bytes
bucket = int(time.time()) // 300
message = b"\0".join([
    b"eidolon-bait-header-v1",
    session,
    b"rel_2025_04_b7f2",
    b"POST",
    b"/api/v2/import/reconcile",
    b"x-migration-trace",
    str(bucket).encode(),
])
tag = hmac.new(secret, message, hashlib.sha256).hexdigest()[:24]
pathlib.Path(sys.argv[3]).write_text(f"mig_w{bucket:x}_{tag}")
PY
  chmod 0600 "$proof_file"
}

restore_state_archive() {
  local image="$1"

  delete_helper_pod || return 1
  create_helper_pod false "$image" || return 1
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec "$helper_pod" -- /bin/sh -ec '
    find /state -mindepth 1 -maxdepth 1 -type f ! -name policy-state.json.lock -delete
  ' || return 1
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec -i "$helper_pod" -- \
    tar --no-same-owner -C /state -xf - <"$tmp_dir/state.tar" \
    || return 1
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec "$helper_pod" -- sync \
    || return 1
}

recover_cluster() {
  local image="$1"

  set -e
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" scale \
    deployment/"$PROXY_DEPLOYMENT" --replicas=0 >/dev/null 2>&1 \
    || return 1
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" scale \
    deployment/"$RENDERER_DEPLOYMENT" --replicas=0 >/dev/null 2>&1 \
    || return 1
  delete_helper_pod || return 1

  if (( recovery_archive_ready && recovery_spec_ready )); then
    if ! "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pvc "$PROXY_PVC" \
      >/dev/null 2>&1; then
      "$KUBECTL_BIN" create -f "$tmp_dir/pvc.json" >/dev/null 2>&1 \
        || return 1
    fi
    restore_state_archive "$image" >/dev/null 2>&1 || return 1
    capture_state_manifest "$tmp_dir/cleanup-state.tsv" >/dev/null 2>&1 \
      || return 1
    cmp -s "$tmp_dir/state-before.tsv" "$tmp_dir/cleanup-state.tsv" \
      || return 1
  fi
  if (( secrets_mutated )); then
    if [[ -d "$tmp_dir/secrets-quiesced" ]]; then
      restore_secrets "$tmp_dir/secrets-quiesced" >/dev/null 2>&1 \
        || return 1
    else
      restore_secrets "$tmp_dir/secrets-before" >/dev/null 2>&1 \
        || return 1
    fi
  fi
  delete_helper_pod || return 1
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" scale \
    deployment/"$RENDERER_DEPLOYMENT" --replicas=1 >/dev/null 2>&1 \
    || return 1
  "$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" rollout status \
    deployment/"$RENDERER_DEPLOYMENT" --timeout=120s >/dev/null 2>&1 \
    || return 1
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" scale \
    deployment/"$PROXY_DEPLOYMENT" --replicas=1 >/dev/null 2>&1 \
    || return 1
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout status \
    deployment/"$PROXY_DEPLOYMENT" --timeout=120s >/dev/null 2>&1 \
    || return 1
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get deployment "$PROXY_DEPLOYMENT" \
    -o json | jq -e '.status.readyReplicas == 1' >/dev/null
}

cleanup() {
  local status=$?
  local proxy_image=""

  set +e
  if [[ -n "$tmp_dir" && -f "$tmp_dir/proxy-image" ]]; then
    proxy_image="$(<"$tmp_dir/proxy-image")"
  fi
  if (( status != 0 && recovery_complete == 0 )) && [[ -n "$proxy_image" ]]; then
    echo "recovery smoke failed; restoring the captured recovery set" >&2
    if (
      trap - EXIT INT TERM
      recover_cluster "$proxy_image"
    ); then
      cleanup_recovered=1
    fi
  fi
  [[ -n "$probe_a" ]] \
    && "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete pod "$probe_a" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$probe_b" ]] \
    && "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete pod "$probe_b" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$helper_pod" ]] \
    && "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete pod "$helper_pod" \
      --ignore-not-found --wait=false >/dev/null 2>&1
  [[ -n "$helper_policy" ]] \
    && "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete networkpolicy "$helper_policy" \
      --ignore-not-found >/dev/null 2>&1

  if (( lock_acquired )) && (( status == 0 || recovery_complete || cleanup_recovered )); then
    "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete configmap "$RECOVERY_LOCK" \
      --ignore-not-found >/dev/null 2>&1
  fi
  if [[ -n "$tmp_dir" ]] && (( status == 0 || recovery_complete || cleanup_recovered )); then
    rm -rf "$tmp_dir"
  elif [[ -n "$tmp_dir" ]]; then
    echo "recovery artifacts retained at: $tmp_dir" >&2
    echo "recovery lock retained: ${PROXY_NAMESPACE}/${RECOVERY_LOCK}" >&2
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
  "$KUBECTL_BIN" "$KIND_BIN" "$DOCKER_BIN" "$PYTHON_BIN" \
  awk chmod cmp cut date grep head jq mkdir mktemp mv sed shasum sort tail tr wc
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-state-recovery.XXXXXX")"
chmod 0700 "$tmp_dir"
evidence_dir="$tmp_dir/evidence"
mkdir -m 0700 "$evidence_dir"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_id="$(date -u +%H%M%S)-$$"
probe_a="eidolon-recovery-a-${run_id}"
probe_b="eidolon-recovery-b-${run_id}"
helper_pod="eidolon-recovery-helper-${run_id}"
helper_policy="eidolon-recovery-${run_id}"
baseline_probe_id="shield-probe-recovery-baseline-${run_id}"
contained_probe_id="shield-probe-recovery-contained-${run_id}"
replay_probe_id="shield-probe-recovery-replay-${run_id}"

if ! "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" create configmap "$RECOVERY_LOCK" \
  --from-literal="run-id=$run_id" >/dev/null 2>&1; then
  fail "recovery lock already exists: ${PROXY_NAMESPACE}/${RECOVERY_LOCK}"
fi
lock_acquired=1

proxy_image="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get deployment "$PROXY_DEPLOYMENT" \
    -o jsonpath='{.spec.template.spec.containers[0].image}'
)"
[[ -n "$proxy_image" ]] || fail "could not resolve proxy image"
printf '%s' "$proxy_image" >"$tmp_dir/proxy-image"

proxy_ip="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get service "$PROXY_SERVICE" \
    -o jsonpath='{.spec.clusterIP}'
)"
[[ -n "$proxy_ip" && "$proxy_ip" != "None" ]] \
  || fail "could not resolve proxy ClusterIP"

write_secret_snapshot "$tmp_dir/secrets-before"
secret_digest_manifest "$tmp_dir/secrets-before" "$tmp_dir/secrets-before-digests.json"
jq -e '
  [.[] | select(.name == "eidolon-controlled-reality-auth") | .sha256]
  | unique | length == 1
' "$tmp_dir/secrets-before-digests.json" >/dev/null \
  || fail "proxy and renderer auth Secrets do not match"
secrets_backed_up=1

create_probe_pod "$probe_a"
create_probe_pod "$probe_b"
wait_for_pod_ready "$PROXY_NAMESPACE" "$probe_a"
wait_for_pod_ready "$PROXY_NAMESPACE" "$probe_b"
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

write_request "$tmp_dir/a-exposure.request" \
  'GET /docs/legacy-import HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nConnection: close\r\n\r\n'
send_request "$probe_a" "$tmp_dir/a-exposure.request" \
  "$tmp_dir/a-exposure.response" "$proxy_ip" 9102
contained_cookie="$(
  sed -n 's/^[Ss]et-[Cc]ookie:[[:space:]]*eidolon_session=\([^;[:space:]]*\).*/\1/p' \
    "$tmp_dir/a-exposure.response" | head -n 1
)"
contained_proof="$(
  grep -Eo 'mig_w[0-9a-f]+_[0-9a-f]+' "$tmp_dir/a-exposure.response" | head -n 1
)"
[[ -n "$contained_cookie" && -n "$contained_proof" ]] \
  || fail "contained session exposure did not mint a cookie and proof"
contained_session_id="$(cut -d. -f4 <<<"$contained_cookie")"
printf '%s' "$contained_cookie" >"$tmp_dir/a.cookie"
printf '%s' "$contained_proof" >"$tmp_dir/a.proof"
chmod 0600 "$tmp_dir/a.cookie" "$tmp_dir/a.proof"

write_request "$tmp_dir/a-action.request" \
  'POST /api/v2/import/reconcile HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nX-Migration-Trace: %s\r\nX-Shield-Lab-Probe: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
  "$contained_cookie" "$contained_proof" "$contained_probe_id"
send_request "$probe_a" "$tmp_dir/a-action.request" \
  "$tmp_dir/a-action.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/a-action.response")" == "202" ]] \
  || fail "contained action did not return 202"
a_action_body="$(http_body "$tmp_dir/a-action.response")"
job_id="$(jq -r -e '.job_id | select(type == "string" and length > 0)' <<<"$a_action_body")"
status_path="$(jq -r -e '.status_path | select(type == "string" and length > 0)' <<<"$a_action_body")"
jq -e '.status == "queued" and .write_committed == false' <<<"$a_action_body" >/dev/null \
  || fail "contained action response was not a queued non-write"

write_request "$tmp_dir/b-cookie.request" \
  'GET / HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nConnection: close\r\n\r\n'
send_request "$probe_b" "$tmp_dir/b-cookie.request" \
  "$tmp_dir/b-cookie.response" "$proxy_ip" 9102
control_cookie="$(
  sed -n 's/^[Ss]et-[Cc]ookie:[[:space:]]*eidolon_session=\([^;[:space:]]*\).*/\1/p' \
    "$tmp_dir/b-cookie.response" | head -n 1
)"
[[ -n "$control_cookie" ]] || fail "control session did not receive a cookie"
control_session_id="$(cut -d. -f4 <<<"$control_cookie")"
[[ "$contained_session_id" != "$control_session_id" ]] \
  || fail "probe sessions unexpectedly merged"
printf '%s' "$control_cookie" >"$tmp_dir/b.cookie"
chmod 0600 "$tmp_dir/b.cookie"
proof_window_remaining="$((300 - ($(date +%s) % 300)))"
if (( proof_window_remaining < 180 )); then
  echo "waiting ${proof_window_remaining}s for a fresh proof window"
  sleep "$proof_window_remaining"
  sleep 1
fi
make_control_proof "$tmp_dir/b.cookie" \
  "$tmp_dir/secrets-before/bait-signing.json" "$tmp_dir/b.proof"
control_proof="$(<"$tmp_dir/b.proof")"

write_request "$tmp_dir/b-seed.request" \
  'POST /api/v2/import/reconcile HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nX-Migration-Trace: %s\r\nX-Shield-Lab-Probe: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
  "$control_cookie" "$control_proof" "$replay_probe_id"
send_request "$probe_b" "$tmp_dir/b-seed.request" \
  "$tmp_dir/b-seed.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/b-seed.response")" == "202" ]] \
  || fail "unlinked control proof did not receive the synthetic 202"

"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  cat /var/lib/eidolon/events.jsonl >"$tmp_dir/events-before.jsonl"
action_link="$(
  jq -c -e -s \
    --arg contained "$contained_session_id" \
    --arg control "$control_session_id" '
      . as $events
      | ($events | map(select(
          .session_id == $contained
          and .kind.type == "bait_exposed"
          and .kind.bait_id == "rel_2025_04_b7f2"
        )) | last) as $exposure
      | ($events | map(select(
          .session_id == $contained
          and .kind.type == "bait_action_observed"
          and .kind.bait_id == "rel_2025_04_b7f2"
          and .kind.header_value_mint_status == "matched_session_value"
          and .kind.exposure_id == $exposure.kind.exposure_id
        )) | last) as $action
      | ($events | map(select(
          .session_id == $control
          and .kind.type == "bait_action_observed"
          and .kind.bait_id == "rel_2025_04_b7f2"
          and .kind.header_value_mint_status == "matched_session_value"
          and .kind.exposure_id == null
        )) | last) as $seed
      | select(
          $exposure != null and $action != null and $seed != null
          and ([$events[] | select(
            .session_id == $control and .kind.type == "bait_exposed"
          )] | length) == 0
        )
      | {
          exposure_request_id: $exposure.request_id,
          exposure_id: $exposure.kind.exposure_id,
          action_request_id: $action.request_id,
          control_seed_request_id: $seed.request_id
        }
    ' "$tmp_dir/events-before.jsonl"
)" || fail "pre-recovery action linkage was missing or ambiguous"
exposure_request_id="$(jq -r '.exposure_request_id' <<<"$action_link")"
exposure_id="$(jq -r '.exposure_id' <<<"$action_link")"
action_request_id="$(jq -r '.action_request_id' <<<"$action_link")"
control_seed_request_id="$(jq -r '.control_seed_request_id' <<<"$action_link")"

capture_policy_pair "$evidence_dir/policy-before.json" \
  "$contained_session_id" "$control_session_id"
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  cat /var/lib/eidolon/events.jsonl.consumed-proofs.json \
  >"$tmp_dir/consumed-before.json"
control_proof_digest="$(
  "$PYTHON_BIN" - "$tmp_dir/b.proof" <<'PY'
import hashlib
import pathlib
import sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
jq -e --arg session "$control_session_id" --arg digest "$control_proof_digest" '
  any(.consumed[];
    .session_id == $session
    and .bait_id == "rel_2025_04_b7f2"
    and .proof_digest_hex == $digest
  )
' "$tmp_dir/consumed-before.json" >/dev/null \
  || fail "control proof digest was not durably consumed before backup"

old_pvc_json="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pvc "$PROXY_PVC" -o json
)"
old_pvc_uid="$(jq -r '.metadata.uid' <<<"$old_pvc_json")"
old_pv_name="$(jq -r '.spec.volumeName' <<<"$old_pvc_json")"
old_pv_uid="$("$KUBECTL_BIN" get pv "$old_pv_name" -o jsonpath='{.metadata.uid}')"
jq '{
  apiVersion: "v1",
  kind: "PersistentVolumeClaim",
  metadata: {
    name: .metadata.name,
    namespace: .metadata.namespace,
    labels: .metadata.labels
  },
  spec: {
    accessModes: .spec.accessModes,
    resources: .spec.resources,
    storageClassName: .spec.storageClassName,
    volumeMode: .spec.volumeMode
  }
}' <<<"$old_pvc_json" >"$tmp_dir/pvc.json"
recovery_spec_ready=1

downtime_start="$(date +%s)"
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" scale \
  deployment/"$PROXY_DEPLOYMENT" --replicas=0 >/dev/null
wait_for_zero_proxy_endpoints
"$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" scale \
  deployment/"$RENDERER_DEPLOYMENT" --replicas=0 >/dev/null
wait_for_zero_renderer_pods

write_secret_snapshot "$tmp_dir/secrets-quiesced"
secret_digest_manifest \
  "$tmp_dir/secrets-quiesced" "$tmp_dir/secrets-quiesced-digests.json"
cmp -s \
  "$tmp_dir/secrets-before-digests.json" \
  "$tmp_dir/secrets-quiesced-digests.json" \
  || fail "a backup-critical Secret changed before quiescence"

create_helper_policy
create_helper_pod true "$proxy_image"
capture_state_manifest "$tmp_dir/state-before.tsv"
cut -f1 "$tmp_dir/state-before.tsv" \
  | "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec -i "$helper_pod" -- \
      tar -C /state -cf - -T - \
  >"$tmp_dir/state.tar"
[[ -s "$tmp_dir/state.tar" ]] || fail "PVC backup archive was empty"
chmod 0600 "$tmp_dir/state.tar"
recovery_archive_ready=1
delete_helper_pod

"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete pvc "$PROXY_PVC" --wait=true >/dev/null
"$KUBECTL_BIN" create -f "$tmp_dir/pvc.json" >/dev/null
secrets_mutated=1
restore_secrets "$tmp_dir/secrets-quiesced"
restore_state_archive "$proxy_image"
capture_state_manifest "$tmp_dir/state-restored.tsv"
cmp -s "$tmp_dir/state-before.tsv" "$tmp_dir/state-restored.tsv" \
  || fail "restored PVC state manifest differs from backup"
delete_helper_pod

new_pvc_json="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pvc "$PROXY_PVC" -o json
)"
new_pvc_uid="$(jq -r '.metadata.uid' <<<"$new_pvc_json")"
new_pv_name="$(jq -r '.spec.volumeName' <<<"$new_pvc_json")"
new_pv_uid="$("$KUBECTL_BIN" get pv "$new_pv_name" -o jsonpath='{.metadata.uid}')"
new_pvc_phase="$(jq -r '.status.phase' <<<"$new_pvc_json")"
new_pvc_modes="$(jq -c '.spec.accessModes' <<<"$new_pvc_json")"
[[ "$old_pvc_uid" != "$new_pvc_uid" && "$old_pv_uid" != "$new_pv_uid" ]] \
  || fail "recovery did not bind a fresh PVC and PV"
[[ "$new_pvc_phase" == "Bound" && "$new_pvc_modes" == '["ReadWriteOnce"]' ]] \
  || fail "replacement PVC was not Bound and ReadWriteOnce"

write_secret_snapshot "$tmp_dir/secrets-restored"
secret_digest_manifest "$tmp_dir/secrets-restored" "$tmp_dir/secrets-restored-digests.json"
cmp -s "$tmp_dir/secrets-before-digests.json" "$tmp_dir/secrets-restored-digests.json" \
  || fail "restored Secret digest manifest differs from backup"

"$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" scale \
  deployment/"$RENDERER_DEPLOYMENT" --replicas=1 >/dev/null
"$KUBECTL_BIN" -n "$RENDERER_NAMESPACE" rollout status \
  deployment/"$RENDERER_DEPLOYMENT" --timeout=120s >/dev/null
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" scale \
  deployment/"$PROXY_DEPLOYMENT" --replicas=1 >/dev/null
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout status \
  deployment/"$PROXY_DEPLOYMENT" --timeout=120s >/dev/null
downtime_seconds="$(( $(date +%s) - downtime_start ))"

capture_policy_pair "$evidence_dir/policy-restored.json" \
  "$contained_session_id" "$control_session_id"
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  cat /var/lib/eidolon/events.jsonl.consumed-proofs.json \
  >"$tmp_dir/consumed-restored.json"
cmp -s "$tmp_dir/consumed-before.json" "$tmp_dir/consumed-restored.json" \
  || fail "consumed-proof store differed immediately after restore"

write_request "$tmp_dir/b-replay.request" \
  'POST /api/v2/import/reconcile HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nX-Migration-Trace: %s\r\nX-Shield-Lab-Probe: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
  "$control_cookie" "$control_proof" "$replay_probe_id"
send_request "$probe_b" "$tmp_dir/b-replay.request" \
  "$tmp_dir/b-replay.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/b-replay.response")" == "403" ]] \
  || fail "consumed proof replay did not fail closed with 403"

write_request "$tmp_dir/a-status.request" \
  'GET %s HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nConnection: close\r\n\r\n' \
  "$status_path" "$contained_cookie"
send_request "$probe_a" "$tmp_dir/a-status.request" \
  "$tmp_dir/a-status.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/a-status.response")" == "200" ]] \
  || fail "restored status path did not return 200"
a_status_body="$(http_body "$tmp_dir/a-status.response")"
jq -e --arg job "$job_id" '
  .job_id == $job and .status == "completed" and .write_committed == false
' <<<"$a_status_body" >/dev/null \
  || fail "restored status path lost deterministic job state"

capture_policy_pair "$evidence_dir/policy-after.json" \
  "$contained_session_id" "$control_session_id"
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  cat /var/lib/eidolon/events.jsonl \
  | jq -c --arg a "$contained_session_id" --arg b "$control_session_id" \
      'select(.session_id == $a or .session_id == $b)' \
  >"$evidence_dir/proxy-events.jsonl"
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  cat /var/lib/eidolon/debug.jsonl \
  | jq -c --arg a "$contained_session_id" --arg b "$control_session_id" \
      'select(.session_id == $a or .session_id == $b)' \
  >"$evidence_dir/proxy-debug.jsonl"

replay_request_id="$(
  jq -r -e -s --arg session "$control_session_id" '
    [.[] | select(
      .session_id == $session
      and .kind.type == "bait_action_observed"
      and .kind.header_value_mint_status == "replay_seen"
      and .kind.exposure_id == null
    )] | last | .request_id
  ' "$evidence_dir/proxy-events.jsonl"
)"
status_request_id="$(
  jq -r -e -s --arg session "$contained_session_id" --arg path "$status_path" '
    [.[] | select(
      .session_id == $session
      and .kind.type == "request_seen"
      and .kind.method == "GET"
      and .kind.path == $path
    )] | last | .request_id
  ' "$evidence_dir/proxy-events.jsonl"
)"

collect_target_audit "$tmp_dir/target-positions.tsv" "$evidence_dir/target-audit.jsonl"

"$PYTHON_BIN" - "$tmp_dir/state-before.tsv" "$tmp_dir/state-before.json" <<'PY'
import json
import pathlib
import sys
records = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    path, digest, size = line.split("\t")
    records.append({"path": path, "sha256": digest, "bytes": int(size)})
pathlib.Path(sys.argv[2]).write_text(json.dumps(records, sort_keys=True, separators=(",", ":")) + "\n")
PY
"$PYTHON_BIN" - "$tmp_dir/state-restored.tsv" "$tmp_dir/state-restored.json" <<'PY'
import json
import pathlib
import sys
records = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    path, digest, size = line.split("\t")
    records.append({"path": path, "sha256": digest, "bytes": int(size)})
pathlib.Path(sys.argv[2]).write_text(json.dumps(records, sort_keys=True, separators=(",", ":")) + "\n")
PY

jq -n \
  --arg old_uid "$old_pvc_uid" \
  --arg new_uid "$new_pvc_uid" \
  --arg old_pv_uid "$old_pv_uid" \
  --arg new_pv_uid "$new_pv_uid" \
  --arg pvc_phase "$new_pvc_phase" \
  --argjson pvc_modes "$new_pvc_modes" \
  --argjson downtime "$downtime_seconds" \
  --slurpfile state_before "$tmp_dir/state-before.json" \
  --slurpfile state_restored "$tmp_dir/state-restored.json" \
  --slurpfile secrets_before "$tmp_dir/secrets-before-digests.json" \
  --slurpfile secrets_restored "$tmp_dir/secrets-restored-digests.json" \
  '{
    schema_version: 1,
    quiesced: {
      proxy_pods: 0,
      proxy_ready_endpoints: 0,
      renderer_pods: 0
    },
    pvc: {
      old_uid: $old_uid,
      new_uid: $new_uid,
      old_pv_uid: $old_pv_uid,
      new_pv_uid: $new_pv_uid,
      phase: $pvc_phase,
      access_modes: $pvc_modes
    },
    state: {before: $state_before[0], restored: $state_restored[0]},
    secrets: {before: $secrets_before[0], restored: $secrets_restored[0]},
    downtime_seconds: $downtime
  }' >"$evidence_dir/recovery.json"

post_restore_set_cookie_count="$(
  echo "$(( \
    $(set_cookie_count "$tmp_dir/b-replay.response") \
    + $(set_cookie_count "$tmp_dir/a-status.response") \
  ))"
)"
jq -n \
  --arg contained_session_id "$contained_session_id" \
  --arg control_session_id "$control_session_id" \
  --arg exposure_request_id "$exposure_request_id" \
  --arg action_request_id "$action_request_id" \
  --arg exposure_id "$exposure_id" \
  --arg control_seed_request_id "$control_seed_request_id" \
  --arg replay_request_id "$replay_request_id" \
  --arg status_request_id "$status_request_id" \
  --arg job_id "$job_id" \
  --arg status_path "$status_path" \
  --arg baseline_probe_id "$baseline_probe_id" \
  --argjson contained_status "$(http_status "$tmp_dir/a-action.response")" \
  --argjson seed_status "$(http_status "$tmp_dir/b-seed.response")" \
  --argjson replay_status "$(http_status "$tmp_dir/b-replay.response")" \
  --argjson status_status "$(http_status "$tmp_dir/a-status.response")" \
  --argjson set_cookie_count "$post_restore_set_cookie_count" \
  --argjson target_replica_count "$target_replica_count" \
  '{
    contained_session_id: $contained_session_id,
    control_session_id: $control_session_id,
    exposure_request_id: $exposure_request_id,
    action_request_id: $action_request_id,
    exposure_id: $exposure_id,
    control_seed_request_id: $control_seed_request_id,
    replay_request_id: $replay_request_id,
    status_request_id: $status_request_id,
    job_id: $job_id,
    status_path: $status_path,
    baseline_probe_id: $baseline_probe_id,
    statuses: {
      contained_action: $contained_status,
      control_seed: $seed_status,
      replay: $replay_status,
      status_read: $status_status
    },
    write_committed: {contained_action: false, status_read: false},
    post_restore_set_cookie_count: $set_cookie_count,
    target_replica_count: $target_replica_count
  }' >"$evidence_dir/flow.json"

validate_evidence "$evidence_dir" | tee "$EVIDENCE_PATH"
chmod 0600 "$EVIDENCE_PATH"
recovery_complete=1
