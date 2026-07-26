#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
KIND_BIN="${KIND_BIN:-kind}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_KIND_CONTEXT:-kind-eidolon-shield}"
KIND_CLUSTER_NAME="${EIDOLON_SHIELD_KIND_CLUSTER_NAME:-eidolon-shield}"
PROBE_IMAGE="${EIDOLON_SHIELD_KIND_PROBE_IMAGE:-busybox:1.37.0-musl}"
PROBE_IMAGE_DIGEST="${EIDOLON_SHIELD_KIND_PROBE_IMAGE_DIGEST:-sha256:222ad6d973c0d198014546a65cd02c5fdedcc172123c5b4c2bf0af636550bd94}"
EVIDENCE_PATH="${EIDOLON_SHIELD_KIND_ROTATION_EVIDENCE_PATH:-/tmp/eidolon-kind-session-key-rotation-evidence.json}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SESSION_KEY_VALIDATOR="${EIDOLON_SHIELD_SESSION_KEY_VALIDATOR:-$SCRIPT_DIR/validate-session-key-file.py}"

PROXY_NAMESPACE="shield-system"
PROXY_DEPLOYMENT="eidolon-shield-proxy"
PROXY_SERVICE="eidolon-shield-proxy"
PROXY_PVC="eidolon-shield-proxy-state"
RENDERER_NAMESPACE="shield-controlled-reality"
RENDERER_DEPLOYMENT="eidolon-controlled-reality"
TARGET_NAMESPACE="shield-targets"
TARGET_SELECTOR="app.kubernetes.io/name=eidolon-owned-demo-target"
ROTATION_LOCK="eidolon-session-key-rotation-lock"
SESSION_SIGNING_SECRET="eidolon-session-signing"
SESSION_SIGNING_KEY="key-ring.json"
BAIT_SIGNING_SECRET="eidolon-bait-signing"

tmp_dir=""
evidence_dir=""
probe_a=""
probe_b=""
lock_acquired=0
secret_mutated=0
recovery_complete=0
cleanup_recovered=0

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-session-key-rotation-kind.sh
       examples/shield-lab/smoke-session-key-rotation-kind.sh --validate-fixture DIR

Installs a controlled v1 session-signing key, creates a contained session plus a
consumed proof, rotates to overlapping v1+v2 keys with v2 active, restarts the
Recreate proxy deployment, and proves the v1 cookie keeps its session and is
reminted under v2 while policy, workflow, request-link, and replay state
survive. Restarts again to prove the v2 cookie stays valid, then restores the
original Secret and a healthy deployment. No protected-upstream write is
allowed at any point.
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
    rotation.json \
    flow.json \
    policy-before.json \
    policy-rotated.json \
    policy-after.json \
    proxy-events.jsonl \
    proxy-debug.jsonl \
    target-audit.jsonl
  do
    [[ -f "$dir/$file" ]] || fail "missing evidence file: $dir/$file"
  done

  jq -e '
    .schema_version == 1
    and (.secret as $s
      | ($s.before.sha256 | test("^[0-9a-f]{64}$"))
      and ($s.before.bytes | type == "number" and . > 0)
      and ($s.before.active_key_version | type == "number")
      and ($s.before.key_version_count | type == "number" and . >= 1)
      and ($s.before.versions | length) == $s.before.key_version_count
      and ($s.before.versions | index($s.before.active_key_version)) != null
      and $s.installed.active_key_version == 1
      and $s.installed.versions == [1]
      and $s.installed.key_version_count == 1
      and ($s.installed.sha256 | test("^[0-9a-f]{64}$"))
      and $s.installed.sha256 != $s.before.sha256
      and $s.rotated.active_key_version == 2
      and $s.rotated.versions == [1, 2]
      and $s.rotated.key_version_count == 2
      and ($s.rotated.sha256 | test("^[0-9a-f]{64}$"))
      and $s.rotated.sha256 != $s.installed.sha256
      and $s.restored.sha256 == $s.before.sha256
      and $s.restored.bytes == $s.before.bytes
      and $s.restored.active_key_version == $s.before.active_key_version
      and $s.restored.versions == $s.before.versions
      and $s.restored.key_version_count == $s.before.key_version_count)
    and (.pod_uids as $u
      | ([$u.initial, $u.installed, $u.rotated, $u.second, $u.restored]
         | unique | length) == 5)
    and (.downtime_seconds | type == "number" and . >= 0)
    and (.total_seconds | type == "number" and . >= 0)
    and (.total_seconds >= .downtime_seconds)
    and (.proxy_started_baseline_count | type == "number" and . >= 0)
  ' "$dir/rotation.json" >/dev/null \
    || fail "rotation evidence did not prove install, overlap, restart, and restore"

  jq -e '
    .contained_session_id != .control_session_id
    and .exposure_request_id != .action_request_id
    and .action_request_id != .control_seed_request_id
    and .status_remint_request_id != .status_final_request_id
    and .replay_after_rotation_request_id != .replay_final_request_id
    and (.exposure_id | type == "string" and length > 0)
    and (.job_id | type == "string" and length > 0)
    and .status_path == ("/api/v2/import/reconcile/jobs/" + .job_id)
    and .statuses.contained_action == 202
    and .statuses.control_seed == 202
    and .statuses.status_remint == 200
    and .statuses.replay_after_rotation == 403
    and .statuses.status_final == 200
    and .statuses.replay_final == 403
    and .write_committed.contained_action == false
    and .write_committed.status_remint == false
    and .write_committed.status_final == false
    and .cookies.contained_initial_key_version == 1
    and .cookies.control_initial_key_version == 1
    and .cookies.reminted_key_version == 2
    and .cookies.reminted_same_session == true
    and .cookies.reminted_signature_changed == true
    and .cookies.status_remint_set_cookie_count == 1
    and .cookies.status_final_set_cookie_count == 0
    and (.baseline_probe_id | type == "string" and length > 0)
    and (.target_replica_count | type == "number" and . > 0)
  ' "$dir/flow.json" >/dev/null \
    || {
      jq -c . "$dir/flow.json" >&2
      fail "rotation flow outcomes were incomplete or contradictory"
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
    || fail "pre-rotation policy state was not the required two-session control"

  jq -e --slurpfile before "$dir/policy-before.json" '
    . == $before[0]
  ' "$dir/policy-rotated.json" >/dev/null \
    || fail "policy state changed across the key-rotation restart"

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
    || fail "post-rotation policy state lost containment or changed the control"

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
    | ([.[] | select(
        .session_id == $f.control_session_id
        and .kind.type == "bait_action_observed"
        and .kind.bait_id == "rel_2025_04_b7f2"
        and .kind.header_value_mint_status == "replay_seen"
        and .kind.exposure_id == null
      )] | sort_by(.request_id)) as $replays
    | [.[] | select(
        .session_id == $f.contained_session_id
        and .request_id == $f.action_request_id
        and .kind.type == "response_served"
        and .kind.status == 202
        and .kind.controlled_reality.kind == "job_submitted"
        and .kind.controlled_reality.origin_request_id == $f.action_request_id
        and .kind.controlled_reality.job_id == $f.job_id
      )] as $entries
    | ([.[] | select(
        .session_id == $f.contained_session_id
        and .kind.type == "response_served"
        and .kind.status == 200
        and .kind.controlled_reality.kind == "status_read"
        and .kind.controlled_reality.origin_request_id == $f.action_request_id
        and .kind.controlled_reality.job_id == $f.job_id
      )] | sort_by(.request_id)) as $statuses
    | select(
        ($exposures | length) == 1
        and ($actions | length) == 1
        and ($seeds | length) == 1
        and ($replays | length) == 2
        and ([$replays[].request_id] | sort)
          == ([$f.replay_after_rotation_request_id, $f.replay_final_request_id] | sort)
        and ($entries | length) == 1
        and ($statuses | length) == 2
        and ([$statuses[].request_id] | sort)
          == ([$f.status_remint_request_id, $f.status_final_request_id] | sort)
      )
    | select(
        [.[] | select(
          .session_id == $f.control_session_id
          and .kind.type == "bait_exposed"
        )] | length == 0
      )
    | select(
        [.[] | select(
          .session_id == $f.control_session_id
          and .kind.type == "policy_changed"
        )] | length == 0
      )
  ' "$dir/proxy-events.jsonl" >/dev/null \
    || fail "event history did not uniquely preserve rotation causality"

  jq -e -s --slurpfile flow "$dir/flow.json" --slurpfile rotation "$dir/rotation.json" '
    $flow[0] as $f
    | $rotation[0] as $r
    | . as $records
    | ([$records[] | select(.event == "proxy_started")]) as $all_starts
    | ($all_starts[$r.proxy_started_baseline_count:]) as $starts
    | select(($starts | length) == 4)
    | select(
        ($starts[0].fields.session_signing.mode == "configured")
        and ($starts[0].fields.session_signing.active_key_version == 1)
        and ($starts[0].fields.session_signing.key_version_count == 1)
      )
    | select(
        ($starts[1].fields.session_signing.mode == "configured")
        and ($starts[1].fields.session_signing.active_key_version == 2)
        and ($starts[1].fields.session_signing.key_version_count == 2)
        and ($starts[1].fields.restored_consumed_bait_proof_count >= 2)
      )
    | select(
        ($starts[2].fields.session_signing.mode == "configured")
        and ($starts[2].fields.session_signing.active_key_version == 2)
        and ($starts[2].fields.session_signing.key_version_count == 2)
        and ($starts[2].fields.restored_consumed_bait_proof_count >= 2)
      )
    | select(
        ($starts[3].fields.session_signing.mode == "configured")
        and ($starts[3].fields.session_signing.active_key_version
          == $r.secret.before.active_key_version)
        and ($starts[3].fields.session_signing.key_version_count
          == $r.secret.before.key_version_count)
        and ($starts[3].fields.restored_consumed_bait_proof_count >= 2)
      )
    | select(
        ($starts[0].observed_at_unix_ms | type == "number")
        and ($starts[0].observed_at_unix_ms < $starts[1].observed_at_unix_ms)
        and ($starts[1].observed_at_unix_ms < $starts[2].observed_at_unix_ms)
        and ($starts[2].observed_at_unix_ms < $starts[3].observed_at_unix_ms)
      )
    | select(
        ([$records[] | select(
          .event == "session_resolved"
          and .session_id == $f.contained_session_id
          and .fields.request_id == $f.status_remint_request_id
          and .fields.session_source == "cookie"
          and .fields.cookie_outcome == "valid"
          and .fields.key_status == "previous"
          and .fields.presented_key_version == 1
          and .fields.active_key_version == 2
        )] | length) == 1
      )
    | select(
        ([$records[] | select(
          .event == "session_resolved"
          and .session_id == $f.contained_session_id
          and .fields.request_id == $f.status_final_request_id
          and .fields.session_source == "cookie"
          and .fields.cookie_outcome == "valid"
          and .fields.key_status == "active"
          and .fields.presented_key_version == 2
          and .fields.active_key_version == 2
        )] | length) == 1
      )
    | select(
        ([$records[] | select(
          .event == "session_resolved"
          and .session_id == $f.control_session_id
          and .fields.request_id == $f.replay_after_rotation_request_id
          and .fields.session_source == "cookie"
          and .fields.cookie_outcome == "valid"
          and .fields.key_status == "previous"
          and .fields.presented_key_version == 1
          and .fields.active_key_version == 2
        )] | length) == 1
      )
    | select(
        ([$records[] | select(
          .event == "session_resolved"
          and .session_id == $f.control_session_id
          and .fields.request_id == $f.replay_final_request_id
          and .fields.session_source == "cookie"
          and .fields.cookie_outcome == "valid"
          and .fields.key_status == "previous"
          and .fields.presented_key_version == 1
          and .fields.active_key_version == 2
        )] | length) == 1
      )
  ' "$dir/proxy-debug.jsonl" >/dev/null \
    || fail "debug history did not prove install, overlap remint, and v2 stability"

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
    --slurpfile rotation "$dir/rotation.json" \
    --slurpfile flow "$dir/flow.json" \
    '{
      schema_version: 1,
      result: "passed",
      session_key_rotated: true,
      overlapping_versions: $rotation[0].secret.rotated.versions,
      v1_cookie_reminted_under_v2: true,
      session_identity_preserved: true,
      consumed_proof_rejected_after_rotation: true,
      consumed_proof_rejected_after_second_restart: true,
      protected_upstream_writes: 0,
      original_secret_restored: true,
      deployment_healthy: true,
      downtime_seconds: $rotation[0].downtime_seconds,
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
        labels: {"app.kubernetes.io/name": "eidolon-session-key-rotation-probe"}
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

key_ring_digest() {
  jq -r --arg key "$SESSION_SIGNING_KEY" '.data[$key]' "$1" \
    | base64 -d \
    | shasum -a 256 \
    | awk '{print $1}'
}

key_ring_bytes() {
  jq -r --arg key "$SESSION_SIGNING_KEY" '.data[$key]' "$1" \
    | base64 -d \
    | wc -c \
    | tr -d ' '
}

key_ring_facts() {
  jq -r --arg key "$SESSION_SIGNING_KEY" '.data[$key]' "$1" \
    | base64 -d \
    | jq -c -e '
        {
          active_key_version,
          versions: ([.keys[].version] | sort),
          key_version_count: (.keys | length)
        }
      '
}

validate_ring_file() {
  local ring_file="$1"

  [[ -f "$SESSION_KEY_VALIDATOR" ]] \
    || fail "session signing key validator not found: $SESSION_KEY_VALIDATOR"
  base64 <"$ring_file" | tr -d '\n' \
    | "$PYTHON_BIN" "$SESSION_KEY_VALIDATOR" >/dev/null 2>&1 \
    || fail "generated session key ring failed validation"
}

build_ring_manifest() {
  local ring_file="$1"
  local output="$2"
  local encoded

  # printf is a shell builtin: key material never appears in process argv.
  encoded="$(base64 <"$ring_file" | tr -d '\n')"
  printf '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"%s","namespace":"%s"},"type":"Opaque","data":{"%s":"%s"}}' \
    "$SESSION_SIGNING_SECRET" "$PROXY_NAMESPACE" "$SESSION_SIGNING_KEY" "$encoded" \
    >"$output"
  chmod 0600 "$output"
}

replace_session_signing_secret() {
  local manifest="$1"

  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete secret "$SESSION_SIGNING_SECRET" \
    --ignore-not-found --wait=true >/dev/null \
    || return 1
  "$KUBECTL_BIN" create -f "$manifest" >/dev/null \
    || return 1
}

restart_proxy_deployment() {
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout restart \
    deployment/"$PROXY_DEPLOYMENT" >/dev/null
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout status \
    deployment/"$PROXY_DEPLOYMENT" --timeout=120s >/dev/null
}

proxy_pod_uid() {
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get pods \
    -l app.kubernetes.io/name="$PROXY_DEPLOYMENT" -o json \
    | jq -r -e 'select(.items | length == 1) | .items[0].metadata.uid'
}

last_started_observed() {
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- cat /var/lib/eidolon/debug.jsonl \
    | jq -r -s '([.[] | select(.event == "proxy_started")] | .[-1] | .observed_at_unix_ms) // 0'
}

assert_last_proxy_started() {
  local expected_active="$1"
  local expected_count="$2"
  local observed_after="$3"

  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- cat /var/lib/eidolon/debug.jsonl \
    | jq -e -s \
      --argjson active "$expected_active" \
      --argjson count "$expected_count" \
      --argjson after "$observed_after" '
        [.[] | select(.event == "proxy_started")] | .[-1]
        | select(.observed_at_unix_ms > $after)
        | select(.fields.session_signing.mode == "configured")
        | select(.fields.session_signing.active_key_version == $active)
        | select(.fields.session_signing.key_version_count == $count)
      ' >/dev/null \
    || fail "proxy did not restart with the expected session key ring (active=${expected_active}, versions=${expected_count})"
}

restored_consumed_proof_count() {
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- cat /var/lib/eidolon/debug.jsonl \
    | jq -r -s '
        [.[] | select(.event == "proxy_started")] | .[-1]
        | .fields.restored_consumed_bait_proof_count
      '
}

# Proof windows are evaluated against the proxy pod clock; the workstation
# clock may be skewed relative to the cluster.
proxy_now_seconds() {
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- date +%s
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
      || fail "protected target pod changed during rotation smoke: $pod"
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
  local now_epoch="$4"

  "$PYTHON_BIN" - "$cookie_file" "$secret_file" "$proof_file" "$now_epoch" <<'PY'
import base64
import hashlib
import hmac
import json
import pathlib
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
bucket = int(sys.argv[4]) // 300
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

assert_consumed_proof_recorded() {
  local session_id="$1"
  local proof_file="$2"

  local proof_digest
  proof_digest="$(
    "$PYTHON_BIN" - "$proof_file" <<'PY'
import hashlib
import pathlib
import sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
  )"
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec \
    deployment/"$PROXY_DEPLOYMENT" -- \
    cat /var/lib/eidolon/events.jsonl.consumed-proofs.json \
    | jq -e --arg session "$session_id" --arg digest "$proof_digest" '
        any(.consumed[];
          .session_id == $session
          and .bait_id == "rel_2025_04_b7f2"
          and .proof_digest_hex == $digest
        )
      ' >/dev/null \
    || fail "control proof digest was not durably consumed"
}

recover_cluster() {
  set -e
  if (( secret_mutated )) \
    && [[ -f "$tmp_dir/secrets-before/session-signing.json" ]]; then
    replace_session_signing_secret \
      "$tmp_dir/secrets-before/session-signing.json" >/dev/null 2>&1 \
      || return 1
  fi
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout restart \
    deployment/"$PROXY_DEPLOYMENT" >/dev/null 2>&1 \
    || return 1
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" rollout status \
    deployment/"$PROXY_DEPLOYMENT" --timeout=120s >/dev/null 2>&1 \
    || return 1
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get deployment "$PROXY_DEPLOYMENT" \
    -o json | jq -e '.status.readyReplicas == 1' >/dev/null \
    || return 1
  snapshot_secret "$PROXY_NAMESPACE" "$SESSION_SIGNING_SECRET" \
    '["key-ring.json"]' "$tmp_dir/secret-recovered.json"
  [[ "$(key_ring_digest "$tmp_dir/secret-recovered.json")" \
    == "$(key_ring_digest "$tmp_dir/secrets-before/session-signing.json")" ]]
}

cleanup() {
  local status=$?

  set +e
  if (( status != 0 && recovery_complete == 0 && secret_mutated == 1 )); then
    echo "rotation smoke failed; restoring the original session key ring" >&2
    if (
      trap - EXIT INT TERM
      recover_cluster
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

  if (( lock_acquired )) && (( status == 0 || recovery_complete || cleanup_recovered )); then
    "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" delete configmap "$ROTATION_LOCK" \
      --ignore-not-found >/dev/null 2>&1
  fi
  if [[ -n "$tmp_dir" ]] && (( status == 0 || recovery_complete || cleanup_recovered )); then
    rm -rf "$tmp_dir"
  elif [[ -n "$tmp_dir" ]]; then
    echo "rotation artifacts retained at: $tmp_dir" >&2
    echo "rotation lock retained: ${PROXY_NAMESPACE}/${ROTATION_LOCK}" >&2
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
  "$KUBECTL_BIN" "$KIND_BIN" "$DOCKER_BIN" "$PYTHON_BIN" "$OPENSSL_BIN" \
  awk base64 chmod cut date grep head jq mkdir mktemp mv sed shasum sort tail tr wc
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-key-rotation.XXXXXX")"
chmod 0700 "$tmp_dir"
evidence_dir="$tmp_dir/evidence"
mkdir -m 0700 "$evidence_dir"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_id="$(date -u +%H%M%S)-$$"
probe_a="eidolon-rotation-a-${run_id}"
probe_b="eidolon-rotation-b-${run_id}"
baseline_probe_id="shield-probe-rotation-baseline-${run_id}"
contained_probe_id="shield-probe-rotation-contained-${run_id}"
replay_probe_id="shield-probe-rotation-replay-${run_id}"
total_start="$(date +%s)"

if ! "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" create configmap "$ROTATION_LOCK" \
  --from-literal="run-id=$run_id" >/dev/null 2>&1; then
  fail "rotation lock already exists: ${PROXY_NAMESPACE}/${ROTATION_LOCK}"
fi
lock_acquired=1

proxy_ip="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get service "$PROXY_SERVICE" \
    -o jsonpath='{.spec.clusterIP}'
)"
[[ -n "$proxy_ip" && "$proxy_ip" != "None" ]] \
  || fail "could not resolve proxy ClusterIP"

mkdir -m 0700 "$tmp_dir/secrets-before"
snapshot_secret "$PROXY_NAMESPACE" "$SESSION_SIGNING_SECRET" \
  '["key-ring.json"]' "$tmp_dir/secrets-before/session-signing.json"
snapshot_secret "$PROXY_NAMESPACE" "$BAIT_SIGNING_SECRET" \
  '["signing-secret.txt"]' "$tmp_dir/secrets-before/bait-signing.json"
before_facts="$(key_ring_facts "$tmp_dir/secrets-before/session-signing.json")"
before_active="$(jq -r '.active_key_version' <<<"$before_facts")"
before_count="$(jq -r '.key_version_count' <<<"$before_facts")"

pod_uid_initial="$(proxy_pod_uid)"

# Phase A: install a controlled active v1 key ring and restart into it.
v1_key="$("$OPENSSL_BIN" rand -hex 32)"
[[ "$v1_key" =~ ^[[:xdigit:]]{64}$ ]] \
  || fail "generated v1 session signing key was malformed"
printf '{"active_key_version":1,"keys":[{"version":1,"key_hex":"%s"}]}' \
  "$v1_key" >"$tmp_dir/ring-v1.json"
chmod 0600 "$tmp_dir/ring-v1.json"
unset v1_key
validate_ring_file "$tmp_dir/ring-v1.json"
build_ring_manifest "$tmp_dir/ring-v1.json" "$tmp_dir/secret-v1-manifest.json"
secret_mutated=1
replace_session_signing_secret "$tmp_dir/secret-v1-manifest.json" \
  || fail "could not install the controlled v1 session key ring"

started_marker="$(last_started_observed)"
restart_proxy_deployment
pod_uid_installed="$(proxy_pod_uid)"
[[ "$pod_uid_installed" != "$pod_uid_initial" ]] \
  || fail "proxy pod identity did not change across the v1 install restart"
assert_last_proxy_started 1 1 "$started_marker"

snapshot_secret "$PROXY_NAMESPACE" "$SESSION_SIGNING_SECRET" \
  '["key-ring.json"]' "$tmp_dir/secret-installed.json"

# Phase B: contained session plus consumed proofs minted under v1.
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
[[ "$contained_cookie" =~ ^v1\.[0-9]+\.[0-9]+\.[0-9a-f-]+\.[0-9a-f]{64}$ ]] \
  || fail "contained session cookie had an unexpected shape"
[[ "$(cut -d. -f2 <<<"$contained_cookie")" == "1" ]] \
  || fail "contained session cookie was not minted under key version 1"
contained_session_id="$(cut -d. -f4 <<<"$contained_cookie")"
contained_signature="$(cut -d. -f5 <<<"$contained_cookie")"
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
[[ "$control_cookie" =~ ^v1\.[0-9]+\.[0-9]+\.[0-9a-f-]+\.[0-9a-f]{64}$ ]] \
  || fail "control session cookie had an unexpected shape"
[[ "$(cut -d. -f2 <<<"$control_cookie")" == "1" ]] \
  || fail "control session cookie was not minted under key version 1"
control_session_id="$(cut -d. -f4 <<<"$control_cookie")"
[[ "$contained_session_id" != "$control_session_id" ]] \
  || fail "probe sessions unexpectedly merged"
printf '%s' "$control_cookie" >"$tmp_dir/b.cookie"
chmod 0600 "$tmp_dir/b.cookie"
proof_now="$(proxy_now_seconds)"
proof_window_remaining="$((300 - (proof_now % 300)))"
if (( proof_window_remaining < 180 )); then
  echo "waiting ${proof_window_remaining}s for a fresh proof window"
  sleep "$proof_window_remaining"
  sleep 1
fi
make_control_proof "$tmp_dir/b.cookie" \
  "$tmp_dir/secrets-before/bait-signing.json" "$tmp_dir/b.proof" \
  "$(proxy_now_seconds)"
control_proof="$(<"$tmp_dir/b.proof")"

write_request "$tmp_dir/b-seed.request" \
  'POST /api/v2/import/reconcile HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nX-Migration-Trace: %s\r\nX-Shield-Lab-Probe: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
  "$control_cookie" "$control_proof" "$replay_probe_id"
send_request "$probe_b" "$tmp_dir/b-seed.request" \
  "$tmp_dir/b-seed.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/b-seed.response")" == "202" ]] \
  || fail "unlinked control proof did not receive the synthetic 202 (got $(http_status "$tmp_dir/b-seed.response"))"

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
)" || fail "pre-rotation action linkage was missing or ambiguous"
exposure_request_id="$(jq -r '.exposure_request_id' <<<"$action_link")"
exposure_id="$(jq -r '.exposure_id' <<<"$action_link")"
action_request_id="$(jq -r '.action_request_id' <<<"$action_link")"
control_seed_request_id="$(jq -r '.control_seed_request_id' <<<"$action_link")"

capture_policy_pair "$evidence_dir/policy-before.json" \
  "$contained_session_id" "$control_session_id"
assert_consumed_proof_recorded "$control_session_id" "$tmp_dir/b.proof"

proxy_started_baseline_count="$(
  "$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
    cat /var/lib/eidolon/debug.jsonl \
    | jq -s '[.[] | select(.event == "proxy_started")] | length'
)"
# The v1-install start is part of this run, not the pre-existing baseline.
proxy_started_baseline_count="$((proxy_started_baseline_count - 1))"

# Phase C: rotate to overlapping v1+v2 keys with v2 active and restart.
v1_key="$(jq -r '.keys[0].key_hex' "$tmp_dir/ring-v1.json")"
v2_key="$("$OPENSSL_BIN" rand -hex 32)"
[[ "$v2_key" =~ ^[[:xdigit:]]{64}$ ]] \
  || fail "generated v2 session signing key was malformed"
printf '{"active_key_version":2,"keys":[{"version":1,"key_hex":"%s"},{"version":2,"key_hex":"%s"}]}' \
  "$v1_key" "$v2_key" >"$tmp_dir/ring-v2.json"
chmod 0600 "$tmp_dir/ring-v2.json"
unset v1_key v2_key
validate_ring_file "$tmp_dir/ring-v2.json"
build_ring_manifest "$tmp_dir/ring-v2.json" "$tmp_dir/secret-v2-manifest.json"
replace_session_signing_secret "$tmp_dir/secret-v2-manifest.json" \
  || fail "could not install the overlapping v1+v2 session key ring"

started_marker="$(last_started_observed)"
downtime_start="$(date +%s)"
restart_proxy_deployment
downtime_seconds="$(( $(date +%s) - downtime_start ))"
pod_uid_rotated="$(proxy_pod_uid)"
[[ "$pod_uid_rotated" != "$pod_uid_installed" ]] \
  || fail "proxy pod identity did not change across the rotation restart"
assert_last_proxy_started 2 2 "$started_marker"
[[ "$(restored_consumed_proof_count)" -ge 2 ]] \
  || fail "consumed proofs were not restored after the rotation restart"

snapshot_secret "$PROXY_NAMESPACE" "$SESSION_SIGNING_SECRET" \
  '["key-ring.json"]' "$tmp_dir/secret-rotated.json"
assert_consumed_proof_recorded "$control_session_id" "$tmp_dir/b.proof"
capture_policy_pair "$evidence_dir/policy-rotated.json" \
  "$contained_session_id" "$control_session_id"
jq -e --slurpfile before "$evidence_dir/policy-before.json" \
  '. == $before[0]' "$evidence_dir/policy-rotated.json" >/dev/null \
  || fail "policy state changed across the key-rotation restart"

# Phase D: the v1 cookie keeps its session and is reminted under v2.
write_request "$tmp_dir/a-status-remint.request" \
  'GET %s HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nConnection: close\r\n\r\n' \
  "$status_path" "$contained_cookie"
send_request "$probe_a" "$tmp_dir/a-status-remint.request" \
  "$tmp_dir/a-status-remint.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/a-status-remint.response")" == "200" ]] \
  || fail "v1 cookie status path did not return 200 after rotation (got $(http_status "$tmp_dir/a-status-remint.response"))"
a_remint_body="$(http_body "$tmp_dir/a-status-remint.response")"
jq -e --arg job "$job_id" '
  .job_id == $job and .status == "completed" and .write_committed == false
' <<<"$a_remint_body" >/dev/null \
  || fail "v1 cookie lost deterministic job state after rotation"
[[ "$(set_cookie_count "$tmp_dir/a-status-remint.response")" == "1" ]] \
  || fail "v1 cookie was not transparently reminted after rotation"
reminted_cookie="$(
  sed -n 's/^[Ss]et-[Cc]ookie:[[:space:]]*eidolon_session=\([^;[:space:]]*\).*/\1/p' \
    "$tmp_dir/a-status-remint.response" | head -n 1
)"
[[ -n "$reminted_cookie" ]] || fail "reminted session cookie was missing"
[[ "$reminted_cookie" =~ ^v1\.[0-9]+\.[0-9]+\.[0-9a-f-]+\.[0-9a-f]{64}$ ]] \
  || fail "reminted session cookie had an unexpected shape"
[[ "$(cut -d. -f2 <<<"$reminted_cookie")" == "2" ]] \
  || fail "reminted session cookie was not minted under key version 2"
[[ "$(cut -d. -f4 <<<"$reminted_cookie")" == "$contained_session_id" ]] \
  || fail "reminted session cookie changed the session identity"
[[ "$(cut -d. -f5 <<<"$reminted_cookie")" != "$contained_signature" ]] \
  || fail "reminted session cookie reused the v1 signature"
printf '%s' "$reminted_cookie" >"$tmp_dir/a-reminted.cookie"
chmod 0600 "$tmp_dir/a-reminted.cookie"

write_request "$tmp_dir/b-replay-rotated.request" \
  'POST /api/v2/import/reconcile HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nX-Migration-Trace: %s\r\nX-Shield-Lab-Probe: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
  "$control_cookie" "$control_proof" "$replay_probe_id"
send_request "$probe_b" "$tmp_dir/b-replay-rotated.request" \
  "$tmp_dir/b-replay-rotated.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/b-replay-rotated.response")" == "403" ]] \
  || fail "consumed proof replay did not fail closed with 403 after rotation (got $(http_status "$tmp_dir/b-replay-rotated.response"))"

capture_policy_pair "$evidence_dir/policy-after.json" \
  "$contained_session_id" "$control_session_id"

# Phase E: restart again; the v2 cookie remains valid and active.
started_marker="$(last_started_observed)"
restart_proxy_deployment
pod_uid_second="$(proxy_pod_uid)"
[[ "$pod_uid_second" != "$pod_uid_rotated" ]] \
  || fail "proxy pod identity did not change across the second restart"
assert_last_proxy_started 2 2 "$started_marker"

write_request "$tmp_dir/a-status-final.request" \
  'GET %s HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nConnection: close\r\n\r\n' \
  "$status_path" "$reminted_cookie"
send_request "$probe_a" "$tmp_dir/a-status-final.request" \
  "$tmp_dir/a-status-final.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/a-status-final.response")" == "200" ]] \
  || fail "v2 cookie status path did not return 200 after the second restart (got $(http_status "$tmp_dir/a-status-final.response"))"
a_final_body="$(http_body "$tmp_dir/a-status-final.response")"
jq -e --arg job "$job_id" '
  .job_id == $job and .status == "completed" and .write_committed == false
' <<<"$a_final_body" >/dev/null \
  || fail "v2 cookie lost deterministic job state after the second restart"
[[ "$(set_cookie_count "$tmp_dir/a-status-final.response")" == "0" ]] \
  || fail "active v2 cookie was unexpectedly reminted after the second restart"

write_request "$tmp_dir/b-replay-final.request" \
  'POST /api/v2/import/reconcile HTTP/1.1\r\nHost: eidolon-shield-proxy\r\nCookie: eidolon_session=%s\r\nX-Migration-Trace: %s\r\nX-Shield-Lab-Probe: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
  "$control_cookie" "$control_proof" "$replay_probe_id"
send_request "$probe_b" "$tmp_dir/b-replay-final.request" \
  "$tmp_dir/b-replay-final.response" "$proxy_ip" 9102
[[ "$(http_status "$tmp_dir/b-replay-final.response")" == "403" ]] \
  || fail "consumed proof replay did not fail closed after the second restart (got $(http_status "$tmp_dir/b-replay-final.response"))"

collect_target_audit "$tmp_dir/target-positions.tsv" "$evidence_dir/target-audit.jsonl"

# Phase F: restore the original Secret and a healthy deployment.
replace_session_signing_secret "$tmp_dir/secrets-before/session-signing.json" \
  || fail "could not restore the original session key ring"
started_marker="$(last_started_observed)"
restart_proxy_deployment
pod_uid_restored="$(proxy_pod_uid)"
[[ "$pod_uid_restored" != "$pod_uid_second" ]] \
  || fail "proxy pod identity did not change across the restore restart"
assert_last_proxy_started "$before_active" "$before_count" "$started_marker"
snapshot_secret "$PROXY_NAMESPACE" "$SESSION_SIGNING_SECRET" \
  '["key-ring.json"]' "$tmp_dir/secret-restored.json"
[[ "$(key_ring_digest "$tmp_dir/secret-restored.json")" \
    == "$(key_ring_digest "$tmp_dir/secrets-before/session-signing.json")" ]] \
  || fail "restored session key ring differs from the original"
[[ "$(key_ring_bytes "$tmp_dir/secret-restored.json")" \
    == "$(key_ring_bytes "$tmp_dir/secrets-before/session-signing.json")" ]] \
  || fail "restored session key ring size differs from the original"
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" get deployment "$PROXY_DEPLOYMENT" \
  -o json | jq -e '.status.readyReplicas == 1' >/dev/null \
  || fail "proxy deployment did not return healthy after the restore"
secret_mutated=0
recovery_complete=1
total_seconds="$(( $(date +%s) - total_start ))"

# Evidence assembly: derived facts only, never raw keys, cookies, or proofs.
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  cat /var/lib/eidolon/events.jsonl \
  | jq -c --arg a "$contained_session_id" --arg b "$control_session_id" \
      'select(.session_id == $a or .session_id == $b)' \
  >"$evidence_dir/proxy-events.jsonl"
"$KUBECTL_BIN" -n "$PROXY_NAMESPACE" exec deployment/"$PROXY_DEPLOYMENT" -- \
  cat /var/lib/eidolon/debug.jsonl \
  | jq -c --arg a "$contained_session_id" --arg b "$control_session_id" \
      'select(.session_id == $a or .session_id == $b or .event == "proxy_started")' \
  >"$evidence_dir/proxy-debug.jsonl"

replay_request_ids="$(
  jq -c -e -s --arg session "$control_session_id" '
    [.[] | select(
      .session_id == $session
      and .kind.type == "bait_action_observed"
      and .kind.header_value_mint_status == "replay_seen"
      and .kind.exposure_id == null
    )] | select(length == 2) | [.[].request_id]
  ' "$evidence_dir/proxy-events.jsonl"
)" || fail "replay events were missing or ambiguous after rotation"
replay_after_rotation_request_id="$(jq -r '.[0]' <<<"$replay_request_ids")"
replay_final_request_id="$(jq -r '.[1]' <<<"$replay_request_ids")"
status_request_ids="$(
  jq -c -e -s --arg session "$contained_session_id" --arg path "$status_path" '
    [.[] | select(
      .session_id == $session
      and .kind.type == "request_seen"
      and .kind.method == "GET"
      and .kind.path == $path
    )] | select(length == 2) | [.[].request_id]
  ' "$evidence_dir/proxy-events.jsonl"
)" || fail "status read events were missing or ambiguous after rotation"
status_remint_request_id="$(jq -r '.[0]' <<<"$status_request_ids")"
status_final_request_id="$(jq -r '.[1]' <<<"$status_request_ids")"

secret_phase_json() {
  jq -n \
    --arg sha256 "$(key_ring_digest "$1")" \
    --argjson bytes "$(key_ring_bytes "$1")" \
    --argjson facts "$(key_ring_facts "$1")" \
    '{
      sha256: $sha256,
      bytes: $bytes,
      active_key_version: $facts.active_key_version,
      versions: $facts.versions,
      key_version_count: $facts.key_version_count
    }'
}

jq -n \
  --argjson before "$(secret_phase_json "$tmp_dir/secrets-before/session-signing.json")" \
  --argjson installed "$(secret_phase_json "$tmp_dir/secret-installed.json")" \
  --argjson rotated "$(secret_phase_json "$tmp_dir/secret-rotated.json")" \
  --argjson restored "$(secret_phase_json "$tmp_dir/secret-restored.json")" \
  --arg uid_initial "$pod_uid_initial" \
  --arg uid_installed "$pod_uid_installed" \
  --arg uid_rotated "$pod_uid_rotated" \
  --arg uid_second "$pod_uid_second" \
  --arg uid_restored "$pod_uid_restored" \
  --argjson downtime "$downtime_seconds" \
  --argjson total "$total_seconds" \
  --argjson started_baseline "$proxy_started_baseline_count" \
  '{
    schema_version: 1,
    secret: {
      before: $before,
      installed: $installed,
      rotated: $rotated,
      restored: $restored
    },
    pod_uids: {
      initial: $uid_initial,
      installed: $uid_installed,
      rotated: $uid_rotated,
      second: $uid_second,
      restored: $uid_restored
    },
    downtime_seconds: $downtime,
    total_seconds: $total,
    proxy_started_baseline_count: $started_baseline
  }' >"$evidence_dir/rotation.json"

jq -n \
  --arg contained_session_id "$contained_session_id" \
  --arg control_session_id "$control_session_id" \
  --arg exposure_request_id "$exposure_request_id" \
  --arg action_request_id "$action_request_id" \
  --arg exposure_id "$exposure_id" \
  --arg control_seed_request_id "$control_seed_request_id" \
  --arg replay_after_rotation_request_id "$replay_after_rotation_request_id" \
  --arg replay_final_request_id "$replay_final_request_id" \
  --arg status_remint_request_id "$status_remint_request_id" \
  --arg status_final_request_id "$status_final_request_id" \
  --arg job_id "$job_id" \
  --arg status_path "$status_path" \
  --arg baseline_probe_id "$baseline_probe_id" \
  --argjson action_status "$(http_status "$tmp_dir/a-action.response")" \
  --argjson seed_status "$(http_status "$tmp_dir/b-seed.response")" \
  --argjson remint_status "$(http_status "$tmp_dir/a-status-remint.response")" \
  --argjson replay_rotated_status "$(http_status "$tmp_dir/b-replay-rotated.response")" \
  --argjson final_status "$(http_status "$tmp_dir/a-status-final.response")" \
  --argjson replay_final_status "$(http_status "$tmp_dir/b-replay-final.response")" \
  --argjson remint_set_cookie "$(set_cookie_count "$tmp_dir/a-status-remint.response")" \
  --argjson final_set_cookie "$(set_cookie_count "$tmp_dir/a-status-final.response")" \
  --argjson target_replica_count "$target_replica_count" \
  '{
    contained_session_id: $contained_session_id,
    control_session_id: $control_session_id,
    exposure_request_id: $exposure_request_id,
    action_request_id: $action_request_id,
    exposure_id: $exposure_id,
    control_seed_request_id: $control_seed_request_id,
    replay_after_rotation_request_id: $replay_after_rotation_request_id,
    replay_final_request_id: $replay_final_request_id,
    status_remint_request_id: $status_remint_request_id,
    status_final_request_id: $status_final_request_id,
    job_id: $job_id,
    status_path: $status_path,
    baseline_probe_id: $baseline_probe_id,
    statuses: {
      contained_action: $action_status,
      control_seed: $seed_status,
      status_remint: $remint_status,
      replay_after_rotation: $replay_rotated_status,
      status_final: $final_status,
      replay_final: $replay_final_status
    },
    write_committed: {
      contained_action: false,
      status_remint: false,
      status_final: false
    },
    cookies: {
      contained_initial_key_version: 1,
      control_initial_key_version: 1,
      reminted_key_version: 2,
      reminted_same_session: true,
      reminted_signature_changed: true,
      status_remint_set_cookie_count: $remint_set_cookie,
      status_final_set_cookie_count: $final_set_cookie
    },
    target_replica_count: $target_replica_count
  }' >"$evidence_dir/flow.json"

validate_evidence "$evidence_dir" | tee "$EVIDENCE_PATH"
chmod 0600 "$EVIDENCE_PATH"
