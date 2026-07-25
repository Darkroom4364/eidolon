#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-state-backup-restore-kind.sh"
PYTHON_BIN="${PYTHON_BIN:-python3}"

new_fixture() {
  local name="$1"
  local dir="$tmp_root/$name"

  mkdir "$dir"
  printf '%s\n' "$dir"
}

write_valid_fixture() {
  local dir="$1"

  cat >"$dir/recovery.json" <<'JSON'
{
  "schema_version": 1,
  "quiesced": {
    "proxy_pods": 0,
    "proxy_ready_endpoints": 0,
    "renderer_pods": 0
  },
  "pvc": {
    "old_uid": "pvc-old",
    "new_uid": "pvc-new",
    "old_pv_uid": "pv-old",
    "new_pv_uid": "pv-new",
    "phase": "Bound",
    "access_modes": ["ReadWriteOnce"]
  },
  "state": {
    "before": [
      {
        "path": "events.jsonl",
        "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "bytes": 2400
      },
      {
        "path": "events.jsonl.consumed-proofs.json",
        "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
        "bytes": 350
      },
      {
        "path": "policy-state.json",
        "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
        "bytes": 1800
      }
    ],
    "restored": [
      {
        "path": "events.jsonl",
        "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "bytes": 2400
      },
      {
        "path": "events.jsonl.consumed-proofs.json",
        "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
        "bytes": 350
      },
      {
        "path": "policy-state.json",
        "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
        "bytes": 1800
      }
    ]
  },
  "secrets": {
    "before": [
      {
        "namespace": "shield-controlled-reality",
        "name": "eidolon-controlled-reality-auth",
        "key": "auth-secret.txt",
        "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "bytes": 32
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-bait-signing",
        "key": "signing-secret.txt",
        "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "bytes": 32
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-controlled-reality-auth",
        "key": "auth-secret.txt",
        "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "bytes": 32
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-session-signing",
        "key": "key-ring.json",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bytes": 320
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-trusted-ingress",
        "key": "continuity-key.txt",
        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "bytes": 32
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-trusted-ingress",
        "key": "transport-auth.txt",
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bytes": 32
      }
    ],
    "restored": [
      {
        "namespace": "shield-controlled-reality",
        "name": "eidolon-controlled-reality-auth",
        "key": "auth-secret.txt",
        "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "bytes": 32
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-bait-signing",
        "key": "signing-secret.txt",
        "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "bytes": 32
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-controlled-reality-auth",
        "key": "auth-secret.txt",
        "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "bytes": 32
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-session-signing",
        "key": "key-ring.json",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bytes": 320
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-trusted-ingress",
        "key": "continuity-key.txt",
        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "bytes": 32
      },
      {
        "namespace": "shield-system",
        "name": "eidolon-trusted-ingress",
        "key": "transport-auth.txt",
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bytes": 32
      }
    ]
  },
  "downtime_seconds": 42
}
JSON

  cat >"$dir/flow.json" <<'JSON'
{
  "contained_session_id": "session-contained",
  "control_session_id": "session-control",
  "exposure_request_id": "request-exposure",
  "action_request_id": "request-action",
  "exposure_id": "exposure-contained",
  "control_seed_request_id": "request-control-seed",
  "replay_request_id": "request-replay",
  "status_request_id": "request-status",
  "job_id": "job-recovery",
  "status_path": "/api/v2/import/reconcile/jobs/job-recovery",
  "baseline_probe_id": "baseline-recovery",
  "statuses": {
    "contained_action": 202,
    "control_seed": 202,
    "replay": 403,
    "status_read": 200
  },
  "write_committed": {
    "contained_action": false,
    "status_read": false
  },
  "post_restore_set_cookie_count": 0,
  "target_replica_count": 2
}
JSON

  cat >"$dir/policy-before.json" <<'JSON'
{
  "contained": {
    "session_id": "session-contained",
    "persisted": true,
    "policy_state": "controlled_reality",
    "controlled_reality_depth": 1,
    "controlled_reality_workflow_state": "queued",
    "controlled_reality_origin_request_id": "request-action",
    "controlled_reality_pending_update": null
  },
  "control": {
    "session_id": "session-control",
    "persisted": false,
    "policy_state": "observe",
    "controlled_reality_depth": 0,
    "controlled_reality_workflow_state": "ready",
    "controlled_reality_origin_request_id": null,
    "controlled_reality_pending_update": null
  }
}
JSON
  cp "$dir/policy-before.json" "$dir/policy-restored.json"

  cat >"$dir/policy-after.json" <<'JSON'
{
  "contained": {
    "session_id": "session-contained",
    "persisted": true,
    "policy_state": "controlled_reality",
    "controlled_reality_depth": 1,
    "controlled_reality_workflow_state": "completed",
    "controlled_reality_origin_request_id": "request-action",
    "controlled_reality_pending_update": null
  },
  "control": {
    "session_id": "session-control",
    "persisted": false,
    "policy_state": "observe",
    "controlled_reality_depth": 0,
    "controlled_reality_workflow_state": "ready",
    "controlled_reality_origin_request_id": null,
    "controlled_reality_pending_update": null
  }
}
JSON

  cat >"$dir/proxy-events.jsonl" <<'JSONL'
{"schema_version":2,"session_id":"session-contained","request_id":"request-exposure","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","exposure_id":"exposure-contained"}}
{"schema_version":2,"session_id":"session-contained","request_id":"request-action","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","header_value_mint_status":"matched_session_value","exposure_id":"exposure-contained"}}
{"schema_version":2,"session_id":"session-contained","request_id":"request-action","kind":{"type":"response_served","status":202,"controlled_reality":{"kind":"job_submitted","origin_request_id":"request-action","job_id":"job-recovery"}}}
{"schema_version":2,"session_id":"session-control","request_id":"request-control-seed","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","header_value_mint_status":"matched_session_value","exposure_id":null}}
{"schema_version":2,"session_id":"session-control","request_id":"request-replay","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","header_value_mint_status":"replay_seen","exposure_id":null}}
{"schema_version":2,"session_id":"session-contained","request_id":"request-status","kind":{"type":"response_served","status":200,"controlled_reality":{"kind":"status_read","origin_request_id":"request-action","job_id":"job-recovery"}}}
JSONL

  cat >"$dir/proxy-debug.jsonl" <<'JSONL'
{"event":"session_resolved","session_id":"session-control","fields":{"request_id":"request-replay","session_source":"cookie","cookie_outcome":"valid","key_status":"active"}}
{"event":"session_resolved","session_id":"session-contained","fields":{"request_id":"request-status","session_source":"cookie","cookie_outcome":"valid","key_status":"active"}}
JSONL

  cat >"$dir/target-audit.jsonl" <<'JSONL'
{"event":"protected_upstream_probe_observed","probe_id":"baseline-recovery","pod":"target-a"}
{"event":"protected_upstream_probe_observed","probe_id":"baseline-recovery","pod":"target-b"}
JSONL
}

clone_valid_fixture() {
  local name="$1"
  local dir

  dir="$(new_fixture "$name")"
  cp -R "$valid/." "$dir/"
  printf '%s\n' "$dir"
}

mutate_json() {
  local file="$1"
  local filter="$2"

  jq "$filter" "$file" >"$file.tmp"
  mv "$file.tmp" "$file"
}

mutate_jsonl() {
  local file="$1"
  local filter="$2"

  jq -c "$filter" "$file" >"$file.tmp"
  mv "$file.tmp" "$file"
}

expect_failure() {
  local name="$1"
  local dir="$2"

  if "$SMOKE_SCRIPT" --validate-fixture "$dir" >/dev/null 2>&1; then
    echo "fixture unexpectedly passed: $name" >&2
    exit 1
  fi
}

assert_static_contract() {
  "$PYTHON_BIN" - "$SMOKE_SCRIPT" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text()

required = [
    '[[ "$context" == "$EXPECTED_CONTEXT" ]]',
    'proxy deployment must use Recreate',
    'proxy deployment must begin with exactly one replica',
    'renderer deployment must begin with exactly one replica',
    'proxy PVC must be Bound and ReadWriteOnce',
    'create configmap "$RECOVERY_LOCK"',
    'recovery lock already exists',
    'trap cleanup EXIT',
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
    'delete configmap "$RECOVERY_LOCK"',
]
for needle in required:
    if needle not in source:
        raise SystemExit(f"missing recovery guard: {needle}")

helper = source.split("create_helper_pod() {", 1)[1].split(
    "\ndelete_helper_pod() {", 1
)[0]
for needle in [
    "automountServiceAccountToken: false",
    "enableServiceLinks: false",
    'restartPolicy: "Never"',
    "runAsNonRoot: true",
    "runAsUser: 65532",
    "runAsGroup: 65532",
    "fsGroup: 65532",
    'fsGroupChangePolicy: "OnRootMismatch"',
    'seccompProfile: {type: "RuntimeDefault"}',
    "allowPrivilegeEscalation: false",
    "readOnlyRootFilesystem: true",
    'capabilities: {drop: ["ALL"]}',
    'mountPath: "/state"',
    "readOnly: $read_only",
    "persistentVolumeClaim: {claimName: $pvc}",
]:
    if needle not in helper:
        raise SystemExit(f"helper lost hardening: {needle}")
for forbidden in ["hostPath", "secret:", "configMap:", "serviceAccountName"]:
    if forbidden in helper:
        raise SystemExit(f"helper gained forbidden volume or identity: {forbidden}")
if helper.count("volumeMounts:") != 1 or helper.count("persistentVolumeClaim:") != 1:
    raise SystemExit("helper must mount exactly one PVC and no other storage")

policy = source.split("create_helper_policy() {", 1)[1].split(
    "\ncreate_helper_pod() {", 1
)[0]
if 'policyTypes: ["Ingress", "Egress"]' not in policy:
    raise SystemExit("helper NetworkPolicy lost ingress/egress isolation")
if "ingress: []" not in policy or "egress: []" not in policy:
    raise SystemExit("helper NetworkPolicy is not default deny")

snapshot = source.split("write_secret_snapshot() {", 1)[1].split(
    "\nsnapshot_secret() {", 1
)[0]
secret_shapes = [
    ('eidolon-session-signing', '["key-ring.json"]'),
    (
        "eidolon-trusted-ingress",
        '["transport-auth.txt","continuity-key.txt"]',
    ),
    ('eidolon-bait-signing', '["signing-secret.txt"]'),
    ('eidolon-controlled-reality-auth', '["auth-secret.txt"]'),
]
for name, keys in secret_shapes:
    if name not in snapshot or keys not in snapshot:
        raise SystemExit(f"missing exact Secret snapshot shape: {name} {keys}")
if snapshot.count("snapshot_secret ") != 5:
    raise SystemExit("recovery must snapshot exactly five Secret objects")
if "$RENDERER_NAMESPACE" not in snapshot or "$PROXY_NAMESPACE" not in snapshot:
    raise SystemExit("both renderer-auth Secret copies must be snapshotted")

secret_restore = source.split("restore_secrets() {", 1)[1].split(
    "\nwrite_request() {", 1
)[0]
if secret_restore.count("|| return 1") != 2:
    raise SystemExit("Secret restore operations must propagate every failure")

lifecycle = source.split('downtime_start="$(date +%s)"', 1)[1]
ordered = [
    'deployment/"$PROXY_DEPLOYMENT" --replicas=0',
    "wait_for_zero_proxy_endpoints",
    'deployment/"$RENDERER_DEPLOYMENT" --replicas=0',
    "wait_for_zero_renderer_pods",
    'delete pvc "$PROXY_PVC" --wait=true',
    'create -f "$tmp_dir/pvc.json"',
    'deployment/"$RENDERER_DEPLOYMENT" --replicas=1',
    'deployment/"$PROXY_DEPLOYMENT" --replicas=1',
]
position = -1
for needle in ordered:
    next_position = lifecycle.find(needle, position + 1)
    if next_position < 0:
        raise SystemExit(f"missing ordered recovery operation: {needle}")
    position = next_position
if (
    '[[ "$old_pvc_uid" != "$new_pvc_uid" && "$old_pv_uid" != "$new_pv_uid" ]]'
    not in lifecycle
):
    raise SystemExit("fresh PVC/PV identity is not enforced")
if 'cut -f1 "$tmp_dir/state-before.tsv"' not in lifecycle:
    raise SystemExit("backup archive is not derived from the allowlisted state manifest")
if "tar -C /state -cf - -T -" not in lifecycle:
    raise SystemExit("backup archive may include PVC-root metadata")
if re.search(r"tar\s+-C\s+/state\s+-cf\s+-\s+\.", lifecycle):
    raise SystemExit("backup archive must not include the PVC root entry")

evidence_names = set(
    re.findall(r'\$evidence_dir/([A-Za-z0-9.-]+)', source)
)
expected_names = {
    "recovery.json",
    "flow.json",
    "policy-before.json",
    "policy-restored.json",
    "policy-after.json",
    "proxy-events.jsonl",
    "proxy-debug.jsonl",
    "target-audit.jsonl",
}
if evidence_names != expected_names:
    raise SystemExit(
        f"unexpected evidence output contract: {sorted(evidence_names)}"
    )

for line in source.splitlines():
    if "evidence_dir" in line and any(
        raw in line
        for raw in (
            ".cookie",
            ".proof",
            "contained_cookie",
            "control_cookie",
            "contained_proof",
            "control_proof",
            "secrets-before",
            "secrets-restored",
        )
    ):
        raise SystemExit(f"raw material may reach evidence output: {line.strip()}")

generation = source.split(
    'jq -n \\\n  --arg old_uid "$old_pvc_uid"', 1
)[1].split('validate_evidence "$evidence_dir"', 1)[0]
for raw in (
    "contained_cookie",
    "control_cookie",
    "contained_proof",
    "control_proof",
    "a.cookie",
    "b.cookie",
    "a.proof",
    "b.proof",
    "secrets-before/",
    "secrets-restored/",
):
    if raw in generation:
        raise SystemExit(f"raw value included in evidence generation: {raw}")
PY
}

command -v jq >/dev/null 2>&1 || {
  echo "missing required tool: jq" >&2
  exit 1
}
command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
  echo "missing required tool: $PYTHON_BIN" >&2
  exit 1
}
[[ -x "$SMOKE_SCRIPT" ]] || {
  echo "smoke script is not executable: $SMOKE_SCRIPT" >&2
  exit 1
}

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-state-recovery-fixtures.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

valid="$(new_fixture valid)"
write_valid_fixture "$valid"

expected_files=(
  flow.json
  policy-after.json
  policy-before.json
  policy-restored.json
  proxy-debug.jsonl
  proxy-events.jsonl
  recovery.json
  target-audit.jsonl
)
fixture_entries=("$valid"/*)
[[ "${#fixture_entries[@]}" == "${#expected_files[@]}" ]] || {
  echo "valid fixture does not contain exactly eight files" >&2
  exit 1
}
for file in "${expected_files[@]}"; do
  [[ -f "$valid/$file" ]] || {
    echo "valid fixture is missing: $file" >&2
    exit 1
  }
done

"$SMOKE_SCRIPT" --validate-fixture "$valid" \
  | jq -e '
      .schema_version == 1
      and .result == "passed"
      and .pvc_replaced == true
      and .contained_session_preserved == true
      and .consumed_proof_rejected_after_restore == true
      and .protected_upstream_writes == 0
      and .downtime_seconds == 42
      and .contained_session_id == "session-contained"
      and .control_session_id == "session-control"
    ' >/dev/null

bad="$(clone_valid_fixture same-pvc-uid)"
mutate_json "$bad/recovery.json" '.pvc.new_uid = .pvc.old_uid'
expect_failure same-pvc-uid "$bad"

bad="$(clone_valid_fixture same-pv-uid)"
mutate_json "$bad/recovery.json" '.pvc.new_pv_uid = .pvc.old_pv_uid'
expect_failure same-pv-uid "$bad"

bad="$(clone_valid_fixture proxy-not-quiesced)"
mutate_json "$bad/recovery.json" '.quiesced.proxy_pods = 1'
expect_failure proxy-not-quiesced "$bad"

bad="$(clone_valid_fixture endpoint-not-quiesced)"
mutate_json "$bad/recovery.json" '.quiesced.proxy_ready_endpoints = 1'
expect_failure endpoint-not-quiesced "$bad"

bad="$(clone_valid_fixture renderer-not-quiesced)"
mutate_json "$bad/recovery.json" '.quiesced.renderer_pods = 1'
expect_failure renderer-not-quiesced "$bad"

bad="$(clone_valid_fixture missing-consumed-sidecar)"
mutate_json "$bad/recovery.json" '
  .state.before |= map(select(.path != "events.jsonl.consumed-proofs.json"))
  | .state.restored |= map(select(.path != "events.jsonl.consumed-proofs.json"))
'
expect_failure missing-consumed-sidecar "$bad"

bad="$(clone_valid_fixture state-digest-mismatch)"
mutate_json "$bad/recovery.json" '
  .state.restored[0].sha256 =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
'
expect_failure state-digest-mismatch "$bad"

bad="$(clone_valid_fixture missing-secret-key)"
mutate_json "$bad/recovery.json" '
  .secrets.before |= map(select(.key != "continuity-key.txt"))
  | .secrets.restored |= map(select(.key != "continuity-key.txt"))
'
expect_failure missing-secret-key "$bad"

bad="$(clone_valid_fixture unexpected-secret-key)"
mutate_json "$bad/recovery.json" '
  .secrets.before += [{
    namespace: "shield-system",
    name: "eidolon-trusted-ingress",
    key: "unexpected.txt",
    sha256: "abababababababababababababababababababababababababababababababab",
    bytes: 32
  }]
  | .secrets.restored += [{
    namespace: "shield-system",
    name: "eidolon-trusted-ingress",
    key: "unexpected.txt",
    sha256: "abababababababababababababababababababababababababababababababab",
    bytes: 32
  }]
'
expect_failure unexpected-secret-key "$bad"

bad="$(clone_valid_fixture secret-digest-mismatch)"
mutate_json "$bad/recovery.json" '
  .secrets.restored[]
  |= if .key == "key-ring.json"
     then .sha256 =
       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     else .
     end
'
expect_failure secret-digest-mismatch "$bad"

bad="$(clone_valid_fixture renderer-auth-mismatch)"
mutate_json "$bad/recovery.json" '
  .secrets.before[]
  |= if .namespace == "shield-controlled-reality"
     then .sha256 =
       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     else .
     end
  | .secrets.restored[]
  |= if .namespace == "shield-controlled-reality"
     then .sha256 =
       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     else .
     end
'
expect_failure renderer-auth-mismatch "$bad"

bad="$(clone_valid_fixture contained-session-mismatch)"
mutate_json "$bad/policy-before.json" '.contained.session_id = "session-other"'
expect_failure contained-session-mismatch "$bad"

bad="$(clone_valid_fixture contained-policy-state)"
mutate_json "$bad/policy-before.json" '.contained.policy_state = "observe"'
expect_failure contained-policy-state "$bad"

bad="$(clone_valid_fixture contained-depth)"
mutate_json "$bad/policy-before.json" '.contained.controlled_reality_depth = 2'
expect_failure contained-depth "$bad"

bad="$(clone_valid_fixture contained-origin)"
mutate_json "$bad/policy-before.json" '
  .contained.controlled_reality_origin_request_id = "request-other"
'
expect_failure contained-origin "$bad"

bad="$(clone_valid_fixture restored-policy-differs)"
mutate_json "$bad/policy-restored.json" '.contained.restore_marker = "changed"'
expect_failure restored-policy-differs "$bad"

bad="$(clone_valid_fixture workflow-not-completed)"
mutate_json "$bad/policy-after.json" '
  .contained.controlled_reality_workflow_state = "queued"
'
expect_failure workflow-not-completed "$bad"

bad="$(clone_valid_fixture action-exposure-unlinked)"
mutate_jsonl "$bad/proxy-events.jsonl" '
  if .request_id == "request-action"
  then .kind.exposure_id = "exposure-other"
  else .
  end
'
expect_failure action-exposure-unlinked "$bad"

bad="$(clone_valid_fixture duplicate-exposure)"
first_event="$(head -n 1 "$bad/proxy-events.jsonl")"
printf '%s\n' "$first_event" >>"$bad/proxy-events.jsonl"
expect_failure duplicate-exposure "$bad"

bad="$(clone_valid_fixture replay-not-403)"
mutate_json "$bad/flow.json" '.statuses.replay = 200'
expect_failure replay-not-403 "$bad"

bad="$(clone_valid_fixture replay-not-replay-seen)"
mutate_jsonl "$bad/proxy-events.jsonl" '
  if .request_id == "request-replay"
  then .kind.header_value_mint_status = "matched_session_value"
  else .
  end
'
expect_failure replay-not-replay-seen "$bad"

bad="$(clone_valid_fixture replay-linked-exposure)"
mutate_jsonl "$bad/proxy-events.jsonl" '
  if .request_id == "request-replay"
  then .kind.exposure_id = "exposure-contained"
  else .
  end
'
expect_failure replay-linked-exposure "$bad"

bad="$(clone_valid_fixture control-policy-transition)"
mutate_json "$bad/policy-after.json" '.control.policy_state = "controlled_reality"'
expect_failure control-policy-transition "$bad"

bad="$(clone_valid_fixture control-policy-event)"
cat >>"$bad/proxy-events.jsonl" <<'JSONL'
{"schema_version":2,"session_id":"session-control","request_id":"request-replay","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality"}}
JSONL
expect_failure control-policy-event "$bad"

bad="$(clone_valid_fixture invalid-old-cookie)"
mutate_jsonl "$bad/proxy-debug.jsonl" '
  if .session_id == "session-control"
  then .fields.cookie_outcome = "invalid"
  else .
  end
'
expect_failure invalid-old-cookie "$bad"

bad="$(clone_valid_fixture missing-target-baseline)"
mutate_jsonl "$bad/target-audit.jsonl" 'select(.pod != "target-b")'
expect_failure missing-target-baseline "$bad"

bad="$(clone_valid_fixture extra-target-write)"
cat >>"$bad/target-audit.jsonl" <<'JSONL'
{"event":"protected_upstream_probe_observed","probe_id":"unexpected-write","pod":"target-a"}
JSONL
expect_failure extra-target-write "$bad"

assert_static_contract

echo "kind state backup/restore fixture tests ok"
