#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-session-key-rotation-kind.sh"
PYTHON_BIN="${PYTHON_BIN:-python3}"

new_fixture() {
  local name="$1"
  local dir="$tmp_root/$name"

  mkdir "$dir"
  printf '%s\n' "$dir"
}

write_valid_fixture() {
  local dir="$1"

  cat >"$dir/rotation.json" <<'JSON'
{
  "schema_version": 1,
  "secret": {
    "before": {
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "bytes": 140,
      "active_key_version": 1,
      "versions": [1],
      "key_version_count": 1
    },
    "installed": {
      "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "bytes": 140,
      "active_key_version": 1,
      "versions": [1],
      "key_version_count": 1
    },
    "rotated": {
      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "bytes": 240,
      "active_key_version": 2,
      "versions": [1, 2],
      "key_version_count": 2
    },
    "restored": {
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "bytes": 140,
      "active_key_version": 1,
      "versions": [1],
      "key_version_count": 1
    }
  },
  "pod_uids": {
    "initial": "pod-initial",
    "installed": "pod-installed",
    "rotated": "pod-rotated",
    "second": "pod-second",
    "restored": "pod-restored"
  },
  "downtime_seconds": 17,
  "total_seconds": 241,
  "proxy_started_baseline_count": 1
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
  "replay_after_rotation_request_id": "request-replay-rotated",
  "replay_final_request_id": "request-replay-final",
  "status_remint_request_id": "request-status-remint",
  "status_final_request_id": "request-status-final",
  "job_id": "job-rotation",
  "status_path": "/api/v2/import/reconcile/jobs/job-rotation",
  "baseline_probe_id": "baseline-rotation",
  "statuses": {
    "contained_action": 202,
    "control_seed": 202,
    "status_remint": 200,
    "replay_after_rotation": 403,
    "status_final": 200,
    "replay_final": 403
  },
  "write_committed": {
    "contained_action": false,
    "status_remint": false,
    "status_final": false
  },
  "cookies": {
    "contained_initial_key_version": 1,
    "control_initial_key_version": 1,
    "reminted_key_version": 2,
    "reminted_same_session": true,
    "reminted_signature_changed": true,
    "status_remint_set_cookie_count": 1,
    "status_final_set_cookie_count": 0
  },
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
  cp "$dir/policy-before.json" "$dir/policy-rotated.json"

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
{"schema_version":2,"session_id":"session-contained","request_id":"request-action","kind":{"type":"response_served","status":202,"controlled_reality":{"kind":"job_submitted","origin_request_id":"request-action","job_id":"job-rotation"}}}
{"schema_version":2,"session_id":"session-control","request_id":"request-control-seed","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","header_value_mint_status":"matched_session_value","exposure_id":null}}
{"schema_version":2,"session_id":"session-control","request_id":"request-replay-rotated","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","header_value_mint_status":"replay_seen","exposure_id":null}}
{"schema_version":2,"session_id":"session-control","request_id":"request-replay-final","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","header_value_mint_status":"replay_seen","exposure_id":null}}
{"schema_version":2,"session_id":"session-contained","request_id":"request-status-remint","kind":{"type":"response_served","status":200,"controlled_reality":{"kind":"status_read","origin_request_id":"request-action","job_id":"job-rotation"}}}
{"schema_version":2,"session_id":"session-contained","request_id":"request-status-final","kind":{"type":"response_served","status":200,"controlled_reality":{"kind":"status_read","origin_request_id":"request-action","job_id":"job-rotation"}}}
JSONL

  cat >"$dir/proxy-debug.jsonl" <<'JSONL'
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":1000,"fields":{"session_signing":{"mode":"configured","active_key_version":1,"key_version_count":1},"restored_consumed_bait_proof_count":0}}
{"event":"session_resolved","session_id":"session-contained","fields":{"request_id":"request-status-remint","session_source":"cookie","cookie_outcome":"valid","key_status":"previous","presented_key_version":1,"active_key_version":2}}
{"event":"session_resolved","session_id":"session-contained","fields":{"request_id":"request-status-final","session_source":"cookie","cookie_outcome":"valid","key_status":"active","presented_key_version":2,"active_key_version":2}}
{"event":"session_resolved","session_id":"session-control","fields":{"request_id":"request-replay-rotated","session_source":"cookie","cookie_outcome":"valid","key_status":"previous","presented_key_version":1,"active_key_version":2}}
{"event":"session_resolved","session_id":"session-control","fields":{"request_id":"request-replay-final","session_source":"cookie","cookie_outcome":"valid","key_status":"previous","presented_key_version":1,"active_key_version":2}}
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":2000,"fields":{"session_signing":{"mode":"configured","active_key_version":1,"key_version_count":1},"restored_consumed_bait_proof_count":0}}
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":3000,"fields":{"session_signing":{"mode":"configured","active_key_version":2,"key_version_count":2},"restored_consumed_bait_proof_count":2}}
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":4000,"fields":{"session_signing":{"mode":"configured","active_key_version":2,"key_version_count":2},"restored_consumed_bait_proof_count":2}}
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":5000,"fields":{"session_signing":{"mode":"configured","active_key_version":1,"key_version_count":1},"restored_consumed_bait_proof_count":2}}
JSONL

  cat >"$dir/target-audit.jsonl" <<'JSONL'
{"event":"protected_upstream_probe_observed","probe_id":"baseline-rotation","pod":"target-a"}
{"event":"protected_upstream_probe_observed","probe_id":"baseline-rotation","pod":"target-b"}
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
    'create configmap "$ROTATION_LOCK"',
    'rotation lock already exists',
    'trap cleanup EXIT',
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
    'delete configmap "$ROTATION_LOCK"',
    'validate-session-key-file.py',
]
for needle in required:
    if needle not in source:
        raise SystemExit(f"missing rotation guard: {needle}")

if "set -x" in source or "set -v" in source or "set -o xtrace" in source:
    raise SystemExit("shell tracing may leak keys, cookies, or proofs")

probe = source.split("create_probe_pod() {", 1)[1].split(
    "\nsnapshot_secret() {", 1
)[0]
for needle in [
    "automountServiceAccountToken: false",
    "enableServiceLinks: false",
    'restartPolicy: "Never"',
    "runAsNonRoot: true",
    "runAsUser: 65532",
    "runAsGroup: 65532",
    'seccompProfile: {type: "RuntimeDefault"}',
    "allowPrivilegeEscalation: false",
    "readOnlyRootFilesystem: true",
    'capabilities: {drop: ["ALL"]}',
]:
    if needle not in probe:
        raise SystemExit(f"probe lost hardening: {needle}")
for forbidden in [
    "hostPath",
    "secret:",
    "configMap:",
    "serviceAccountName",
    "persistentVolumeClaim",
    "volumeMounts",
]:
    if forbidden in probe:
        raise SystemExit(f"probe gained forbidden volume or identity: {forbidden}")

if source.count("snapshot_secret ") != 6:
    raise SystemExit("rotation must snapshot exactly six Secret states")
if source.count('\'["key-ring.json"]\'') != 5:
    raise SystemExit("session-signing Secret must be snapshotted at five phases")
if source.count('\'["signing-secret.txt"]\'') != 1:
    raise SystemExit("bait-signing Secret must be snapshotted exactly once")

replace = source.split("replace_session_signing_secret() {", 1)[1].split(
    "\nrestart_proxy_deployment() {", 1
)[0]
if replace.count("|| return 1") != 2:
    raise SystemExit("Secret replacement must propagate every failure")

if source.count("restart_proxy_deployment") != 5:
    raise SystemExit("rotation must restart the proxy deployment exactly four times")

ordered = [
    "printf '{\"active_key_version\":1,",
    'replace_session_signing_secret "$tmp_dir/secret-v1-manifest.json"',
    "restart_proxy_deployment",
    "printf '{\"active_key_version\":2,",
    'replace_session_signing_secret "$tmp_dir/secret-v2-manifest.json"',
    "restart_proxy_deployment",
    'replace_session_signing_secret "$tmp_dir/secrets-before/session-signing.json"',
    "recovery_complete=1",
]
position = -1
for needle in ordered:
    next_position = source.find(needle, position + 1)
    if next_position < 0:
        raise SystemExit(f"missing ordered rotation operation: {needle}")
    position = next_position

for needle in [
    '[[ "$(cut -d. -f2 <<<"$contained_cookie")" == "1" ]]',
    '[[ "$(cut -d. -f2 <<<"$control_cookie")" == "1" ]]',
    '[[ "$(cut -d. -f2 <<<"$reminted_cookie")" == "2" ]]',
    '[[ "$(cut -d. -f4 <<<"$reminted_cookie")" == "$contained_session_id" ]]',
    '[[ "$(cut -d. -f5 <<<"$reminted_cookie")" != "$contained_signature" ]]',
    '[[ "$(set_cookie_count "$tmp_dir/a-status-remint.response")" == "1" ]]',
    '[[ "$(set_cookie_count "$tmp_dir/a-status-final.response")" == "0" ]]',
    '[[ "$(restored_consumed_proof_count)" -ge 2 ]]',
    'assert_last_proxy_started 1 1 "$started_marker"',
    'assert_last_proxy_started "$before_active" "$before_count" "$started_marker"',
]:
    if needle not in source:
        raise SystemExit(f"missing rotation assertion: {needle}")
if source.count('assert_last_proxy_started 2 2 "$started_marker"') != 2:
    raise SystemExit("the overlapping ring must be asserted after both restarts")

for line in source.splitlines():
    if "key_hex" in line and "printf" not in line and ".keys[0].key_hex" not in line:
        raise SystemExit(f"key material may reach process argv: {line.strip()}")

facts = source.split("key_ring_facts() {", 1)[1].split(
    "\nvalidate_ring_file() {", 1
)[0]
if "key_hex" in facts:
    raise SystemExit("key ring facts must only contain versions, never key material")

evidence_names = set(
    re.findall(r'\$evidence_dir/([A-Za-z0-9.-]+)', source)
)
expected_names = {
    "rotation.json",
    "flow.json",
    "policy-before.json",
    "policy-rotated.json",
    "policy-after.json",
    "proxy-events.jsonl",
    "proxy-debug.jsonl",
    "target-audit.jsonl",
}
if evidence_names != expected_names:
    raise SystemExit(
        f"unexpected evidence output contract: {sorted(evidence_names)}"
    )

raw_tokens = (
    ".cookie",
    ".proof",
    "contained_cookie",
    "control_cookie",
    "reminted_cookie",
    "contained_proof",
    "control_proof",
    "ring-v1",
    "ring-v2",
    "secret-v1-manifest",
    "secret-v2-manifest",
    "v1_key",
    "v2_key",
)
for line in source.splitlines():
    if "evidence_dir" in line and any(raw in line for raw in raw_tokens):
        raise SystemExit(f"raw material may reach evidence output: {line.strip()}")

generation = source.split("secret_phase_json() {", 1)[1].split(
    'validate_evidence "$evidence_dir"', 1
)[0]
for raw in raw_tokens + (
    "a.cookie",
    "b.cookie",
    "a.proof",
    "b.proof",
    "ring-v1.json",
    "ring-v2.json",
    "key_hex",
):
    if raw in generation:
        raise SystemExit(f"raw value included in evidence generation: {raw}")
for needle in [
    "sha256: $sha256,",
    "bytes: $bytes,",
    "active_key_version: $facts.active_key_version,",
    "versions: $facts.versions,",
    "key_version_count: $facts.key_version_count",
]:
    if needle not in generation:
        raise SystemExit(f"secret phases must only record digests and versions: {needle}")
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

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-key-rotation-fixtures.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

valid="$(new_fixture valid)"
write_valid_fixture "$valid"

expected_files=(
  flow.json
  policy-after.json
  policy-before.json
  policy-rotated.json
  proxy-debug.jsonl
  proxy-events.jsonl
  rotation.json
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
      and .session_key_rotated == true
      and .overlapping_versions == [1, 2]
      and .v1_cookie_reminted_under_v2 == true
      and .session_identity_preserved == true
      and .consumed_proof_rejected_after_rotation == true
      and .consumed_proof_rejected_after_second_restart == true
      and .protected_upstream_writes == 0
      and .original_secret_restored == true
      and .deployment_healthy == true
      and .downtime_seconds == 17
      and .contained_session_id == "session-contained"
      and .control_session_id == "session-control"
    ' >/dev/null

bad="$(clone_valid_fixture same-pod-uid)"
mutate_json "$bad/rotation.json" '.pod_uids.rotated = .pod_uids.installed'
expect_failure same-pod-uid "$bad"

bad="$(clone_valid_fixture installed-not-v1)"
mutate_json "$bad/rotation.json" '.secret.installed.active_key_version = 2'
expect_failure installed-not-v1 "$bad"

bad="$(clone_valid_fixture installed-extra-version)"
mutate_json "$bad/rotation.json" '.secret.installed.versions = [1, 2]'
expect_failure installed-extra-version "$bad"

bad="$(clone_valid_fixture rotated-missing-v1)"
mutate_json "$bad/rotation.json" '.secret.rotated.versions = [2]'
expect_failure rotated-missing-v1 "$bad"

bad="$(clone_valid_fixture rotated-v1-still-active)"
mutate_json "$bad/rotation.json" '.secret.rotated.active_key_version = 1'
expect_failure rotated-v1-still-active "$bad"

bad="$(clone_valid_fixture rotated-same-digest)"
mutate_json "$bad/rotation.json" '.secret.rotated.sha256 = .secret.installed.sha256'
expect_failure rotated-same-digest "$bad"

bad="$(clone_valid_fixture install-same-digest)"
mutate_json "$bad/rotation.json" '.secret.installed.sha256 = .secret.before.sha256'
expect_failure install-same-digest "$bad"

bad="$(clone_valid_fixture restore-digest-mismatch)"
mutate_json "$bad/rotation.json" '
  .secret.restored.sha256 =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
'
expect_failure restore-digest-mismatch "$bad"

bad="$(clone_valid_fixture restore-version-drift)"
mutate_json "$bad/rotation.json" '.secret.restored.active_key_version = 7'
expect_failure restore-version-drift "$bad"

bad="$(clone_valid_fixture baseline-count-drift)"
mutate_json "$bad/rotation.json" '.proxy_started_baseline_count = 0'
expect_failure baseline-count-drift "$bad"

bad="$(clone_valid_fixture replay-rotated-not-403)"
mutate_json "$bad/flow.json" '.statuses.replay_after_rotation = 200'
expect_failure replay-rotated-not-403 "$bad"

bad="$(clone_valid_fixture replay-final-not-403)"
mutate_json "$bad/flow.json" '.statuses.replay_final = 200'
expect_failure replay-final-not-403 "$bad"

bad="$(clone_valid_fixture remint-wrong-version)"
mutate_json "$bad/flow.json" '.cookies.reminted_key_version = 1'
expect_failure remint-wrong-version "$bad"

bad="$(clone_valid_fixture remint-different-session)"
mutate_json "$bad/flow.json" '.cookies.reminted_same_session = false'
expect_failure remint-different-session "$bad"

bad="$(clone_valid_fixture remint-signature-unchanged)"
mutate_json "$bad/flow.json" '.cookies.reminted_signature_changed = false'
expect_failure remint-signature-unchanged "$bad"

bad="$(clone_valid_fixture status-final-reminted)"
mutate_json "$bad/flow.json" '.cookies.status_final_set_cookie_count = 1'
expect_failure status-final-reminted "$bad"

bad="$(clone_valid_fixture status-remint-not-reminted)"
mutate_json "$bad/flow.json" '.cookies.status_remint_set_cookie_count = 0'
expect_failure status-remint-not-reminted "$bad"

bad="$(clone_valid_fixture sessions-merged)"
mutate_json "$bad/flow.json" '.control_session_id = "session-contained"'
expect_failure sessions-merged "$bad"

bad="$(clone_valid_fixture contained-depth)"
mutate_json "$bad/policy-before.json" '.contained.controlled_reality_depth = 2'
expect_failure contained-depth "$bad"

bad="$(clone_valid_fixture contained-origin)"
mutate_json "$bad/policy-before.json" '
  .contained.controlled_reality_origin_request_id = "request-other"
'
expect_failure contained-origin "$bad"

bad="$(clone_valid_fixture workflow-not-queued-before)"
mutate_json "$bad/policy-before.json" '
  .contained.controlled_reality_workflow_state = "completed"
'
expect_failure workflow-not-queued-before "$bad"

bad="$(clone_valid_fixture rotated-policy-differs)"
mutate_json "$bad/policy-rotated.json" '.contained.rotation_marker = "changed"'
expect_failure rotated-policy-differs "$bad"

bad="$(clone_valid_fixture control-persisted-after-rotation)"
mutate_json "$bad/policy-rotated.json" '.control.persisted = true'
expect_failure control-persisted-after-rotation "$bad"

bad="$(clone_valid_fixture workflow-not-completed-after)"
mutate_json "$bad/policy-after.json" '
  .contained.controlled_reality_workflow_state = "queued"
'
expect_failure workflow-not-completed-after "$bad"

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

bad="$(clone_valid_fixture replay-not-replay-seen)"
mutate_jsonl "$bad/proxy-events.jsonl" '
  if .request_id == "request-replay-rotated"
  then .kind.header_value_mint_status = "matched_session_value"
  else .
  end
'
expect_failure replay-not-replay-seen "$bad"

bad="$(clone_valid_fixture second-replay-missing)"
mutate_jsonl "$bad/proxy-events.jsonl" '
  select(.request_id != "request-replay-final")
'
expect_failure second-replay-missing "$bad"

bad="$(clone_valid_fixture duplicate-status-read)"
cat >>"$bad/proxy-events.jsonl" <<'JSONL'
{"schema_version":2,"session_id":"session-contained","request_id":"request-status-final","kind":{"type":"response_served","status":200,"controlled_reality":{"kind":"status_read","origin_request_id":"request-action","job_id":"job-rotation"}}}
JSONL
expect_failure duplicate-status-read "$bad"

bad="$(clone_valid_fixture control-policy-event)"
cat >>"$bad/proxy-events.jsonl" <<'JSONL'
{"schema_version":2,"session_id":"session-control","request_id":"request-replay-final","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality"}}
JSONL
expect_failure control-policy-event "$bad"

bad="$(clone_valid_fixture remint-not-previous)"
mutate_jsonl "$bad/proxy-debug.jsonl" '
  if .fields.request_id == "request-status-remint"
  then .fields.key_status = "active"
  else .
  end
'
expect_failure remint-not-previous "$bad"

bad="$(clone_valid_fixture final-not-active)"
mutate_jsonl "$bad/proxy-debug.jsonl" '
  if .fields.request_id == "request-status-final"
  then .fields.key_status = "previous"
  else .
  end
'
expect_failure final-not-active "$bad"

bad="$(clone_valid_fixture wrong-presented-version)"
mutate_jsonl "$bad/proxy-debug.jsonl" '
  if .fields.request_id == "request-status-remint"
  then .fields.presented_key_version = 2
  else .
  end
'
expect_failure wrong-presented-version "$bad"

bad="$(clone_valid_fixture install-start-missing)"
mutate_jsonl "$bad/proxy-debug.jsonl" '
  if .observed_at_unix_ms == 2000
  then .fields.session_signing.active_key_version = 2
  else .
  end
'
expect_failure install-start-missing "$bad"

bad="$(clone_valid_fixture rotation-restored-count-zero)"
mutate_jsonl "$bad/proxy-debug.jsonl" '
  if .observed_at_unix_ms == 3000
  then .fields.restored_consumed_bait_proof_count = 0
  else .
  end
'
expect_failure rotation-restored-count-zero "$bad"

bad="$(clone_valid_fixture starts-not-increasing)"
mutate_jsonl "$bad/proxy-debug.jsonl" '
  if .observed_at_unix_ms == 4000
  then .observed_at_unix_ms = 3000
  else .
  end
'
expect_failure starts-not-increasing "$bad"

bad="$(clone_valid_fixture missing-target-baseline)"
mutate_jsonl "$bad/target-audit.jsonl" 'select(.pod != "target-b")'
expect_failure missing-target-baseline "$bad"

bad="$(clone_valid_fixture control-replay-not-previous)"
mutate_jsonl "$bad/proxy-debug.jsonl" '
  if .fields.request_id == "request-replay-rotated"
  then .fields.key_status = "active"
  else .
  end
'
expect_failure control-replay-not-previous "$bad"

bad="$(clone_valid_fixture control-exposure-present)"
cat >>"$bad/proxy-events.jsonl" <<'JSONL'
{"schema_version":2,"session_id":"session-control","request_id":"request-control-exposure","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","exposure_id":"exposure-control"}}
JSONL
expect_failure control-exposure-present "$bad"

bad="$(clone_valid_fixture control-seed-missing)"
mutate_jsonl "$bad/proxy-events.jsonl" '
  select(.request_id != "request-control-seed")
'
expect_failure control-seed-missing "$bad"

bad="$(clone_valid_fixture job-entry-missing)"
mutate_jsonl "$bad/proxy-events.jsonl" '
  select(.kind.type != "response_served" or .kind.status != 202)
'
expect_failure job-entry-missing "$bad"

bad="$(clone_valid_fixture restored-bytes-mismatch)"
mutate_json "$bad/rotation.json" '.secret.restored.bytes = 999'
expect_failure restored-bytes-mismatch "$bad"

bad="$(clone_valid_fixture control-seed-not-202)"
mutate_json "$bad/flow.json" '.statuses.control_seed = 200'
expect_failure control-seed-not-202 "$bad"

bad="$(clone_valid_fixture extra-target-write)"
cat >>"$bad/target-audit.jsonl" <<'JSONL'
{"event":"protected_upstream_probe_observed","probe_id":"unexpected-write","pod":"target-a"}
JSONL
expect_failure extra-target-write "$bad"

assert_static_contract
