#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-overlapping-writer-lease-kind.sh"
PYTHON_BIN="${PYTHON_BIN:-python3}"

new_fixture() {
  local name="$1"
  local dir="$tmp_root/$name"

  mkdir "$dir"
  printf '%s\n' "$dir"
}

write_valid_fixture() {
  local dir="$1"

  cat >"$dir/lease-proof.json" <<'JSON'
{
  "schema_version": 1,
  "primary": {
    "pod_uid": "pod-primary",
    "node_name": "node-a",
    "restart_count_before": 1,
    "restart_count_after": 1,
    "ready_after": true
  },
  "interloper": {
    "pod_name": "pod-interloper",
    "node_name": "node-a",
    "phase": "Failed",
    "lease_error_observed": true,
    "restart_count": 0
  },
  "state": {
    "events_digest_before": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "events_digest_after": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "debug_lines_before": 100,
    "debug_lines_after": 102,
    "debug_added_records_allowed": true,
    "policy_digest_before": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "policy_digest_after": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "proxy_started_count_before": 3,
    "proxy_started_count_after": 3
  }
}
JSON

  cat >"$dir/flow.json" <<'JSON'
{
  "primary_pod_uid": "pod-primary",
  "node_name": "node-a",
  "interloper_pod_name": "pod-interloper",
  "baseline_probe_id": "baseline-lease",
  "statuses": {
    "interloper_failed": true,
    "primary_ready": true,
    "state_digests_unchanged": true,
    "lease_error_observed": true,
    "proxy_started_unchanged": true
  },
  "target_replica_count": 2
}
JSON

  cat >"$dir/proxy-debug.jsonl" <<'JSONL'
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":1000,"fields":{"session_signing":{"mode":"configured","active_key_version":1,"key_version_count":1},"restored_consumed_bait_proof_count":0}}
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":2000,"fields":{"session_signing":{"mode":"configured","active_key_version":1,"key_version_count":1},"restored_consumed_bait_proof_count":0}}
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":3000,"fields":{"session_signing":{"mode":"configured","active_key_version":1,"key_version_count":1},"restored_consumed_bait_proof_count":0}}
JSONL

  cat >"$dir/target-audit.jsonl" <<'JSONL'
{"event":"protected_upstream_probe_observed","probe_id":"baseline-lease","pod":"target-a"}
{"event":"protected_upstream_probe_observed","probe_id":"baseline-lease","pod":"target-b"}
JSONL

  cat >"$dir/proxy-debug-added.jsonl" <<'JSONL'
{"event":"connection_closed_without_request","session_id":null,"observed_at_unix_ms":3100,"fields":{"client_peer":"10.0.0.1:5000"}}
{"event":"connection_closed_without_request","session_id":null,"observed_at_unix_ms":3200,"fields":{"client_peer":"10.0.0.1:5001"}}
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
    'create configmap "$LEASE_LOCK"',
    'lease lock already exists',
    'delete configmap "$LEASE_LOCK"',
    'trap cleanup EXIT',
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
    'durable state already has an active writer',
]
for needle in required:
    if needle not in source:
        raise SystemExit(f"missing lease-proof guard: {needle}")

if "set -x" in source or "set -v" in source or "set -o xtrace" in source:
    raise SystemExit("shell tracing may leak sensitive material")

probe = source.split("create_probe_pod() {", 1)[1].split(
    "\nwrite_request() {", 1
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

interloper = source.split("# Start the overlapping writer on the same node and the same PVC.", 1)[1]
for needle in [
    "($deployment[0].spec.template.spec) as $spec",
    'restartPolicy: "Never"',
    "nodeName: $node",
    "terminationGracePeriodSeconds: 1",
]:
    if needle not in interloper:
        raise SystemExit(f"interloper pod lost its overlap mechanics: {needle}")

if 'delete pod "$interloper"' not in source:
    raise SystemExit("cleanup must always delete the interloper pod")

ordered = [
    'create configmap "$LEASE_LOCK"',
    "primary_pod_json=",
    "baseline.request",
    '"$KUBECTL_BIN" apply -f - >/dev/null',
    '[[ "$interloper_phase" == "Failed" ]]',
    "collect_target_audit",
    "proof_complete=1",
]
position = -1
for needle in ordered:
    next_position = source.find(needle, position + 1)
    if next_position < 0:
        raise SystemExit(f"missing ordered lease-proof operation: {needle}")
    position = next_position

evidence_names = set(
    re.findall(r'\$evidence_dir/([A-Za-z0-9.-]+)', source)
)
expected_names = {
    "lease-proof.json",
    "flow.json",
    "proxy-debug.jsonl",
    "proxy-debug-added.jsonl",
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
    "contained_proof",
    "control_proof",
    "key_hex",
    "signing-secret",
    "key-ring",
)
for line in source.splitlines():
    if "evidence_dir" in line and any(raw in line for raw in raw_tokens):
        raise SystemExit(f"raw material may reach evidence output: {line.strip()}")
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

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-lease-proof-fixtures.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

valid="$(new_fixture valid)"
write_valid_fixture "$valid"

expected_files=(
  flow.json
  lease-proof.json
  proxy-debug-added.jsonl
  proxy-debug.jsonl
  target-audit.jsonl
)
fixture_entries=("$valid"/*)
[[ "${#fixture_entries[@]}" == "${#expected_files[@]}" ]] || {
  echo "valid fixture does not contain exactly five files" >&2
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
      and .overlapping_writer_failed_closed == true
      and .lease_error_observed == true
      and .primary_writer_stable == true
      and .durable_state_unchanged == true
      and .protected_upstream_writes == 0
      and .interloper_pod_name == "pod-interloper"
      and .primary_pod_uid == "pod-primary"
    ' >/dev/null

bad="$(clone_valid_fixture interloper-not-failed)"
mutate_json "$bad/lease-proof.json" '.interloper.phase = "Running"'
expect_failure interloper-not-failed "$bad"

bad="$(clone_valid_fixture lease-error-missing)"
mutate_json "$bad/lease-proof.json" '.interloper.lease_error_observed = false'
expect_failure lease-error-missing "$bad"

bad="$(clone_valid_fixture interloper-restarted)"
mutate_json "$bad/lease-proof.json" '.interloper.restart_count = 1'
expect_failure interloper-restarted "$bad"

bad="$(clone_valid_fixture node-mismatch)"
mutate_json "$bad/lease-proof.json" '.interloper.node_name = "node-b"'
expect_failure node-mismatch "$bad"

bad="$(clone_valid_fixture primary-restarted)"
mutate_json "$bad/lease-proof.json" '.primary.restart_count_after = 2'
expect_failure primary-restarted "$bad"

bad="$(clone_valid_fixture primary-not-ready)"
mutate_json "$bad/lease-proof.json" '.primary.ready_after = false'
expect_failure primary-not-ready "$bad"

bad="$(clone_valid_fixture primary-uid-drift)"
mutate_json "$bad/flow.json" '.primary_pod_uid = "pod-other"'
expect_failure primary-uid-drift "$bad"

bad="$(clone_valid_fixture events-digest-changed)"
mutate_json "$bad/lease-proof.json" '
  .state.events_digest_after =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
'
expect_failure events-digest-changed "$bad"

bad="$(clone_valid_fixture added-record-not-noise)"
mutate_jsonl "$bad/proxy-debug-added.jsonl" '.event = "session_resolved"'
expect_failure added-record-not-noise "$bad"

bad="$(clone_valid_fixture debug-lines-decreased)"
mutate_json "$bad/lease-proof.json" '.state.debug_lines_after = 50'
expect_failure debug-lines-decreased "$bad"

bad="$(clone_valid_fixture policy-digest-changed)"
mutate_json "$bad/lease-proof.json" '
  .state.policy_digest_after =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
'
expect_failure policy-digest-changed "$bad"

bad="$(clone_valid_fixture started-count-changed)"
mutate_json "$bad/lease-proof.json" '.state.proxy_started_count_after = 4'
expect_failure started-count-changed "$bad"

bad="$(clone_valid_fixture zero-started-baseline)"
mutate_json "$bad/lease-proof.json" '
  .state.proxy_started_count_before = 0
  | .state.proxy_started_count_after = 0
'
expect_failure zero-started-baseline "$bad"

bad="$(clone_valid_fixture extra-debug-start)"
cat >>"$bad/proxy-debug.jsonl" <<'JSONL'
{"event":"proxy_started","session_id":null,"observed_at_unix_ms":4000,"fields":{"session_signing":{"mode":"configured","active_key_version":1,"key_version_count":1},"restored_consumed_bait_proof_count":0}}
JSONL
expect_failure extra-debug-start "$bad"

bad="$(clone_valid_fixture missing-target-baseline)"
mutate_jsonl "$bad/target-audit.jsonl" 'select(.pod != "target-b")'
expect_failure missing-target-baseline "$bad"

bad="$(clone_valid_fixture extra-target-write)"
cat >>"$bad/target-audit.jsonl" <<'JSONL'
{"event":"protected_upstream_probe_observed","probe_id":"unexpected-write","pod":"target-a"}
JSONL
expect_failure extra-target-write "$bad"

assert_static_contract
