#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-kali-vm.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-kali-vm-runner-test.XXXXXX"
}

test_help_mentions_vm_contract() {
  "$RUNNER" --help | rg -q 'Kali Linux VM'
  "$RUNNER" --help | rg -q 'OrbStack'
  "$RUNNER" --help | rg -q -- '--preflight'
  "$RUNNER" --help | rg -q 'same_vm_loopback'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_KALI_VM_DRY_RUN'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_KALI_VM_PREFLIGHT'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_MAX_ATTEMPTS'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_FIXTURE_ID'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_EVIDENCE_TRACK'
}

test_rejects_non_kali_without_override() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_TEST_FORCE_NON_KALI=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'run this inside a Kali Linux VM' <<<"$output"
}

test_rejects_non_kali_override_without_dry_run() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_TEST_FORCE_NON_KALI=1 \
      EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_ALLOW_NON_KALI_VM is only allowed with EIDOLON_M3_KALI_VM_DRY_RUN=1' <<<"$output"
}

test_dry_run_records_vm_local_contract() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
    EIDOLON_M3_KALI_VM_DRY_RUN=1 \
    EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private \
    EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
    "$RUNNER" 2 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/sample-plan.txt" ]]
  rg -q '^run_count=2$' "$sample_dir/sample-plan.txt"
  rg -q '^runner_environment=kali_vm$' "$sample_dir/sample-plan.txt"
  rg -q '^network_topology=same_vm_loopback$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_max_attempts=3$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_timeout_seconds=1800$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_fixture_id=pwnkit-v0\.12\.0-private$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_evidence_track=local_patched_pwnkit$' "$sample_dir/sample-plan.txt"
}

test_preflight_writes_runner_metadata() {
  local sample_dir
  local output
  sample_dir="$(new_temp_dir)"

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_PIN_SESSION=0 \
      EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
      PWNKIT_BIN=true \
      "$RUNNER" --preflight 2 "$sample_dir" 2>&1
  )"

  rg -q 'kali-vm preflight ok:' <<<"$output"
  [[ -f "$sample_dir/private/kali-vm-preflight/pwnkit-runner-metadata.json" ]]
  jq -e '
    .mode == "preflight"
    and .environment.runner_environment == "kali_vm"
    and .environment.network_topology == "same_vm_loopback"
    and .pwnkit.max_attempts == 3
    and .pwnkit.timeout_seconds == 1800
    and .pwnkit.command_source == "PWNKIT_BIN"
    and .pwnkit.fixture == {
      id: "pwnkit-v0.12.0-private",
      pinned: true
    }
    and .pwnkit.evidence_track == "local_patched_pwnkit"
  ' "$sample_dir/private/kali-vm-preflight/pwnkit-runner-metadata.json" >/dev/null
}

test_preflight_requires_pwnkit_runner() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_PIN_SESSION=0 \
      PWNKIT_NODE_ENTRY="$(new_temp_dir)/missing-pwnkit.js" \
      "$RUNNER" --preflight 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'PWNKIT_NODE_ENTRY does not exist' <<<"$output"
}

test_rejects_non_vm_topology() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_NETWORK_TOPOLOGY=vm_loopback_forward \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_NETWORK_TOPOLOGY must be same_vm_loopback' <<<"$output"
}

test_rejects_local_patched_track_without_fixture_id() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_PWNKIT_FIXTURE_ID is required' <<<"$output"
}

test_rejects_upstream_current_track_with_fixture_id() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current \
      EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_PWNKIT_FIXTURE_ID must be unset' <<<"$output"
}

test_rejects_userinfo_loopback_smuggling() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_LAB_TARGET_URL='http://localhost:pw@192.168.64.2:9001' \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'must not include userinfo' <<<"$output"
}

test_rejects_repo_local_sample_dir() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      "$RUNNER" 1 "$REPO_ROOT/tmp-kali-vm-sample" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'sample-dir must be outside the Eidolon repo' <<<"$output"
}

test_rejects_symlinked_repo_local_sample_dir() {
  local temp_dir
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  ln -s "$REPO_ROOT" "$temp_dir/repo-link"

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      "$RUNNER" 1 "$temp_dir/repo-link/tmp-kali-vm-sample" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'sample-dir must be outside the Eidolon repo' <<<"$output"
}

test_help_mentions_vm_contract
test_rejects_non_kali_without_override
test_rejects_non_kali_override_without_dry_run
test_dry_run_records_vm_local_contract
test_preflight_writes_runner_metadata
test_preflight_requires_pwnkit_runner
test_rejects_non_vm_topology
test_rejects_local_patched_track_without_fixture_id
test_rejects_upstream_current_track_with_fixture_id
test_rejects_userinfo_loopback_smuggling
test_rejects_repo_local_sample_dir
test_rejects_symlinked_repo_local_sample_dir

printf 'run-pwnkit-kali-vm fixture tests passed\n'
