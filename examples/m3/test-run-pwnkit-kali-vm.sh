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
  "$RUNNER" --help | rg -q 'same_vm_loopback'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_KALI_VM_DRY_RUN'
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
    "$RUNNER" 2 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/sample-plan.txt" ]]
  rg -q '^run_count=2$' "$sample_dir/sample-plan.txt"
  rg -q '^runner_environment=kali_vm$' "$sample_dir/sample-plan.txt"
  rg -q '^network_topology=same_vm_loopback$' "$sample_dir/sample-plan.txt"
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
test_rejects_non_vm_topology
test_rejects_userinfo_loopback_smuggling
test_rejects_repo_local_sample_dir
test_rejects_symlinked_repo_local_sample_dir

printf 'run-pwnkit-kali-vm fixture tests passed\n'
