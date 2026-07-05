#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUN_SCRIPT="$SCRIPT_DIR/run-pwnkit-microvm.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-microvm-run-test.XXXXXX"
}

test_dry_run_writes_sample_plan() {
  local temp_dir output
  temp_dir="$(new_temp_dir)"

  output="$(
    bash "$RUN_SCRIPT" 2 "$temp_dir/sample"
  )"

  rg -q 'dry-run microVM sample plan:' <<<"$output"
  [[ -f "$temp_dir/sample/sample-plan.json" ]]
  jq -e '
    .schema_version == 1
    and .run_kind == "pwnkit_microvm_sample_plan"
    and .mode == "dry_run"
    and .implemented == false
    and .runner_environment == "microvm"
    and .network_topology == "microvm_to_orbstack_nodeport"
    and .hypervisor == "firecracker"
    and .guest_profile == "microvm_min"
    and .run_count == 2
    and (.runs | length) == 2
    and (.plan_template_path | endswith("/examples/microvm/configs/default-run-plan.json"))
    and (.guest_profile_config_path | endswith("/examples/microvm/configs/guest-profile-microvm-min.json"))
    and .constraints.repo_mount_writable == false
    and .planned_outputs.sample_manifest == "pwnkit-stability-sample.json"
  ' "$temp_dir/sample/sample-plan.json" >/dev/null
  [[ -d "$temp_dir/sample/run-1/private" ]]
  [[ -d "$temp_dir/sample/run-2/private" ]]
}

test_non_dry_run_is_rejected() {
  local temp_dir
  temp_dir="$(new_temp_dir)"

  if EIDOLON_MICROVM_DRY_RUN=0 bash "$RUN_SCRIPT" 1 "$temp_dir/sample" >/dev/null 2>&1; then
    echo "expected non-dry-run execution to fail" >&2
    exit 1
  fi
}

test_dry_run_writes_sample_plan
test_non_dry_run_is_rejected

printf 'microvm run scaffold checks passed\n'
