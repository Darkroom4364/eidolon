#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SPOOLER="$SCRIPT_DIR/spool-pwnkit-qualification-orbstack-vms.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-vm-spool-test.XXXXXX"
}

write_spool_plan() {
  local path="$1"
  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_vm_spool_plan",
    boundary: "scanner_qualification",
    generated_at: "2026-06-30T00:00:00Z",
    vm_profiles: [
      {
        vm_profile: "kali_vm_same_vm_loopback",
        lane: "kali_vm_transfer",
        substrate: "kali_vm_same_vm_loopback",
        defense_mode: "comparison",
        runner_kinds: ["m3_kali_same_vm"],
        control_kinds: ["transfer_control"],
        variant_ids: ["kali_same_vm_transfer_control"],
        hypothesis_ids: ["kali_same_vm_loopback_transfer"]
      },
      {
        vm_profile: "kali_vm_to_orbstack_nodeport",
        lane: "kali_vm_transfer",
        substrate: "kali_vm_orbstack_nodeport",
        defense_mode: "comparison",
        runner_kinds: ["shield_lab_kali_orbstack"],
        control_kinds: ["transfer_control"],
        variant_ids: ["kali_orbstack_transfer_control"],
        hypothesis_ids: ["kali_orbstack_nodeport_transfer"]
      }
    ]
  }' > "$path"
}

write_stub_orbctl() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

log_file="${EIDOLON_TEST_ORBCTL_LOG:?}"
subcommand="${1:-}"
shift || true

printf '%s' "$subcommand" >> "$log_file"
for arg in "$@"; do
  printf ' %s' "$arg" >> "$log_file"
done
printf '\n' >> "$log_file"

case "$subcommand" in
  list)
    if [[ "${1:-}" == "-q" ]]; then
      printf '%s' "${EIDOLON_TEST_ORBCTL_LIST_OUTPUT:-}"
      exit 0
    fi
    ;;
  create|start)
    exit 0
    ;;
esac

echo "unexpected orbctl invocation: $subcommand $*" >&2
exit 1
SH
  chmod +x "$path"
}

test_help_mentions_orbstack_and_helpers() {
  "$SPOOLER" --help | rg -q 'OrbStack Kali VMs'
  "$SPOOLER" --help | rg -q 'run-<vm-profile>.sh'
  "$SPOOLER" --help | rg -q 'PWNKIT_SOURCE_DIR'
}

test_dry_run_writes_manifest_and_helper_scripts() {
  local temp_dir
  local spool_plan
  local output_dir

  temp_dir="$(new_temp_dir)"
  spool_plan="$temp_dir/vm-spool-plan.json"
  output_dir="$temp_dir/output"
  write_spool_plan "$spool_plan"

  EIDOLON_PWNKIT_VM_SPOOL_DRY_RUN=1 \
    PWNKIT_SOURCE_DIR="/Users/tester/Projects/pwnkit" \
    "$SPOOLER" "$spool_plan" "$output_dir"

  [[ -f "$output_dir/vm-spool-manifest.json" ]]
  [[ -f "$output_dir/README.md" ]]
  [[ -f "$output_dir/cloud-init/kali_vm_same_vm_loopback.yaml" ]]
  [[ -f "$output_dir/cloud-init/kali_vm_to_orbstack_nodeport.yaml" ]]
  [[ -x "$output_dir/run-kali_vm_same_vm_loopback.sh" ]]
  [[ -x "$output_dir/run-kali_vm_to_orbstack_nodeport.sh" ]]

  jq -e '
    .run_kind == "pwnkit_qualification_orbstack_vm_spool_manifest"
    and .claim_posture == "scanner_qualification_only"
    and .evaluation_lane_version == 1
    and .provider == "orbstack"
    and .dry_run == true
    and (.profiles | length == 2)
    and (.profiles[0].machine_name | startswith("eidolon-qual-"))
    and all(.profiles[]; .lane == "kali_vm_transfer")
    and all(.profiles[]; .defense_mode == "comparison")
  ' "$output_dir/vm-spool-manifest.json" >/dev/null

  rg -q 'examples/m3/run-pwnkit-kali-vm.sh' "$output_dir/run-kali_vm_same_vm_loopback.sh"
  rg -q 'examples/shield-lab/run-pwnkit-kali-vm.sh' "$output_dir/run-kali_vm_to_orbstack_nodeport.sh"
  rg -q 'HOST_PWNKIT_SOURCE_DIR="\$\{PWNKIT_SOURCE_DIR:-/Users/tester/Projects/pwnkit\}"' "$output_dir/run-kali_vm_same_vm_loopback.sh"
  rg -q 'LINUX_PWNKIT_SOURCE_DIR="\$\(host_path_to_linux_mount "\$HOST_PWNKIT_SOURCE_DIR"\)"' "$output_dir/run-kali_vm_same_vm_loopback.sh"
  rg -q 'append_remote_env PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN' "$output_dir/run-kali_vm_to_orbstack_nodeport.sh"
  rg -q 'deploy the Shield lab on the macOS host' "$output_dir/vm-spool-manifest.json"
}

test_execution_creates_missing_and_reuses_existing_machines() {
  local temp_dir
  local spool_plan
  local output_dir
  local orbctl_stub
  local orbctl_log

  temp_dir="$(new_temp_dir)"
  spool_plan="$temp_dir/vm-spool-plan.json"
  output_dir="$temp_dir/output"
  orbctl_stub="$temp_dir/orbctl"
  orbctl_log="$temp_dir/orbctl.log"

  write_spool_plan "$spool_plan"
  write_stub_orbctl "$orbctl_stub"

  EIDOLON_TEST_ORBCTL_LOG="$orbctl_log" \
    EIDOLON_TEST_ORBCTL_LIST_OUTPUT=$'eidolon-qual-kali-loopback\n' \
    ORBCTL_BIN="$orbctl_stub" \
    PWNKIT_SOURCE_DIR="/Users/tester/Projects/pwnkit" \
    "$SPOOLER" "$spool_plan" "$output_dir"

  rg -q '^list -q$' "$orbctl_log"
  rg -q '^start eidolon-qual-kali-loopback$' "$orbctl_log"
  rg -q '^create --cpus 2 --memory 4G --disk 32G --user-data .*/kali_vm_to_orbstack_nodeport.yaml kali:current eidolon-qual-kali-orbstack$' "$orbctl_log"
  rg -q '^start eidolon-qual-kali-orbstack$' "$orbctl_log"

  jq -e '
    .dry_run == false
    and (.profiles[] | select(.vm_profile == "kali_vm_same_vm_loopback") | .existed == true and .created == false)
    and (.profiles[] | select(.vm_profile == "kali_vm_to_orbstack_nodeport") | .existed == false and .created == true)
    and (.profiles[] | select(.vm_profile == "kali_vm_same_vm_loopback") | .substrate == "kali_vm_same_vm_loopback")
    and (.profiles[] | select(.vm_profile == "kali_vm_to_orbstack_nodeport") | .substrate == "kali_vm_orbstack_nodeport")
    and (.profiles[] | .artifact_identity.artifact_kind == "pwnkit_qualification_orbstack_vm_spool_profile")
  ' "$output_dir/vm-spool-manifest.json" >/dev/null
}

test_rejects_invalid_spool_plan() {
  local temp_dir
  local spool_plan
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  spool_plan="$temp_dir/vm-spool-plan.json"
  printf '{"run_kind":"wrong"}\n' > "$spool_plan"

  output="$("$SPOOLER" "$spool_plan" "$temp_dir/output" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'invalid vm-spool plan' <<<"$output"
}

test_help_mentions_orbstack_and_helpers
test_dry_run_writes_manifest_and_helper_scripts
test_execution_creates_missing_and_reuses_existing_machines
test_rejects_invalid_spool_plan

printf 'orbstack qualification VM spool fixture tests passed\n'
