#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-kali-vm.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-kali-runner-test.XXXXXX"
}

make_stub_bin_dir() {
  local dir="$1"

  mkdir -p "$dir"
  cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exit 0
SH
  chmod +x "$dir/curl"
}

test_help_mentions_orbstack_contract() {
  "$RUNNER" --help | rg -q 'OrbStack Kubernetes Shield'
  "$RUNNER" --help | rg -q 'host.internal:31080'
  "$RUNNER" --help | rg -q 'host.internal:31081'
  "$RUNNER" --help | rg -q 'kali_vm_to_orbstack_nodeport'
  "$RUNNER" --help | rg -q -- '--preflight'
}

test_rejects_non_kali_without_override() {
  local output
  local status=0

  output="$(
    EIDOLON_M4_TEST_FORCE_NON_KALI=1 \
      EIDOLON_SHIELD_KALI_VM_DRY_RUN=1 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'run this inside a Kali Linux VM' <<<"$output"
}

test_rejects_non_kali_override_without_dry_run() {
  local output
  local status=0

  output="$(
    EIDOLON_M4_TEST_FORCE_NON_KALI=1 \
      EIDOLON_SHIELD_ALLOW_NON_KALI_VM=1 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_SHIELD_ALLOW_NON_KALI_VM is only allowed with EIDOLON_SHIELD_KALI_VM_DRY_RUN=1' <<<"$output"
}

test_dry_run_records_orbstack_topology() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M4_TEST_FORCE_NON_KALI=1 \
    EIDOLON_SHIELD_ALLOW_NON_KALI_VM=1 \
    EIDOLON_SHIELD_KALI_VM_DRY_RUN=1 \
    EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private \
    EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
    PWNKIT_SOURCE_DIR=/tmp/kali-pwnkit-source \
    "$RUNNER" 2 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/sample-plan.txt" ]]
  rg -q '^runner_environment=kali_vm$' "$sample_dir/sample-plan.txt"
  rg -q '^network_topology=kali_vm_to_orbstack_nodeport$' "$sample_dir/sample-plan.txt"
  rg -q '^target_url=http://host.internal:31081$' "$sample_dir/sample-plan.txt"
  rg -q '^proxy_url=http://host.internal:31080$' "$sample_dir/sample-plan.txt"
  rg -q '^host_side_evidence_export_required=true$' "$sample_dir/sample-plan.txt"
  rg -q '^host_linked_manifest_supported=true$' "$sample_dir/sample-plan.txt"
}

test_preflight_writes_runner_metadata() {
  local sample_dir
  local output
  local bin_dir
  sample_dir="$(new_temp_dir)"
  bin_dir="$(new_temp_dir)"
  make_stub_bin_dir "$bin_dir"

  output="$(
    PATH="$bin_dir:$PATH" \
      EIDOLON_M4_TEST_FORCE_NON_KALI=1 \
      EIDOLON_SHIELD_ALLOW_NON_KALI_VM=1 \
      EIDOLON_SHIELD_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_PIN_SESSION=0 \
      EIDOLON_LAB_TARGET_URL=http://edge.example.test:31081 \
      EIDOLON_LAB_PROXY_URL=http://edge.example.test:31080 \
      EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
      PWNKIT_BIN=true \
      "$RUNNER" --preflight 2 "$sample_dir" 2>&1
  )"

  rg -q 'orbstack-kali preflight ok:' <<<"$output"
  [[ -f "$sample_dir/private/kali-nodeport-preflight/pwnkit-runner-metadata.json" ]]
  jq -e '
    .mode == "preflight"
    and .environment.runner_environment == "kali_vm"
    and .environment.network_topology == "kali_vm_to_orbstack_nodeport"
    and .pwnkit.command_source == "PWNKIT_BIN"
    and .pwnkit.fixture == {
      id: "pwnkit-v0.12.0-private",
      pinned: true
    }
    and .pwnkit.evidence_track == "local_patched_pwnkit"
  ' "$sample_dir/private/kali-nodeport-preflight/pwnkit-runner-metadata.json" >/dev/null
}

test_rejects_loopback_urls() {
  local output
  local status=0

  output="$(
    EIDOLON_M4_TEST_FORCE_NON_KALI=1 \
      EIDOLON_SHIELD_ALLOW_NON_KALI_VM=1 \
      EIDOLON_SHIELD_KALI_VM_DRY_RUN=1 \
      EIDOLON_LAB_TARGET_URL=http://127.0.0.1:31081 \
      EIDOLON_LAB_PROXY_URL=http://127.0.0.1:31080 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'must not use loopback URLs' <<<"$output"
}

test_rejects_mismatched_hosts() {
  local output
  local status=0

  output="$(
    EIDOLON_M4_TEST_FORCE_NON_KALI=1 \
      EIDOLON_SHIELD_ALLOW_NON_KALI_VM=1 \
      EIDOLON_SHIELD_KALI_VM_DRY_RUN=1 \
      EIDOLON_LAB_TARGET_URL=http://target.internal:31081 \
      EIDOLON_LAB_PROXY_URL=http://shield.internal:31080 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'must share the same host' <<<"$output"
}

test_rejects_wrong_topology_label() {
  local output
  local status=0

  output="$(
    EIDOLON_M4_TEST_FORCE_NON_KALI=1 \
      EIDOLON_SHIELD_ALLOW_NON_KALI_VM=1 \
      EIDOLON_SHIELD_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_NETWORK_TOPOLOGY=same_vm_loopback \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_NETWORK_TOPOLOGY must be kali_vm_to_orbstack_nodeport' <<<"$output"
}

test_help_mentions_orbstack_contract
test_rejects_non_kali_without_override
test_rejects_non_kali_override_without_dry_run
test_dry_run_records_orbstack_topology
test_preflight_writes_runner_metadata
test_rejects_loopback_urls
test_rejects_mismatched_hosts
test_rejects_wrong_topology_label

printf 'shield-lab Kali wrapper fixture tests passed\n'
