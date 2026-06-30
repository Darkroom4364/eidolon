#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-qualification-orbstack-vm-variant.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-vm-variant-test.XXXXXX"
}

canonical_dir() {
  (
    cd "$1"
    pwd -P
  )
}

write_matrix_dir() {
  local matrix_dir="$1"

  mkdir -p "$matrix_dir"
  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_matrix_manifest",
    boundary: "scanner_qualification",
    variants: [
      {
        variant_id: "kali_transfer",
        enabled: true,
        control_kind: "transfer_control",
        hypothesis_id: "kali_transfer",
        hypothesis: "kali transfer control",
        expected_observation: "signal_survives_transfer",
        runner_kind: "shield_lab_kali_orbstack",
        vm_profile: "kali_vm_to_orbstack_nodeport",
        run_count: 2
      },
      {
        variant_id: "disabled_variant",
        enabled: false,
        control_kind: "transfer_control",
        hypothesis_id: "disabled_variant",
        hypothesis: "disabled",
        expected_observation: "blocked",
        runner_kind: "m3_kali_same_vm",
        vm_profile: "kali_vm_same_vm_loopback",
        blocked_reason: "disabled"
      }
    ]
  }' > "$matrix_dir/pwnkit-qualification-variants.json"

  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_vm_spool_plan",
    boundary: "scanner_qualification",
    vm_profiles: [
      {
        vm_profile: "kali_vm_to_orbstack_nodeport",
        runner_kinds: ["shield_lab_kali_orbstack"],
        control_kinds: ["transfer_control"],
        variant_ids: ["kali_transfer"],
        hypothesis_ids: ["kali_transfer"]
      }
    ]
  }' > "$matrix_dir/vm-spool-plan.json"
}

write_spooler_stub() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

spool_plan="$1"
output_dir="$2"
mkdir -p "$output_dir"
printf '%s\n' "$output_dir" > "${EIDOLON_TEST_SPOOLER_LOG:?}"

cat > "$output_dir/run-kali_vm_to_orbstack_nodeport.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'run_count=%s\n' "\$1" > "${EIDOLON_TEST_HELPER_LOG:?}"
printf 'sample_dir=%s\n' "\$2" >> "${EIDOLON_TEST_HELPER_LOG:?}"
EOF
chmod +x "$output_dir/run-kali_vm_to_orbstack_nodeport.sh"

jq -n \
  --arg helper "$output_dir/run-kali_vm_to_orbstack_nodeport.sh" \
  '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_orbstack_vm_spool_manifest",
    boundary: "scanner_qualification",
    provider: "orbstack",
    profiles: [
      {
        vm_profile: "kali_vm_to_orbstack_nodeport",
        machine_name: "eidolon-qual-kali-orbstack",
        helper_script: $helper,
        sample_dir: "/tmp/eidolon-pwnkit-qualification-kali-orbstack"
      }
    ]
  }' > "$output_dir/vm-spool-manifest.json"
SH
  chmod +x "$path"
}

write_collector_stub() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

args=("$@")
dest="${args[$#-1]}"
sample_dir="${args[$#-2]}"
printf 'sample_dir=%s\n' "$sample_dir" > "${EIDOLON_TEST_COLLECTOR_LOG:?}"
printf 'dest=%s\n' "$dest" >> "${EIDOLON_TEST_COLLECTOR_LOG:?}"
mkdir -p "$dest"
cat > "$dest/pwnkit-stability-sample.json" <<EOF
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_sample",
  "artifact_count": 1,
  "valid_summary_count": 1,
  "strongest_claim_level": "same_session_bait_action_confirmed",
  "weakest_claim_level": "bait_exposed_without_action",
  "evidence_tracks": ["local_patched_pwnkit"],
  "runner_environments": ["kali_vm"],
  "runner_network_topologies": ["kali_vm_to_orbstack_nodeport"],
  "strict_stability": { "ready_for_stability_claim": false },
  "artifacts": [
    { "direct_finding_count": 2, "eidolon_finding_count": 1 }
  ]
}
EOF
printf 'copied Kali sample to %s\n' "$dest"
SH
  chmod +x "$path"
}

write_matrix_collector_stub() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
manifest="$1"
matrix_dir="$2"
printf '%s\n' "$manifest" > "${EIDOLON_TEST_MATRIX_COLLECTOR_LOG:?}"
printf '%s\n' "$matrix_dir" >> "${EIDOLON_TEST_MATRIX_COLLECTOR_LOG:?}"
jq -n --arg matrix_dir "$matrix_dir" '{
  schema_version: 1,
  run_kind: "pwnkit_qualification_matrix_summary",
  boundary: "scanner_qualification",
  matrix_dir: $matrix_dir,
  variants: [
    {variant_id: "kali_transfer", execution_state: "completed"}
  ]
}'
SH
  chmod +x "$path"
}

test_help_mentions_spool_and_refresh() {
  "$RUNNER" --help | rg -q 'refreshes the matrix summary'
  "$RUNNER" --help | rg -q 'orbstack-vm-spool'
  "$RUNNER" --help | rg -q 'EIDOLON_PWNKIT_QUAL_VM_OVERWRITE'
}

test_runner_spools_executes_collects_and_refreshes() {
  local temp_dir matrix_dir spool_dir spooler collector matrix_collector
  local spool_log helper_log collector_log matrix_collector_log

  temp_dir="$(new_temp_dir)"
  matrix_dir="$temp_dir/matrix"
  spool_dir="$temp_dir/spool"
  spooler="$temp_dir/spooler.sh"
  collector="$temp_dir/collector.sh"
  matrix_collector="$temp_dir/matrix-collector.sh"
  spool_log="$temp_dir/spool.log"
  helper_log="$temp_dir/helper.log"
  collector_log="$temp_dir/collector.log"
  matrix_collector_log="$temp_dir/matrix-collector.log"

  write_matrix_dir "$matrix_dir"
  write_spooler_stub "$spooler"
  write_collector_stub "$collector"
  write_matrix_collector_stub "$matrix_collector"

  matrix_dir="$(canonical_dir "$matrix_dir")"
  mkdir -p "$spool_dir"
  spool_dir="$(canonical_dir "$spool_dir")"

  EIDOLON_TEST_SPOOLER_LOG="$spool_log" \
    EIDOLON_TEST_HELPER_LOG="$helper_log" \
    EIDOLON_TEST_COLLECTOR_LOG="$collector_log" \
    EIDOLON_TEST_MATRIX_COLLECTOR_LOG="$matrix_collector_log" \
    EIDOLON_PWNKIT_QUAL_VM_SPOOLER="$spooler" \
    EIDOLON_PWNKIT_QUAL_VM_COLLECTOR="$collector" \
    EIDOLON_PWNKIT_QUAL_MATRIX_COLLECTOR="$matrix_collector" \
    "$RUNNER" "$matrix_dir" "kali_transfer" "$spool_dir"

  [[ -f "$matrix_dir/kali_transfer/pwnkit-stability-sample.json" ]]
  [[ -f "$matrix_dir/kali_transfer/vm-run-manifest.json" ]]
  [[ -f "$matrix_dir/pwnkit-qualification-matrix.json" ]]

  rg -q "$spool_dir" "$spool_log"
  rg -q '^run_count=2$' "$helper_log"
  rg -q '^sample_dir=/tmp/eidolon-pwnkit-qualification-kali-orbstack$' "$helper_log"
  rg -q '^sample_dir=/tmp/eidolon-pwnkit-qualification-kali-orbstack$' "$collector_log"
  rg -q "^dest=$matrix_dir/kali_transfer$" "$collector_log"
  rg -q "^$matrix_dir$" "$matrix_collector_log"

  jq -e '
    .run_kind == "pwnkit_qualification_orbstack_vm_variant_run"
    and .variant_id == "kali_transfer"
    and .machine_name == "eidolon-qual-kali-orbstack"
    and .run_count == 2
    and (.observability.watcher_script | endswith("/examples/qualification/watch-pwnkit-qualification-vm-run.sh"))
    and .observability.vm_sample_dir == "/tmp/eidolon-pwnkit-qualification-kali-orbstack"
  ' "$matrix_dir/kali_transfer/vm-run-manifest.json" >/dev/null
}

test_runner_reuses_existing_spool_manifest() {
  local temp_dir matrix_dir spool_dir collector matrix_collector
  local collector_log matrix_collector_log

  temp_dir="$(new_temp_dir)"
  matrix_dir="$temp_dir/matrix"
  spool_dir="$temp_dir/spool"
  collector="$temp_dir/collector.sh"
  matrix_collector="$temp_dir/matrix-collector.sh"
  collector_log="$temp_dir/collector.log"
  matrix_collector_log="$temp_dir/matrix-collector.log"

  write_matrix_dir "$matrix_dir"
  mkdir -p "$spool_dir"
  matrix_dir="$(canonical_dir "$matrix_dir")"
  spool_dir="$(canonical_dir "$spool_dir")"
  write_collector_stub "$collector"
  write_matrix_collector_stub "$matrix_collector"

  cat > "$spool_dir/run-kali_vm_to_orbstack_nodeport.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'run_count=%s\nsample_dir=%s\n' "$1" "$2" > "${EIDOLON_TEST_HELPER_LOG:?}"
SH
  chmod +x "$spool_dir/run-kali_vm_to_orbstack_nodeport.sh"

  jq -n --arg helper "$spool_dir/run-kali_vm_to_orbstack_nodeport.sh" '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_orbstack_vm_spool_manifest",
    boundary: "scanner_qualification",
    provider: "orbstack",
    profiles: [
      {
        vm_profile: "kali_vm_to_orbstack_nodeport",
        machine_name: "eidolon-qual-kali-orbstack",
        helper_script: $helper,
        sample_dir: "/tmp/eidolon-pwnkit-qualification-kali-orbstack"
      }
    ]
  }' > "$spool_dir/vm-spool-manifest.json"

  EIDOLON_TEST_HELPER_LOG="$temp_dir/helper.log" \
    EIDOLON_TEST_COLLECTOR_LOG="$collector_log" \
    EIDOLON_TEST_MATRIX_COLLECTOR_LOG="$matrix_collector_log" \
    EIDOLON_PWNKIT_QUAL_VM_COLLECTOR="$collector" \
    EIDOLON_PWNKIT_QUAL_MATRIX_COLLECTOR="$matrix_collector" \
    "$RUNNER" "$matrix_dir" "kali_transfer" "$spool_dir"

  [[ -f "$matrix_dir/kali_transfer/pwnkit-stability-sample.json" ]]
}

test_runner_rejects_disabled_or_non_vm_variants() {
  local temp_dir matrix_dir output status=0

  temp_dir="$(new_temp_dir)"
  matrix_dir="$temp_dir/matrix"
  write_matrix_dir "$matrix_dir"

  output="$("$RUNNER" "$matrix_dir" "disabled_variant" "$temp_dir/spool" 2>&1)" || status="$?"
  [[ "$status" -eq 2 ]]
  rg -q 'disabled or blocked' <<<"$output"
}

test_help_mentions_spool_and_refresh
test_runner_spools_executes_collects_and_refreshes
test_runner_reuses_existing_spool_manifest
test_runner_rejects_disabled_or_non_vm_variants

printf 'orbstack VM qualification variant runner fixture tests passed\n'
