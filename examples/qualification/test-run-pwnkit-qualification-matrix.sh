#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-qualification-matrix.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-qualification-test.XXXXXX"
}

write_stub_runner() {
  local path="$1"
  local runner_id="$2"

  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

runner_id="$EIDOLON_TEST_STUB_RUNNER_ID"
run_count="$1"
sample_dir="$2"

mkdir -p "$sample_dir"
{
  printf 'runner_id=%s\n' "$runner_id"
  printf 'run_count=%s\n' "$run_count"
  printf 'fixture_id=%s\n' "${EIDOLON_M3_PWNKIT_FIXTURE_ID:-none}"
  printf 'evidence_track=%s\n' "${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-none}"
  printf 'runner_environment=%s\n' "${EIDOLON_M3_RUNNER_ENVIRONMENT:-none}"
  printf 'network_topology=%s\n' "${EIDOLON_M3_NETWORK_TOPOLOGY:-none}"
  printf 'dry_run=%s\n' "${EIDOLON_M3_SAMPLE_DRY_RUN:-${EIDOLON_M3_KALI_VM_DRY_RUN:-${EIDOLON_SHIELD_KALI_VM_DRY_RUN:-0}}}"
} > "$sample_dir/sample-plan.txt"

if [[ "${EIDOLON_M3_SAMPLE_DRY_RUN:-0}" == "1" \
   || "${EIDOLON_M3_KALI_VM_DRY_RUN:-0}" == "1" \
   || "${EIDOLON_SHIELD_KALI_VM_DRY_RUN:-0}" == "1" ]]; then
  exit 0
fi

jq -n \
  --arg runner_id "$runner_id" \
  --arg evidence_track "${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-unknown}" \
  --arg runner_environment "${EIDOLON_M3_RUNNER_ENVIRONMENT:-unknown}" \
  --arg network_topology "${EIDOLON_M3_NETWORK_TOPOLOGY:-unknown}" \
  '{
    schema_version: 1,
    run_kind: "pwnkit_stability_sample",
    artifact_count: 1,
    valid_summary_count: 1,
    strongest_claim_level: "same_session_bait_action_confirmed",
    weakest_claim_level: "bait_exposed_without_action",
    evidence_tracks: [$evidence_track],
    runner_environments: [$runner_environment],
    runner_network_topologies: [$network_topology],
    no_signal_diagnostics: null,
    strict_stability: {
      ready_for_stability_claim: false
    },
    artifacts: [
      {
        direct_finding_count: 2,
        eidolon_finding_count: 1,
        runner_environment: $runner_environment,
        runner_network_topology: $network_topology,
        runner_id: $runner_id
      }
    ]
  }' > "$sample_dir/pwnkit-stability-sample.json"
SH
  chmod +x "$path"
}

write_manifest() {
  local manifest="$1"

  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_matrix_manifest",
    boundary: "scanner_qualification",
    variants: [
      {
        variant_id: "local_positive",
        enabled: true,
        control_kind: "positive_control",
        hypothesis_id: "host_positive",
        hypothesis: "local positive control",
        expected_observation: "direct_findings_present",
        runner_kind: "m3_local_sample",
        run_count: 2,
        env: {
          EIDOLON_M3_PWNKIT_EVIDENCE_TRACK: "local_patched_pwnkit",
          EIDOLON_M3_PWNKIT_FIXTURE_ID: "fixture-local"
        }
      },
      {
        variant_id: "kali_transfer",
        enabled: true,
        control_kind: "transfer_control",
        hypothesis_id: "kali_transfer",
        hypothesis: "kali transfer control",
        expected_observation: "signal_survives_transfer",
        runner_kind: "shield_lab_kali_orbstack",
        vm_profile: "kali_vm_to_orbstack_nodeport",
        env: {
          EIDOLON_M3_PWNKIT_EVIDENCE_TRACK: "local_patched_pwnkit",
          EIDOLON_M3_PWNKIT_FIXTURE_ID: "fixture-kali"
        }
      },
      {
        variant_id: "negative_blocked",
        enabled: false,
        control_kind: "negative_control",
        hypothesis_id: "negative_blocked",
        hypothesis: "negative control placeholder",
        expected_observation: "quiet_result",
        runner_kind: "m3_local_sample",
        blocked_reason: "waiting on hardened target"
      }
    ]
  }' > "$manifest"
}

test_help_mentions_vm_spool_plan() {
  "$RUNNER" --help | rg -q 'vm-spool plan'
  "$RUNNER" --help | rg -q 'EIDOLON_PWNKIT_QUAL_RUNNER_SHIELD_LAB_KALI_ORBSTACK'
}

test_rejects_invalid_default_run_count() {
  local temp_dir
  local manifest
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  write_manifest "$manifest"

  output="$(
    EIDOLON_PWNKIT_QUAL_RUNS=0 \
      "$RUNNER" "$manifest" "$temp_dir/matrix" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_PWNKIT_QUAL_RUNS must be a positive integer' <<<"$output"
}

test_dry_run_writes_sample_plans_and_vm_spool_plan() {
  local temp_dir
  local manifest
  local matrix_dir
  local local_stub
  local kali_stub

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  local_stub="$temp_dir/local-stub.sh"
  kali_stub="$temp_dir/kali-stub.sh"
  write_manifest "$manifest"
  write_stub_runner "$local_stub" local_positive
  write_stub_runner "$kali_stub" kali_transfer

  EIDOLON_PWNKIT_QUAL_DRY_RUN=1 \
    EIDOLON_TEST_STUB_RUNNER_ID=local_positive \
    EIDOLON_PWNKIT_QUAL_RUNNER_M3_LOCAL_SAMPLE="$local_stub" \
    EIDOLON_PWNKIT_QUAL_RUNNER_SHIELD_LAB_KALI_ORBSTACK="$kali_stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  [[ -f "$matrix_dir/matrix-plan.json" ]]
  [[ -f "$matrix_dir/vm-spool-plan.json" ]]
  [[ -f "$matrix_dir/pwnkit-qualification-matrix.json" ]]
  [[ -f "$matrix_dir/local_positive/sample-plan.txt" ]]
  [[ -f "$matrix_dir/kali_transfer/sample-plan.txt" ]]
  [[ -f "$matrix_dir/negative_blocked/variant-status.txt" ]]

  jq -e '
    .run_kind == "pwnkit_qualification_vm_spool_plan"
    and (.vm_profiles | length == 1)
    and .vm_profiles[0].vm_profile == "kali_vm_to_orbstack_nodeport"
    and .vm_profiles[0].variant_ids == ["kali_transfer"]
  ' "$matrix_dir/vm-spool-plan.json" >/dev/null

  rg -q '^fixture_id=fixture-local$' "$matrix_dir/local_positive/sample-plan.txt"
  rg -q '^dry_run=1$' "$matrix_dir/local_positive/sample-plan.txt"
  rg -q '^fixture_id=fixture-kali$' "$matrix_dir/kali_transfer/sample-plan.txt"
  rg -q '^dry_run=1$' "$matrix_dir/kali_transfer/sample-plan.txt"
  rg -q '^blocked_reason=waiting on hardened target$' \
    "$matrix_dir/negative_blocked/variant-status.txt"

  jq -e '
    .planned_variant_count == 2
    and .blocked_variant_count == 1
    and .completed_variant_count == 0
    and .acceptance_coverage.positive_control_completed == false
    and .acceptance_coverage.negative_control_completed == false
    and .variants[0].execution_state == "planned"
    and .variants[1].execution_state == "planned"
    and .variants[2].execution_state == "blocked"
  ' "$matrix_dir/pwnkit-qualification-matrix.json" >/dev/null
}

test_execution_collects_completed_variants() {
  local temp_dir
  local manifest
  local matrix_dir
  local local_stub
  local kali_stub

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  local_stub="$temp_dir/local-stub.sh"
  kali_stub="$temp_dir/kali-stub.sh"
  write_manifest "$manifest"
  write_stub_runner "$local_stub" local_positive
  write_stub_runner "$kali_stub" kali_transfer

  EIDOLON_TEST_STUB_RUNNER_ID=local_positive \
    EIDOLON_PWNKIT_QUAL_RUNNER_M3_LOCAL_SAMPLE="$local_stub" \
    EIDOLON_PWNKIT_QUAL_RUNNER_SHIELD_LAB_KALI_ORBSTACK="$kali_stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  [[ -f "$matrix_dir/local_positive/pwnkit-stability-sample.json" ]]
  [[ -f "$matrix_dir/kali_transfer/pwnkit-stability-sample.json" ]]

  jq -e '
    .completed_variant_count == 2
    and .blocked_variant_count == 1
    and .acceptance_coverage.positive_control_completed == true
    and .acceptance_coverage.transfer_control_completed == true
    and .acceptance_coverage.negative_control_completed == false
    and ([.variants[] | select(.execution_state == "completed")] | length == 2)
    and (.variants[] | select(.variant_id == "local_positive") | .direct_finding_count_total == 2)
    and (.variants[] | select(.variant_id == "kali_transfer") | .eidolon_finding_count_total == 1)
  ' "$matrix_dir/pwnkit-qualification-matrix.json" >/dev/null
}

test_rejects_invalid_variant_id() {
  local temp_dir
  local manifest
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_matrix_manifest",
    boundary: "scanner_qualification",
    variants: [
      {
        variant_id: "../bad",
        enabled: true,
        control_kind: "positive_control",
        hypothesis_id: "bad",
        hypothesis: "bad",
        expected_observation: "bad",
        runner_kind: "m3_local_sample"
      }
    ]
  }' > "$manifest"

  output="$(
    "$RUNNER" "$manifest" "$temp_dir/matrix" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'invalid variant_id' <<<"$output"
}

test_help_mentions_vm_spool_plan
test_rejects_invalid_default_run_count
test_dry_run_writes_sample_plans_and_vm_spool_plan
test_execution_collects_completed_variants
test_rejects_invalid_variant_id

printf 'pwnkit qualification matrix fixture tests passed\n'
