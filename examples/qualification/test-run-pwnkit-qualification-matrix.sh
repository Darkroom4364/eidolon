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
        lane: "eidolon_owned_target",
        substrate: "host_local",
        defense_mode: "comparison",
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
        lane: "kali_vm_transfer",
        substrate: "kali_vm_orbstack_nodeport",
        defense_mode: "comparison",
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
        lane: "eidolon_owned_target",
        substrate: "host_local",
        defense_mode: "none",
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
  "$RUNNER" --help | rg -q 'EIDOLON_PWNKIT_QUAL_RUNNER_STOCK_VS_PATCHED_SAMPLE'
}

write_stock_stub_runner() {
  local path="$1"

  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"

mkdir -p "$sample_dir"
printf 'run_count=%s\n' "$run_count" > "$sample_dir/sample-plan.txt"

if [[ "${EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DRY_RUN:-0}" == "1" ]]; then
  exit 0
fi

jq -n '{
  schema_version: 1,
  run_kind: "pwnkit_stock_vs_patched_qualification_sample",
  boundary: "scanner_qualification",
  generated_at: "2026-06-29T00:00:00Z",
  artifact_count: 2,
  valid_summary_count: 2,
  evidence_tracks: ["local_patched_pwnkit", "upstream_current"],
  runner_environments: ["host_mac"],
  runner_network_topologies: ["same_host_loopback"],
  strongest_claim_level: "controlled_reality_entered",
  weakest_claim_level: "controlled_reality_entered",
  no_signal_diagnostics: {
    likely_cause: null
  },
  strict_stability: {
    ready_for_stability_claim: true
  },
  comparison: {
    parity_status: "parity_reproduced",
    parity_reproduced: true,
    next_question: "parity_reproduced"
  },
  artifacts: [
    {direct_finding_count: 0, eidolon_finding_count: 1},
    {direct_finding_count: 0, eidolon_finding_count: 1}
  ]
}' > "$sample_dir/pwnkit-stability-sample.json"
SH
  chmod +x "$path"
}

write_benchmark_stub_runner() {
  local path="$1"

  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"
mkdir -p "$sample_dir/raw-sample/run-1/private"
printf 'run_count=%s\n' "$run_count" > "$sample_dir/sample-plan.txt"

jq -n '{
  schema_version: 1,
  run_kind: "pwnkit_benchmark_sample",
  boundary: "scanner_qualification",
  claim_posture: "benchmark_capability_only",
  evaluation_lane_version: 1,
  generated_at: "2026-07-06T00:00:00Z",
  lane: "xbow_benchmark",
  benchmark_family: "xbow_public",
  benchmark_task_id: "task-alpha",
  benchmark_snapshot_id: "snap-001",
  benchmark_model_id: "gpt-5.4",
  benchmark_prompt_bundle_hash: "sha256:benchprompt",
  benchmark_validation_rule: "validated_exploit_required",
  substrate: "host_local",
  defense_mode: "comparison",
  artifact_identity: {
    artifact_kind: "pwnkit_benchmark_sample",
    raw_sample_summary_path: "/private/tmp/raw-sample/pwnkit-stability-sample.json",
    validation_artifact_path: "/private/tmp/raw-sample/benchmark-validation.json"
  },
  budget: {
    benchmark_action_budget: 40,
    benchmark_token_budget: 120000,
    benchmark_wall_clock_budget_seconds: 900,
    observed_artifact_count: 1,
    observed_valid_summary_count: 1
  },
  counts: {
    raw_artifact_count: 1,
    raw_valid_summary_count: 1,
    direct_findings: 0,
    eidolon_findings: 1,
    positive_differential_findings: 1
  },
  validation: {
    status: "validated",
    validator_kind: "fixture_validator",
    exploit_rule: "validated_exploit_required",
    notes: ["fixture benchmark validation"]
  },
  artifacts: [
    {
      artifact_id: "raw-sample",
      lane: "xbow_benchmark",
      benchmark_family: "xbow_public",
      benchmark_task_id: "task-alpha",
      substrate: "host_local",
      defense_mode: "comparison",
      artifact_identity: {
        artifact_kind: "pwnkit_benchmark_raw_sample",
        raw_sample_summary_path: "/private/tmp/raw-sample/pwnkit-stability-sample.json"
      },
      validation_status: "validated",
      strongest_claim_level: "controlled_reality_entered",
      direct_findings: 0,
      eidolon_findings: 1
    }
  ]
}' > "$sample_dir/pwnkit-stability-sample.json"
SH
  chmod +x "$path"
}

write_stock_manifest() {
  local manifest="$1"

  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_matrix_manifest",
    boundary: "scanner_qualification",
    variants: [
      {
        variant_id: "stock_compare",
        enabled: true,
        lane: "eidolon_owned_target",
        substrate: "host_local",
        defense_mode: "comparison",
        control_kind: "stock_vs_patched",
        hypothesis_id: "stock_compare",
        hypothesis: "stock compare",
        expected_observation: "parity_reproduced",
        runner_kind: "qualification_stock_vs_patched_sample",
        run_count: 1
      }
    ]
  }' > "$manifest"
}

write_benchmark_manifest() {
  local manifest="$1"

  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_matrix_manifest",
    boundary: "scanner_qualification",
    variants: [
      {
        variant_id: "xbow_task_alpha",
        enabled: true,
        lane: "xbow_benchmark",
        benchmark_family: "xbow_public",
        benchmark_task_id: "task-alpha",
        benchmark_snapshot_id: "snap-001",
        benchmark_model_id: "gpt-5.4",
        benchmark_prompt_bundle_hash: "sha256:benchprompt",
        benchmark_validation_rule: "validated_exploit_required",
        benchmark_action_budget: 40,
        benchmark_token_budget: 120000,
        benchmark_wall_clock_budget_seconds: 900,
        substrate: "host_local",
        defense_mode: "comparison",
        control_kind: "positive_control",
        hypothesis_id: "xbow_task_alpha",
        hypothesis: "benchmark capability task",
        expected_observation: "validated_exploit",
        runner_kind: "qualification_benchmark_sample",
        run_count: 1
      }
    ]
  }' > "$manifest"
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
    and .vm_profiles[0].lane == "kali_vm_transfer"
    and .vm_profiles[0].substrate == "kali_vm_orbstack_nodeport"
    and .vm_profiles[0].defense_mode == "comparison"
    and .vm_profiles[0].variant_ids == ["kali_transfer"]
  ' "$matrix_dir/vm-spool-plan.json" >/dev/null

  rg -q '^fixture_id=fixture-local$' "$matrix_dir/local_positive/sample-plan.txt"
  rg -q '^dry_run=1$' "$matrix_dir/local_positive/sample-plan.txt"
  rg -q '^fixture_id=fixture-kali$' "$matrix_dir/kali_transfer/sample-plan.txt"
  rg -q '^dry_run=1$' "$matrix_dir/kali_transfer/sample-plan.txt"
  rg -q '^blocked_reason=waiting on hardened target$' \
    "$matrix_dir/negative_blocked/variant-status.txt"

  jq -e '
    (.manifest_sha256 | type) == "string"
    and (.manifest_sha256 | length) == 64
    and .rerun_identity.comparison_scope == "partial_qualification_matrix"
    and .rerun_identity.lane_set == ["eidolon_owned_target", "kali_vm_transfer"]
    and .rerun_identity.substrate_set == ["host_local", "kali_vm_orbstack_nodeport"]
    and .rerun_identity.defense_mode_set == ["comparison", "none"]
    and .rerun_identity.runner_kind_set == ["m3_local_sample", "shield_lab_kali_orbstack"]
    and .rerun_identity.control_kind_set == ["negative_control", "positive_control", "transfer_control"]
    and .rerun_identity.evidence_track_set == []
    and .rerun_identity.fixture_id_set == []
    and .planned_variant_count == 2
    and .blocked_variant_count == 1
    and .completed_variant_count == 0
    and .acceptance_results.positive_control == "inconclusive"
    and .acceptance_results.transfer_control == "inconclusive"
    and .acceptance_results.negative_control == "inconclusive"
    and .acceptance_coverage.positive_control_completed == false
    and .acceptance_coverage.negative_control_completed == false
    and .qualification_contract.qualification_status == "not_ready"
    and .qualification_contract.ready_for_qualification_claim == false
    and (.qualification_contract.missing_control_kinds | index("stock_vs_patched")) != null
    and (.qualification_contract.incomplete_control_kinds | index("positive_control")) != null
    and (.qualification_contract.incomplete_control_kinds | index("transfer_control")) != null
    and (.qualification_contract.incomplete_control_kinds | index("negative_control")) != null
    and .variants[0].execution_state == "planned"
    and .variants[0].result_class == "inconclusive"
    and .variants[0].lane == "eidolon_owned_target"
    and .variants[1].execution_state == "planned"
    and .variants[1].lane == "kali_vm_transfer"
    and .variants[2].execution_state == "blocked"
    and .variants[2].result_class == "inconclusive"
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
    (.manifest_sha256 | type) == "string"
    and (.manifest_sha256 | length) == 64
    and .rerun_identity.comparison_scope == "partial_qualification_matrix"
    and .rerun_identity.lane_set == ["eidolon_owned_target", "kali_vm_transfer"]
    and .rerun_identity.evidence_track_set == ["local_patched_pwnkit"]
    and .rerun_identity.fixture_id_set == []
    and .completed_variant_count == 2
    and .blocked_variant_count == 1
    and .lane_counts == [
      {"lane":"eidolon_owned_target","count":2},
      {"lane":"kali_vm_transfer","count":1}
    ]
    and .result_counts == [
      {"result_class":"inconclusive","count":1},
      {"result_class":"pass","count":2}
    ]
    and .acceptance_coverage.positive_control_completed == true
    and .acceptance_coverage.transfer_control_completed == true
    and .acceptance_coverage.negative_control_completed == false
    and .acceptance_results.positive_control == "pass"
    and .acceptance_results.transfer_control == "pass"
    and .acceptance_results.negative_control == "inconclusive"
    and .qualification_contract.qualification_status == "not_ready"
    and .qualification_contract.ready_for_qualification_claim == false
    and (.qualification_contract.missing_control_kinds | index("stock_vs_patched")) != null
    and (.qualification_contract.incomplete_control_kinds | index("negative_control")) != null
    and ([.variants[] | select(.execution_state == "completed")] | length == 2)
    and (.variants[] | select(.variant_id == "local_positive") | .direct_finding_count_total == 2)
    and (.variants[] | select(.variant_id == "local_positive") | .result_class == "pass")
    and (.variants[] | select(.variant_id == "kali_transfer") | .eidolon_finding_count_total == 1)
    and (.variants[] | select(.variant_id == "kali_transfer") | .result_class == "pass")
  ' "$matrix_dir/pwnkit-qualification-matrix.json" >/dev/null
}

test_execution_collects_stock_vs_patched_parity_metadata() {
  local temp_dir manifest matrix_dir stock_stub

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  stock_stub="$temp_dir/stock-stub.sh"
  write_stock_manifest "$manifest"
  write_stock_stub_runner "$stock_stub"

  EIDOLON_PWNKIT_QUAL_RUNNER_STOCK_VS_PATCHED_SAMPLE="$stock_stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  jq -e '
    (.manifest_sha256 | type) == "string"
    and (.manifest_sha256 | length) == 64
    and .rerun_identity.comparison_scope == "partial_qualification_matrix"
    and .rerun_identity.lane_set == ["eidolon_owned_target"]
    and .rerun_identity.evidence_track_set == ["local_patched_pwnkit", "upstream_current"]
    and .rerun_identity.fixture_id_set == []
    and .completed_variant_count == 1
    and .acceptance_coverage.stock_vs_patched_completed == true
    and .acceptance_results.stock_vs_patched == "pass"
    and .qualification_contract.qualification_status == "not_ready"
    and .qualification_contract.ready_for_qualification_claim == false
    and (.qualification_contract.missing_control_kinds | index("positive_control")) != null
    and (.qualification_contract.missing_control_kinds | index("negative_control")) != null
    and (.qualification_contract.missing_control_kinds | index("transfer_control")) != null
    and (.variants[0].stock_vs_patched_parity_status == "parity_reproduced")
    and (.variants[0].stock_vs_patched_parity_reproduced == true)
    and (.variants[0].stock_vs_patched_next_question == "parity_reproduced")
    and (.variants[0].result_class == "pass")
  ' "$matrix_dir/pwnkit-qualification-matrix.json" >/dev/null
}

test_execution_collects_benchmark_lane_metadata() {
  local temp_dir manifest matrix_dir benchmark_stub

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  benchmark_stub="$temp_dir/benchmark-stub.sh"
  write_benchmark_manifest "$manifest"
  write_benchmark_stub_runner "$benchmark_stub"

  EIDOLON_PWNKIT_QUAL_RUNNER_BENCHMARK_SAMPLE="$benchmark_stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  jq -e '
    .claim_posture == "benchmark_capability_only"
    and (.manifest_sha256 | type) == "string"
    and (.manifest_sha256 | length) == 64
    and .qualification_contract.qualification_status == "benchmark_only"
    and .qualification_contract.ready_for_qualification_claim == false
    and .qualification_contract.qualification_reasons == ["benchmark_lane_only"]
    and .rerun_identity.comparison_scope == "benchmark_lane_only"
    and .rerun_identity.lane_set == ["xbow_benchmark"]
    and .rerun_identity.evidence_track_set == []
    and .rerun_identity.fixture_id_set == []
    and .benchmark_contract.benchmark_variant_count == 1
    and .benchmark_contract.mixed_benchmark_and_nonbenchmark == false
    and .benchmark_contract.benchmark_families == ["xbow_public"]
    and .benchmark_contract.benchmark_task_ids == ["task-alpha"]
    and .variants[0].lane == "xbow_benchmark"
    and .variants[0].benchmark_family == "xbow_public"
    and .variants[0].benchmark_task_id == "task-alpha"
    and .variants[0].benchmark_snapshot_id == "snap-001"
    and .variants[0].benchmark_model_id == "gpt-5.4"
    and .variants[0].benchmark_prompt_bundle_hash == "sha256:benchprompt"
    and .variants[0].benchmark_validation_rule == "validated_exploit_required"
    and .variants[0].budget.benchmark_action_budget == 40
    and .variants[0].budget.benchmark_token_budget == 120000
    and .variants[0].budget.benchmark_wall_clock_budget_seconds == 900
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
test_execution_collects_stock_vs_patched_parity_metadata
test_execution_collects_benchmark_lane_metadata
test_rejects_invalid_variant_id

printf 'pwnkit qualification matrix fixture tests passed\n'
