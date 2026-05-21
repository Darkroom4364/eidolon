#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-promotion-matrix.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-promotion-collector-test.XXXXXX"
}

write_manifest() {
  local manifest="$1"

  jq -n '{
    schema_version: 1,
    run_kind: "m3_pwnkit_promotion_matrix_manifest",
    boundary: "owned_loopback_lab",
    variants: [
      {
        variant_id: "default_m3_catalog",
        bait_profile: null,
        hypothesis: "baseline",
        knobs: [],
        expected_observation: "behavior_only"
      },
      {
        variant_id: "promoted_probe",
        bait_profile: "examples/m3/bait-profiles/openapi-promotion-probe.json",
        hypothesis: "finding promotion",
        knobs: ["openapi.summary"],
        expected_observation: "diagnostic_delta_or_promoted_finding"
      },
      {
        variant_id: "missing_probe",
        bait_profile: null,
        hypothesis: "missing fixture",
        knobs: [],
        expected_observation: "behavior_only"
      }
    ]
  }' > "$manifest"
}

write_sample() {
  local sample_file="$1"
  local direct_findings="$2"
  local eidolon_findings="$3"
  local positive_differential="$4"

  jq -n \
    --argjson direct_findings "$direct_findings" \
    --argjson eidolon_findings "$eidolon_findings" \
    --argjson positive_differential "$positive_differential" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_codex_sample",
      generated_at: "2026-05-21T00:00:00Z",
      artifact_count: 1,
      valid_summary_count: 1,
      counts: {
        missing_summary: 0,
        target_interaction_observed: 1,
        bait_reached: 1,
        bait_action_observed: 1,
        same_session_confirmed_bait_action: 1,
        controlled_reality_entered: 1,
        direct_quiet: (if $direct_findings == 0 then 1 else 0 end),
        direct_findings: (if $direct_findings > 0 then 1 else 0 end),
        eidolon_findings: (if $eidolon_findings > 0 then 1 else 0 end),
        positive_differential_findings: (
          if $positive_differential then 1 else 0 end
        ),
        bait_reached_without_eidolon_findings: (
          if $eidolon_findings == 0 then 1 else 0 end
        ),
        bait_action_without_eidolon_findings: (
          if $eidolon_findings == 0 then 1 else 0 end
        ),
        controlled_reality_without_eidolon_findings: (
          if $eidolon_findings == 0 then 1 else 0 end
        ),
        pinned_session_present: 1,
        pinned_cookie_preserved: 1
      },
      rates: {
        target_interaction_rate: 1,
        bait_reach_rate: 1,
        bait_action_rate: 1,
        same_session_confirmed_bait_action_rate: 1,
        controlled_reality_entry_rate: 1,
        direct_quiet_rate: (if $direct_findings == 0 then 1 else 0 end),
        eidolon_finding_rate: (if $eidolon_findings > 0 then 1 else 0 end),
        positive_differential_finding_rate: (
          if $positive_differential then 1 else 0 end
        ),
        pinned_cookie_preservation_rate: 1
      },
      claim_level_counts: [
        {
          claim_level: "controlled_reality_entered",
          count: 1
        }
      ],
      weakest_claim_level: "controlled_reality_entered",
      strongest_claim_level: "controlled_reality_entered",
      runner_git_heads: ["abc123"],
      runner_package_versions: ["0.11.1"],
      source_checkout: {
        all_runners_clean: true,
        all_runners_origin_main_synced: true
      },
      differential_findings: {
        ready_for_differential_finding_claim: $positive_differential,
        direct_finding_run_count: (if $direct_findings > 0 then 1 else 0 end),
        eidolon_finding_run_count: (if $eidolon_findings > 0 then 1 else 0 end),
        positive_differential_run_count: (
          if $positive_differential then 1 else 0 end
        )
      },
      strict_stability: {
        ready_for_stability_claim: true
      }
    }' > "$sample_file"
}

test_help_mentions_matrix_summary() {
  "$COLLECTOR" --help | rg -q 'bait-promotion matrix summary'
}

test_collects_variant_observation_classes() {
  local temp_dir
  local manifest
  local matrix_dir
  local output

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  output="$temp_dir/summary.json"

  write_manifest "$manifest"
  mkdir -p "$matrix_dir/default_m3_catalog" "$matrix_dir/promoted_probe"
  write_sample "$matrix_dir/default_m3_catalog/pwnkit-stability-sample.json" \
    0 0 false
  write_sample "$matrix_dir/promoted_probe/pwnkit-stability-sample.json" \
    0 1 true

  "$COLLECTOR" "$manifest" "$matrix_dir" > "$output"

  jq -e '
    .run_kind == "m3_pwnkit_promotion_matrix"
    and .variant_count == 3
    and .observed_variant_count == 2
    and (.ready_for_differential_finding_claim_variants == ["promoted_probe"])
    and (.ready_for_stability_claim_variants == ["default_m3_catalog", "promoted_probe"])
  ' "$output" >/dev/null

  jq -e '
    .variants[]
    | select(.variant_id == "default_m3_catalog")
    | .present == true
      and .observation_class == "behavior_only"
      and .counts.controlled_reality_without_eidolon_findings == 1
  ' "$output" >/dev/null

  jq -e '
    .variants[]
    | select(.variant_id == "promoted_probe")
    | .present == true
      and .observation_class == "promoted_finding"
      and .counts.positive_differential_findings == 1
  ' "$output" >/dev/null

  jq -e '
    .variants[]
    | select(.variant_id == "missing_probe")
    | .present == false
      and .observation_class == "missing"
      and .missing_reason == "pwnkit-stability-sample.json not found"
  ' "$output" >/dev/null
}

test_rejects_invalid_variant_id() {
  local temp_dir
  local manifest
  local matrix_dir
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  mkdir -p "$matrix_dir"
  jq -n '{
    schema_version: 1,
    run_kind: "m3_pwnkit_promotion_matrix_manifest",
    boundary: "owned_loopback_lab",
    variants: [
      {
        variant_id: "../bad",
        bait_profile: null,
        expected_observation: "behavior_only"
      }
    ]
  }' > "$manifest"

  output="$("$COLLECTOR" "$manifest" "$matrix_dir" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'invalid variant_id' <<<"$output"
}

test_help_mentions_matrix_summary
test_collects_variant_observation_classes
test_rejects_invalid_variant_id

printf 'collect-pwnkit-promotion-matrix fixture tests passed\n'
