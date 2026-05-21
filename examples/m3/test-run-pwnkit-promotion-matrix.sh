#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-promotion-matrix.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-promotion-runner-test.XXXXXX"
}

canonical_file_path() {
  local path="$1"
  local dir
  local base

  dir="$(dirname "$path")"
  base="$(basename "$path")"
  (
    cd "$dir"
    printf '%s/%s' "$(pwd -P)" "$base"
  )
}

write_manifest() {
  local manifest="$1"
  local profile="$2"

  jq -n \
    --arg profile "$profile" \
    '{
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
          variant_id: "openapi_promotion_probe",
          bait_profile: $profile,
          hypothesis: "promotion probe",
          knobs: ["openapi.summary"],
          expected_observation: "diagnostic_delta_or_promoted_finding"
        }
      ]
    }' > "$manifest"
}

test_help_mentions_matrix_summary() {
  "$RUNNER" --help | rg -q 'pwnkit bait-promotion manifest'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PROMOTION_DRY_RUN'
}

test_rejects_invalid_run_count() {
  local temp_dir
  local manifest
  local profile
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  profile="$temp_dir/profile.json"
  printf '{"schema_version":1,"profile_id":"fixture"}\n' > "$profile"
  write_manifest "$manifest" "$profile"

  output="$(
    EIDOLON_M3_PROMOTION_RUNS=0 \
      EIDOLON_M3_PROMOTION_DRY_RUN=1 \
      "$RUNNER" "$manifest" "$temp_dir/matrix" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_PROMOTION_RUNS must be a positive integer' <<<"$output"
}

test_dry_run_creates_variant_sample_plans() {
  local temp_dir
  local manifest
  local profile
  local canonical_profile
  local matrix_dir

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  profile="$temp_dir/profile.json"
  matrix_dir="$temp_dir/matrix"
  printf '{"schema_version":1,"profile_id":"fixture"}\n' > "$profile"
  write_manifest "$manifest" "$profile"
  canonical_profile="$(canonical_file_path "$profile")"

  EIDOLON_M3_PROMOTION_DRY_RUN=1 \
    EIDOLON_M3_PROMOTION_RUNS=2 \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  [[ -f "$matrix_dir/matrix-plan.json" ]]
  [[ -f "$matrix_dir/bait-promotion-variants.json" ]]
  [[ -f "$matrix_dir/default_m3_catalog/sample-plan.txt" ]]
  [[ -f "$matrix_dir/openapi_promotion_probe/sample-plan.txt" ]]

  jq -e '
    .run_kind == "m3_pwnkit_promotion_matrix_plan"
    and .run_count == 2
    and .dry_run == true
    and (.variants | length == 2)
  ' "$matrix_dir/matrix-plan.json" >/dev/null
  rg -q '^run_count=2$' "$matrix_dir/default_m3_catalog/sample-plan.txt"
  rg -q '^bait_profile=default$' "$matrix_dir/default_m3_catalog/sample-plan.txt"
  rg -q "^bait_profile=$canonical_profile$" \
    "$matrix_dir/openapi_promotion_probe/sample-plan.txt"
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

  output="$(
    EIDOLON_M3_PROMOTION_DRY_RUN=1 \
      "$RUNNER" "$manifest" "$temp_dir/matrix" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'invalid variant_id' <<<"$output"
}

test_rejects_missing_profile() {
  local temp_dir
  local manifest
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  write_manifest "$manifest" "$temp_dir/missing-profile.json"

  output="$(
    EIDOLON_M3_PROMOTION_DRY_RUN=1 \
      "$RUNNER" "$manifest" "$temp_dir/matrix" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'bait_profile must point to an existing file' <<<"$output"
}

test_help_mentions_matrix_summary
test_rejects_invalid_run_count
test_dry_run_creates_variant_sample_plans
test_rejects_invalid_variant_id
test_rejects_missing_profile

printf 'run-pwnkit-promotion-matrix fixture tests passed\n'
