#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="$SCRIPT_DIR/check-pwnkit-promotion-matrix-health.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-promotion-matrix-health-test.XXXXXX"
}

write_matrix() {
  local path="$1"
  local ready="$2"
  local missing_variant_count="$3"
  local agent_error_count="$4"
  local all_variants_observed="$5"
  local all_agent_error_free="$6"
  local all_clean="$7"
  local all_synced="$8"

  jq -n \
    --argjson ready "$ready" \
    --argjson missing_variant_count "$missing_variant_count" \
    --argjson agent_error_count "$agent_error_count" \
    --argjson all_variants_observed "$all_variants_observed" \
    --argjson all_agent_error_free "$all_agent_error_free" \
    --argjson all_clean "$all_clean" \
    --argjson all_synced "$all_synced" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_promotion_matrix",
      manifest_path: "/private/tmp/eidolon-secret/manifest.json",
      matrix_dir: "/private/tmp/eidolon-secret/matrix",
      raw_pwnkit_fixture: {
        token: "secret-token",
        path: "/api/private?token=secret-token"
      },
      matrix_health: {
        missing_variant_count: $missing_variant_count,
        all_variants_observed: $all_variants_observed,
        total_pwnkit_agent_errors: $agent_error_count,
        all_observed_samples_agent_error_free: $all_agent_error_free,
        source_checkout_clean_variant_count: (
          if $all_clean then 2 else 1 end
        ),
        source_checkout_synced_variant_count: (
          if $all_synced then 2 else 1 end
        ),
        all_observed_source_checkouts_clean: $all_clean,
        all_observed_source_checkouts_synced: $all_synced,
        runner_git_heads: ["abc123"],
        runner_package_versions: ["0.11.1"],
        ready_for_matrix_interpretation: $ready
      },
      variants: [
        {
          variant_id: "diagnostic_probe",
          variant_bundle_dir: "/private/tmp/eidolon-secret/variant",
          no_signal_diagnostics: {
            proxy_path_counts: [
              {
                path: "/docs?token=secret-token",
                count: 1
              }
            ]
          }
        }
      ]
    }' > "$path"
}

test_accepts_clean_matrix() {
  local dir
  dir="$(new_temp_dir)"
  write_matrix "$dir/pwnkit-promotion-matrix.json" true 0 0 true true true true

  "$CHECKER" "$dir/pwnkit-promotion-matrix.json"
}

test_rejects_unhealthy_matrix_with_sanitized_output() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_matrix "$dir/pwnkit-promotion-matrix.json" false 1 2 false false false false

  output="$("$CHECKER" "$dir/pwnkit-promotion-matrix.json" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'pwnkit promotion matrix is not healthy enough to interpret' <<<"$output"
  rg -q 'matrix_health.ready_for_matrix_interpretation=false' <<<"$output"
  rg -q 'matrix_health.missing_variant_count=1' <<<"$output"
  rg -q 'matrix_health.total_pwnkit_agent_errors=2' <<<"$output"
  rg -q 'matrix_health.runner_git_heads=abc123' <<<"$output"
  rg -q 'matrix_health.runner_package_versions=0.11.1' <<<"$output"
  ! rg -q '/private/tmp|secret-token|/docs|variant_bundle_dir|raw_pwnkit_fixture' <<<"$output"
}

test_allows_unhealthy_matrix_when_explicitly_requested() {
  local dir
  dir="$(new_temp_dir)"
  write_matrix "$dir/pwnkit-promotion-matrix.json" false 1 2 false false false false

  EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX=1 \
    "$CHECKER" "$dir/pwnkit-promotion-matrix.json"
}

test_rejects_unhealthy_matrix_when_bypass_is_not_exactly_one() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_matrix "$dir/pwnkit-promotion-matrix.json" false 1 2 false false false false

  output="$(
    EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX=true \
      "$CHECKER" "$dir/pwnkit-promotion-matrix.json" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'pwnkit promotion matrix is not healthy enough to interpret' <<<"$output"
}

test_rejects_missing_matrix() {
  local output
  local status=0

  output="$("$CHECKER" "$(new_temp_dir)/missing.json" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'pwnkit promotion matrix not found' <<<"$output"
}

test_accepts_clean_matrix
test_rejects_unhealthy_matrix_with_sanitized_output
test_allows_unhealthy_matrix_when_explicitly_requested
test_rejects_unhealthy_matrix_when_bypass_is_not_exactly_one
test_rejects_missing_matrix

printf 'check-pwnkit-promotion-matrix-health fixture tests passed\n'
