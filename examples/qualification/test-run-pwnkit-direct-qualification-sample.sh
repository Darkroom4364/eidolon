#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-direct-qualification-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-direct-qualification-test.XXXXXX"
}

test_help_mentions_negative_control_profile() {
  "$RUNNER" --help | rg -q 'qualification_negative_control'
  "$RUNNER" --help | rg -q 'direct-only pwnkit qualification sample'
}

test_dry_run_records_target_profile() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_PWNKIT_QUAL_DIRECT_DRY_RUN=1 \
    EIDOLON_LAB_TARGET_PROFILE=qualification_negative_control \
    "$RUNNER" 2 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/sample-plan.txt" ]]
  rg -q '^run_count=2$' "$sample_dir/sample-plan.txt"
  rg -q '^target_profile=qualification_negative_control$' "$sample_dir/sample-plan.txt"
  rg -q '^sample_summary=pwnkit-stability-sample.json$' "$sample_dir/sample-plan.txt"
}

test_rejects_non_negative_control_profile() {
  local output
  local status=0

  output="$(
    EIDOLON_PWNKIT_QUAL_DIRECT_DRY_RUN=1 \
      EIDOLON_LAB_TARGET_PROFILE=default \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_LAB_TARGET_PROFILE must be qualification_negative_control' <<<"$output"
}

test_help_mentions_negative_control_profile
test_dry_run_records_target_profile
test_rejects_non_negative_control_profile

printf 'direct qualification runner fixture tests passed\n'
