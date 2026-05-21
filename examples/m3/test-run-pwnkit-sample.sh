#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-sample-runner-test.XXXXXX"
}

test_help_mentions_sample_summary() {
  "$RUNNER" --help | rg -q 'pwnkit-stability-sample\.json'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_BAIT_PROFILE'
}

test_rejects_invalid_run_count() {
  local output
  local status=0

  output="$("$RUNNER" 0 "$(new_temp_dir)" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'run-count must be a positive integer' <<<"$output"
}

test_rejects_urls_with_query_values() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_SAMPLE_DRY_RUN=1 \
      EIDOLON_LAB_TARGET_URL='http://127.0.0.1:9101?token=secret' \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'must not include a path, query, or fragment' <<<"$output"
}

test_dry_run_creates_private_layout() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 "$RUNNER" 2 "$sample_dir" >/dev/null

  [[ -d "$sample_dir/run-1/private" ]]
  [[ -d "$sample_dir/run-2/private" ]]
  [[ -f "$sample_dir/sample-plan.txt" ]]
  rg -q '^run_count=2$' "$sample_dir/sample-plan.txt"
  rg -q '^pin_session=1$' "$sample_dir/sample-plan.txt"
  rg -q '^bait_profile=default$' "$sample_dir/sample-plan.txt"
  rg -q '^debug_log=run-\*/private/eidolon-debug\.jsonl$' "$sample_dir/sample-plan.txt"
}

test_dry_run_records_bait_profile() {
  local sample_dir
  local profile
  sample_dir="$(new_temp_dir)"
  profile="$sample_dir/bait-profile.json"
  printf '{"schema_version":1,"profile_id":"fixture"}\n' > "$profile"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_M3_BAIT_PROFILE="$profile" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q "^bait_profile=$profile$" "$sample_dir/sample-plan.txt"
}

test_rejects_missing_bait_profile() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_SAMPLE_DRY_RUN=1 \
      EIDOLON_M3_BAIT_PROFILE="$(new_temp_dir)/missing.json" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_BAIT_PROFILE must point to an existing file' <<<"$output"
}

test_dry_run_accepts_localhost_urls() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_LAB_TARGET_URL=http://localhost:9101 \
    EIDOLON_LAB_PROXY_URL=http://localhost:9102 \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q '^target_addr=127\.0\.0\.1:9101$' "$sample_dir/sample-plan.txt"
  rg -q '^proxy_addr=127\.0\.0\.1:9102$' "$sample_dir/sample-plan.txt"
}

test_help_mentions_sample_summary
test_rejects_invalid_run_count
test_rejects_urls_with_query_values
test_dry_run_creates_private_layout
test_dry_run_records_bait_profile
test_rejects_missing_bait_profile
test_dry_run_accepts_localhost_urls

printf 'run-pwnkit-sample fixture tests passed\n'
