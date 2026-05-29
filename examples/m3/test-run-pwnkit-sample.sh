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
  "$RUNNER" --help | rg -q 'EIDOLON_M3_ALLOW_AGENT_ERRORS'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_MAX_ATTEMPTS'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_CODEX_AUTH_FILE'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_RUNNER_ENVIRONMENT'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_NETWORK_TOPOLOGY'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_FIXTURE_ID'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS'
  "$RUNNER" --help | rg -q 'PWNKIT_SOURCE_DIR'
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
  rg -q '^allow_agent_errors=0$' "$sample_dir/sample-plan.txt"
  rg -q '^allow_unfresh_pwnkit_source=0$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_max_attempts=2$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_timeout_seconds=900$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_heartbeat_seconds=60$' "$sample_dir/sample-plan.txt"
  rg -q '^runner_environment=auto$' "$sample_dir/sample-plan.txt"
  rg -q '^network_topology=same_host_loopback$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_fixture_id=none$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_evidence_track=auto$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_source_dir=' "$sample_dir/sample-plan.txt"
  rg -q '^debug_log=run-\*/private/eidolon-debug\.jsonl$' "$sample_dir/sample-plan.txt"
}

test_dry_run_records_pwnkit_source_dir() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    PWNKIT_SOURCE_DIR=/tmp/local-pwnkit-source \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q '^pwnkit_source_dir=/tmp/local-pwnkit-source$' "$sample_dir/sample-plan.txt"
}

test_dry_run_records_runner_environment_overrides() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_M3_RUNNER_ENVIRONMENT=kali_vm \
    EIDOLON_M3_NETWORK_TOPOLOGY=vm_loopback_forward \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q '^runner_environment=kali_vm$' "$sample_dir/sample-plan.txt"
  rg -q '^network_topology=vm_loopback_forward$' "$sample_dir/sample-plan.txt"
}

test_rejects_invalid_pwnkit_max_attempts() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_PWNKIT_MAX_ATTEMPTS=0 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_PWNKIT_MAX_ATTEMPTS must be a positive integer' <<<"$output"
}

test_rejects_invalid_pwnkit_timeout_seconds() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS=0 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS must be a positive integer' <<<"$output"
}

test_rejects_invalid_pwnkit_heartbeat_seconds() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS=0 \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS must be a positive integer' <<<"$output"
}

test_dry_run_records_agent_error_override() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_M3_ALLOW_AGENT_ERRORS=1 \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q '^allow_agent_errors=1$' "$sample_dir/sample-plan.txt"
}

test_dry_run_records_unfresh_source_override() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE=1 \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q '^allow_unfresh_pwnkit_source=1$' "$sample_dir/sample-plan.txt"
}

test_dry_run_records_pwnkit_fixture_id() {
  local sample_dir
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private \
    EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q '^pwnkit_fixture_id=pwnkit-v0\.12\.0-private$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_evidence_track=local_patched_pwnkit$' "$sample_dir/sample-plan.txt"
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
test_rejects_invalid_pwnkit_max_attempts
test_rejects_invalid_pwnkit_timeout_seconds
test_rejects_invalid_pwnkit_heartbeat_seconds
test_rejects_urls_with_query_values
test_dry_run_creates_private_layout
test_dry_run_records_pwnkit_source_dir
test_dry_run_records_runner_environment_overrides
test_dry_run_records_agent_error_override
test_dry_run_records_unfresh_source_override
test_dry_run_records_pwnkit_fixture_id
test_dry_run_records_bait_profile
test_rejects_missing_bait_profile
test_dry_run_accepts_localhost_urls

printf 'run-pwnkit-sample fixture tests passed\n'
