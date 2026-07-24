#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-sample-runner-test.XXXXXX"
}

sha256_file() {
  local path="$1"
  local output

  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum "$path")"
  else
    output="$(shasum -a 256 "$path")"
  fi
  printf '%s' "${output%% *}"
}

test_help_mentions_sample_summary() {
  "$RUNNER" --help | rg -q 'pwnkit-stability-sample\.json'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_BAIT_PROFILE'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_BAIT_SIGNING_SECRET_FILE'
  "$RUNNER" --help | rg -q 'Required when'
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
  [[ -f "$sample_dir/run-1/sample-run-metadata.json" ]]
  [[ -f "$sample_dir/run-2/sample-run-metadata.json" ]]
  rg -q '^run_count=2$' "$sample_dir/sample-plan.txt"
  rg -q '^pin_session=1$' "$sample_dir/sample-plan.txt"
  rg -q '^bait_profile=default$' "$sample_dir/sample-plan.txt"
  rg -q '^bait_profile_sha256=none$' "$sample_dir/sample-plan.txt"
  rg -q '^bait_profile_snapshot=none$' "$sample_dir/sample-plan.txt"
  rg -q '^bait_profile_metadata=none$' "$sample_dir/sample-plan.txt"
  rg -q '^sample_run_metadata=run-\*/sample-run-metadata\.json$' \
    "$sample_dir/sample-plan.txt"
  rg -q '^bait_signing_secret=default$' "$sample_dir/sample-plan.txt"
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
  jq -e '
    .schema_version == 1
    and .run_kind == "m3_pwnkit_sample_run"
    and (.execution_id | test("^exec_[0-9a-f]{32}$"))
    and .profile_sha256 == null
  ' "$sample_dir/run-1/sample-run-metadata.json" >/dev/null
  jq -e '
    .schema_version == 1
    and .run_kind == "m3_pwnkit_sample_run"
    and (.execution_id | test("^exec_[0-9a-f]{32}$"))
    and .profile_sha256 == null
  ' "$sample_dir/run-2/sample-run-metadata.json" >/dev/null
  [[ "$(
    jq -r .execution_id "$sample_dir/run-1/sample-run-metadata.json"
  )" != "$(
    jq -r .execution_id "$sample_dir/run-2/sample-run-metadata.json"
  )" ]]
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
  local expected_sha256
  sample_dir="$(new_temp_dir)"
  profile="$sample_dir/bait-profile.json"
  jq -n '{
    schema_version: 1,
    profile_id: "fixture",
    baits: [
      {
        id: "fixture_docs_bait",
        bait_class: "docs",
        expected_action: {
          header_name: "X-Fixture",
          header_value: "must-not-enter-metadata"
        }
      }
    ]
  }' > "$profile"
  expected_sha256="$(sha256_file "$profile")"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_M3_BAIT_PROFILE="$profile" \
    "$RUNNER" 2 "$sample_dir/output" >/dev/null

  rg -q '^bait_profile=configured$' "$sample_dir/output/sample-plan.txt"
  rg -q "^bait_profile_sha256=$expected_sha256$" \
    "$sample_dir/output/sample-plan.txt"
  rg -q '^bait_profile_snapshot=run-\*/private/bait-profile\.json$' \
    "$sample_dir/output/sample-plan.txt"
  rg -q '^bait_profile_metadata=run-\*/bait-profile-metadata\.json$' \
    "$sample_dir/output/sample-plan.txt"
  ! rg -Fq "$profile" "$sample_dir/output/sample-plan.txt"
  [[ -f "$sample_dir/output/private/bait-profile.json" ]]
  [[ -f "$sample_dir/output/run-1/private/bait-profile.json" ]]
  [[ -f "$sample_dir/output/run-2/private/bait-profile.json" ]]
  cmp "$profile" "$sample_dir/output/private/bait-profile.json"
  cmp "$profile" "$sample_dir/output/run-1/private/bait-profile.json"
  cmp "$profile" "$sample_dir/output/run-2/private/bait-profile.json"
  jq -e --arg sha256 "$expected_sha256" '
    keys == ["baits", "profile_id", "schema_version", "sha256"]
    and .schema_version == 1
    and .profile_id == "fixture"
    and .sha256 == $sha256
    and .baits == [
      {
        bait_id: "fixture_docs_bait",
        bait_class: "docs"
      }
    ]
  ' "$sample_dir/output/run-1/bait-profile-metadata.json" >/dev/null
  cmp "$sample_dir/output/run-1/bait-profile-metadata.json" \
    "$sample_dir/output/run-2/bait-profile-metadata.json"
  ! rg -q 'header|expected_action|must-not-enter-metadata' \
    "$sample_dir/output/run-1/bait-profile-metadata.json"
  jq -e --arg sha256 "$expected_sha256" '
    keys == [
      "execution_id",
      "profile_sha256",
      "run_kind",
      "schema_version"
    ]
    and .schema_version == 1
    and .run_kind == "m3_pwnkit_sample_run"
    and (.execution_id | test("^exec_[0-9a-f]{32}$"))
    and .profile_sha256 == $sha256
  ' "$sample_dir/output/run-1/sample-run-metadata.json" >/dev/null
  jq -e --arg sha256 "$expected_sha256" '
    .profile_sha256 == $sha256
    and (.execution_id | test("^exec_[0-9a-f]{32}$"))
  ' "$sample_dir/output/run-2/sample-run-metadata.json" >/dev/null
  [[ "$(
    jq -r .execution_id \
      "$sample_dir/output/run-1/sample-run-metadata.json"
  )" != "$(
    jq -r .execution_id \
      "$sample_dir/output/run-2/sample-run-metadata.json"
  )" ]]
  ! rg -Fq "$profile" \
    "$sample_dir/output/run-1/sample-run-metadata.json" \
    "$sample_dir/output/run-1/bait-profile-metadata.json"
  ! rg -q 'must-not-enter-metadata' \
    "$sample_dir/output/run-1/sample-run-metadata.json" \
    "$sample_dir/output/run-1/bait-profile-metadata.json"
}

test_profile_source_toctou_uses_frozen_run_snapshot() {
  local temp_dir
  local profile
  local replacement
  local sample_dir
  local shim_dir
  local marker
  local real_cp
  local expected_sha256

  temp_dir="$(new_temp_dir)"
  profile="$temp_dir/source-profile.json"
  replacement="$temp_dir/replacement-profile.json"
  sample_dir="$temp_dir/output"
  shim_dir="$temp_dir/bin"
  marker="$temp_dir/profile-mutated"
  real_cp="$(command -v cp)"
  mkdir -p "$shim_dir"
  jq -n '{
    schema_version: 1,
    profile_id: "frozen_original",
    baits: [{id: "original_bait", bait_class: "docs"}]
  }' > "$profile"
  jq -n '{
    schema_version: 1,
    profile_id: "mutated_source",
    baits: [{id: "mutated_bait", bait_class: "open_api"}]
  }' > "$replacement"
  expected_sha256="$(sha256_file "$profile")"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    '"$REAL_CP" "$@"' \
    'if [[ "${1:-}" == "$PROFILE_SOURCE" \
      && "${2:-}" == */private/bait-profile.json.tmp \
      && ! -e "$PROFILE_MUTATION_MARKER" ]]; then' \
    '  "$REAL_CP" "$PROFILE_REPLACEMENT" "$PROFILE_SOURCE"' \
    '  : > "$PROFILE_MUTATION_MARKER"' \
    'fi' > "$shim_dir/cp"
  chmod +x "$shim_dir/cp"

  PATH="$shim_dir:$PATH" \
    REAL_CP="$real_cp" \
    PROFILE_SOURCE="$profile" \
    PROFILE_REPLACEMENT="$replacement" \
    PROFILE_MUTATION_MARKER="$marker" \
    EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_M3_BAIT_PROFILE="$profile" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  [[ -f "$marker" ]]
  jq -e '.profile_id == "mutated_source"' "$profile" >/dev/null
  jq -e '.profile_id == "frozen_original"' \
    "$sample_dir/run-1/private/bait-profile.json" >/dev/null
  [[ "$(sha256_file "$sample_dir/run-1/private/bait-profile.json")" \
    == "$expected_sha256" ]]
  jq -e --arg sha256 "$expected_sha256" '
    .sha256 == $sha256
    and .profile_id == "frozen_original"
    and .baits == [{bait_id: "original_bait", bait_class: "docs"}]
  ' "$sample_dir/run-1/bait-profile-metadata.json" >/dev/null
  jq -e --arg sha256 "$expected_sha256" '
    .profile_sha256 == $sha256
  ' "$sample_dir/run-1/sample-run-metadata.json" >/dev/null
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

test_rejects_malformed_bait_profile_before_dry_run_output() {
  local temp_dir
  local profile
  local sample_dir
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  profile="$temp_dir/malformed.json"
  sample_dir="$temp_dir/output"
  printf '{"schema_version":1,"profile_id":' > "$profile"

  output="$(
    EIDOLON_M3_SAMPLE_DRY_RUN=1 \
      EIDOLON_M3_BAIT_PROFILE="$profile" \
      "$RUNNER" 1 "$sample_dir" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_BAIT_PROFILE must contain valid JSON' <<<"$output"
  [[ ! -e "$sample_dir" ]]
}

test_dry_run_redacts_configured_bait_signing_secret() {
  local sample_dir
  local secret_file
  local secret_value='fixture-bait-signing-secret'
  sample_dir="$(new_temp_dir)"
  secret_file="$sample_dir/private-secret.txt"
  printf '%s\n' "$secret_value" > "$secret_file"

  EIDOLON_M3_SAMPLE_DRY_RUN=1 \
    EIDOLON_M3_BAIT_SIGNING_SECRET_FILE="$secret_file" \
    "$RUNNER" 1 "$sample_dir/output" >/dev/null

  rg -q '^bait_signing_secret=configured$' "$sample_dir/output/sample-plan.txt"
  ! rg -Fq "$secret_file" "$sample_dir/output/sample-plan.txt"
  ! rg -Fq "$secret_value" "$sample_dir/output/sample-plan.txt"
}

test_rejects_missing_bait_signing_secret_file() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_SAMPLE_DRY_RUN=1 \
      EIDOLON_M3_BAIT_SIGNING_SECRET_FILE="$(new_temp_dir)/missing-secret" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_BAIT_SIGNING_SECRET_FILE must point to an existing file' <<<"$output"
}

test_minted_profile_requires_bait_signing_secret_file() {
  local output
  local status=0

  output="$(
    EIDOLON_M3_SAMPLE_DRY_RUN=1 \
      EIDOLON_M3_BAIT_PROFILE="$SCRIPT_DIR/bait-profiles/docs-session-minted-probe.json" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_BAIT_SIGNING_SECRET_FILE is required' <<<"$output"
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
test_profile_source_toctou_uses_frozen_run_snapshot
test_rejects_missing_bait_profile
test_rejects_malformed_bait_profile_before_dry_run_output
test_dry_run_redacts_configured_bait_signing_secret
test_rejects_missing_bait_signing_secret_file
test_minted_profile_requires_bait_signing_secret_file
test_dry_run_accepts_localhost_urls

printf 'run-pwnkit-sample fixture tests passed\n'
