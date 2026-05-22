#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="$SCRIPT_DIR/check-pwnkit-runner-freshness.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-runner-freshness-test.XXXXXX"
}

write_metadata() {
  local path="$1"
  local repo_dir="$2"
  local git_dirty="$3"
  local in_sync="$4"
  local ahead="$5"
  local behind="$6"

  jq -n \
    --arg repo_dir "$repo_dir" \
    --argjson git_dirty "$git_dirty" \
    --argjson in_sync "$in_sync" \
    --argjson ahead "$ahead" \
    --argjson behind "$behind" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_codex_runner",
      pwnkit: {
        repo_dir: (if $repo_dir == "" then null else $repo_dir end),
        git_dirty: $git_dirty,
        origin_main: {
          in_sync: $in_sync,
          ahead: $ahead,
          behind: $behind
        }
      }
    }' > "$path"
}

test_accepts_synced_clean_source_checkout() {
  local dir
  dir="$(new_temp_dir)"
  write_metadata "$dir/pwnkit-runner-metadata.json" "/tmp/pwnkit" false true 0 0

  "$CHECKER" "$dir/pwnkit-runner-metadata.json"
}

test_accepts_non_source_runner_metadata() {
  local dir
  dir="$(new_temp_dir)"
  write_metadata "$dir/pwnkit-runner-metadata.json" "" true false 3 4

  "$CHECKER" "$dir/pwnkit-runner-metadata.json"
}

test_rejects_dirty_source_checkout() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_metadata "$dir/pwnkit-runner-metadata.json" "/tmp/pwnkit" true true 0 0

  output="$("$CHECKER" "$dir/pwnkit-runner-metadata.json" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'pwnkit source checkout is not fresh' <<<"$output"
  rg -q 'git_dirty=true' <<<"$output"
}

test_rejects_unsynced_source_checkout() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_metadata "$dir/pwnkit-runner-metadata.json" "/tmp/pwnkit" false false 1 2

  output="$("$CHECKER" "$dir/pwnkit-runner-metadata.json" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'origin_main.in_sync=false' <<<"$output"
  rg -q 'ahead=1 behind=2' <<<"$output"
}

test_allows_unfresh_source_when_explicitly_requested() {
  local dir
  dir="$(new_temp_dir)"
  write_metadata "$dir/pwnkit-runner-metadata.json" "/tmp/pwnkit" true false 1 0

  EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE=1 \
    "$CHECKER" "$dir/pwnkit-runner-metadata.json"
}

test_rejects_missing_metadata() {
  local output
  local status=0

  output="$("$CHECKER" "$(new_temp_dir)/missing.json" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'pwnkit runner metadata not found' <<<"$output"
}

test_accepts_synced_clean_source_checkout
test_accepts_non_source_runner_metadata
test_rejects_dirty_source_checkout
test_rejects_unsynced_source_checkout
test_allows_unfresh_source_when_explicitly_requested
test_rejects_missing_metadata

printf 'check-pwnkit-runner-freshness fixture tests passed\n'
