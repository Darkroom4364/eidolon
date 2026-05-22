#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="$SCRIPT_DIR/check-pwnkit-sample-health.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-sample-health-test.XXXXXX"
}

write_sample() {
  local path="$1"
  local direct_count="$2"
  local eidolon_count="$3"
  local eidolon_class="${4:-codex_token_refresh_failed}"

  jq -n \
    --argjson direct_count "$direct_count" \
    --argjson eidolon_count "$eidolon_count" \
    --arg eidolon_class "$eidolon_class" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_codex_sample",
      raw_agent_error_fixture: "sensitive-refresh-detail",
      no_signal_diagnostics: {
        totals: {
          direct_pwnkit_agent_errors: $direct_count,
          eidolon_pwnkit_agent_errors: $eidolon_count
        },
        eidolon_agent_error_class_counts: (
          if $eidolon_count > 0 then
            [{error_class: $eidolon_class, count: $eidolon_count}]
          else
            []
          end
        )
      },
      artifacts: [
        {
          agent_error_diagnostics: {
            direct: {count: $direct_count},
            eidolon: {count: $eidolon_count}
          }
        }
      ]
    }' > "$path"
}

test_accepts_clean_sample() {
  local dir
  dir="$(new_temp_dir)"
  write_sample "$dir/pwnkit-stability-sample.json" 0 0

  "$CHECKER" "$dir/pwnkit-stability-sample.json"
}

test_rejects_agent_error_sample_with_sanitized_output() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_sample "$dir/pwnkit-stability-sample.json" 0 2 codex_token_refresh_failed

  output="$("$CHECKER" "$dir/pwnkit-stability-sample.json" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'pwnkit agent errors detected in sample' <<<"$output"
  rg -q 'totals: direct=0 eidolon=2' <<<"$output"
  rg -q 'eidolon classes=codex_token_refresh_failed=2' <<<"$output"
  ! rg -q 'sensitive-refresh-detail' <<<"$output"
}

test_allows_agent_errors_when_explicitly_requested() {
  local dir
  dir="$(new_temp_dir)"
  write_sample "$dir/pwnkit-stability-sample.json" 1 1

  EIDOLON_M3_ALLOW_AGENT_ERRORS=1 "$CHECKER" "$dir/pwnkit-stability-sample.json"
}

test_rejects_missing_sample() {
  local output
  local status=0

  output="$("$CHECKER" "$(new_temp_dir)/missing.json" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'pwnkit sample summary not found' <<<"$output"
}

test_accepts_clean_sample
test_rejects_agent_error_sample_with_sanitized_output
test_allows_agent_errors_when_explicitly_requested
test_rejects_missing_sample

printf 'check-pwnkit-sample-health fixture tests passed\n'
