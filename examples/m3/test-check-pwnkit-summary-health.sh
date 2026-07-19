#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="$SCRIPT_DIR/check-pwnkit-summary-health.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-summary-health-test.XXXXXX"
}

write_summary() {
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
      run_kind: "m3_pwnkit_codex_comparison",
      raw_agent_error_fixture: "sensitive-refresh-detail",
      runs: {
        direct: {
          artifact_status: "present",
          agent_error_diagnostics: {
            count: $direct_count,
            class_counts: (
              if $direct_count > 0 then
                [{error_class: "agent_api_error", count: $direct_count}]
              else
                []
              end
            )
          }
        },
        eidolon: {
          artifact_status: "present",
          agent_error_diagnostics: {
            count: $eidolon_count,
            class_counts: (
              if $eidolon_count > 0 then
                [{error_class: $eidolon_class, count: $eidolon_count}]
              else
                []
              end
            )
          }
        }
      }
    }' > "$path"
}

test_accepts_clean_summary() {
  local dir
  dir="$(new_temp_dir)"
  write_summary "$dir/pwnkit-summary.json" 0 0

  "$CHECKER" "$dir/pwnkit-summary.json"
}

test_rejects_agent_error_summary_with_sanitized_output() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_summary "$dir/pwnkit-summary.json" 0 2 codex_token_refresh_failed

  output="$("$CHECKER" "$dir/pwnkit-summary.json" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'pwnkit agent errors detected' <<<"$output"
  rg -q 'eidolon: count=2 classes=codex_token_refresh_failed=2' <<<"$output"
  ! rg -q 'sensitive-refresh-detail' <<<"$output"
}

test_allows_agent_errors_when_explicitly_requested() {
  local dir
  dir="$(new_temp_dir)"
  write_summary "$dir/pwnkit-summary.json" 1 1

  EIDOLON_M3_ALLOW_AGENT_ERRORS=1 "$CHECKER" "$dir/pwnkit-summary.json"
}

test_accepts_clean_execution_contract() {
  local dir
  dir="$(new_temp_dir)"
  write_summary "$dir/pwnkit-summary.json" 0 0
  jq '
    .runs.direct.execution_contract = {result_class: "pass", reason_codes: []}
    | .runs.eidolon.execution_contract = {result_class: "pass", reason_codes: []}
  ' "$dir/pwnkit-summary.json" > "$dir/pwnkit-summary.json.tmp"
  mv "$dir/pwnkit-summary.json.tmp" "$dir/pwnkit-summary.json"

  "$CHECKER" "$dir/pwnkit-summary.json"
}

test_accepts_recovered_transient_retry() {
  local dir
  dir="$(new_temp_dir)"
  write_summary "$dir/pwnkit-summary.json" 0 0
  jq '
    .runs.direct.execution_contract = {result_class: "pass", reason_codes: []}
    | .runs.eidolon.execution_contract = {result_class: "pass", reason_codes: []}
    | .runs.eidolon.agent_error_diagnostics = {
        event_count: 1,
        count: 0,
        terminal_count: 0,
        recovered_transient_count: 1,
        class_counts: [{error_class: "recovered_transient_retry", count: 1}],
        terminal_class_counts: []
      }
  ' "$dir/pwnkit-summary.json" > "$dir/pwnkit-summary.json.tmp"
  mv "$dir/pwnkit-summary.json.tmp" "$dir/pwnkit-summary.json"

  "$CHECKER" "$dir/pwnkit-summary.json"
}

test_rejects_inconclusive_execution_contract() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_summary "$dir/pwnkit-summary.json" 0 0
  jq '
    .runs.direct.execution_contract = {result_class: "pass", reason_codes: []}
    | .runs.eidolon.execution_contract = {
        result_class: "inconclusive",
        reason_codes: [
          "nonterminal_agent_session",
          "missing_scan_complete_event"
        ]
      }
  ' "$dir/pwnkit-summary.json" > "$dir/pwnkit-summary.json.tmp"
  mv "$dir/pwnkit-summary.json.tmp" "$dir/pwnkit-summary.json"

  output="$("$CHECKER" "$dir/pwnkit-summary.json" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'execution contract is not clean' <<<"$output"
  rg -q 'eidolon: result=inconclusive' <<<"$output"
  rg -q 'nonterminal_agent_session' <<<"$output"
  rg -q 'missing_scan_complete_event' <<<"$output"
}

test_rejects_missing_leg_artifacts_even_when_agent_errors_allowed() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_summary "$dir/pwnkit-summary.json" 0 0
  jq '
    .runs.direct.artifact_status = "missing"
    | del(.runs.eidolon.artifact_status)
  ' "$dir/pwnkit-summary.json" > "$dir/pwnkit-summary.json.tmp"
  mv "$dir/pwnkit-summary.json.tmp" "$dir/pwnkit-summary.json"

  output="$(
    EIDOLON_M3_ALLOW_AGENT_ERRORS=1 \
      "$CHECKER" "$dir/pwnkit-summary.json" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'missing required leg artifacts' <<<"$output"
  rg -q 'direct=missing' <<<"$output"
  rg -q 'eidolon=missing' <<<"$output"
  ! rg -q 'sensitive-refresh-detail' <<<"$output"
}

test_rejects_missing_summary() {
  local output
  local status=0

  output="$("$CHECKER" "$(new_temp_dir)/missing.json" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'pwnkit summary not found' <<<"$output"
}

test_accepts_clean_summary
test_rejects_agent_error_summary_with_sanitized_output
test_allows_agent_errors_when_explicitly_requested
test_accepts_clean_execution_contract
test_accepts_recovered_transient_retry
test_rejects_inconclusive_execution_contract
test_rejects_missing_leg_artifacts_even_when_agent_errors_allowed
test_rejects_missing_summary

printf 'check-pwnkit-summary-health fixture tests passed\n'
