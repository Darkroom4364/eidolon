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
      evidence_tracks: ["upstream_current"],
      single_evidence_track: true,
      mixed_evidence_tracks: false,
      unknown_evidence_track_count: 0,
      counts: {
        positive_differential_findings: 0
      },
      rates: {
        positive_differential_finding_rate: 0
      },
      finding_reconciliation: {
        direct_final_json_finding_total: 0,
        eidolon_final_json_finding_total: 0,
        direct_db_saved_finding_total: 0,
        eidolon_db_saved_finding_total: 0,
        final_json_counts_still_drive_finding_claims: true
      },
      differential_findings: {
        ready_for_differential_finding_claim: false
      },
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
          evidence_track: "upstream_current",
          present: true,
          direct_final_json_finding_count: 0,
          eidolon_final_json_finding_count: 0,
          finding_gap: {
            positive_differential_findings: false
          },
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

  [[ "$status" -eq 1 ]] || return 1
  rg -q 'pwnkit agent errors detected in sample' <<<"$output"
  rg -q 'totals: direct=0 eidolon=2' <<<"$output"
  rg -q 'eidolon classes=codex_token_refresh_failed=2' <<<"$output"
  ! rg -q 'sensitive-refresh-detail' <<<"$output" || return 1
}

test_redacts_unknown_agent_error_class() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_sample "$dir/pwnkit-stability-sample.json" 0 2 EIDOLON_HEALTH_SECRET_228

  output="$("$CHECKER" "$dir/pwnkit-stability-sample.json" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]] || return 1
  rg -q 'eidolon classes=redacted_unknown=2' <<<"$output"
  ! rg -q 'EIDOLON_HEALTH_SECRET_228' <<<"$output" || return 1
}

test_allows_agent_errors_when_explicitly_requested() {
  local dir
  dir="$(new_temp_dir)"
  write_sample "$dir/pwnkit-stability-sample.json" 1 1

  EIDOLON_M3_ALLOW_AGENT_ERRORS=1 "$CHECKER" "$dir/pwnkit-stability-sample.json"
}

test_rejects_mixed_evidence_tracks_even_when_agent_errors_allowed() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_sample "$dir/pwnkit-stability-sample.json" 1 1
  jq '
    .evidence_tracks = ["upstream_current", "local_patched_pwnkit"]
    | .single_evidence_track = false
    | .mixed_evidence_tracks = true
    | .artifacts += [
        {
          evidence_track: "local_patched_pwnkit",
          present: true,
          direct_final_json_finding_count: 0,
          eidolon_final_json_finding_count: 0,
          finding_gap: {positive_differential_findings: false},
          agent_error_diagnostics: {
            direct: {count: 0},
            eidolon: {count: 0}
          }
        }
      ]
  ' "$dir/pwnkit-stability-sample.json" > "$dir/sample.tmp"
  mv "$dir/sample.tmp" "$dir/pwnkit-stability-sample.json"

  output="$(
    EIDOLON_M3_ALLOW_AGENT_ERRORS=1 \
      "$CHECKER" "$dir/pwnkit-stability-sample.json" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]] || return 1
  rg -q 'evidence tracks are not claim-safe' <<<"$output"
  rg -q 'mixed_upstream_and_patched=true' <<<"$output"
}

test_rejects_db_only_positive_finding_claim() {
  local dir
  local output
  local status=0
  dir="$(new_temp_dir)"
  write_sample "$dir/pwnkit-stability-sample.json" 0 0
  jq '
    .counts.positive_differential_findings = 1
    | .finding_reconciliation.eidolon_db_saved_finding_total = 1
    | .finding_reconciliation.eidolon_db_active_finding_total = 1
    | .finding_reconciliation.any_db_saved_findings_omitted_from_final_json = true
    | .artifacts[0].eidolon_db_saved_finding_count = 1
    | .artifacts[0].eidolon_db_active_finding_count = 1
    | .artifacts[0].finding_gap.positive_differential_findings = true
  ' "$dir/pwnkit-stability-sample.json" > "$dir/sample.tmp"
  mv "$dir/sample.tmp" "$dir/pwnkit-stability-sample.json"

  output="$("$CHECKER" "$dir/pwnkit-stability-sample.json" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]] || return 1
  rg -q 'infers finding claims without final JSON support' <<<"$output"
  rg -q 'positive_differential_count_without_final_json_delta' <<<"$output"
}

test_rejects_missing_sample() {
  local output
  local status=0

  output="$("$CHECKER" "$(new_temp_dir)/missing.json" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]] || return 1
  rg -q 'pwnkit sample summary not found' <<<"$output"
}

test_accepts_clean_sample
test_rejects_agent_error_sample_with_sanitized_output
test_redacts_unknown_agent_error_class
test_allows_agent_errors_when_explicitly_requested
test_rejects_mixed_evidence_tracks_even_when_agent_errors_allowed
test_rejects_db_only_positive_finding_claim
test_rejects_missing_sample

printf 'check-pwnkit-sample-health fixture tests passed\n'
