#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-parity.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-parity-collect-test.XXXXXX"
}

write_sample() {
  local output="$1"
  local evidence_track="$2"
  local git_head="$3"
  local fixture_id="$4"
  local differential_ready="$5"
  local positive_runs="$6"

  jq -n \
    --arg evidence_track "$evidence_track" \
    --arg git_head "$git_head" \
    --arg fixture_id "$fixture_id" \
    --argjson differential_ready "$differential_ready" \
    --argjson positive_runs "$positive_runs" \
    '{
      evidence_tracks: [$evidence_track],
      runner_git_heads: [$git_head],
      runner_package_versions: ["0.12.0"],
      runner_pwnkit_fixture_ids: (if $fixture_id == "" then [] else [$fixture_id] end),
      valid_summary_count: 3,
      strongest_claim_level: "controlled_reality_entered",
      weakest_claim_level: "controlled_reality_entered",
      strict_stability: {
        ready_for_stability_claim: true,
        sample_size: 3,
        all_same_session_confirmed_bait_action: true,
        all_controlled_reality_entered: true,
        all_direct_quiet: true
      },
      differential_findings: {
        ready_for_differential_finding_claim: $differential_ready,
        positive_differential_run_count: $positive_runs,
        direct_finding_run_count: 0,
        eidolon_finding_run_count: $positive_runs,
        controlled_reality_without_eidolon_finding_run_count: (3 - $positive_runs)
      },
      counts: {
        bait_reached: 3,
        bait_action_observed: 3,
        same_session_confirmed_bait_action: 3,
        controlled_reality_entered: 3,
        direct_quiet: 3,
        direct_findings: 0,
        eidolon_findings: $positive_runs,
        positive_differential_findings: $positive_runs
      },
      rates: {
        target_interaction_rate: 1,
        bait_reach_rate: 1,
        bait_action_rate: 1,
        same_session_confirmed_bait_action_rate: 1,
        controlled_reality_entry_rate: 1,
        direct_quiet_rate: 1,
        eidolon_finding_rate: ($positive_runs / 3),
        positive_differential_finding_rate: ($positive_runs / 3)
      }
    }' > "$output"
}

test_emits_parity_reproduced_when_both_tracks_are_ready() {
  local dir upstream local output

  dir="$(new_temp_dir)"
  upstream="$dir/upstream.json"
  local="$dir/local.json"
  output="$dir/parity.json"

  write_sample "$upstream" upstream_current c644108 "" true 3
  write_sample "$local" local_patched_pwnkit abd034b eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02 true 3

  "$COLLECTOR" "$upstream" "$local" > "$output"

  jq -e '.comparison.parity_status == "parity_reproduced"' "$output" >/dev/null
  jq -e '.comparison.parity_reproduced == true' "$output" >/dev/null
  jq -e '.comparison.positive_differential_run_count_delta == 0' "$output" >/dev/null
}

test_emits_upstream_current_finding_gap_when_only_local_track_is_ready() {
  local dir upstream local output

  dir="$(new_temp_dir)"
  upstream="$dir/upstream.json"
  local="$dir/local.json"
  output="$dir/parity.json"

  write_sample "$upstream" upstream_current c644108 "" false 2
  write_sample "$local" local_patched_pwnkit abd034b eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02 true 3

  "$COLLECTOR" "$upstream" "$local" > "$output"

  jq -e '.comparison.parity_status == "upstream_current_finding_gap"' "$output" >/dev/null
  jq -e '.comparison.next_question == "why_upstream_current_still_lags_the_canonical_local_patched_track"' "$output" >/dev/null
  jq -e '.comparison.positive_differential_run_count_delta == 1' "$output" >/dev/null
}

test_rejects_wrong_track_order() {
  local dir upstream local output status=0

  dir="$(new_temp_dir)"
  upstream="$dir/upstream.json"
  local="$dir/local.json"
  output="$dir/parity.json"

  write_sample "$upstream" local_patched_pwnkit abd034b eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02 true 3
  write_sample "$local" upstream_current c644108 "" false 2

  "$COLLECTOR" "$upstream" "$local" > "$output" 2>"$dir/stderr" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'first sample must be an upstream_current summary' "$dir/stderr"
}

test_emits_parity_reproduced_when_both_tracks_are_ready
test_emits_upstream_current_finding_gap_when_only_local_track_is_ready
test_rejects_wrong_track_order

printf 'collect-pwnkit-parity fixture tests passed\n'
