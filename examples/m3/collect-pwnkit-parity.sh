#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/m3/collect-pwnkit-parity.sh <upstream-current-sample.json> <local-patched-sample.json>

Compares one upstream-current pwnkit sample summary against one
local-patched canonical sample summary and emits a parity summary JSON.

Requires jq.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_file() {
  local path="$1"

  [[ -f "$path" ]] || fail "sample summary not found: $path"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ "$#" -eq 2 ]] || fail "pass exactly two sample summaries: upstream-current then local-patched"
command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"

UPSTREAM_SAMPLE="$1"
LOCAL_PATCHED_SAMPLE="$2"

require_file "$UPSTREAM_SAMPLE"
require_file "$LOCAL_PATCHED_SAMPLE"

jq -e '.evidence_tracks == ["upstream_current"]' "$UPSTREAM_SAMPLE" >/dev/null \
  || fail "first sample must be an upstream_current summary"
jq -e '.evidence_tracks == ["local_patched_pwnkit"]' "$LOCAL_PATCHED_SAMPLE" >/dev/null \
  || fail "second sample must be a local_patched_pwnkit summary"

jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg upstream_sample_path "$UPSTREAM_SAMPLE" \
  --arg local_patched_sample_path "$LOCAL_PATCHED_SAMPLE" \
  --slurpfile upstream "$UPSTREAM_SAMPLE" \
  --slurpfile local "$LOCAL_PATCHED_SAMPLE" '
  def sample_projection($sample_path; $sample):
    {
      sample_path: $sample_path,
      runner_git_head: ($sample.runner_git_heads[0] // null),
      runner_package_version: ($sample.runner_package_versions[0] // null),
      runner_pwnkit_fixture_id: (
        if ($sample.runner_pwnkit_fixture_ids | length) == 0 then
          null
        else
          ($sample.runner_pwnkit_fixture_ids[0] // null)
        end
      ),
      evidence_track: ($sample.evidence_tracks[0] // null),
      valid_summary_count: ($sample.valid_summary_count // 0),
      strongest_claim_level: ($sample.strongest_claim_level // null),
      weakest_claim_level: ($sample.weakest_claim_level // null),
      strict_stability: {
        ready_for_stability_claim: ($sample.strict_stability.ready_for_stability_claim // false),
        sample_size: ($sample.strict_stability.sample_size // 0),
        all_same_session_confirmed_bait_action: ($sample.strict_stability.all_same_session_confirmed_bait_action // false),
        all_controlled_reality_entered: ($sample.strict_stability.all_controlled_reality_entered // false),
        all_direct_quiet: ($sample.strict_stability.all_direct_quiet // false)
      },
      differential_findings: {
        ready_for_differential_finding_claim: ($sample.differential_findings.ready_for_differential_finding_claim // false),
        positive_differential_run_count: ($sample.differential_findings.positive_differential_run_count // 0),
        direct_finding_run_count: ($sample.differential_findings.direct_finding_run_count // 0),
        eidolon_finding_run_count: ($sample.differential_findings.eidolon_finding_run_count // 0),
        controlled_reality_without_eidolon_finding_run_count: ($sample.differential_findings.controlled_reality_without_eidolon_finding_run_count // 0)
      },
      counts: {
        bait_reached: ($sample.counts.bait_reached // 0),
        bait_action_observed: ($sample.counts.bait_action_observed // 0),
        same_session_confirmed_bait_action: ($sample.counts.same_session_confirmed_bait_action // 0),
        controlled_reality_entered: ($sample.counts.controlled_reality_entered // 0),
        direct_quiet: ($sample.counts.direct_quiet // 0),
        direct_findings: ($sample.counts.direct_findings // 0),
        eidolon_findings: ($sample.counts.eidolon_findings // 0),
        positive_differential_findings: ($sample.counts.positive_differential_findings // 0)
      },
      rates: {
        target_interaction_rate: ($sample.rates.target_interaction_rate // null),
        bait_reach_rate: ($sample.rates.bait_reach_rate // null),
        bait_action_rate: ($sample.rates.bait_action_rate // null),
        same_session_confirmed_bait_action_rate: ($sample.rates.same_session_confirmed_bait_action_rate // null),
        controlled_reality_entry_rate: ($sample.rates.controlled_reality_entry_rate // null),
        direct_quiet_rate: ($sample.rates.direct_quiet_rate // null),
        eidolon_finding_rate: ($sample.rates.eidolon_finding_rate // null),
        positive_differential_finding_rate: ($sample.rates.positive_differential_finding_rate // null)
      }
    };

  ($upstream[0]) as $upstream_sample
  | ($local[0]) as $local_sample
  | {
      schema_version: 1,
      generated_at: $generated_at,
      canonical_track: "local_patched_pwnkit",
      tracks: {
        upstream_current: sample_projection($upstream_sample_path; $upstream_sample),
        local_patched_pwnkit: sample_projection($local_patched_sample_path; $local_sample)
      },
      comparison: {
        upstream_matches_local_patched_stability: (
          ($upstream_sample.strict_stability.ready_for_stability_claim // false)
          and ($local_sample.strict_stability.ready_for_stability_claim // false)
        ),
        upstream_matches_local_patched_differential_findings: (
          ($upstream_sample.differential_findings.ready_for_differential_finding_claim // false)
          and ($local_sample.differential_findings.ready_for_differential_finding_claim // false)
        ),
        upstream_matches_local_patched_claim_level: (
          ($upstream_sample.weakest_claim_level // null)
          == ($local_sample.weakest_claim_level // null)
          and ($upstream_sample.strongest_claim_level // null)
          == ($local_sample.strongest_claim_level // null)
        ),
        positive_differential_run_count_delta: (
          ($local_sample.differential_findings.positive_differential_run_count // 0)
          - ($upstream_sample.differential_findings.positive_differential_run_count // 0)
        ),
        upstream_direct_finding_run_count: ($upstream_sample.differential_findings.direct_finding_run_count // 0),
        local_patched_direct_finding_run_count: ($local_sample.differential_findings.direct_finding_run_count // 0),
        parity_reproduced: (
          ($upstream_sample.strict_stability.ready_for_stability_claim // false)
          and ($local_sample.strict_stability.ready_for_stability_claim // false)
          and ($upstream_sample.differential_findings.ready_for_differential_finding_claim // false)
          and ($local_sample.differential_findings.ready_for_differential_finding_claim // false)
        ),
        parity_status: (
          if (
            ($upstream_sample.strict_stability.ready_for_stability_claim // false)
            and ($local_sample.strict_stability.ready_for_stability_claim // false)
            and ($upstream_sample.differential_findings.ready_for_differential_finding_claim // false)
            and ($local_sample.differential_findings.ready_for_differential_finding_claim // false)
          ) then
            "parity_reproduced"
          elif (
            ($upstream_sample.strict_stability.ready_for_stability_claim // false)
            and ($local_sample.strict_stability.ready_for_stability_claim // false)
          ) then
            "upstream_current_finding_gap"
          else
            "upstream_current_stability_gap"
          end
        ),
        next_question: (
          if (
            ($upstream_sample.strict_stability.ready_for_stability_claim // false)
            and ($local_sample.strict_stability.ready_for_stability_claim // false)
            and ($upstream_sample.differential_findings.ready_for_differential_finding_claim // false)
            and ($local_sample.differential_findings.ready_for_differential_finding_claim // false)
          ) then
            "parity_reproduced"
          elif (
            ($upstream_sample.strict_stability.ready_for_stability_claim // false)
            and ($local_sample.strict_stability.ready_for_stability_claim // false)
          ) then
            "why_upstream_current_still_lags_the_canonical_local_patched_track"
          else
            "why_upstream_current_does_not_match_the_canonical_local_patched_stability_contract"
          end
        )
      }
    }
  '
