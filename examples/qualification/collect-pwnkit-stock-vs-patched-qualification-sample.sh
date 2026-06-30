#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/qualification/collect-pwnkit-stock-vs-patched-qualification-sample.sh \
  <upstream-current-sample.json> <local-patched-sample.json> <parity.json>

Collects a stock-vs-patched scanner-qualification summary from one
upstream_current sample summary, one local_patched_pwnkit sample summary, and
their parity comparison emitted by examples/m3/collect-pwnkit-parity.sh.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "required file not found: $path"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ "$#" -eq 3 ]] || fail "pass exactly three files: upstream-current sample, local-patched sample, parity summary"
command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"

UPSTREAM_SAMPLE="$1"
LOCAL_PATCHED_SAMPLE="$2"
PARITY_FILE="$3"

require_file "$UPSTREAM_SAMPLE"
require_file "$LOCAL_PATCHED_SAMPLE"
require_file "$PARITY_FILE"

jq -e '.evidence_tracks == ["upstream_current"]' "$UPSTREAM_SAMPLE" >/dev/null \
  || fail "first sample must be an upstream_current summary"
jq -e '.evidence_tracks == ["local_patched_pwnkit"]' "$LOCAL_PATCHED_SAMPLE" >/dev/null \
  || fail "second sample must be a local_patched_pwnkit summary"
jq -e '.canonical_track == "local_patched_pwnkit"' "$PARITY_FILE" >/dev/null \
  || fail "parity summary must declare local_patched_pwnkit as the canonical track"

jq -n \
  --slurpfile upstream "$UPSTREAM_SAMPLE" \
  --slurpfile local "$LOCAL_PATCHED_SAMPLE" \
  --slurpfile parity "$PARITY_FILE" '
  def count_values($values; $label):
    $values
    | map(select(. != null and . != ""))
    | sort
    | group_by(.)
    | map({($label): .[0], count: length});

  ($upstream[0]) as $upstream_sample
  | ($local[0]) as $local_sample
  | ($parity[0]) as $parity_sample
  | (($upstream_sample.evidence_tracks // []) + ($local_sample.evidence_tracks // [])) as $combined_tracks
  | ($combined_tracks | unique) as $unique_tracks
  | {
      schema_version: 1,
      run_kind: "pwnkit_stock_vs_patched_qualification_sample",
      boundary: "scanner_qualification",
      generated_at: (now | todateiso8601),
      artifact_count: 2,
      valid_summary_count: 2,
      counts: {
        upstream_current_direct_findings: ($upstream_sample.counts.direct_findings // 0),
        local_patched_direct_findings: ($local_sample.counts.direct_findings // 0),
        upstream_current_eidolon_findings: ($upstream_sample.counts.eidolon_findings // 0),
        local_patched_eidolon_findings: ($local_sample.counts.eidolon_findings // 0),
        upstream_current_positive_differential_findings: ($upstream_sample.counts.positive_differential_findings // 0),
        local_patched_positive_differential_findings: ($local_sample.counts.positive_differential_findings // 0)
      },
      rates: {
        upstream_current_target_interaction_rate: ($upstream_sample.rates.target_interaction_rate // null),
        local_patched_target_interaction_rate: ($local_sample.rates.target_interaction_rate // null),
        upstream_current_eidolon_finding_rate: ($upstream_sample.rates.eidolon_finding_rate // null),
        local_patched_eidolon_finding_rate: ($local_sample.rates.eidolon_finding_rate // null),
        upstream_current_positive_differential_finding_rate: ($upstream_sample.rates.positive_differential_finding_rate // null),
        local_patched_positive_differential_finding_rate: ($local_sample.rates.positive_differential_finding_rate // null)
      },
      claim_level_counts: count_values(
        [
          ($upstream_sample.weakest_claim_level // null),
          ($local_sample.weakest_claim_level // null)
        ];
        "claim_level"
      ),
      weakest_claim_level: ($upstream_sample.weakest_claim_level // null),
      strongest_claim_level: ($upstream_sample.strongest_claim_level // null),
      runner_git_heads: (
        (($upstream_sample.runner_git_heads // []) + ($local_sample.runner_git_heads // []))
        | unique
      ),
      runner_package_versions: (
        (($upstream_sample.runner_package_versions // []) + ($local_sample.runner_package_versions // []))
        | unique
      ),
      runner_pwnkit_fixture_ids: (
        (($upstream_sample.runner_pwnkit_fixture_ids // []) + ($local_sample.runner_pwnkit_fixture_ids // []))
        | unique
      ),
      evidence_track_counts: count_values($combined_tracks; "evidence_track"),
      evidence_tracks: $unique_tracks,
      single_evidence_track: (($unique_tracks | length) == 1),
      mixed_evidence_tracks: (($unique_tracks | length) > 1),
      unknown_evidence_track_count: ($combined_tracks | map(select(. == "unknown")) | length),
      runner_environments: (
        (($upstream_sample.runner_environments // []) + ($local_sample.runner_environments // []))
        | unique
      ),
      runner_network_topologies: (
        (($upstream_sample.runner_network_topologies // []) + ($local_sample.runner_network_topologies // []))
        | unique
      ),
      tool_fingerprint_summary: (
        (($upstream_sample.tool_fingerprint_summary // []) + ($local_sample.tool_fingerprint_summary // []))
        | unique
      ),
      source_checkout: {
        all_runners_clean: (
          ($upstream_sample.source_checkout.all_runners_clean // false)
          and ($local_sample.source_checkout.all_runners_clean // false)
        ),
        all_runners_origin_main_synced: (
          ($upstream_sample.source_checkout.all_runners_origin_main_synced // false)
          and ($local_sample.source_checkout.all_runners_origin_main_synced // false)
        ),
        upstream_current_all_runners_clean: ($upstream_sample.source_checkout.all_runners_clean // null),
        local_patched_all_runners_clean: ($local_sample.source_checkout.all_runners_clean // null),
        upstream_current_origin_main_synced: ($upstream_sample.source_checkout.all_runners_origin_main_synced // null),
        local_patched_origin_main_synced: ($local_sample.source_checkout.all_runners_origin_main_synced // null)
      },
      no_signal_diagnostics: {
        likely_cause: ($upstream_sample.no_signal_diagnostics.likely_cause // null),
        next_question: ($parity_sample.comparison.next_question // null),
        next_questions: (
          if ($parity_sample.comparison.next_question // null) == null then
            []
          else
            [$parity_sample.comparison.next_question]
          end
        )
      },
      differential_findings: {
        ready_for_differential_finding_claim: (
          $parity_sample.comparison.upstream_matches_local_patched_differential_findings // false
        ),
        parity_reproduced: ($parity_sample.comparison.parity_reproduced // false),
        parity_status: ($parity_sample.comparison.parity_status // null),
        positive_differential_run_count_delta: (
          $parity_sample.comparison.positive_differential_run_count_delta // 0
        )
      },
      strict_stability: {
        ready_for_stability_claim: (
          $parity_sample.comparison.upstream_matches_local_patched_stability // false
        )
      },
      comparison: $parity_sample.comparison,
      tracks: $parity_sample.tracks,
      artifacts: [
        {
          artifact_id: "upstream-current",
          parity_role: "candidate",
          evidence_track: "upstream_current",
          sample_path: ($parity_sample.tracks.upstream_current.sample_path // null),
          runner_git_head: ($parity_sample.tracks.upstream_current.runner_git_head // null),
          runner_package_version: ($parity_sample.tracks.upstream_current.runner_package_version // null),
          runner_pwnkit_fixture_id: ($parity_sample.tracks.upstream_current.runner_pwnkit_fixture_id // null),
          claim_level: ($upstream_sample.weakest_claim_level // null),
          direct_finding_count: ($upstream_sample.counts.direct_findings // 0),
          eidolon_finding_count: ($upstream_sample.counts.eidolon_findings // 0),
          positive_differential_findings: ($upstream_sample.counts.positive_differential_findings // 0),
          strict_stability_ready_for_stability_claim: (
            $upstream_sample.strict_stability.ready_for_stability_claim // false
          ),
          differential_findings_ready_for_differential_finding_claim: (
            $upstream_sample.differential_findings.ready_for_differential_finding_claim // false
          )
        },
        {
          artifact_id: "local-patched",
          parity_role: "canonical",
          evidence_track: "local_patched_pwnkit",
          sample_path: ($parity_sample.tracks.local_patched_pwnkit.sample_path // null),
          runner_git_head: ($parity_sample.tracks.local_patched_pwnkit.runner_git_head // null),
          runner_package_version: ($parity_sample.tracks.local_patched_pwnkit.runner_package_version // null),
          runner_pwnkit_fixture_id: ($parity_sample.tracks.local_patched_pwnkit.runner_pwnkit_fixture_id // null),
          claim_level: ($local_sample.weakest_claim_level // null),
          direct_finding_count: ($local_sample.counts.direct_findings // 0),
          eidolon_finding_count: ($local_sample.counts.eidolon_findings // 0),
          positive_differential_findings: ($local_sample.counts.positive_differential_findings // 0),
          strict_stability_ready_for_stability_claim: (
            $local_sample.strict_stability.ready_for_stability_claim // false
          ),
          differential_findings_ready_for_differential_finding_claim: (
            $local_sample.differential_findings.ready_for_differential_finding_claim // false
          )
        }
      ]
    }
  '
