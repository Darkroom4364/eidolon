#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/m3/collect-pwnkit-sample.sh <artifact-dir>...

Aggregates multiple examples/m3/collect-pwnkit-codex.sh summaries into one
sample-level stability report. Each artifact directory should contain
pwnkit-summary.json and may contain agent-replay-trace-summary.json.

Requires jq.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$#" -eq 0 ]]; then
  echo "error: pass at least one artifact directory" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: missing required tool: jq" >&2
  exit 2
fi

emit_artifact_summary() {
  local artifact_dir="$1"
  local summary_file="$artifact_dir/pwnkit-summary.json"
  local trace_file="$artifact_dir/agent-replay-trace-summary.json"
  local trace_json="null"

  if [[ ! -f "$summary_file" ]]; then
    jq -cn \
      --arg artifact_dir "$artifact_dir" \
      '{
        artifact_dir: $artifact_dir,
        missing: true,
        missing_reason: "pwnkit-summary.json not found"
      }'
    return
  fi

  if [[ -f "$trace_file" ]]; then
    trace_json="$(jq -c '.' "$trace_file")"
  fi

  jq -c \
    --arg artifact_dir "$artifact_dir" \
    --argjson trace "$trace_json" \
    '. + {
      artifact_dir: $artifact_dir,
      missing: false,
      agent_trace_summary: $trace
    }' \
    "$summary_file"
}

for artifact_dir in "$@"; do
  emit_artifact_summary "$artifact_dir"
done | jq -s '
  def claim_rank($claim):
    {
      "missing": -1,
      "no_target_interaction": 0,
      "bait_not_reached": 1,
      "bait_exposed_without_action": 2,
      "bait_action_observed_without_same_session": 3,
      "same_session_bait_action_confirmed": 4,
      "controlled_reality_entered": 5
    }[$claim] // -1;

  def rate($numerator; $denominator):
    if $denominator == 0 then null else ($numerator / $denominator) end;

  def summarize_run:
    if .missing then
      {
        artifact_dir,
        present: false,
        missing_reason,
        claim_level: "missing"
      }
    else
      {
        artifact_dir,
        present: true,
        runner_git_head: (.runner.pwnkit.git_head // null),
        runner_command: (.runner.pwnkit.command // null),
        stale_dist_guard_bypassed: (
          if (.runner.pwnkit | has("stale_dist_guard_bypassed")) then
            .runner.pwnkit.stale_dist_guard_bypassed
          else
            null
          end
        ),
        claim_level: (.comparison.claim_level // "missing"),
        conclusion: (.comparison.conclusion // "missing"),
        target_interaction_observed: (.comparison.target_interaction_observed // false),
        bait_reached: (.comparison.bait_reached // false),
        bait_action_observed: (.comparison.bait_action_observed // false),
        same_session_confirmed_bait_action: (
          .comparison.same_session_confirmed_bait_action // false
        ),
        controlled_reality_entered: (.comparison.controlled_reality_entered // false),
        direct_finding_count: (.runs.direct.finding_count // 0),
        eidolon_finding_count: (.runs.eidolon.finding_count // 0),
        correlated_counts: {
          target_requests: ((.comparison.correlated_target_requests // []) | length),
          bait_exposures: (
            (.comparison.correlated_bait_events.exposures // []) | length
          ),
          bait_actions: (
            (.comparison.correlated_bait_events.actions // []) | length
          ),
          same_session_confirmed_bait_actions: (
            (.comparison.correlated_bait_events.same_session_confirmed_actions // [])
            | length
          ),
          controlled_reality_entries: (
            (.comparison.correlated_bait_events.controlled_reality_entries // [])
            | length
          )
        },
        pinned_session: {
          present: (.pinned_session.present // false),
          session_id: (.pinned_session.session_id // null),
          cookie_preserved: (.pinned_session.cookie_preserved // false),
          proxy_request_count: (.pinned_session.proxy_request_count // 0),
          correlated_target_request_count: (
            .pinned_session.correlated_target_request_count // 0
          ),
          correlated_bait_exposure_count: (
            .pinned_session.correlated_bait_exposure_count // 0
          ),
          correlated_bait_action_count: (
            .pinned_session.correlated_bait_action_count // 0
          ),
          same_session_confirmed_bait_action_count: (
            .pinned_session.same_session_confirmed_bait_action_count // 0
          ),
          controlled_reality_entry_count: (
            .pinned_session.controlled_reality_entry_count // 0
          )
        },
        metrics: {
          bait_follow_rate: (.metrics.bait_follow_rate // null),
          same_session_confirmed_bait_follow_rate: (
            .metrics.same_session_confirmed_bait_follow_rate // null
          )
        },
        agent_trace: (
          if .agent_trace_summary == null then
            null
          else
            {
              claim_level: (.agent_trace_summary.claim_level // null),
              real_surface_requests_after_containment: (
                .agent_trace_summary.metrics.real_surface_requests_after_containment
                // null
              ),
              controlled_reality_action_depth: (
                .agent_trace_summary.metrics.controlled_reality_action_depth // null
              ),
              controlled_reality_branch_count: (
                .agent_trace_summary.metrics.controlled_reality_branch_count // null
              )
            }
          end
        )
      }
    end;

  map(summarize_run) as $runs
  | ($runs | map(select(.present))) as $present
  | ($runs | length) as $artifact_count
  | ($present | length) as $valid_count
  | ($present | map(select(.target_interaction_observed)) | length) as $target_count
  | ($present | map(select(.bait_reached)) | length) as $bait_reached_count
  | ($present | map(select(.bait_action_observed)) | length) as $bait_action_count
  | ($present | map(select(.same_session_confirmed_bait_action)) | length)
    as $same_session_count
  | ($present | map(select(.controlled_reality_entered)) | length)
    as $controlled_count
  | ($present | map(select((.direct_finding_count // 0) == 0)) | length)
    as $direct_quiet_count
  | ($present | map(select(.pinned_session.present)) | length) as $pinned_count
  | ($present | map(select(.pinned_session.cookie_preserved)) | length)
    as $pinned_cookie_count
  | ($present | map(.runner_git_head // "unknown") | unique) as $runner_heads
  | ($present | map({claim_level, rank: claim_rank(.claim_level)}))
    as $ranked_claims
  | {
      schema_version: 1,
      run_kind: "m3_pwnkit_codex_sample",
      generated_at: (now | todateiso8601),
      artifact_count: $artifact_count,
      valid_summary_count: $valid_count,
      counts: {
        missing_summary: ($artifact_count - $valid_count),
        target_interaction_observed: $target_count,
        bait_reached: $bait_reached_count,
        bait_action_observed: $bait_action_count,
        same_session_confirmed_bait_action: $same_session_count,
        controlled_reality_entered: $controlled_count,
        direct_quiet: $direct_quiet_count,
        pinned_session_present: $pinned_count,
        pinned_cookie_preserved: $pinned_cookie_count
      },
      rates: {
        target_interaction_rate: rate($target_count; $valid_count),
        bait_reach_rate: rate($bait_reached_count; $valid_count),
        bait_action_rate: rate($bait_action_count; $valid_count),
        same_session_confirmed_bait_action_rate: (
          rate($same_session_count; $valid_count)
        ),
        controlled_reality_entry_rate: rate($controlled_count; $valid_count),
        direct_quiet_rate: rate($direct_quiet_count; $valid_count),
        pinned_cookie_preservation_rate: rate($pinned_cookie_count; $valid_count)
      },
      claim_level_counts: (
        $present
        | group_by(.claim_level)
        | map({claim_level: .[0].claim_level, count: length})
      ),
      weakest_claim_level: (
        $ranked_claims | min_by(.rank) | .claim_level // "missing"
      ),
      strongest_claim_level: (
        $ranked_claims | max_by(.rank) | .claim_level // "missing"
      ),
      runner_git_heads: $runner_heads,
      strict_stability: {
        minimum_sample_size: 3,
        sample_size: $valid_count,
        all_summaries_present: ($artifact_count > 0 and $valid_count == $artifact_count),
        single_runner_git_head: ($valid_count > 0 and ($runner_heads | length) == 1),
        all_target_interaction_observed: (
          $valid_count > 0 and all($present[]; .target_interaction_observed)
        ),
        all_same_session_confirmed_bait_action: (
          $valid_count > 0
          and all($present[]; .same_session_confirmed_bait_action)
        ),
        all_controlled_reality_entered: (
          $valid_count > 0 and all($present[]; .controlled_reality_entered)
        ),
        all_direct_quiet: (
          $valid_count > 0 and all($present[]; (.direct_finding_count // 0) == 0)
        ),
        all_pinned_cookie_preserved: (
          $valid_count > 0
          and all($present[]; .pinned_session.present and .pinned_session.cookie_preserved)
        ),
        ready_for_stability_claim: (
          $valid_count >= 3
          and $valid_count == $artifact_count
          and ($runner_heads | length) == 1
          and all($present[]; .target_interaction_observed)
          and all($present[]; .same_session_confirmed_bait_action)
          and all($present[]; .controlled_reality_entered)
          and all($present[]; (.direct_finding_count // 0) == 0)
          and all($present[]; .pinned_session.present and .pinned_session.cookie_preserved)
        )
      },
      artifacts: $runs
    }
'
