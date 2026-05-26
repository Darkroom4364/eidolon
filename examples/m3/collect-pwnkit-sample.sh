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

  def count_values($values):
    $values
    | map(select(. != null and . != ""))
    | sort
    | group_by(.)
    | map({value: .[0], count: length});

  def merge_value_counts($entries; $key_name):
    $entries
    | sort_by(.value)
    | group_by(.value)
    | map({($key_name): .[0].value, count: (map(.count) | add)});

  def no_signal_likely_cause(
    $valid_count;
    $no_target_count;
    $request_artifacts;
    $proxy_requests;
    $agent_errors;
    $token_refresh_failures;
    $backend_timeouts
  ):
    if $valid_count == 0 then
      "no_valid_summaries"
    elif $no_target_count < $valid_count then
      null
    elif $request_artifacts == 0 and $token_refresh_failures > 0 then
      "pwnkit_codex_token_refresh_failure_prevented_request_artifacts"
    elif $request_artifacts == 0 and $backend_timeouts > 0 then
      "pwnkit_codex_backend_timeout_prevented_request_artifacts"
    elif $request_artifacts == 0 and $agent_errors > 0 then
      "pwnkit_agent_errors_prevented_request_artifacts"
    elif $request_artifacts == 0 and $proxy_requests == 0 then
      "no_pwnkit_request_artifacts_and_no_proxy_requests"
    elif $request_artifacts == 0 and $proxy_requests > 0 then
      "eidolon_proxy_saw_uncorrelated_requests_but_pwnkit_emitted_no_request_artifacts"
    elif $request_artifacts > 0 and $proxy_requests == 0 then
      "pwnkit_emitted_request_artifacts_but_eidolon_proxy_saw_no_requests"
    else
      "pwnkit_request_artifacts_and_proxy_requests_did_not_correlate"
    end;

  def no_signal_next_questions(
    $request_artifacts;
    $proxy_requests;
    $pinned_without_cookie_count;
    $agent_errors;
    $token_refresh_failures;
    $backend_timeouts
  ):
    if $request_artifacts == 0 and $token_refresh_failures > 0 then
      [
        "refresh_pwnkit_codex_auth_before_rerun",
        "rerun_matrix_after_agent_error_free_scan"
      ]
    elif $request_artifacts == 0 and $backend_timeouts > 0 then
      [
        "rerun_after_codex_backend_timeout",
        "rerun_matrix_after_agent_error_free_scan"
      ]
    elif $request_artifacts == 0 and $agent_errors > 0 then
      [
        "inspect_sanitized_pwnkit_agent_error_classes",
        "rerun_matrix_after_agent_error_free_scan"
      ]
    elif $request_artifacts == 0 and $proxy_requests > 0 then
      ([
        "why_pwnkit_emitted_no_request_artifacts",
        "which_runner_or_probe_generated_uncorrelated_proxy_requests"
      ] + (
        if $pinned_without_cookie_count > 0 then
          ["why_pinned_session_cookie_was_not_reused_by_pwnkit"]
        else
          []
        end
      ))
    elif $request_artifacts == 0 then
      [
        "why_pwnkit_emitted_no_request_artifacts",
        "whether_updated_pwnkit_changed_tool_artifact_persistence"
      ]
    elif $proxy_requests == 0 then
      [
        "why_eidolon_proxy_saw_no_requests",
        "whether_pwnkit_bypassed_the_proxy_target"
      ]
    else
      [
        "whether_timestamp_or_path_correlation_window_is_too_strict",
        "whether_pwnkit_request_artifacts_match_proxy_request_shape"
      ]
    end;

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
        runner_package_version: (.runner.pwnkit.package_version // null),
        runner_git_dirty: (
          if (.runner.pwnkit | has("git_dirty")) then
            .runner.pwnkit.git_dirty
          else
            null
          end
        ),
        runner_origin_main: (.runner.pwnkit.origin_main // null),
        runner_origin_main_in_sync: (
          if ((.runner.pwnkit.origin_main // {}) | has("in_sync")) then
            .runner.pwnkit.origin_main.in_sync
          else
            null
          end
        ),
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
        finding_diagnostics: {
          direct: (.runs.direct.finding_diagnostics // null),
          eidolon: (.runs.eidolon.finding_diagnostics // null)
        },
        pwnkit_events: {
          direct: (.runs.direct.pwnkit_events // null),
          eidolon: (.runs.eidolon.pwnkit_events // null)
        },
        target_evidence_diagnostics: {
          direct: (.runs.direct.target_evidence_diagnostics // null),
          eidolon: (.runs.eidolon.target_evidence_diagnostics // null)
        },
        agent_error_diagnostics: {
          direct: (.runs.direct.agent_error_diagnostics // null),
          eidolon: (.runs.eidolon.agent_error_diagnostics // null)
        },
        eidolon_proxy: {
          present: (.eidolon_proxy.present // false),
          request_count: (.eidolon_proxy.request_count // 0),
          protected_upstream_request_count: (
            .eidolon_proxy.counts.protected_upstream_requests // 0
          ),
          bait_exposure_count: (.eidolon_proxy.counts.bait_exposures // 0),
          bait_action_count: (.eidolon_proxy.counts.bait_actions // 0),
          controlled_reality_entry_count: (
            .eidolon_proxy.counts.controlled_reality_entries // 0
          ),
          kind_counts: (.eidolon_proxy.kind_counts // []),
          routing_counts: (.eidolon_proxy.routing_counts // []),
          request_path_counts: count_values(
            (.eidolon_proxy.request_paths // []) | map(.path // null)
          )
        },
        target_correlation_diagnostics: (
          .comparison.target_correlation_diagnostics // (
            (.runs.eidolon.pwnkit_events.tool_artifacts // 0) as $tool_artifacts
            | (.runs.eidolon.target_evidence_diagnostics.request_artifact_count // 0)
              as $request_artifacts
            | (.eidolon_proxy.request_count // 0) as $proxy_requests
            | ((.comparison.correlated_target_requests // []) | length)
              as $correlated_requests
            | (.runs.eidolon.agent_error_diagnostics.count // 0) as $agent_errors
            | (
                if (.runs.eidolon.agent_error_diagnostics.has_codex_token_refresh_failure // false) then
                  1
                else
                  0
                end
              ) as $token_refresh_failures
            | (
                if (
                  (.runs.eidolon.agent_error_diagnostics.has_codex_backend_api_error // false)
                  or any(
                    .runs.eidolon.agent_error_diagnostics.class_counts[]?;
                    .error_class == "codex_backend_timeout"
                    or .error_class == "codex_backend_api_error"
                  )
                ) then
                  1
                else
                  0
                end
              ) as $backend_errors
            | {
                pwnkit_eidolon_tool_artifact_count: $tool_artifacts,
                pwnkit_eidolon_request_artifact_count: $request_artifacts,
                pwnkit_eidolon_agent_error_count: $agent_errors,
                pwnkit_eidolon_agent_error_classes: (
                  .runs.eidolon.agent_error_diagnostics.class_counts // []
                ),
                eidolon_proxy_request_count: $proxy_requests,
                correlated_target_request_count: $correlated_requests,
                uncorrelated_proxy_request_count: (
                  if $proxy_requests > $correlated_requests then
                    $proxy_requests - $correlated_requests
                  else
                    0
                  end
                ),
                likely_cause: (
                  if $correlated_requests > 0 then
                    "correlated_target_interaction_observed"
                  else
                    no_signal_likely_cause(
                      1;
                      1;
                      $request_artifacts;
                      $proxy_requests;
                      $agent_errors;
                      $token_refresh_failures;
                      $backend_errors
                    )
                  end
                ),
                next_questions: (
                  if $correlated_requests > 0 then
                    []
                  else
                    no_signal_next_questions(
                      $request_artifacts;
                      $proxy_requests;
                      if .pinned_session.present and (.pinned_session.cookie_preserved | not) then
                        1
                      else
                        0
                      end;
                      $agent_errors;
                      $token_refresh_failures;
                      $backend_errors
                    )
                  end
                )
              }
          )
        ),
        finding_gap: (
          .comparison.finding_gap // {
            direct_finding_count: (.runs.direct.finding_count // 0),
            eidolon_finding_count: (.runs.eidolon.finding_count // 0),
            differential_finding_count: (
              (.runs.eidolon.finding_count // 0) - (.runs.direct.finding_count // 0)
            ),
            positive_differential_findings: (
              (.runs.eidolon.finding_count // 0) > (.runs.direct.finding_count // 0)
            ),
            direct_quiet: ((.runs.direct.finding_count // 0) == 0),
            eidolon_has_findings: ((.runs.eidolon.finding_count // 0) > 0),
            eidolon_observed_target_evidence_without_findings: false,
            eidolon_bait_reached_without_findings: (
              (.runs.eidolon.finding_count // 0) == 0 and (.comparison.bait_reached // false)
            ),
            eidolon_bait_action_without_findings: (
              (.runs.eidolon.finding_count // 0) == 0
              and (.comparison.bait_action_observed // false)
            ),
            eidolon_controlled_reality_without_findings: (
              (.runs.eidolon.finding_count // 0) == 0
              and (.comparison.controlled_reality_entered // false)
            ),
            next_question: null
          }
        ),
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
        ),
        trace_gap: (
          (.agent_trace_summary.claim_level // null) as $trace_claim
          | (.comparison.claim_level // "missing") as $strict_claim
          | (.comparison.controlled_reality_entered // false) as $strict_controlled
          | (.comparison.same_session_confirmed_bait_action // false) as $strict_same_session
          | (.runs.eidolon.finding_count // 0) as $eidolon_findings
          | (
              (.agent_trace_summary.metrics.real_surface_requests_after_containment // null)
            ) as $real_surface_after_containment
          | ($trace_claim == "controlled_reality_entered") as $trace_controlled
          | {
              proxy_trace_present: (.agent_trace_summary != null),
              proxy_trace_claim_level: $trace_claim,
              proxy_trace_controlled_reality_entered: $trace_controlled,
              proxy_trace_real_surface_quiet: (
                $trace_controlled and $real_surface_after_containment == 0
              ),
              pwnkit_strict_claim_level: $strict_claim,
              pwnkit_strict_same_session_confirmed: $strict_same_session,
              pwnkit_strict_controlled_reality_entered: $strict_controlled,
              proxy_trace_controlled_reality_without_strict_confirmation: (
                $trace_controlled and ($strict_controlled | not)
              ),
              strict_controlled_reality_without_eidolon_finding: (
                $strict_controlled and $eidolon_findings == 0
              ),
              positive_differential_without_strict_controlled_reality: (
                ((.comparison.finding_gap.positive_differential_findings // false) == true)
                and ($strict_controlled | not)
              ),
              next_question: (
                if $trace_controlled and ($strict_controlled | not) then
                  "why_proxy_trace_containment_was_not_confirmed_by_strict_pwnkit_correlation"
                elif $strict_controlled and $eidolon_findings == 0 then
                  "why_controlled_reality_chain_was_not_promoted_to_finding"
                elif (
                  ((.comparison.finding_gap.positive_differential_findings // false) == true)
                  and ($strict_controlled | not)
                ) then
                  "why_findings_emerged_without_strict_controlled_reality_confirmation"
                else
                  null
                end
              )
            }
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
  | ($present | map(select((.direct_finding_count // 0) > 0)) | length)
    as $direct_findings_count
  | ($present | map(select((.eidolon_finding_count // 0) > 0)) | length)
    as $eidolon_findings_count
  | ($present | map(select(.finding_gap.positive_differential_findings)) | length)
    as $positive_differential_count
  | ($present | map(select(.finding_gap.eidolon_bait_reached_without_findings)) | length)
    as $bait_reached_without_findings_count
  | ($present | map(select(.finding_gap.eidolon_bait_action_without_findings)) | length)
    as $bait_action_without_findings_count
  | ($present | map(select(.finding_gap.eidolon_controlled_reality_without_findings)) | length)
    as $controlled_without_findings_count
  | ($present | map(select(.pinned_session.present)) | length) as $pinned_count
  | ($present | map(select(.pinned_session.cookie_preserved)) | length)
    as $pinned_cookie_count
  | ($present | map(.runner_git_head // "unknown") | unique) as $runner_heads
  | ($present | map(.runner_package_version // "unknown") | unique) as $runner_versions
  | ($present | map(select(.runner_git_dirty == false)) | length)
    as $clean_runner_count
  | ($present | map(select(.runner_git_dirty == true)) | length)
    as $dirty_runner_count
  | ($present | map(select(.runner_git_dirty == null)) | length)
    as $unknown_dirty_runner_count
  | ($present | map(select(.runner_origin_main_in_sync == true)) | length)
    as $origin_synced_count
  | ($present | map(select(.runner_origin_main_in_sync == false)) | length)
    as $origin_drifted_count
  | ($present | map(select(.runner_origin_main_in_sync == null)) | length)
    as $unknown_origin_sync_count
  | ($present | map({claim_level, rank: claim_rank(.claim_level)}))
    as $ranked_claims
  | ($valid_count - $target_count) as $no_target_count
  | ($present | map(.pwnkit_events.direct.tool_artifacts // 0) | add // 0)
    as $direct_tool_artifact_total
  | ($present | map(.pwnkit_events.eidolon.tool_artifacts // 0) | add // 0)
    as $eidolon_tool_artifact_total
  | ($present | map(.agent_error_diagnostics.direct.count // 0) | add // 0)
    as $direct_agent_error_total
  | ($present | map(.agent_error_diagnostics.eidolon.count // 0) | add // 0)
    as $eidolon_agent_error_total
  | ($present | map(.target_evidence_diagnostics.direct.request_artifact_count // 0) | add // 0)
    as $direct_request_artifact_total
  | (
      $present
      | map(
          .target_evidence_diagnostics.eidolon.request_artifact_count
          // .target_correlation_diagnostics.pwnkit_eidolon_request_artifact_count
          // 0
        )
      | add // 0
    ) as $eidolon_request_artifact_total
  | ($present | map(.eidolon_proxy.request_count // 0) | add // 0)
    as $eidolon_proxy_request_total
  | ($present | map(.correlated_counts.target_requests // 0) | add // 0)
    as $correlated_target_request_total
  | (
      $present
      | map(
          select(
            (
              .target_evidence_diagnostics.eidolon.request_artifact_count
              // .target_correlation_diagnostics.pwnkit_eidolon_request_artifact_count
              // 0
            ) > 0
          )
        )
      | length
    ) as $runs_with_eidolon_request_artifacts
  | ($present | map(select((.eidolon_proxy.request_count // 0) > 0)) | length)
    as $runs_with_eidolon_proxy_requests
  | (
      $present
      | map(
          select(
            (.eidolon_proxy.request_count // 0) > 0
            and (
              (
                .target_evidence_diagnostics.eidolon.request_artifact_count
                // .target_correlation_diagnostics.pwnkit_eidolon_request_artifact_count
                // 0
              ) == 0
            )
          )
        )
      | length
    ) as $runs_with_proxy_requests_but_no_pwnkit_request_artifacts
  | (
      $present
      | map(select((.agent_error_diagnostics.eidolon.count // 0) > 0))
      | length
    ) as $runs_with_eidolon_agent_errors
  | (
      $present
      | map(
          select(
            .agent_error_diagnostics.eidolon.has_codex_token_refresh_failure // false
          )
        )
      | length
    ) as $runs_with_eidolon_codex_token_refresh_failure
  | (
      $present
      | map(
          select(
            (.agent_error_diagnostics.eidolon.has_codex_backend_timeout // false)
            or any(
              .agent_error_diagnostics.eidolon.class_counts[]?;
              .error_class == "codex_backend_timeout"
            )
          )
        )
      | length
    ) as $runs_with_eidolon_codex_backend_timeout
  | (
      $present
      | map(
          select(
            (.agent_error_diagnostics.eidolon.has_codex_backend_api_error // false)
            or any(
              .agent_error_diagnostics.eidolon.class_counts[]?;
              .error_class == "codex_backend_timeout"
              or .error_class == "codex_backend_api_error"
            )
          )
        )
      | length
    ) as $runs_with_eidolon_codex_backend_error
  | (
      $present
      | map(select(.pinned_session.present and (.pinned_session.cookie_preserved | not)))
      | length
    ) as $pinned_without_cookie_count
  | ($present | map(select(.trace_gap.proxy_trace_present)) | length)
    as $proxy_trace_present_count
  | (
      $present
      | map(select(.trace_gap.proxy_trace_controlled_reality_entered))
      | length
    ) as $proxy_trace_controlled_count
  | (
      $present
      | map(select(.trace_gap.proxy_trace_real_surface_quiet))
      | length
    ) as $proxy_trace_quiet_count
  | (
      $present
      | map(select(.trace_gap.proxy_trace_controlled_reality_without_strict_confirmation))
      | length
    ) as $proxy_trace_without_strict_count
  | (
      $present
      | map(select(.trace_gap.strict_controlled_reality_without_eidolon_finding))
      | length
    ) as $strict_controlled_without_finding_count
  | (
      $present
      | map(select(.trace_gap.positive_differential_without_strict_controlled_reality))
      | length
    ) as $positive_without_strict_count
  | ($present | map(.eidolon_proxy.request_path_counts[]?)) as $proxy_path_entries
  | (
      $present
      | map(.agent_error_diagnostics.eidolon.class_counts[]? | {
          value: .error_class,
          count
        })
    ) as $eidolon_agent_error_class_entries
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
        direct_findings: $direct_findings_count,
        eidolon_findings: $eidolon_findings_count,
        positive_differential_findings: $positive_differential_count,
        bait_reached_without_eidolon_findings: $bait_reached_without_findings_count,
        bait_action_without_eidolon_findings: $bait_action_without_findings_count,
        controlled_reality_without_eidolon_findings: $controlled_without_findings_count,
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
        eidolon_finding_rate: rate($eidolon_findings_count; $valid_count),
        positive_differential_finding_rate: (
          rate($positive_differential_count; $valid_count)
        ),
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
      runner_package_versions: $runner_versions,
      source_checkout: {
        clean_runner_count: $clean_runner_count,
        dirty_runner_count: $dirty_runner_count,
        unknown_dirty_runner_count: $unknown_dirty_runner_count,
        origin_main_synced_count: $origin_synced_count,
        origin_main_drifted_count: $origin_drifted_count,
        unknown_origin_main_sync_count: $unknown_origin_sync_count,
        all_runners_clean: (
          $valid_count > 0 and all($present[]; .runner_git_dirty == false)
        ),
        all_runners_origin_main_synced: (
          $valid_count > 0 and all($present[]; .runner_origin_main_in_sync == true)
        )
      },
      no_signal_diagnostics: {
        sample_size: $valid_count,
        no_target_interaction_run_count: $no_target_count,
        all_runs_no_target_interaction: (
          $valid_count > 0 and $no_target_count == $valid_count
        ),
        runs_with_eidolon_pwnkit_request_artifacts: $runs_with_eidolon_request_artifacts,
        runs_with_eidolon_proxy_requests: $runs_with_eidolon_proxy_requests,
        runs_with_proxy_requests_but_no_pwnkit_request_artifacts: (
          $runs_with_proxy_requests_but_no_pwnkit_request_artifacts
        ),
        runs_with_eidolon_agent_errors: $runs_with_eidolon_agent_errors,
        runs_with_eidolon_codex_token_refresh_failure: (
          $runs_with_eidolon_codex_token_refresh_failure
        ),
        runs_with_eidolon_codex_backend_timeout: (
          $runs_with_eidolon_codex_backend_timeout
        ),
        runs_with_eidolon_codex_backend_error: (
          $runs_with_eidolon_codex_backend_error
        ),
        runs_with_pinned_session_but_no_cookie_preservation: $pinned_without_cookie_count,
        totals: {
          direct_pwnkit_tool_artifacts: $direct_tool_artifact_total,
          eidolon_pwnkit_tool_artifacts: $eidolon_tool_artifact_total,
          direct_pwnkit_agent_errors: $direct_agent_error_total,
          eidolon_pwnkit_agent_errors: $eidolon_agent_error_total,
          direct_pwnkit_request_artifacts: $direct_request_artifact_total,
          eidolon_pwnkit_request_artifacts: $eidolon_request_artifact_total,
          eidolon_proxy_requests: $eidolon_proxy_request_total,
          correlated_target_requests: $correlated_target_request_total,
          uncorrelated_eidolon_proxy_requests: (
            if $eidolon_proxy_request_total > $correlated_target_request_total then
              $eidolon_proxy_request_total - $correlated_target_request_total
            else
              0
            end
          )
        },
        proxy_path_counts: merge_value_counts($proxy_path_entries; "path"),
        eidolon_agent_error_class_counts: merge_value_counts(
          $eidolon_agent_error_class_entries;
          "error_class"
        ),
        likely_cause: no_signal_likely_cause(
          $valid_count;
          $no_target_count;
          $eidolon_request_artifact_total;
          $eidolon_proxy_request_total;
          $eidolon_agent_error_total;
          $runs_with_eidolon_codex_token_refresh_failure;
          $runs_with_eidolon_codex_backend_error
        ),
        next_questions: (
          if $valid_count > 0 and $no_target_count == $valid_count then
            no_signal_next_questions(
              $eidolon_request_artifact_total;
              $eidolon_proxy_request_total;
              $pinned_without_cookie_count;
              $eidolon_agent_error_total;
              $runs_with_eidolon_codex_token_refresh_failure;
              $runs_with_eidolon_codex_backend_error
            )
          else
            []
          end
        )
      },
      differential_findings: {
        minimum_sample_size: 3,
        sample_size: $valid_count,
        direct_finding_run_count: $direct_findings_count,
        eidolon_finding_run_count: $eidolon_findings_count,
        positive_differential_run_count: $positive_differential_count,
        bait_reached_without_eidolon_finding_run_count: $bait_reached_without_findings_count,
        bait_action_without_eidolon_finding_run_count: $bait_action_without_findings_count,
        controlled_reality_without_eidolon_finding_run_count: $controlled_without_findings_count,
        all_direct_quiet: (
          $valid_count > 0 and all($present[]; (.direct_finding_count // 0) == 0)
        ),
        ready_for_differential_finding_claim: (
          $valid_count >= 3
          and $valid_count == $artifact_count
          and all($present[]; (.direct_finding_count // 0) == 0)
          and all($present[]; .finding_gap.positive_differential_findings)
        ),
        next_questions: (
          $present
          | map(.finding_gap.next_question // null)
          | map(select(. != null))
          | unique
        )
      },
      evidence_gap_diagnostics: {
        sample_size: $valid_count,
        proxy_trace_present_run_count: $proxy_trace_present_count,
        proxy_trace_controlled_reality_run_count: $proxy_trace_controlled_count,
        proxy_trace_real_surface_quiet_run_count: $proxy_trace_quiet_count,
        pwnkit_strict_controlled_reality_run_count: $controlled_count,
        pwnkit_strict_same_session_run_count: $same_session_count,
        proxy_trace_without_strict_controlled_reality_run_count: (
          $proxy_trace_without_strict_count
        ),
        strict_controlled_reality_without_eidolon_finding_run_count: (
          $strict_controlled_without_finding_count
        ),
        positive_differential_without_strict_controlled_reality_run_count: (
          $positive_without_strict_count
        ),
        all_proxy_trace_contained: (
          $valid_count > 0
          and $proxy_trace_present_count == $valid_count
          and $proxy_trace_controlled_count == $valid_count
          and $proxy_trace_quiet_count == $valid_count
        ),
        all_strict_pwnkit_controlled_reality: (
          $valid_count > 0 and $controlled_count == $valid_count
        ),
        all_strict_controlled_reality_promoted_to_findings: (
          $controlled_count > 0 and $strict_controlled_without_finding_count == 0
        ),
        observed_gaps: (
          [
            if $proxy_trace_without_strict_count > 0 then
              "proxy_trace_controlled_reality_without_strict_pwnkit_correlation"
            else
              empty
            end,
            if $strict_controlled_without_finding_count > 0 then
              "strict_controlled_reality_without_eidolon_findings"
            else
              empty
            end,
            if $positive_without_strict_count > 0 then
              "positive_differential_findings_without_strict_controlled_reality"
            else
              empty
            end,
            if $positive_differential_count > 0 and $positive_differential_count < $valid_count then
              "partial_positive_differential_findings"
            else
              empty
            end
          ] as $gaps
          | if ($gaps | length) == 0 then ["none"] else $gaps end
        ),
        next_questions: (
          $present
          | map(.trace_gap.next_question // null)
          | map(select(. != null))
          | unique
        )
      },
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
        all_runners_clean: (
          $valid_count > 0 and all($present[]; .runner_git_dirty == false)
        ),
        all_runners_origin_main_synced: (
          $valid_count > 0 and all($present[]; .runner_origin_main_in_sync == true)
        ),
        ready_for_stability_claim: (
          $valid_count >= 3
          and $valid_count == $artifact_count
          and ($runner_heads | length) == 1
          and all($present[]; .runner_git_dirty == false)
          and all($present[]; .runner_origin_main_in_sync == true)
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
