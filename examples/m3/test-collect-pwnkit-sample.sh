#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-sample.sh"

new_artifact() {
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-sample-test.XXXXXX")"
  printf '%s\n' "$dir"
}

write_summary() {
  local dir="$1"
  local claim_level="$2"
  local git_head="$3"
  local direct_findings="$4"
  local pinned_cookie_preserved="$5"
  local controlled_entries="$6"
  local eidolon_findings="${7:-0}"

  local bait_reached=false
  local bait_action=false
  local same_session=false
  local controlled=false

  case "$claim_level" in
    bait_exposed_without_action)
      bait_reached=true
      ;;
    bait_action_observed_without_same_session)
      bait_reached=true
      bait_action=true
      ;;
    same_session_bait_action_confirmed)
      bait_reached=true
      bait_action=true
      same_session=true
      ;;
    controlled_reality_entered)
      bait_reached=true
      bait_action=true
      same_session=true
      controlled=true
      ;;
    no_target_interaction|bait_not_reached)
      ;;
    *)
      echo "unknown fixture claim: $claim_level" >&2
      exit 2
      ;;
  esac

  jq -n \
    --arg claim_level "$claim_level" \
    --arg git_head "$git_head" \
    --argjson direct_findings "$direct_findings" \
    --argjson eidolon_findings "$eidolon_findings" \
    --argjson bait_reached "$bait_reached" \
    --argjson bait_action "$bait_action" \
    --argjson same_session "$same_session" \
    --argjson controlled "$controlled" \
    --argjson pinned_cookie_preserved "$pinned_cookie_preserved" \
    --argjson controlled_entries "$controlled_entries" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_codex_comparison",
      runner: {
        pwnkit: {
          git_head: $git_head,
          package_version: "9.8.7",
          git_dirty: false,
          origin_main: {
            head: $git_head,
            ahead: 0,
            behind: 0,
            in_sync: true
          },
          command: "node /tmp/pwnkit/dist/pwnkit.js",
          stale_dist_guard_bypassed: false
        }
      },
      runs: {
        direct: {
          finding_count: $direct_findings,
          finding_diagnostics: {count: $direct_findings}
        },
        eidolon: {
          finding_count: $eidolon_findings,
          finding_diagnostics: {count: $eidolon_findings}
        }
      },
      comparison: {
        claim_level: $claim_level,
        conclusion: (
          if $controlled then "bait_action_observed"
          elif $same_session then "bait_action_observed"
          elif $bait_action then "bait_action_observed"
          elif $bait_reached then "bait_reached"
          else "no_target_interaction"
          end
        ),
        target_interaction_observed: ($claim_level != "no_target_interaction"),
        bait_reached: $bait_reached,
        bait_action_observed: $bait_action,
        same_session_confirmed_bait_action: $same_session,
        controlled_reality_entered: $controlled,
        finding_gap: {
          direct_finding_count: $direct_findings,
          eidolon_finding_count: $eidolon_findings,
          differential_finding_count: ($eidolon_findings - $direct_findings),
          positive_differential_findings: ($eidolon_findings > $direct_findings),
          direct_quiet: ($direct_findings == 0),
          eidolon_has_findings: ($eidolon_findings > 0),
          eidolon_observed_target_evidence_without_findings: (
            $eidolon_findings == 0 and $claim_level != "no_target_interaction"
          ),
          eidolon_bait_reached_without_findings: (
            $eidolon_findings == 0 and $bait_reached
          ),
          eidolon_bait_action_without_findings: (
            $eidolon_findings == 0 and $bait_action
          ),
          eidolon_controlled_reality_without_findings: (
            $eidolon_findings == 0 and $controlled
          ),
          next_question: (
            if $eidolon_findings > $direct_findings then
              "differential_finding_observed"
            elif $controlled then
              "why_controlled_reality_chain_was_not_promoted_to_finding"
            elif $bait_action then
              "why_bait_action_was_not_promoted_to_finding"
            elif $bait_reached then
              "why_bait_exposure_was_not_promoted_to_finding_or_action"
            else
              null
            end
          )
        },
        correlated_target_requests: (
          if $claim_level == "no_target_interaction" then [] else [{path: "/openapi.json"}] end
        ),
        correlated_bait_events: {
          exposures: (if $bait_reached then [{bait_id: "openapi_reconcile_trace"}] else [] end),
          actions: (if $bait_action then [{bait_id: "openapi_reconcile_trace"}] else [] end),
          same_session_confirmed_actions: (
            if $same_session then [{bait_id: "openapi_reconcile_trace"}] else [] end
          ),
          controlled_reality_entries: (
            [range(0; $controlled_entries) | {kind: "controlled_reality_entered"}]
          )
        }
      },
      pinned_session: {
        present: true,
        session_id: "fixture-session",
        cookie_preserved: $pinned_cookie_preserved,
        proxy_request_count: (if $pinned_cookie_preserved then 10 else 0 end),
        correlated_target_request_count: (
          if $claim_level == "no_target_interaction" then 0 else 1 end
        ),
        correlated_bait_exposure_count: (if $bait_reached then 1 else 0 end),
        correlated_bait_action_count: (if $bait_action then 1 else 0 end),
        same_session_confirmed_bait_action_count: (if $same_session then 1 else 0 end),
        controlled_reality_entry_count: $controlled_entries
      },
      metrics: {
        bait_follow_rate: (if $bait_reached then (if $bait_action then 1 else 0 end) else null end),
        same_session_confirmed_bait_follow_rate: (
          if $bait_reached then (if $same_session then 1 else 0 end) else null end
        )
      }
    }' > "$dir/pwnkit-summary.json"
}

write_agent_trace_summary() {
  local dir="$1"
  local claim_level="$2"
  local real_surface_after_containment="$3"
  local controlled_depth="$4"
  local controlled_branch_count="$5"

  jq -n \
    --arg claim_level "$claim_level" \
    --argjson real_surface_after_containment "$real_surface_after_containment" \
    --argjson controlled_depth "$controlled_depth" \
    --argjson controlled_branch_count "$controlled_branch_count" \
    '{
      schema_version: 1,
      claim_level: $claim_level,
      metrics: {
        real_surface_requests_after_containment: $real_surface_after_containment,
        controlled_reality_action_depth: $controlled_depth,
        controlled_reality_branch_count: $controlled_branch_count
      }
    }' > "$dir/agent-replay-trace-summary.json"
}

mutate_summary() {
  local dir="$1"
  local filter="$2"
  local tmp="$dir/pwnkit-summary.json.tmp"

  jq "$filter" "$dir/pwnkit-summary.json" > "$tmp"
  mv "$tmp" "$dir/pwnkit-summary.json"
}

add_proxy_no_signal_fixture() {
  local dir="$1"

  mutate_summary "$dir" '
    .runs.direct.pwnkit_events = {
      pipeline_events: 19,
      tool_artifacts: 0,
      tool_counts: [],
      bash_http_output_requests: 0
    }
    | .runs.eidolon.pwnkit_events = {
      pipeline_events: 19,
      tool_artifacts: 0,
      tool_counts: [],
      bash_http_output_requests: 0
    }
    | .runs.direct.target_evidence_diagnostics = {
      request_artifact_count: 0,
      http_request_artifact_count: 0,
      bash_http_output_request_count: 0,
      observed_request_evidence_without_findings: false
    }
    | .runs.eidolon.target_evidence_diagnostics = {
      request_artifact_count: 0,
      http_request_artifact_count: 0,
      bash_http_output_request_count: 0,
      observed_request_evidence_without_findings: false
    }
    | .eidolon_proxy = {
      present: true,
      event_count: 4,
      request_count: 2,
      kind_counts: [{kind: "request_seen", count: 2}],
      routing_counts: [{routing_decision: "protected_upstream", count: 2}],
      counts: {
        bait_exposures: 0,
        bait_actions: 0,
        same_session_confirmed_bait_actions: 0,
        unconfirmed_bait_actions: 0,
        controlled_reality_entries: 0,
        protected_upstream_requests: 2
      },
      request_paths: [
        {method: "GET", path: "/wp-login.php", routing_decision: "protected_upstream"},
        {method: "GET", path: "/readme.html", routing_decision: "protected_upstream"}
      ]
    }
    | .comparison.target_correlation_diagnostics = {
      pwnkit_eidolon_tool_artifact_count: 0,
      pwnkit_eidolon_request_artifact_count: 0,
      eidolon_proxy_request_count: 2,
      correlated_target_request_count: 0,
      uncorrelated_proxy_request_count: 2,
      likely_cause: "eidolon_proxy_saw_uncorrelated_requests_but_pwnkit_emitted_no_request_artifacts",
      next_questions: [
        "why_pwnkit_emitted_no_request_artifacts",
        "which_runner_or_probe_generated_uncorrelated_proxy_requests",
        "why_pinned_session_cookie_was_not_reused_by_pwnkit"
      ]
    }
  '
}

add_agent_error_no_signal_fixture() {
  local dir="$1"

  mutate_summary "$dir" '
    .runs.eidolon.pwnkit_events.agent_errors = 1
    | .runs.eidolon.agent_error_diagnostics = {
      count: 1,
      stage_counts: [{stage: "attack", agentRole: "attack", count: 1}],
      class_counts: [{error_class: "codex_token_refresh_failed", count: 1}],
      has_agent_error: true,
      has_codex_token_refresh_failure: true,
      has_codex_authentication_failure: true,
      has_codex_backend_api_error: true,
      has_codex_backend_timeout: false
    }
    | .runs.direct.agent_error_diagnostics = {
      count: 0,
      stage_counts: [],
      class_counts: [],
      has_agent_error: false,
      has_codex_token_refresh_failure: false,
      has_codex_authentication_failure: false,
      has_codex_backend_api_error: false,
      has_codex_backend_timeout: false
    }
    | .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_count = 1
    | .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_classes = [
      {error_class: "codex_token_refresh_failed", count: 1}
    ]
    | .comparison.target_correlation_diagnostics.likely_cause = "pwnkit_codex_token_refresh_failure_prevented_request_artifacts"
    | .comparison.target_correlation_diagnostics.next_questions = [
      "refresh_pwnkit_codex_auth_before_rerun",
      "rerun_matrix_after_agent_error_free_scan"
    ]
  '
}

add_backend_timeout_no_signal_fixture() {
  local dir="$1"

  mutate_summary "$dir" '
    .runs.eidolon.pwnkit_events.agent_errors = 1
    | .runs.eidolon.agent_error_diagnostics = {
      count: 1,
      stage_counts: [{stage: "attack", agentRole: "attack", count: 1}],
      class_counts: [{error_class: "codex_backend_timeout", count: 1}],
      has_agent_error: true,
      has_codex_token_refresh_failure: false,
      has_codex_authentication_failure: false,
      has_codex_backend_api_error: true
    }
    | .runs.direct.agent_error_diagnostics = {
      count: 0,
      stage_counts: [],
      class_counts: [],
      has_agent_error: false,
      has_codex_token_refresh_failure: false,
      has_codex_authentication_failure: false,
      has_codex_backend_api_error: false
    }
    | .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_count = 1
    | .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_classes = [
      {error_class: "codex_backend_timeout", count: 1}
    ]
    | .comparison.target_correlation_diagnostics.likely_cause = "pwnkit_codex_backend_timeout_prevented_request_artifacts"
    | .comparison.target_correlation_diagnostics.next_questions = [
      "rerun_after_codex_backend_timeout",
      "rerun_matrix_after_agent_error_free_scan"
    ]
  '
}

add_backend_api_no_signal_fixture() {
  local dir="$1"

  mutate_summary "$dir" '
    .runs.eidolon.pwnkit_events.agent_errors = 1
    | .runs.eidolon.agent_error_diagnostics = {
      count: 1,
      stage_counts: [{stage: "attack", agentRole: "attack", count: 1}],
      class_counts: [{error_class: "codex_backend_api_error", count: 1}],
      has_agent_error: true,
      has_codex_token_refresh_failure: false,
      has_codex_authentication_failure: false,
      has_codex_backend_api_error: true,
      has_codex_backend_timeout: false
    }
    | .runs.direct.agent_error_diagnostics = {
      count: 0,
      stage_counts: [],
      class_counts: [],
      has_agent_error: false,
      has_codex_token_refresh_failure: false,
      has_codex_authentication_failure: false,
      has_codex_backend_api_error: false,
      has_codex_backend_timeout: false
    }
    | .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_count = 1
    | .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_classes = [
      {error_class: "codex_backend_api_error", count: 1}
    ]
    | .comparison.target_correlation_diagnostics.likely_cause = "pwnkit_codex_backend_timeout_prevented_request_artifacts"
    | .comparison.target_correlation_diagnostics.next_questions = [
      "rerun_after_codex_backend_timeout",
      "rerun_matrix_after_agent_error_free_scan"
    ]
  '
}

test_mixed_sample_counts_claims_and_missing_dirs() {
  local controlled
  local same_session
  local missing
  local output

  controlled="$(new_artifact)"
  same_session="$(new_artifact)"
  missing="$(new_artifact)"

  write_summary "$controlled" controlled_reality_entered head-a 0 true 4
  write_summary "$same_session" same_session_bait_action_confirmed head-a 0 true 0

  output="$controlled/sample.json"
  "$COLLECTOR" "$controlled" "$same_session" "$missing" > "$output"

  jq -e '
    .artifact_count == 3
    and .valid_summary_count == 2
    and .counts.missing_summary == 1
    and .counts.same_session_confirmed_bait_action == 2
    and .counts.controlled_reality_entered == 1
    and .rates.controlled_reality_entry_rate == 0.5
    and .weakest_claim_level == "same_session_bait_action_confirmed"
    and .strongest_claim_level == "controlled_reality_entered"
    and .strict_stability.ready_for_stability_claim == false
  ' "$output" >/dev/null
}

test_stability_claim_requires_three_matching_successes() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" controlled_reality_entered head-a 0 true 3
  write_summary "$second" controlled_reality_entered head-a 0 true 4
  write_summary "$third" controlled_reality_entered head-a 0 true 5

  output="$first/sample.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .valid_summary_count == 3
    and .runner_git_heads == ["head-a"]
    and .runner_package_versions == ["9.8.7"]
    and .source_checkout.all_runners_clean == true
    and .source_checkout.all_runners_origin_main_synced == true
    and .rates.controlled_reality_entry_rate == 1
    and .strict_stability.all_summaries_present == true
    and .strict_stability.single_runner_git_head == true
    and .strict_stability.all_direct_quiet == true
    and .strict_stability.all_pinned_cookie_preserved == true
    and .strict_stability.all_runners_clean == true
    and .strict_stability.all_runners_origin_main_synced == true
    and .strict_stability.ready_for_stability_claim == true
  ' "$output" >/dev/null
}

test_stability_rejects_mixed_runner_heads_or_direct_findings() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" controlled_reality_entered head-a 0 true 3
  write_summary "$second" controlled_reality_entered head-b 0 true 4
  write_summary "$third" controlled_reality_entered head-a 1 true 5

  output="$first/sample.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .strict_stability.single_runner_git_head == false
    and .counts.direct_quiet == 2
    and .strict_stability.all_direct_quiet == false
    and .strict_stability.ready_for_stability_claim == false
  ' "$output" >/dev/null
}

test_stability_rejects_dirty_or_unsynced_runner() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" controlled_reality_entered head-a 0 true 3
  write_summary "$second" controlled_reality_entered head-a 0 true 3
  write_summary "$third" controlled_reality_entered head-a 0 true 3
  mutate_summary "$first" '.runner.pwnkit.git_dirty = true'
  mutate_summary "$second" '.runner.pwnkit.origin_main.in_sync = false
    | .runner.pwnkit.origin_main.behind = 2'

  output="$first/sample-dirty.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .source_checkout.dirty_runner_count == 1
    and .source_checkout.origin_main_drifted_count == 1
    and .source_checkout.all_runners_clean == false
    and .source_checkout.all_runners_origin_main_synced == false
    and .strict_stability.all_runners_clean == false
    and .strict_stability.all_runners_origin_main_synced == false
    and .strict_stability.ready_for_stability_claim == false
  ' "$output" >/dev/null
}

test_no_signal_diagnostics_aggregate_proxy_without_pwnkit_artifacts() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" no_target_interaction head-a 0 false 0
  write_summary "$second" no_target_interaction head-a 0 false 0
  write_summary "$third" no_target_interaction head-a 0 false 0
  add_proxy_no_signal_fixture "$first"
  add_proxy_no_signal_fixture "$second"
  add_proxy_no_signal_fixture "$third"

  output="$first/sample-no-signal.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .no_signal_diagnostics.sample_size == 3
    and .no_signal_diagnostics.no_target_interaction_run_count == 3
    and .no_signal_diagnostics.all_runs_no_target_interaction == true
    and .no_signal_diagnostics.runs_with_eidolon_pwnkit_request_artifacts == 0
    and .no_signal_diagnostics.runs_with_eidolon_proxy_requests == 3
    and .no_signal_diagnostics.runs_with_proxy_requests_but_no_pwnkit_request_artifacts == 3
    and .no_signal_diagnostics.runs_with_pinned_session_but_no_cookie_preservation == 3
    and .no_signal_diagnostics.totals.eidolon_pwnkit_request_artifacts == 0
    and .no_signal_diagnostics.totals.eidolon_proxy_requests == 6
    and .no_signal_diagnostics.totals.uncorrelated_eidolon_proxy_requests == 6
    and .no_signal_diagnostics.likely_cause == "eidolon_proxy_saw_uncorrelated_requests_but_pwnkit_emitted_no_request_artifacts"
    and (.no_signal_diagnostics.next_questions | index("why_pwnkit_emitted_no_request_artifacts"))
    and (.no_signal_diagnostics.next_questions | index("which_runner_or_probe_generated_uncorrelated_proxy_requests"))
    and (.no_signal_diagnostics.next_questions | index("why_pinned_session_cookie_was_not_reused_by_pwnkit"))
    and (.no_signal_diagnostics.proxy_path_counts | index({path: "/wp-login.php", count: 3}))
    and (.no_signal_diagnostics.proxy_path_counts | index({path: "/readme.html", count: 3}))
  ' "$output" >/dev/null
}

test_no_signal_diagnostics_prioritize_agent_auth_errors() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" no_target_interaction head-a 0 false 0
  write_summary "$second" no_target_interaction head-a 0 false 0
  write_summary "$third" no_target_interaction head-a 0 false 0
  add_proxy_no_signal_fixture "$first"
  add_proxy_no_signal_fixture "$second"
  add_proxy_no_signal_fixture "$third"
  add_agent_error_no_signal_fixture "$first"
  add_agent_error_no_signal_fixture "$second"
  add_agent_error_no_signal_fixture "$third"

  output="$first/sample-agent-error.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .no_signal_diagnostics.runs_with_eidolon_agent_errors == 3
    and .no_signal_diagnostics.runs_with_eidolon_codex_token_refresh_failure == 3
    and .no_signal_diagnostics.totals.eidolon_pwnkit_agent_errors == 3
    and .no_signal_diagnostics.eidolon_agent_error_class_counts == [
      {error_class: "codex_token_refresh_failed", count: 3}
    ]
    and .no_signal_diagnostics.likely_cause == "pwnkit_codex_token_refresh_failure_prevented_request_artifacts"
    and (.no_signal_diagnostics.next_questions | index("refresh_pwnkit_codex_auth_before_rerun"))
    and (.no_signal_diagnostics.next_questions | index("rerun_matrix_after_agent_error_free_scan"))
    and .artifacts[0].agent_error_diagnostics.eidolon.count == 1
  ' "$output" >/dev/null
}

test_no_signal_diagnostics_classify_backend_timeouts() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" no_target_interaction head-a 0 false 0
  write_summary "$second" no_target_interaction head-a 0 false 0
  write_summary "$third" no_target_interaction head-a 0 false 0
  add_proxy_no_signal_fixture "$first"
  add_proxy_no_signal_fixture "$second"
  add_proxy_no_signal_fixture "$third"
  add_backend_timeout_no_signal_fixture "$first"
  add_backend_timeout_no_signal_fixture "$second"
  add_backend_timeout_no_signal_fixture "$third"

  output="$first/sample-backend-timeout.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .no_signal_diagnostics.runs_with_eidolon_agent_errors == 3
    and .no_signal_diagnostics.runs_with_eidolon_codex_token_refresh_failure == 0
    and .no_signal_diagnostics.runs_with_eidolon_codex_backend_timeout == 3
    and .no_signal_diagnostics.runs_with_eidolon_codex_backend_error == 3
    and .no_signal_diagnostics.totals.eidolon_pwnkit_agent_errors == 3
    and .no_signal_diagnostics.eidolon_agent_error_class_counts == [
      {error_class: "codex_backend_timeout", count: 3}
    ]
    and .no_signal_diagnostics.likely_cause == "pwnkit_codex_backend_timeout_prevented_request_artifacts"
    and (.no_signal_diagnostics.next_questions | index("rerun_after_codex_backend_timeout"))
    and (.no_signal_diagnostics.next_questions | index("rerun_matrix_after_agent_error_free_scan"))
    and (
      .artifacts[0].agent_error_diagnostics.eidolon.class_counts
      | index({error_class: "codex_backend_timeout", count: 1})
    )
  ' "$output" >/dev/null
}

test_no_signal_diagnostics_classify_backend_api_errors() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" no_target_interaction head-a 0 false 0
  write_summary "$second" no_target_interaction head-a 0 false 0
  write_summary "$third" no_target_interaction head-a 0 false 0
  add_proxy_no_signal_fixture "$first"
  add_proxy_no_signal_fixture "$second"
  add_proxy_no_signal_fixture "$third"
  add_backend_api_no_signal_fixture "$first"
  add_backend_api_no_signal_fixture "$second"
  add_backend_api_no_signal_fixture "$third"

  output="$first/sample-backend-api-error.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .no_signal_diagnostics.runs_with_eidolon_agent_errors == 3
    and .no_signal_diagnostics.runs_with_eidolon_codex_token_refresh_failure == 0
    and .no_signal_diagnostics.runs_with_eidolon_codex_backend_timeout == 0
    and .no_signal_diagnostics.runs_with_eidolon_codex_backend_error == 3
    and .no_signal_diagnostics.totals.eidolon_pwnkit_agent_errors == 3
    and .no_signal_diagnostics.eidolon_agent_error_class_counts == [
      {error_class: "codex_backend_api_error", count: 3}
    ]
    and .no_signal_diagnostics.likely_cause == "pwnkit_codex_backend_timeout_prevented_request_artifacts"
    and (.no_signal_diagnostics.next_questions | index("rerun_after_codex_backend_timeout"))
    and (.no_signal_diagnostics.next_questions | index("rerun_matrix_after_agent_error_free_scan"))
    and (
      .artifacts[0].agent_error_diagnostics.eidolon.class_counts
      | index({error_class: "codex_backend_api_error", count: 1})
    )
  ' "$output" >/dev/null
}

test_differential_finding_diagnostics_count_open_gap() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" controlled_reality_entered head-a 0 true 3
  write_summary "$second" controlled_reality_entered head-a 0 true 4
  write_summary "$third" controlled_reality_entered head-a 0 true 5 2

  output="$first/sample.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .counts.eidolon_findings == 1
    and .counts.positive_differential_findings == 1
    and .counts.controlled_reality_without_eidolon_findings == 2
    and .rates.positive_differential_finding_rate == (1 / 3)
    and .differential_findings.positive_differential_run_count == 1
    and .differential_findings.controlled_reality_without_eidolon_finding_run_count == 2
    and .differential_findings.ready_for_differential_finding_claim == false
    and (.differential_findings.next_questions | index("why_controlled_reality_chain_was_not_promoted_to_finding"))
    and (.differential_findings.next_questions | index("differential_finding_observed"))
  ' "$output" >/dev/null
}

test_evidence_gap_diagnostics_compare_strict_and_proxy_trace() {
  local first
  local second
  local third
  local output

  first="$(new_artifact)"
  second="$(new_artifact)"
  third="$(new_artifact)"

  write_summary "$first" bait_action_observed_without_same_session head-a 0 true 0 2
  write_summary "$second" controlled_reality_entered head-a 0 true 4
  write_summary "$third" controlled_reality_entered head-a 0 true 5
  mutate_summary "$first" '
    .comparison.strict_correlation_gap = {
      proxy_confirmed_action_count: 1,
      strict_correlated_action_count: 1,
      strict_confirmed_action_count: 0,
      unconfirmed_strict_action_count: 1,
      proxy_confirmed_action_not_strict_count: 1,
      matching_proxy_exposure_not_pwnkit_correlated_count: 1,
      unconfirmed_actions: [
        {
          bait_id: "openapi_reconcile_trace",
          action_path: "/api/v2/import/reconcile",
          has_exposure_id: true,
          matching_proxy_exposure_count: 1,
          matching_strict_exposure_count: 0,
          matching_proxy_exposure_surfaces: ["/docs/legacy-import"],
          reason: "matching_proxy_exposure_not_pwnkit_correlated"
        }
      ],
      likely_cause: "matching_proxy_exposure_not_pwnkit_correlated",
      next_questions: ["why_pwnkit_did_not_emit_request_artifact_for_exposure_surface"]
    }
  '
  write_agent_trace_summary "$first" controlled_reality_entered 0 15 11
  write_agent_trace_summary "$second" controlled_reality_entered 0 21 15
  write_agent_trace_summary "$third" controlled_reality_entered 0 48 38

  output="$first/sample-gap.json"
  "$COLLECTOR" "$first" "$second" "$third" > "$output"

  jq -e '
    .evidence_gap_diagnostics.sample_size == 3
    and .evidence_gap_diagnostics.proxy_trace_present_run_count == 3
    and .evidence_gap_diagnostics.proxy_trace_controlled_reality_run_count == 3
    and .evidence_gap_diagnostics.proxy_trace_real_surface_quiet_run_count == 3
    and .evidence_gap_diagnostics.pwnkit_strict_controlled_reality_run_count == 2
    and .evidence_gap_diagnostics.pwnkit_strict_same_session_run_count == 2
    and .evidence_gap_diagnostics.proxy_trace_without_strict_controlled_reality_run_count == 1
    and .evidence_gap_diagnostics.strict_controlled_reality_without_eidolon_finding_run_count == 2
    and .evidence_gap_diagnostics.positive_differential_without_strict_controlled_reality_run_count == 1
    and .evidence_gap_diagnostics.matching_proxy_exposure_not_pwnkit_correlated_run_count == 1
    and .evidence_gap_diagnostics.strict_correlation_gap_likely_causes == [
      {likely_cause: "matching_proxy_exposure_not_pwnkit_correlated", count: 1}
    ]
    and .evidence_gap_diagnostics.all_proxy_trace_contained == true
    and .evidence_gap_diagnostics.all_strict_pwnkit_controlled_reality == false
    and .evidence_gap_diagnostics.all_strict_controlled_reality_promoted_to_findings == false
    and (
      .evidence_gap_diagnostics.observed_gaps
      | index("proxy_trace_controlled_reality_without_strict_pwnkit_correlation")
    )
    and (
      .evidence_gap_diagnostics.observed_gaps
      | index("strict_controlled_reality_without_eidolon_findings")
    )
    and (
      .evidence_gap_diagnostics.observed_gaps
      | index("positive_differential_findings_without_strict_controlled_reality")
    )
    and (
      .evidence_gap_diagnostics.next_questions
      | index("why_proxy_trace_containment_was_not_confirmed_by_strict_pwnkit_correlation")
    )
    and (
      .evidence_gap_diagnostics.next_questions
      | index("why_controlled_reality_chain_was_not_promoted_to_finding")
    )
    and .artifacts[0].trace_gap.proxy_trace_controlled_reality_without_strict_confirmation == true
    and .artifacts[0].trace_gap.positive_differential_without_strict_controlled_reality == true
    and .artifacts[0].strict_correlation_gap.likely_cause == "matching_proxy_exposure_not_pwnkit_correlated"
    and .artifacts[1].trace_gap.strict_controlled_reality_without_eidolon_finding == true
  ' "$output" >/dev/null
}

test_mixed_sample_counts_claims_and_missing_dirs
test_stability_claim_requires_three_matching_successes
test_stability_rejects_mixed_runner_heads_or_direct_findings
test_stability_rejects_dirty_or_unsynced_runner
test_no_signal_diagnostics_aggregate_proxy_without_pwnkit_artifacts
test_no_signal_diagnostics_prioritize_agent_auth_errors
test_no_signal_diagnostics_classify_backend_timeouts
test_no_signal_diagnostics_classify_backend_api_errors
test_differential_finding_diagnostics_count_open_gap
test_evidence_gap_diagnostics_compare_strict_and_proxy_trace

printf 'collect-pwnkit-sample fixture tests passed\n'
