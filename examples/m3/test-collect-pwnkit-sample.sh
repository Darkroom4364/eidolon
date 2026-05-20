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

mutate_summary() {
  local dir="$1"
  local filter="$2"
  local tmp="$dir/pwnkit-summary.json.tmp"

  jq "$filter" "$dir/pwnkit-summary.json" > "$tmp"
  mv "$tmp" "$dir/pwnkit-summary.json"
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

test_mixed_sample_counts_claims_and_missing_dirs
test_stability_claim_requires_three_matching_successes
test_stability_rejects_mixed_runner_heads_or_direct_findings
test_stability_rejects_dirty_or_unsynced_runner
test_differential_finding_diagnostics_count_open_gap

printf 'collect-pwnkit-sample fixture tests passed\n'
