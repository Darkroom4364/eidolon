#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/qualification/collect-pwnkit-direct-qualification-sample.sh <artifact-dir>...

Aggregates repeated direct-only pwnkit qualification runs into one
scanner-qualification sample summary. Each artifact directory should contain
`pwnkit-summary.json` produced from `examples/m3/collect-pwnkit-codex.sh`.
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

  jq -c \
    --arg artifact_dir "$artifact_dir" \
    '
      def valid_track:
        . == "upstream_current"
        or . == "local_patched_pwnkit"
        or . == "historical_stale";
      def inferred_evidence_track:
        (.runner.pwnkit.evidence_track // null) as $explicit
        | if ($explicit | valid_track) then
          $explicit
        elif (.runner.pwnkit.stale_dist_guard_bypassed // false) == true then
          "historical_stale"
        elif .runner.pwnkit.git_dirty == true then
          "local_patched_pwnkit"
        elif ((.runner.pwnkit.origin_main.ahead // 0) > 0) then
          "local_patched_pwnkit"
        elif .runner.pwnkit.git_dirty == false
          and (.runner.pwnkit.origin_main.in_sync // null) == true then
          "upstream_current"
        elif ((.runner.pwnkit.origin_main.behind // 0) > 0) then
          "historical_stale"
        elif (.runner.pwnkit.fixture.pinned // false) == true
          and ((.runner.pwnkit.git_head // "") != "")
          and .runner.pwnkit.git_dirty == false then
          "local_patched_pwnkit"
        else
          "unknown"
        end;
      def target_interaction_observed:
        ((.runs.direct.pwnkit_events.tool_artifacts // 0) > 0)
        or ((.runs.direct.target_evidence_diagnostics.request_artifact_count // 0) > 0)
        or ((.runs.direct.target_evidence_diagnostics.crawl_artifact_count // 0) > 0)
        or ((.runs.direct.finding_count // 0) > 0);
      . + {
        artifact_dir: $artifact_dir,
        missing: false,
        evidence_track: inferred_evidence_track,
        target_interaction_observed: target_interaction_observed,
        claim_level: (
          if (.runs.direct.finding_count // 0) > 0 then
            "direct_findings_present"
          elif target_interaction_observed then
            "no_direct_findings"
          else
            "no_target_interaction"
          end
        )
      }
    ' \
    "$summary_file"
}

for artifact_dir in "$@"; do
  emit_artifact_summary "$artifact_dir"
done | jq -s '
  def rate($numerator; $denominator):
    if $denominator == 0 then null else ($numerator / $denominator) end;

  def count_values($values; $label):
    $values
    | map(select(. != null and . != ""))
    | sort
    | group_by(.)
    | map({($label): .[0], count: length});

  def tool_fingerprint_summary:
    [
      (.[] | select(.missing != true) | .runner.environment.tool_fingerprint // [])[]
      | {
          name: (.name // "unknown"),
          present: (.present // false),
          version: (.version // "unknown")
        }
    ]
    | sort_by(.name, .present, .version)
    | group_by(.name)
    | map({
        name: .[0].name,
        present_count: (map(select(.present == true)) | length),
        missing_count: (map(select(.present != true)) | length),
        versions: (map(select(.present == true) | .version) | unique)
      });

  def summarize_run:
    if .missing then
      {
        artifact_dir,
        present: false,
        missing_reason,
        evidence_track: "missing",
        claim_level: "missing"
      }
    else
      {
        artifact_dir,
        present: true,
        evidence_track,
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
        runner_pwnkit_fixture: (
          if (.runner.pwnkit.fixture // null) == null then
            null
          else
            {
              id: (.runner.pwnkit.fixture.id // null),
              pinned: (.runner.pwnkit.fixture.pinned // false)
            }
          end
        ),
        runner_pwnkit_fixture_id: (.runner.pwnkit.fixture.id // null),
        stale_dist_guard_bypassed: (
          if (.runner.pwnkit | has("stale_dist_guard_bypassed")) then
            .runner.pwnkit.stale_dist_guard_bypassed
          else
            null
          end
        ),
        runner_environment: (.runner.environment.runner_environment // null),
        runner_environment_source: (.runner.environment.runner_environment_source // null),
        runner_network_topology: (.runner.environment.network_topology // null),
        runner_os: (.runner.environment.os // null),
        runner_tool_fingerprint: (.runner.environment.tool_fingerprint // []),
        claim_level,
        target_interaction_observed,
        direct_finding_count: (.runs.direct.finding_count // 0),
        direct_final_json_finding_count: (.runs.direct.final_json_finding_count // 0),
        direct_db_saved_finding_count: (.runs.direct.db_saved_finding_count // 0),
        direct_db_active_finding_count: (.runs.direct.db_active_finding_count // 0),
        finding_diagnostics: (.runs.direct.finding_diagnostics // null),
        finding_reconciliation: (.runs.direct.finding_reconciliation // null),
        pwnkit_events: (.runs.direct.pwnkit_events // null),
        target_evidence_diagnostics: (.runs.direct.target_evidence_diagnostics // null),
        agent_error_diagnostics: (.runs.direct.agent_error_diagnostics // null)
      }
    end;

  . as $raw
  | (map(summarize_run)) as $artifacts
  | ($artifacts | map(select(.present == true))) as $valid
  | ($valid | length) as $valid_count
  | ($valid | map(.target_interaction_observed | if . then 1 else 0 end) | add // 0) as $target_interaction_count
  | ($valid | map(select((.direct_finding_count // 0) == 0)) | length) as $quiet_count
  | ($valid | map(select((.direct_finding_count // 0) > 0)) | length) as $noisy_count
  | ($valid | map(select((.agent_error_diagnostics.count // 0) > 0)) | length) as $agent_error_count
  | ($valid | map(.direct_finding_count // 0) | add // 0) as $direct_finding_total
  | ($valid | map(.direct_db_saved_finding_count // 0) | add // 0) as $direct_db_saved_total
  | ($valid | map(.direct_db_active_finding_count // 0) | add // 0) as $direct_db_active_total
  | ($valid | map(.direct_final_json_finding_count // 0) | add // 0) as $direct_final_json_total
  | {
      schema_version: 1,
      run_kind: "pwnkit_direct_qualification_sample",
      boundary: "scanner_qualification",
      generated_at: (now | todateiso8601),
      artifact_count: ($raw | length),
      valid_summary_count: $valid_count,
      counts: {
        missing_summary: (($raw | length) - $valid_count),
        target_interaction_observed: $target_interaction_count,
        quiet_runs: $quiet_count,
        noisy_runs: $noisy_count,
        agent_error_runs: $agent_error_count,
        direct_findings: (
          if $direct_finding_total > 0 then $noisy_count else 0 end
        )
      },
      rates: {
        target_interaction_rate: rate($target_interaction_count; $valid_count),
        quiet_run_rate: rate($quiet_count; $valid_count),
        noisy_run_rate: rate($noisy_count; $valid_count),
        agent_error_run_rate: rate($agent_error_count; $valid_count)
      },
      claim_level_counts: count_values(($artifacts | map(.claim_level)); "claim_level"),
      weakest_claim_level: (
        if $target_interaction_count == 0 then
          "no_target_interaction"
        elif $quiet_count > 0 then
          "no_direct_findings"
        else
          "direct_findings_present"
        end
      ),
      strongest_claim_level: (
        if $noisy_count > 0 then
          "direct_findings_present"
        elif $target_interaction_count > 0 then
          "no_direct_findings"
        else
          "no_target_interaction"
        end
      ),
      runner_git_heads: ($valid | map(.runner_git_head) | map(select(. != null and . != "")) | unique),
      runner_package_versions: ($valid | map(.runner_package_version) | map(select(. != null and . != "")) | unique),
      runner_pwnkit_fixture_ids: ($valid | map(.runner_pwnkit_fixture_id) | map(select(. != null and . != "")) | unique),
      evidence_track_counts: count_values(($artifacts | map(.evidence_track)); "evidence_track"),
      evidence_tracks: ($valid | map(.evidence_track) | map(select(. != null and . != "")) | unique),
      single_evidence_track: (($valid | map(.evidence_track) | map(select(. != null and . != "")) | unique | length) == 1),
      mixed_evidence_tracks: (($valid | map(.evidence_track) | map(select(. != null and . != "")) | unique | length) > 1),
      unknown_evidence_track_count: ($valid | map(select(.evidence_track == "unknown")) | length),
      runner_environments: ($valid | map(.runner_environment) | map(select(. != null and . != "")) | unique),
      runner_network_topologies: ($valid | map(.runner_network_topology) | map(select(. != null and . != "")) | unique),
      tool_fingerprint_summary: tool_fingerprint_summary,
      source_checkout: {
        all_runners_clean: all($valid[]?; .runner_git_dirty == false),
        all_runners_origin_main_synced: all($valid[]?; .runner_origin_main_in_sync == true)
      },
      finding_reconciliation: {
        direct_final_json_finding_total: $direct_final_json_total,
        direct_db_saved_finding_total: $direct_db_saved_total,
        direct_db_active_finding_total: $direct_db_active_total
      },
      no_signal_diagnostics: {
        sample_size: $valid_count,
        no_target_interaction_run_count: ($valid_count - $target_interaction_count),
        all_runs_no_target_interaction: ($target_interaction_count == 0),
        totals: {
          direct_pwnkit_agent_errors: (
            $valid
            | map(.agent_error_diagnostics.count // 0)
            | add // 0
          ),
          direct_request_artifacts: (
            $valid
            | map(.target_evidence_diagnostics.request_artifact_count // 0)
            | add // 0
          )
        },
        direct_agent_error_class_counts: (
          [
            $valid[]
            | (.agent_error_diagnostics.class_counts // [])[]
          ]
          | sort_by(.error_class)
          | group_by(.error_class)
          | map({
              error_class: .[0].error_class,
              count: (map(.count // 0) | add)
            })
        ),
        likely_cause: (
          if $target_interaction_count > 0 then
            null
          elif $agent_error_count > 0 then
            "pwnkit_agent_errors_prevented_target_interaction"
          else
            "pwnkit_emitted_no_target_interaction"
          end
        ),
        next_questions: (
          if $target_interaction_count > 0 then
            []
          elif $agent_error_count > 0 then
            [
              "inspect_sanitized_pwnkit_agent_error_classes",
              "rerun_after_agent_error_free_scan"
            ]
          else
            [
              "why_pwnkit_emitted_no_target_interaction",
              "whether_the_negative_control_target_surface_is_too_thin"
            ]
          end
        )
      },
      qualification_result: {
        ready_for_negative_control_claim: (
          $valid_count > 0
          and $target_interaction_count == $valid_count
          and $noisy_count == 0
          and $agent_error_count == 0
        ),
        quiet_run_count: $quiet_count,
        noisy_run_count: $noisy_count,
        target_interaction_run_count: $target_interaction_count
      },
      strict_stability: {
        ready_for_stability_claim: false
      },
      artifacts: $artifacts
    }
  '
