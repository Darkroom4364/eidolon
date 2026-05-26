#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

SAMPLE_DIR="${1:-}"
BUNDLE_DIR="${2:-}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/package-pwnkit-sample.sh <sample-dir> <bundle-dir>

Packages a completed examples/m3/run-pwnkit-sample.sh output directory into a
commit-safe M3 evidence bundle.

Inputs:
  <sample-dir>/pwnkit-stability-sample.json
  <sample-dir>/run-*/pwnkit-summary.json
  <sample-dir>/run-*/agent-replay-trace-summary.json

Outputs:
  <bundle-dir>/README.md
  <bundle-dir>/pwnkit-stability-sample.json
  <bundle-dir>/run-*/pwnkit-summary.redacted.json
  <bundle-dir>/run-*/agent-replay-trace-summary.json
  <bundle-dir>/SHA256SUMS

The bundle intentionally omits raw pwnkit DBs, auth JSON, stdout/stderr logs,
full proxy event logs, and private Eidolon debug logs.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

sha256_file() {
  local path="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path"
    return
  fi

  shasum -a 256 "$path"
}

ensure_empty_bundle_dir() {
  if [[ -e "$BUNDLE_DIR" && ! -d "$BUNDLE_DIR" ]]; then
    fail "bundle path exists and is not a directory: $BUNDLE_DIR"
  fi

  if [[ -d "$BUNDLE_DIR" ]] && [[ -n "$(find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    fail "bundle directory must be empty: $BUNDLE_DIR"
  fi

  mkdir -p "$BUNDLE_DIR"
}

redact_sample_summary() {
  local input="$1"
  local output="$2"

  jq '
    def omitted_source_path: "<source-artifact-path-omitted>";
    def safe_path:
      if type == "string" then split("?")[0] | split("#")[0] else . end;
    def clean_no_signal_diagnostics:
      if . == null then
        null
      else
        . + {
          proxy_path_counts: [
            (.proxy_path_counts // [])[] |
            {
              path: ((.path // .value) | safe_path),
              count
            }
          ]
        }
      end;
    def clean_sample_proxy:
      if . == null then
        null
      else
        . + {
          request_path_counts: [
            (.request_path_counts // [])[] |
            {
              value: ((.value // .path) | safe_path),
              count
            }
          ]
        }
      end;
    {
      schema_version,
      run_kind,
      generated_at,
      artifact_count,
      valid_summary_count,
      counts,
      rates,
      claim_level_counts,
      weakest_claim_level,
      strongest_claim_level,
      runner_git_heads,
      runner_package_versions,
      source_checkout,
      no_signal_diagnostics: (.no_signal_diagnostics | clean_no_signal_diagnostics),
      differential_findings,
      strict_stability,
      artifacts: [
        (.artifacts // [])[] |
        {
          artifact_dir: omitted_source_path,
          present,
          missing_reason,
          runner_git_head,
          runner_package_version,
          runner_git_dirty,
          runner_origin_main,
          runner_origin_main_in_sync,
          stale_dist_guard_bypassed,
          claim_level,
          conclusion,
          target_interaction_observed,
          bait_reached,
          bait_action_observed,
          same_session_confirmed_bait_action,
          controlled_reality_entered,
          direct_finding_count,
          eidolon_finding_count,
          finding_diagnostics,
          pwnkit_events,
          target_evidence_diagnostics,
          agent_error_diagnostics,
          eidolon_proxy: (.eidolon_proxy | clean_sample_proxy),
          target_correlation_diagnostics,
          finding_gap,
          correlated_counts,
          pinned_session,
          metrics,
          agent_trace
        }
      ],
      redaction: {
        raw_run_summaries_omitted: true,
        raw_requested_paths_omitted: true,
        raw_tool_evidence_labels_omitted: true,
        raw_agent_error_text_omitted: true,
        raw_pwnkit_artifacts_omitted: true,
        raw_proxy_events_omitted: true,
        private_debug_logs_omitted: true,
        source_artifact_paths_omitted: true,
        runner_command_paths_omitted: true
      }
    }
  ' "$input" > "$output"
}

redact_pwnkit_summary() {
  local input="$1"
  local output="$2"

  jq '
    def omitted_source_path: "<source-artifact-path-omitted>";
    def safe_path:
      if type == "string" then split("?")[0] | split("#")[0] else . end;
    def clean_scopes:
      if type == "object" then
        with_entries(.value |= (if type == "object" then del(.path) else . end))
      else
        .
      end;
    def clean_matrix:
      [
        (. // [])[] |
        {
          bait_id,
          exposure_count,
          action_count,
          same_session_confirmed_action_count,
          surfaces: [(.surfaces // [])[] | safe_path],
          action_paths: [(.action_paths // [])[] | safe_path]
        }
      ];
    def run_summary($run):
      {
        target: $run.target,
        scan_depth: $run.scan_depth,
        duration_ms: $run.duration_ms,
        finding_count: ($run.finding_count // 0),
        warning_count: (($run.warnings // []) | length),
        pwnkit_events: ($run.pwnkit_events // null),
        finding_diagnostics: ($run.finding_diagnostics // null),
        target_evidence_diagnostics: ($run.target_evidence_diagnostics // null),
        agent_error_diagnostics: ($run.agent_error_diagnostics // null)
      };
    {
      schema_version,
      run_kind,
      boundary,
      source_artifact_dir: omitted_source_path,
      runner: {
        schema_version: .runner.schema_version,
        run_kind: .runner.run_kind,
        created_at: .runner.created_at,
        mode: .runner.mode,
        urls: .runner.urls,
        pwnkit: {
          depth: .runner.pwnkit.depth,
          mode: .runner.pwnkit.mode,
          runtime: .runner.pwnkit.runtime,
          rate_limit: .runner.pwnkit.rate_limit,
          command_source: .runner.pwnkit.command_source,
          package_version: .runner.pwnkit.package_version,
          git_head: .runner.pwnkit.git_head,
          git_head_short: .runner.pwnkit.git_head_short,
          git_head_time_seconds: .runner.pwnkit.git_head_time_seconds,
          git_dirty: .runner.pwnkit.git_dirty,
          origin_main: .runner.pwnkit.origin_main,
          stale_dist_guard_bypassed: .runner.pwnkit.stale_dist_guard_bypassed,
          scopes: (.runner.pwnkit.scopes | clean_scopes)
        },
        eidolon: .runner.eidolon
      },
      runs: {
        eidolon: run_summary(.runs.eidolon // {}),
        direct: run_summary(.runs.direct // {})
      },
      eidolon_proxy: {
        present: .eidolon_proxy.present,
        event_count: .eidolon_proxy.event_count,
        request_count: .eidolon_proxy.request_count,
        kind_counts: .eidolon_proxy.kind_counts,
        routing_counts: .eidolon_proxy.routing_counts,
        counts: .eidolon_proxy.counts
      },
      comparison: {
        target_interaction_observed: .comparison.target_interaction_observed,
        bait_reached: .comparison.bait_reached,
        bait_action_observed: .comparison.bait_action_observed,
        same_session_confirmed_bait_action: .comparison.same_session_confirmed_bait_action,
        controlled_reality_entered: .comparison.controlled_reality_entered,
        conclusion: .comparison.conclusion,
        claim_level: .comparison.claim_level,
        correlated_target_request_count: ((.comparison.correlated_target_requests // []) | length),
        eidolon_requested_path_count: ((.comparison.eidolon_requested_paths // []) | length),
        direct_requested_path_count: ((.comparison.direct_requested_paths // []) | length),
        paths_only_eidolon_count: ((.comparison.paths_only_eidolon // []) | length),
        paths_only_direct_count: ((.comparison.paths_only_direct // []) | length),
        correlated_bait_event_counts: {
          exposures: ((.comparison.correlated_bait_events.exposures // []) | length),
          actions: ((.comparison.correlated_bait_events.actions // []) | length),
          same_session_confirmed_actions: ((.comparison.correlated_bait_events.same_session_confirmed_actions // []) | length),
          controlled_reality_entries: ((.comparison.correlated_bait_events.controlled_reality_entries // []) | length)
        },
        correlated_bait_matrix: ((.comparison.correlated_bait_events.matrix // []) | clean_matrix),
        target_correlation_diagnostics: .comparison.target_correlation_diagnostics,
        finding_gap: .comparison.finding_gap
      },
      metrics,
      pinned_session,
      notes,
      redaction: {
        raw_requested_paths_omitted: true,
        raw_correlated_target_requests_omitted: true,
        raw_correlated_bait_events_omitted: true,
        raw_agent_error_text_omitted: true,
        raw_tool_evidence_labels_omitted: true,
        warning_text_omitted: true,
        query_values_omitted: true,
        source_artifact_path_omitted: true,
        runner_command_paths_omitted: true,
        pwnkit_scope_paths_omitted: true
      }
    }
  ' "$input" > "$output"
}

redact_agent_trace() {
  local input="$1"
  local output="$2"

  jq '
    def omitted_source_path: "<source-artifact-path-omitted>";
    def safe_path:
      if type == "string" then split("?")[0] | split("#")[0] else . end;
    def redact_event_path:
      if has("surface") then .surface = (.surface | safe_path)
      elif has("path") then .path = (.path | safe_path)
      else .
      end;
    . as $root
    | {
        schema_version: $root.schema_version,
        run_kind: $root.run_kind,
        boundary: $root.boundary,
        evidence_source: $root.evidence_source,
        artifact_dir: omitted_source_path,
        claim_level: $root.claim_level,
        counts: $root.counts,
        metrics: $root.metrics,
        pinned_session: $root.pinned_session,
        sessions: $root.sessions,
        bait_events: {
          exposures: [($root.bait_events.exposures // [])[] | redact_event_path],
          actions: [($root.bait_events.actions // [])[] | redact_event_path],
          same_session_confirmed_actions: [
            ($root.bait_events.same_session_confirmed_actions // [])[] | redact_event_path
          ],
          controlled_reality_entries_after_confirmed_action: (
            $root.bait_events.controlled_reality_entries_after_confirmed_action // []
          )
        },
        notes: $root.notes,
        redaction: {
          query_values_omitted: true,
          full_proxy_events_omitted: true,
          private_debug_logs_omitted: true,
          source_artifact_path_omitted: true
        }
      }
  ' "$input" > "$output"
}

sample_value() {
  local filter="$1"
  jq -r "($filter) as \$value | if \$value == null then \"unknown\" else \$value end" \
    "$BUNDLE_DIR/pwnkit-stability-sample.json"
}

write_readme() {
  local collected_on
  local valid_count
  local ready
  local heads
  local versions
  local direct_counts
  local eidolon_counts
  local claim_counts

  collected_on="$(date -u +%F)"
  valid_count="$(sample_value '.valid_summary_count')"
  ready="$(sample_value '.strict_stability.ready_for_stability_claim')"
  heads="$(jq -r '(.runner_git_heads // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  versions="$(jq -r '(.runner_package_versions // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  direct_counts="$(jq -r '[(.artifacts // [])[] | (.direct_finding_count // 0)] | join("/")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  eidolon_counts="$(jq -r '[(.artifacts // [])[] | (.eidolon_finding_count // 0)] | join("/")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  claim_counts="$(jq -r '(.claim_level_counts // []) | map("`" + .claim_level + "`: `" + (.count|tostring) + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"

  {
    printf '# M3 pwnkit Sample Evidence\n\n'
    printf 'Lab-only evidence bundle packaged on %s.\n\n' "$collected_on"
    printf '## Scope\n\n'
    printf -- '- Boundary: owned loopback lab.\n'
    printf -- '- Source sample directory: omitted from the committed bundle.\n'
    printf -- '- pwnkit runner head(s): %s.\n' "${heads:-unknown}"
    printf -- '- pwnkit package version(s): %s.\n' "${versions:-unknown}"
    printf -- '- Session control: pinned Eidolon session cookie when enabled by the sample runner.\n\n'
    printf '## Contents\n\n'
    printf -- '- `pwnkit-stability-sample.json`: sample-level aggregate from `examples/m3/collect-pwnkit-sample.sh`.\n'
    printf -- '- `run-*/pwnkit-summary.redacted.json`: claim-focused redaction of each run summary.\n'
    printf -- '- `run-*/agent-replay-trace-summary.json`: sanitized proxy-trace summary for each run.\n'
    printf -- '- `SHA256SUMS`: checksums for committed evidence files.\n\n'
    printf '## Redaction\n\n'
    printf 'This bundle intentionally omits raw artifacts:\n\n'
    printf -- '- pwnkit SQLite databases\n'
    printf -- '- pwnkit auth JSON files\n'
    printf -- '- raw stdout and stderr logs\n'
    printf -- '- full proxy JSONL event logs\n'
    printf -- '- private Eidolon debug logs\n'
    printf -- '- raw pwnkit agent error text\n'
    printf -- '- raw requested-path arrays and tool evidence labels from pwnkit summaries\n\n'
    printf 'Redacted summaries preserve runner freshness metadata, finding counts, shape-only finding diagnostics, no-signal diagnostics, claim-level booleans, correlated evidence counts, bait matrix counts, pinned-session metrics, proxy count summaries, and M3 notes.\n\n'
    printf '## Result\n\n'
    printf -- '- valid summaries: `%s`\n' "$valid_count"
    printf -- '- claim levels: %s\n' "${claim_counts:-unknown}"
    printf -- '- direct findings: `%s`\n' "${direct_counts:-unknown}"
    printf -- '- Eidolon findings: `%s`\n' "${eidolon_counts:-unknown}"
    printf -- '- `strict_stability.ready_for_stability_claim`: `%s`\n\n' "$ready"
    printf 'This remains Lab-only evidence. It does not claim production readiness, autonomous-attacker identity, or stability beyond this sample on the recorded pwnkit head.\n'
  } > "$BUNDLE_DIR/README.md"
}

write_checksums() {
  (
    cd "$BUNDLE_DIR"
    find . -type f ! -name SHA256SUMS | sort | while read -r path; do
      sha256_file "${path#./}"
    done
  ) > "$BUNDLE_DIR/SHA256SUMS"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ -z "$SAMPLE_DIR" || -z "$BUNDLE_DIR" ]]; then
    usage >&2
    exit 2
  fi

  require_command jq
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
  fi

  if [[ ! -d "$SAMPLE_DIR" ]]; then
    fail "sample directory does not exist: $SAMPLE_DIR"
  fi

  local sample_summary="$SAMPLE_DIR/pwnkit-stability-sample.json"
  if [[ ! -f "$sample_summary" ]]; then
    fail "missing sample summary: $sample_summary"
  fi

  ensure_empty_bundle_dir
  "$SCRIPT_DIR/check-pwnkit-sample-health.sh" "$sample_summary"
  redact_sample_summary "$sample_summary" "$BUNDLE_DIR/pwnkit-stability-sample.json"

  local found_run=false
  local run_dir
  for run_dir in "$SAMPLE_DIR"/run-*; do
    [[ -d "$run_dir" ]] || continue
    found_run=true

    local run_name
    local output_run_dir
    run_name="$(basename "$run_dir")"
    output_run_dir="$BUNDLE_DIR/$run_name"
    mkdir -p "$output_run_dir"

    if [[ ! -f "$run_dir/pwnkit-summary.json" ]]; then
      fail "missing run summary: $run_dir/pwnkit-summary.json"
    fi
    if [[ ! -f "$run_dir/agent-replay-trace-summary.json" ]]; then
      fail "missing agent trace summary: $run_dir/agent-replay-trace-summary.json"
    fi

    redact_pwnkit_summary \
      "$run_dir/pwnkit-summary.json" \
      "$output_run_dir/pwnkit-summary.redacted.json"
    redact_agent_trace \
      "$run_dir/agent-replay-trace-summary.json" \
      "$output_run_dir/agent-replay-trace-summary.json"
  done

  if [[ "$found_run" != true ]]; then
    fail "sample directory contains no run-* directories: $SAMPLE_DIR"
  fi

  write_readme
  write_checksums

  echo "packaged pwnkit evidence bundle: $BUNDLE_DIR"
}

main "$@"
