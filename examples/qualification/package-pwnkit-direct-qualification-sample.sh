#!/usr/bin/env bash
set -euo pipefail

SAMPLE_DIR="${1:-}"
BUNDLE_DIR="${2:-}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/package-pwnkit-direct-qualification-sample.sh <sample-dir> <bundle-dir>

Packages a completed direct-only pwnkit qualification sample into a commit-safe
bundle.
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
    {
      schema_version,
      run_kind,
      boundary,
      claim_posture,
      evaluation_lane_version,
      lane,
      benchmark_family,
      defense_mode,
      substrate,
      artifact_identity,
      budget,
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
      runner_pwnkit_fixture_ids,
      evidence_track_counts,
      evidence_tracks,
      single_evidence_track,
      mixed_evidence_tracks,
      unknown_evidence_track_count,
      runner_environments,
      substrate_counts,
      runner_network_topologies,
      tool_fingerprint_summary,
      source_checkout,
      finding_reconciliation,
      no_signal_diagnostics,
      qualification_result,
      strict_stability,
      artifacts: [
        (.artifacts // [])[] |
        {
          artifact_dir: omitted_source_path,
          present,
          missing_reason,
          lane,
          benchmark_family,
          defense_mode,
          substrate,
          artifact_identity: (
            if (.artifact_identity // null) == null then
              null
            else
              (.artifact_identity + {artifact_dir: omitted_source_path})
            end
          ),
          evidence_track,
          runner_git_head,
          runner_package_version,
          runner_git_dirty,
          runner_origin_main,
          runner_origin_main_in_sync,
          runner_pwnkit_fixture,
          runner_pwnkit_fixture_id,
          stale_dist_guard_bypassed,
          runner_environment,
          runner_environment_source,
          runner_network_topology,
          runner_os,
          runner_tool_fingerprint,
          claim_level,
          target_interaction_observed,
          direct_finding_count,
          direct_final_json_finding_count,
          direct_db_saved_finding_count,
          direct_db_active_finding_count,
          finding_diagnostics,
          finding_reconciliation,
          pwnkit_events,
          target_evidence_diagnostics,
          agent_error_diagnostics
        }
      ],
      redaction: {
        source_artifact_paths_omitted: true,
        raw_pwnkit_artifacts_omitted: true,
        raw_agent_error_text_omitted: true,
        raw_stdout_stderr_omitted: true
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
        urls: {
          target: .runner.urls.target,
          proxy: "<proxy-url-omitted>"
        },
        environment: .runner.environment,
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
          evidence_track: .runner.pwnkit.evidence_track,
          fixture: (
            if (.runner.pwnkit.fixture // null) == null then
              null
            else
              {
                id: (.runner.pwnkit.fixture.id // null),
                pinned: (.runner.pwnkit.fixture.pinned // false)
              }
            end
          ),
          stale_dist_guard_bypassed: .runner.pwnkit.stale_dist_guard_bypassed
        }
      },
      runs: {
        direct: {
          target: .runs.direct.target,
          scan_depth: .runs.direct.scan_depth,
          duration_ms: .runs.direct.duration_ms,
          finding_count: (.runs.direct.finding_count // 0),
          final_json_finding_count: (.runs.direct.final_json_finding_count // 0),
          db_saved_finding_count: (.runs.direct.db_saved_finding_count // 0),
          db_active_finding_count: (.runs.direct.db_active_finding_count // 0),
          pwnkit_events: (.runs.direct.pwnkit_events // null),
          target_evidence_diagnostics: (.runs.direct.target_evidence_diagnostics // null),
          agent_error_diagnostics: (.runs.direct.agent_error_diagnostics // null)
        },
        eidolon: {
          artifact_status: (.runs.eidolon.artifact_status // "missing")
        }
      },
      redaction: {
        source_artifact_path_omitted: true,
        query_values_omitted: true
      }
    }
  ' "$input" > "$output"
}

write_readme() {
  {
    printf '# pwnkit Direct Qualification Sample\n\n'
    printf 'scanner-qualification direct-only negative-control bundle.\n\n'
    printf 'lane: `eidolon_owned_target`; defense: `none`.\n\n'
    printf '## Contents\n\n'
    printf -- '- `pwnkit-stability-sample.json`: aggregate direct-only qualification summary.\n'
    printf -- '- `run-*/pwnkit-summary.redacted.json`: redacted per-run direct scan summaries.\n'
    printf -- '- `SHA256SUMS`: checksums for committed bundle files.\n'
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
  local sample_summary
  local found_run=false
  local run_dir
  local output_run_dir

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

  sample_summary="$SAMPLE_DIR/pwnkit-stability-sample.json"
  if [[ ! -f "$sample_summary" ]]; then
    fail "missing sample summary: $sample_summary"
  fi

  ensure_empty_bundle_dir
  redact_sample_summary "$sample_summary" "$BUNDLE_DIR/pwnkit-stability-sample.json"

  for run_dir in "$SAMPLE_DIR"/run-*; do
    [[ -d "$run_dir" ]] || continue
    found_run=true
    output_run_dir="$BUNDLE_DIR/$(basename "$run_dir")"
    mkdir -p "$output_run_dir"

    if [[ ! -f "$run_dir/pwnkit-summary.json" ]]; then
      fail "missing run summary: $run_dir/pwnkit-summary.json"
    fi

    redact_pwnkit_summary \
      "$run_dir/pwnkit-summary.json" \
      "$output_run_dir/pwnkit-summary.redacted.json"
  done

  if [[ "$found_run" != true ]]; then
    fail "sample directory contains no run-* directories: $SAMPLE_DIR"
  fi

  write_readme
  write_checksums
  echo "packaged direct qualification bundle: $BUNDLE_DIR"
}

main "$@"
