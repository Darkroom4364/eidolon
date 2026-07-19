#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/qualification/collect-pwnkit-benchmark-sample.sh <raw-sample-summary.json> [benchmark-validation.json]

Collects a benchmark-capability summary from one raw pwnkit sample summary and
an optional benchmark validation artifact.

Required environment:
  EIDOLON_PWNKIT_BENCHMARK_FAMILY
  EIDOLON_PWNKIT_BENCHMARK_TASK_ID
  EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID
  EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE

Optional environment:
  EIDOLON_PWNKIT_BENCHMARK_MODEL_ID
  EIDOLON_PWNKIT_BENCHMARK_PROMPT_BUNDLE_HASH
  EIDOLON_PWNKIT_BENCHMARK_ACTION_BUDGET
  EIDOLON_PWNKIT_BENCHMARK_TOKEN_BUDGET
  EIDOLON_PWNKIT_BENCHMARK_WALL_CLOCK_BUDGET_SECONDS
  EIDOLON_PWNKIT_BENCHMARK_DEFENSE_MODE
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

require_env() {
  local name="$1"
  local value="${!name:-}"
  [[ -n "$value" ]] || fail "$name must not be empty"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ "$#" -ge 1 && "$#" -le 2 ]] || fail "pass raw-sample summary and optional benchmark validation artifact"
command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"

RAW_SAMPLE="$1"
VALIDATION_FILE="${2:-}"

require_file "$RAW_SAMPLE"
if [[ -n "$VALIDATION_FILE" ]]; then
  require_file "$VALIDATION_FILE"
fi

require_env EIDOLON_PWNKIT_BENCHMARK_FAMILY
require_env EIDOLON_PWNKIT_BENCHMARK_TASK_ID
require_env EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID
require_env EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE

jq -n \
  --slurpfile raw "$RAW_SAMPLE" \
  --slurpfile validation "${VALIDATION_FILE:-/dev/null}" \
  --arg raw_path "$RAW_SAMPLE" \
  --arg validation_path "$VALIDATION_FILE" \
  --arg benchmark_family "$EIDOLON_PWNKIT_BENCHMARK_FAMILY" \
  --arg benchmark_task_id "$EIDOLON_PWNKIT_BENCHMARK_TASK_ID" \
  --arg benchmark_snapshot_id "$EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID" \
  --arg benchmark_model_id "${EIDOLON_PWNKIT_BENCHMARK_MODEL_ID:-}" \
  --arg benchmark_prompt_bundle_hash "${EIDOLON_PWNKIT_BENCHMARK_PROMPT_BUNDLE_HASH:-}" \
  --arg benchmark_validation_rule "$EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE" \
  --arg defense_mode "${EIDOLON_PWNKIT_BENCHMARK_DEFENSE_MODE:-none}" \
  --arg action_budget "${EIDOLON_PWNKIT_BENCHMARK_ACTION_BUDGET:-}" \
  --arg token_budget "${EIDOLON_PWNKIT_BENCHMARK_TOKEN_BUDGET:-}" \
  --arg wall_clock_budget_seconds "${EIDOLON_PWNKIT_BENCHMARK_WALL_CLOCK_BUDGET_SECONDS:-}" '
  ($raw[0]) as $sample
  | ($validation[0] // null) as $validation_artifact
  | {
      schema_version: 1,
      run_kind: "pwnkit_benchmark_sample",
      boundary: "scanner_qualification",
      claim_posture: "benchmark_capability_only",
      evaluation_lane_version: 1,
      generated_at: (now | todateiso8601),
      lane: "xbow_benchmark",
      benchmark_family: $benchmark_family,
      benchmark_task_id: $benchmark_task_id,
      benchmark_snapshot_id: $benchmark_snapshot_id,
      benchmark_model_id: (if $benchmark_model_id == "" then null else $benchmark_model_id end),
      benchmark_prompt_bundle_hash: (
        if $benchmark_prompt_bundle_hash == "" then null else $benchmark_prompt_bundle_hash end
      ),
      benchmark_validation_rule: $benchmark_validation_rule,
      substrate: (
        if (($sample.substrate // null) != null) then
          $sample.substrate
        elif (($sample.runner_network_topologies // []) | length) > 0 then
          ($sample.runner_network_topologies[0])
        else
          "unknown"
        end
      ),
      defense_mode: $defense_mode,
      artifact_identity: {
        artifact_kind: "pwnkit_benchmark_sample",
        raw_sample_summary_path: $raw_path,
        validation_artifact_path: (if $validation_path == "" then null else $validation_path end)
      },
      budget: {
        benchmark_action_budget: (if $action_budget == "" then null else ($action_budget | tonumber) end),
        benchmark_token_budget: (if $token_budget == "" then null else ($token_budget | tonumber) end),
        benchmark_wall_clock_budget_seconds: (
          if $wall_clock_budget_seconds == "" then null else ($wall_clock_budget_seconds | tonumber) end
        ),
        observed_artifact_count: ($sample.artifact_count // 0),
        observed_valid_summary_count: ($sample.valid_summary_count // 0)
      },
      counts: {
        raw_artifact_count: ($sample.artifact_count // 0),
        raw_valid_summary_count: ($sample.valid_summary_count // 0),
        direct_findings: ($sample.counts.direct_findings // 0),
        eidolon_findings: ($sample.counts.eidolon_findings // 0),
        positive_differential_findings: ($sample.counts.positive_differential_findings // 0)
      },
      validation: (
        if $validation_artifact == null then
          {
            status: "inconclusive",
            validator_kind: "none",
            exploit_rule: $benchmark_validation_rule,
            notes: ["no benchmark validation artifact supplied"]
          }
        else
          {
            status: ($validation_artifact.validation_status // "inconclusive"),
            validator_kind: ($validation_artifact.validator_kind // "unknown"),
            exploit_rule: ($validation_artifact.exploit_rule // $benchmark_validation_rule),
            notes: ($validation_artifact.notes // [])
          }
        end
      ),
      raw_sample: {
        run_kind: ($sample.run_kind // null),
        strongest_claim_level: ($sample.strongest_claim_level // null),
        weakest_claim_level: ($sample.weakest_claim_level // null),
        runner_git_heads: ($sample.runner_git_heads // []),
        runner_package_versions: ($sample.runner_package_versions // []),
        runner_environments: ($sample.runner_environments // []),
        runner_network_topologies: ($sample.runner_network_topologies // []),
        evidence_tracks: ($sample.evidence_tracks // [])
      },
      artifacts: [
        {
          artifact_id: "raw-sample",
          lane: "xbow_benchmark",
          benchmark_family: $benchmark_family,
          benchmark_task_id: $benchmark_task_id,
          substrate: (
            if (($sample.substrate // null) != null) then
              $sample.substrate
            elif (($sample.runner_network_topologies // []) | length) > 0 then
              ($sample.runner_network_topologies[0])
            else
              "unknown"
            end
          ),
          defense_mode: $defense_mode,
          artifact_identity: {
            artifact_kind: "pwnkit_benchmark_raw_sample",
            raw_sample_summary_path: $raw_path
          },
          validation_status: (
            if $validation_artifact == null then
              "inconclusive"
            else
              ($validation_artifact.validation_status // "inconclusive")
            end
          ),
          strongest_claim_level: ($sample.strongest_claim_level // null),
          direct_findings: ($sample.counts.direct_findings // 0),
          eidolon_findings: ($sample.counts.eidolon_findings // 0)
        }
      ]
    }
  '
