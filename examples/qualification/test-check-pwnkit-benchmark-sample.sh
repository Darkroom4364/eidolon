#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CHECKER="$SCRIPT_DIR/check-pwnkit-benchmark-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-check-test.XXXXXX"
}

write_summary() {
  local output="$1"
  local mixed="${2:-false}"
  local unknown="${3:-0}"

  cat > "$output" <<JSON
{
  "schema_version": 1,
  "run_kind": "pwnkit_benchmark_sample",
  "boundary": "scanner_qualification",
  "claim_posture": "benchmark_capability_only",
  "evaluation_lane_version": 1,
  "generated_at": "2026-07-08T00:00:00Z",
  "lane": "xbow_benchmark",
  "benchmark_family": "xbow_public",
  "benchmark_task_id": "task-alpha",
  "benchmark_snapshot_id": "snap-001",
  "benchmark_model_id": "gpt-5.4",
  "benchmark_prompt_bundle_hash": "sha256:alpha",
  "benchmark_validation_rule": "validated_exploit_required",
  "substrate": "host_local",
  "defense_mode": "comparison",
  "artifact_identity": {
    "artifact_kind": "pwnkit_benchmark_sample",
    "raw_sample_summary_path": "/private/tmp/raw-sample/pwnkit-stability-sample.json",
    "validation_artifact_path": "/private/tmp/raw-sample/benchmark-validation.json"
  },
  "budget": {
    "benchmark_action_budget": 40,
    "benchmark_token_budget": 120000,
    "benchmark_wall_clock_budget_seconds": 900,
    "observed_artifact_count": 1,
    "observed_valid_summary_count": 1
  },
  "counts": {
    "raw_artifact_count": 1,
    "raw_valid_summary_count": 1,
    "direct_findings": 0,
    "eidolon_findings": 1,
    "positive_differential_findings": 1
  },
  "validation": {
    "status": "validated",
    "validator_kind": "fixture_validator",
    "exploit_rule": "validated_exploit_required",
    "notes": ["fixture benchmark validation"]
  },
  "raw_sample": {
    "run_kind": "m3_pwnkit_codex_sample",
    "strongest_claim_level": "controlled_reality_entered",
    "weakest_claim_level": "controlled_reality_entered",
    "runner_git_heads": ["fixture-head"],
    "runner_package_versions": ["fixture-version"],
    "runner_environments": ["host_mac"],
    "runner_network_topologies": ["same_host_loopback"],
    "evidence_tracks": ["upstream_current"],
    "mixed_evidence_tracks": $mixed,
    "unknown_evidence_track_count": $unknown
  },
  "artifacts": [
    {
      "artifact_id": "raw-sample",
      "lane": "xbow_benchmark",
      "benchmark_family": "xbow_public",
      "benchmark_task_id": "task-alpha",
      "substrate": "host_local",
      "defense_mode": "comparison",
      "artifact_identity": {
        "artifact_kind": "pwnkit_benchmark_raw_sample",
        "raw_sample_summary_path": "/private/tmp/raw-sample/pwnkit-stability-sample.json"
      },
      "validation_status": "validated",
      "strongest_claim_level": "controlled_reality_entered",
      "direct_findings": 0,
      "eidolon_findings": 1
    }
  ]
}
JSON
}

test_checker_accepts_valid_sample() {
  local temp_dir summary
  temp_dir="$(new_temp_dir)"
  summary="$temp_dir/pwnkit-stability-sample.json"
  write_summary "$summary"
  "$CHECKER" "$summary"
}

test_checker_rejects_mixed_tracks() {
  local temp_dir summary output status=0
  temp_dir="$(new_temp_dir)"
  summary="$temp_dir/pwnkit-stability-sample.json"
  write_summary "$summary" true 0
  output="$("$CHECKER" "$summary" 2>&1)" || status="$?"
  [[ "$status" -eq 1 ]]
  rg -q 'benchmark sample evidence tracks are not claim-safe' <<<"$output"
}

test_checker_rejects_missing_task_identity() {
  local temp_dir summary output status=0
  temp_dir="$(new_temp_dir)"
  summary="$temp_dir/pwnkit-stability-sample.json"
  write_summary "$summary"
  jq 'del(.benchmark_task_id)' "$summary" > "$summary.tmp"
  mv "$summary.tmp" "$summary"
  output="$("$CHECKER" "$summary" 2>&1)" || status="$?"
  [[ "$status" -eq 2 ]]
  rg -q 'invalid benchmark sample contract' <<<"$output"
}

test_checker_accepts_valid_sample
test_checker_rejects_mixed_tracks
test_checker_rejects_missing_task_identity

printf 'benchmark sample checker fixture tests passed\n'
