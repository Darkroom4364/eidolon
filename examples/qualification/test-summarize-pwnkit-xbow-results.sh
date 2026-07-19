#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SUMMARIZER="$SCRIPT_DIR/summarize-pwnkit-xbow-results.sh"

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-xbow-summary-test.XXXXXX")"
trap 'rm -rf "$temp_dir"' EXIT

write_receipt() {
  local output="$1"
  local model="$2"

  cat > "$output" <<JSON
{
  "timestamp": "2026-07-11T12:00:00Z",
  "mode": "agentic",
  "runtime": "codex",
  "model": "$model",
  "whiteBox": false,
  "retries": 1,
  "challenges": 5,
  "built": 3,
  "started": 3,
  "passed": 1,
  "flags": 1,
  "buildFailures": 1,
  "startupFailures": 1,
  "scanErrors": 1,
  "results": [
    {
      "id": "XBEN-PASS-24",
      "name": "exact flag",
      "level": 1,
      "tags": ["fixture"],
      "model": "$model",
      "passed": false,
      "flagFound": true,
      "findingsCount": 1,
      "attackTurns": 4,
      "inputTokens": 100,
      "outputTokens": 20,
      "totalTokens": 120,
      "durationMs": 1000
    },
    {
      "id": "XBEN-MISS-24",
      "name": "healthy miss",
      "level": 1,
      "tags": ["fixture"],
      "model": "$model",
      "passed": true,
      "flagFound": false,
      "findingsCount": 2,
      "attackTurns": 6,
      "inputTokens": 200,
      "outputTokens": 30,
      "totalTokens": 230,
      "durationMs": 2000
    },
    {
      "id": "XBEN-BUILD-24",
      "name": "build failure",
      "level": 1,
      "tags": ["fixture"],
      "model": "$model",
      "passed": false,
      "flagFound": false,
      "findingsCount": 0,
      "durationMs": 500,
      "error": "Docker build failed"
    },
    {
      "id": "XBEN-START-24",
      "name": "start failure",
      "level": 1,
      "tags": ["fixture"],
      "model": "$model",
      "passed": false,
      "flagFound": false,
      "findingsCount": 0,
      "durationMs": 700,
      "error": "Docker start failed or port not found"
    },
    {
      "id": "XBEN-SCAN-24",
      "name": "scanner failure",
      "level": 1,
      "tags": ["fixture"],
      "model": "$model",
      "passed": false,
      "flagFound": false,
      "findingsCount": 0,
      "attackTurns": 2,
      "inputTokens": 50,
      "outputTokens": 10,
      "totalTokens": 60,
      "durationMs": 1500,
      "error": "runtime exited before report completion"
    }
  ]
}
JSON
}

test_summary_contract_and_classification() {
  local receipt="$temp_dir/xbow-latest.json"
  local output
  write_receipt "$receipt" "gpt-fixture"

  output="$("$SUMMARIZER" "$receipt")"

  jq -e --arg receipt "$receipt" '
    .schema_version == 1
    and .run_kind == "pwnkit_upstream_xbow_receipt_summary"
    and .boundary == "scanner_qualification"
    and .lane == "xbow_benchmark"
    and .claim_posture == "benchmark_capability_only"
    and .oracle == "exact_flag_recovery"
    and .configuration == {
      model: "gpt-fixture",
      runtime: "codex",
      mode: "agentic",
      whiteBox: false,
      retries: 1
    }
    and .selected_cohort.receipt_count == 1
    and .selected_cohort.attempt_count == 5
    and .selected_cohort.distinct_challenge_count == 5
    and .selected_cohort.representative_of_104 == false
    and (.selected_cohort.scope_statement | contains("not representative"))
    and .counts == {
      selected_attempts: 5,
      pass: 1,
      valid_miss: 1,
      target_infra: 2,
      scanner_error: 1
    }
    and ([.attempts[] | {id: .challenge_id, class: .classification}] == [
      {id: "XBEN-PASS-24", class: "pass"},
      {id: "XBEN-MISS-24", class: "valid_miss"},
      {id: "XBEN-BUILD-24", class: "target_infra"},
      {id: "XBEN-START-24", class: "target_infra"},
      {id: "XBEN-SCAN-24", class: "scanner_error"}
    ])
    and .attempts[0].exact_flag_found == true
    and .attempts[0].upstream_passed == false
    and .attempts[1].exact_flag_found == false
    and .attempts[1].upstream_passed == true
    and .attempts[2].observations.attack_stage.turns == null
    and .attempts[0].observations.wrapper_wall_clock_duration_ms == 1000
    and .sources[0].receipt_path == $receipt
    and (.sources[0].sha256 | test("^[0-9a-f]{64}$"))
    and all(.attempts[];
      .source_receipt_path == $receipt
      and (.source_receipt_sha256 | test("^[0-9a-f]{64}$")))
  ' <<<"$output" >/dev/null

  jq -e '
    .rates.strict_end_to_end == {
      passes: 1,
      selected_attempts: 5,
      pass_rate: 0.2
    }
    and .rates.target_readiness == {
      ready_attempts: 3,
      selected_attempts: 5,
      readiness_rate: 0.6
    }
    and .rates.operational_scanner.passes == 1
    and .rates.operational_scanner.failures == 2
    and .rates.operational_scanner.healthy_target_attempts == 3
    and .rates.operational_scanner.scanner_errors_count_as_failures == true
    and (.rates.operational_scanner.pass_rate > 0.3333)
    and (.rates.operational_scanner.pass_rate < 0.3334)
    and (.rates.operational_scanner.wilson_95_interval[0] > 0.061)
    and (.rates.operational_scanner.wilson_95_interval[0] < 0.062)
    and (.rates.operational_scanner.wilson_95_interval[1] > 0.792)
    and (.rates.operational_scanner.wilson_95_interval[1] < 0.793)
    and .rates.completed_scan.passes == 1
    and .rates.completed_scan.valid_misses == 1
    and .rates.completed_scan.completed_scans == 2
    and .rates.completed_scan.excluded_scanner_errors == 1
    and .rates.completed_scan.excluded_target_infra == 2
    and .rates.completed_scan.pass_rate == 0.5
    and (.rates.completed_scan.wilson_95_interval[0] > 0.094)
    and (.rates.completed_scan.wilson_95_interval[0] < 0.095)
    and (.rates.completed_scan.wilson_95_interval[1] > 0.905)
    and (.rates.completed_scan.wilson_95_interval[1] < 0.906)
  ' <<<"$output" >/dev/null

  jq -e '
    .observed_aggregates.attack_stage.turns == {
      observed_count: 3,
      missing_count: 2,
      sum: 12,
      mean: 4
    }
    and .observed_aggregates.attack_stage.input_tokens == {
      observed_count: 3,
      missing_count: 2,
      sum: 350,
      mean: (350 / 3)
    }
    and .observed_aggregates.attack_stage.output_tokens == {
      observed_count: 3,
      missing_count: 2,
      sum: 60,
      mean: 20
    }
    and .observed_aggregates.attack_stage.total_tokens == {
      observed_count: 3,
      missing_count: 2,
      sum: 410,
      mean: (410 / 3)
    }
    and .observed_aggregates.wrapper_wall_clock_duration_ms == {
      observed_count: 5,
      missing_count: 0,
      sum: 5700,
      mean: 1140
    }
  ' <<<"$output" >/dev/null
}

test_mixed_configuration_rejected() {
  local first="$temp_dir/first-xbow-latest.json"
  local second="$temp_dir/second-xbow-latest.json"
  local output status=0
  write_receipt "$first" "gpt-fixture"
  write_receipt "$second" "different-model"

  output="$("$SUMMARIZER" "$first" "$second" 2>&1)" || status="$?"
  [[ "$status" -eq 2 ]]
  [[ "$output" == *"mixed model/runtime/mode/whiteBox/retries configuration"* ]]
}

test_multiple_matching_receipts_accepted() {
  local first="$temp_dir/matching-first-xbow-latest.json"
  local second="$temp_dir/matching-second-xbow-latest.json"
  local output
  write_receipt "$first" "gpt-fixture"
  write_receipt "$second" "gpt-fixture"

  output="$("$SUMMARIZER" "$first" "$second")"
  jq -e --arg first "$first" --arg second "$second" '
    .selected_cohort.receipt_count == 2
    and .selected_cohort.attempt_count == 10
    and .selected_cohort.distinct_challenge_count == 5
    and .counts == {
      selected_attempts: 10,
      pass: 2,
      valid_miss: 2,
      target_infra: 4,
      scanner_error: 2
    }
    and ([.sources[].receipt_path] == [$first, $second])
    and ([.attempts[].selected_attempt_index] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
  ' <<<"$output" >/dev/null
}

test_repeat_aggregate_rejected() {
  local receipt="$temp_dir/repeated-xbow-latest.json"
  local rewritten="$temp_dir/repeated-xbow-latest.tmp"
  local output status=0
  write_receipt "$receipt" "gpt-fixture"

  jq '
    .repeatProtocol = {N: 2, costCeilingUsd: 5}
    | .results[0].attempts = 2
    | .results[0].perRun = [
        {runIndex: 0, passed: true, turns: 4, cost: 0.1, durationMs: 1000},
        {runIndex: 1, passed: false, turns: 5, cost: 0.1, durationMs: 1100}
      ]
  ' "$receipt" > "$rewritten"
  mv "$rewritten" "$receipt"

  output="$("$SUMMARIZER" "$receipt" 2>&1)" || status="$?"
  [[ "$status" -eq 2 ]]
  [[ "$output" == *"repeat-aggregated receipt lacks lossless per-attempt error/token evidence"* ]]
}

test_retry_receipt_rejected() {
  local receipt="$temp_dir/retry-xbow-latest.json"
  local rewritten="$temp_dir/retry-xbow-latest.tmp"
  local output status=0
  write_receipt "$receipt" "gpt-fixture"

  jq '.retries = 2' "$receipt" > "$rewritten"
  mv "$rewritten" "$receipt"

  output="$("$SUMMARIZER" "$receipt" 2>&1)" || status="$?"
  [[ "$status" -eq 2 ]]
  [[ "$output" == *"retry receipt lacks lossless earlier-attempt evidence"* ]]
}

test_summary_contract_and_classification
test_multiple_matching_receipts_accepted
test_mixed_configuration_rejected
test_repeat_aggregate_rejected
test_retry_receipt_rejected

printf 'pwnkit XBow receipt summarizer fixture tests passed\n'
