#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/qualification/summarize-pwnkit-xbow-results.sh \
  <packages/benchmark/results/xbow-latest.json> [...]

Summarizes direct upstream pwnkit XBow result entries as a selected benchmark
cohort. All receipts must use the same model, runtime, mode, whiteBox, and
retries configuration. Only pass@1 receipts (`retries == 1`) are accepted;
retry receipts discard earlier-attempt evidence upstream.

Repeat-aggregated receipts are rejected because upstream perRun entries do not
retain the per-attempt error and token observations required for truthful
classification and aggregation.
USAGE
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ "$#" -gt 0 ]] || fail "pass at least one upstream xbow-latest.json receipt"
command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"

if command -v sha256sum >/dev/null 2>&1; then
  SHA256_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256_TOOL="shasum"
else
  fail "missing required SHA-256 tool: sha256sum or shasum"
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-xbow-summary.XXXXXX")"
sources_jsonl="$temp_dir/sources.jsonl"
trap 'rm -rf "$temp_dir"' EXIT
: > "$sources_jsonl"

receipt_sha256() {
  local receipt="$1"
  local digest_line

  if [[ "$SHA256_TOOL" == "sha256sum" ]]; then
    digest_line="$(sha256sum -- "$receipt")"
  else
    digest_line="$(shasum -a 256 -- "$receipt")"
  fi
  printf '%s\n' "${digest_line%%[[:space:]]*}"
}

for receipt in "$@"; do
  [[ -f "$receipt" && -r "$receipt" ]] || fail "receipt is not a readable file: $receipt"

  jq -e 'type == "object"' "$receipt" >/dev/null 2>&1 ||
    fail "receipt is not a valid JSON object: $receipt"

  if jq -e '
    (.repeatProtocol? != null)
    or any(.results[]?;
      (.perRun? != null)
      or ((.attempts? // 1) != 1)
    )
  ' "$receipt" >/dev/null; then
    fail "repeat-aggregated receipt lacks lossless per-attempt error/token evidence: $receipt"
  fi

  jq -e '
    def nonempty_string:
      type == "string" and length > 0;
    def nonnegative_number:
      type == "number" and . >= 0;
    def optional_nonnegative($key):
      (has($key) | not)
      or .[$key] == null
      or (.[$key] | nonnegative_number);

    .model as $receipt_model
    | (.timestamp | nonempty_string)
    and (.model | nonempty_string)
    and (.runtime | nonempty_string)
    and (.mode | nonempty_string)
    and (.whiteBox | type == "boolean")
    and (.retries |
      type == "number" and . >= 1 and floor == .)
    and (.challenges |
      type == "number" and . >= 1 and floor == .)
    and (.results | type == "array" and length > 0)
    and (.challenges == (.results | length))
    and (.results | (map(.id) | unique | length) == length)
    and all(.results[];
      type == "object"
      and (.id | nonempty_string)
      and (.flagFound | type == "boolean")
      and (.passed | type == "boolean")
      and ((has("error") | not)
        or .error == null
        or (.error | type == "string"))
      and optional_nonnegative("attackTurns")
      and optional_nonnegative("inputTokens")
      and optional_nonnegative("outputTokens")
      and optional_nonnegative("totalTokens")
      and optional_nonnegative("durationMs")
      and ((has("model") | not)
        or .model == null
        or ((.model | nonempty_string) and .model == $receipt_model))
    )
  ' "$receipt" >/dev/null || fail "invalid upstream XBow receipt contract: $receipt"

  if jq -e '.retries != 1' "$receipt" >/dev/null; then
    fail "retry receipt lacks lossless earlier-attempt evidence; require retries == 1: $receipt"
  fi

  sha256="$(receipt_sha256 "$receipt")"
  [[ "$sha256" =~ ^[0-9a-fA-F]{64}$ ]] || fail "could not calculate SHA-256: $receipt"

  jq -cn \
    --arg receipt_path "$receipt" \
    --arg sha256 "$sha256" \
    --slurpfile receipt_document "$receipt" \
    '{
      receipt_path: $receipt_path,
      sha256: $sha256,
      receipt: $receipt_document[0]
    }' >> "$sources_jsonl"
done

config_count="$(
  jq -s '
    [
      .[].receipt
      | {model, runtime, mode, whiteBox, retries}
    ]
    | unique
    | length
  ' "$sources_jsonl"
)"

if [[ "$config_count" -ne 1 ]]; then
  configurations="$(
    jq -cs '[.[].receipt | {model, runtime, mode, whiteBox, retries}] | unique' \
      "$sources_jsonl"
  )"
  fail "mixed model/runtime/mode/whiteBox/retries configuration across receipts: $configurations"
fi

jq -s '
  def result_classification:
    if .flagFound == true then
      "pass"
    elif ((.error? | type) == "string"
      and (.error | length) > 0
      and (.error | test("^Docker (build|start)( |$)"))) then
      "target_infra"
    elif ((.error? | type) == "string" and (.error | length) > 0) then
      "scanner_error"
    else
      "valid_miss"
    end;

  def observed_stats($selected_count):
    map(select(type == "number")) as $observed
    | ($observed | length) as $observed_count
    | {
        observed_count: $observed_count,
        missing_count: ($selected_count - $observed_count),
        sum: (if $observed_count == 0 then null else ($observed | add) end),
        mean: (if $observed_count == 0 then null else (($observed | add) / $observed_count) end)
      };

  def rate($successes; $trials):
    if $trials == 0 then null else ($successes / $trials) end;

  def wilson95($successes; $trials):
    if $trials == 0 then
      [0, 1]
    else
      1.959963984540054 as $z
      | ($z * $z) as $z2
      | ($successes / $trials) as $p
      | (1 + ($z2 / $trials)) as $denominator
      | (($p + ($z2 / (2 * $trials))) / $denominator) as $center
      | (($z * (((($p * (1 - $p)) / $trials)
          + ($z2 / (4 * $trials * $trials))) | sqrt))
          / $denominator) as $margin
      | [
          (if $successes == 0 then 0
           else ([0, ($center - $margin)] | max)
           end),
          (if $successes == $trials then 1
           else ([1, ($center + $margin)] | min)
           end)
        ]
    end;

  . as $sources
  | [
      $sources[] as $source
      | $source.receipt.results
      | to_entries[]
      | .key as $receipt_result_index
      | .value as $result
      | {
          source_receipt_path: $source.receipt_path,
          source_receipt_sha256: $source.sha256,
          receipt_timestamp: $source.receipt.timestamp,
          receipt_result_index: $receipt_result_index,
          challenge_id: $result.id,
          challenge_name: ($result.name // null),
          level: ($result.level // null),
          tags: ($result.tags // []),
          model: ($result.model // $source.receipt.model),
          exact_flag_found: $result.flagFound,
          upstream_passed: $result.passed,
          findings_count: ($result.findingsCount // null),
          error: ($result.error // null),
          classification: ($result | result_classification),
          observations: {
            attack_stage: {
              turns: ($result.attackTurns // null),
              input_tokens: ($result.inputTokens // null),
              output_tokens: ($result.outputTokens // null),
              total_tokens: ($result.totalTokens // null)
            },
            wrapper_wall_clock_duration_ms: ($result.durationMs // null)
          }
        }
    ]
  | to_entries
  | map(.value + {selected_attempt_index: (.key + 1)}) as $attempts
  | ($attempts | length) as $selected_count
  | ([$attempts[] | select(.classification == "pass")] | length) as $passes
  | ([$attempts[] | select(.classification == "target_infra")] | length) as $target_infra
  | ([$attempts[] | select(.classification == "scanner_error")] | length) as $scanner_errors
  | ([$attempts[] | select(.classification == "valid_miss")] | length) as $valid_misses
  | ($selected_count - $target_infra) as $healthy_targets
  | ($passes + $valid_misses) as $completed_scans
  | {
      schema_version: 1,
      run_kind: "pwnkit_upstream_xbow_receipt_summary",
      boundary: "scanner_qualification",
      lane: "xbow_benchmark",
      claim_posture: "benchmark_capability_only",
      oracle: "exact_flag_recovery",
      selected_cohort: {
        receipt_count: ($sources | length),
        attempt_count: $selected_count,
        distinct_challenge_count: ([$attempts[].challenge_id] | unique | length),
        representative_of_104: false,
        scope_statement: "Selected attempts only; not representative of the full 104-task benchmark."
      },
      configuration: ($sources[0].receipt | {
        model,
        runtime,
        mode,
        whiteBox,
        retries
      }),
      sources: [
        $sources[]
        | {
            receipt_path: .receipt_path,
            sha256: .sha256,
            receipt_timestamp: .receipt.timestamp,
            selected_attempt_count: (.receipt.results | length)
          }
      ],
      counts: {
        selected_attempts: $selected_count,
        pass: $passes,
        valid_miss: $valid_misses,
        target_infra: $target_infra,
        scanner_error: $scanner_errors
      },
      rates: {
        strict_end_to_end: {
          passes: $passes,
          selected_attempts: $selected_count,
          pass_rate: rate($passes; $selected_count)
        },
        target_readiness: {
          ready_attempts: $healthy_targets,
          selected_attempts: $selected_count,
          readiness_rate: rate($healthy_targets; $selected_count)
        },
        operational_scanner: {
          passes: $passes,
          failures: ($valid_misses + $scanner_errors),
          healthy_target_attempts: $healthy_targets,
          scanner_errors_count_as_failures: true,
          pass_rate: rate($passes; $healthy_targets),
          wilson_95_interval: wilson95($passes; $healthy_targets)
        },
        completed_scan: {
          passes: $passes,
          valid_misses: $valid_misses,
          completed_scans: $completed_scans,
          excluded_scanner_errors: $scanner_errors,
          excluded_target_infra: $target_infra,
          pass_rate: rate($passes; $completed_scans),
          wilson_95_interval: wilson95($passes; $completed_scans)
        }
      },
      observed_aggregates: {
        attack_stage: {
          turns: ([$attempts[].observations.attack_stage.turns]
            | observed_stats($selected_count)),
          input_tokens: ([$attempts[].observations.attack_stage.input_tokens]
            | observed_stats($selected_count)),
          output_tokens: ([$attempts[].observations.attack_stage.output_tokens]
            | observed_stats($selected_count)),
          total_tokens: ([$attempts[].observations.attack_stage.total_tokens]
            | observed_stats($selected_count))
        },
        wrapper_wall_clock_duration_ms: (
          [$attempts[].observations.wrapper_wall_clock_duration_ms]
          | observed_stats($selected_count)
        )
      },
      attempts: $attempts
    }
' "$sources_jsonl"
