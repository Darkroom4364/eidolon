#!/usr/bin/env bash
set -euo pipefail

QUALIFICATION_ARTIFACT="${1:-${EIDOLON_PWNKIT_QUAL_ARTIFACT:-}}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/report-pwnkit-qualification-matrix.sh <matrix-dir|matrix-summary.json>

Emits a Markdown scanner-qualification summary from a pwnkit qualification
matrix. The input may be either the matrix directory or the
`pwnkit-qualification-matrix.json` summary file.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

resolve_summary_path() {
  local path="$1"

  if [[ -d "$path" ]]; then
    path="$path/pwnkit-qualification-matrix.json"
  fi

  if [[ ! -f "$path" ]]; then
    fail "qualification matrix summary not found: $path"
  fi

  printf '%s' "$path"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$QUALIFICATION_ARTIFACT" ]]; then
  fail "pass a matrix directory or pwnkit-qualification-matrix.json"
fi

if ! command -v jq >/dev/null 2>&1; then
  fail "missing required tool: jq"
fi

SUMMARY_PATH="$(resolve_summary_path "$QUALIFICATION_ARTIFACT")"

jq -r '
  def yesno($value):
    if $value then "yes" else "no" end;

  def maybe_list($values):
    if ($values // []) | length == 0 then
      "none"
    else
      ($values | map("`" + . + "`") | join(", "))
    end;

  def report_title:
    if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      "# pwnkit Benchmark Matrix"
    else
      "# pwnkit Qualification Matrix"
    end;

  def variant_line:
    "- `\(.variant_id)` [\(.control_kind)] " +
    "lane=`\(.lane)`" +
    (if .benchmark_family != null then " benchmark_family=`\(.benchmark_family)`" else "" end) +
    (if .benchmark_task_id != null then " task=`\(.benchmark_task_id)`" else "" end) +
    (if .substrate != null then " substrate=`\(.substrate)`" else "" end) +
    (if .defense_mode != null then " defense=`\(.defense_mode)`" else "" end) +
    " state=`\(.execution_state)`" +
    " result=`\(.result_class)`" +
    (if .vm_profile != null then " vm=`\(.vm_profile)`" else "" end) +
    (if .runner_kind != null then " runner=`\(.runner_kind)`" else "" end) +
    (if .strongest_claim_level != null then " strongest_claim=`\(.strongest_claim_level)`" else "" end) +
    (if .stock_vs_patched_parity_status != null then " parity_status=`\(.stock_vs_patched_parity_status)`" else "" end) +
    (if .blocked_reason != null then " blocked_reason=`\(.blocked_reason)`" else "" end) +
    (if .interpretation_basis != null then " basis=`\(.interpretation_basis)`" else "" end);

  [
    report_title,
    "",
    "Generated: `\(.generated_at)`",
    "",
    "Claim posture: `\(.claim_posture // "scanner_qualification_only")`",
    (if (.qualification_contract | type) == "object" and (.qualification_contract | has("qualification_status")) then
      "Qualification status: `\(.qualification_contract.qualification_status)`"
    else
      empty
    end),
    (if (.qualification_contract | type) == "object" and (.qualification_contract | has("ready_for_qualification_claim")) then
      "Ready for qualification claim: `\(yesno(.qualification_contract.ready_for_qualification_claim))`"
    else
      empty
    end),
    (if ((.qualification_contract.qualification_reasons // []) | length) > 0 then
    "Qualification reasons: \(maybe_list(.qualification_contract.qualification_reasons))"
    else
      empty
    end),
    "",
    "## Rerun Identity",
    "",
    "- manifest sha256: `\(.rerun_identity.manifest_sha256 // "unknown")`",
    "- comparison scope: `\(.rerun_identity.comparison_scope // "unknown")`",
    "- lanes: \(maybe_list(.rerun_identity.lane_set))",
    "- substrates: \(maybe_list(.rerun_identity.substrate_set))",
    "- defense modes: \(maybe_list(.rerun_identity.defense_mode_set))",
    "- runner kinds: \(maybe_list(.rerun_identity.runner_kind_set))",
    "- control kinds: \(maybe_list(.rerun_identity.control_kind_set))",
    "- evidence tracks: \(maybe_list(.rerun_identity.evidence_track_set))",
    "- fixture ids: \(maybe_list(.rerun_identity.fixture_id_set))",
    "",
    "## Coverage",
    "",
    "- variants: `\(.variant_count)`",
    "- completed: `\(.completed_variant_count)`",
    "- planned: `\(.planned_variant_count)`",
    "- blocked: `\(.blocked_variant_count)`",
    "- missing: `\(.missing_variant_count)`",
    "- VM profiles: \(maybe_list(.vm_profiles))",
    "",
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      "## Benchmark Contract"
    else
      "## Acceptance Coverage"
    end),
    "",
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      "- benchmark families: \(maybe_list(.benchmark_contract.benchmark_families))"
    else
      "- positive control completed: `\(yesno(.acceptance_coverage.positive_control_completed))`"
    end),
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      "- benchmark tasks: \(maybe_list(.benchmark_contract.benchmark_task_ids))"
    else
      "- negative control completed: `\(yesno(.acceptance_coverage.negative_control_completed))`"
    end),
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      "- mixed benchmark/non-benchmark lanes: `\(yesno(.benchmark_contract.mixed_benchmark_and_nonbenchmark))`"
    else
      "- transfer control completed: `\(yesno(.acceptance_coverage.transfer_control_completed))`"
    end),
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      "- benchmark variants: `\(.benchmark_contract.benchmark_variant_count)`"
    else
      "- stock-vs-patched completed: `\(yesno(.acceptance_coverage.stock_vs_patched_completed))`"
    end),
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      "- result counts: \(maybe_list((.result_counts // []) | map(.result_class + ":" + (.count|tostring))))"
    else
      "- positive control result: `\(.acceptance_results.positive_control)`"
    end),
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      ""
    else
      "- negative control result: `\(.acceptance_results.negative_control)`"
    end),
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      ""
    else
      "- transfer control result: `\(.acceptance_results.transfer_control)`"
    end),
    (if (.claim_posture // "scanner_qualification_only") == "benchmark_capability_only" then
      ""
    else
      "- stock-vs-patched result: `\(.acceptance_results.stock_vs_patched)`"
    end),
    "",
    "## Lane Shape",
    "",
    "- lane counts: \(maybe_list((.lane_counts // []) | map(.lane + ":" + (.count|tostring))))",
    "- substrate counts: \(maybe_list((.substrate_counts // []) | map(.substrate + ":" + (.count|tostring))))",
    "- defense counts: \(maybe_list((.defense_mode_counts // []) | map(.defense_mode + ":" + (.count|tostring))))",
    "- result counts: \(maybe_list((.result_counts // []) | map(.result_class + ":" + (.count|tostring))))",
    "",
    "## Variants",
    ""
  ]
  + (.variants | map(variant_line))
  | join("\n")
' "$SUMMARY_PATH"
