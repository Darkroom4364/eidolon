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

  def variant_line:
    "- `\(.variant_id)` [\(.control_kind)] " +
    "state=`\(.execution_state)`" +
    (if .vm_profile != null then " vm=`\(.vm_profile)`" else "" end) +
    (if .runner_kind != null then " runner=`\(.runner_kind)`" else "" end) +
    (if .strongest_claim_level != null then " strongest_claim=`\(.strongest_claim_level)`" else "" end) +
    (if .blocked_reason != null then " blocked_reason=`\(.blocked_reason)`" else "" end);

  [
    "# pwnkit Qualification Matrix",
    "",
    "Generated: `\(.generated_at)`",
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
    "## Acceptance Coverage",
    "",
    "- positive control completed: `\(yesno(.acceptance_coverage.positive_control_completed))`",
    "- negative control completed: `\(yesno(.acceptance_coverage.negative_control_completed))`",
    "- transfer control completed: `\(yesno(.acceptance_coverage.transfer_control_completed))`",
    "- stock-vs-patched completed: `\(yesno(.acceptance_coverage.stock_vs_patched_completed))`",
    "",
    "## Variants",
    ""
  ]
  + (.variants | map(variant_line))
  | join("\n")
' "$SUMMARY_PATH"
