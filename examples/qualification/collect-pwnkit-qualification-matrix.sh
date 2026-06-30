#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
CALLER_PWD="$(pwd -P)"

MANIFEST="${1:-${EIDOLON_PWNKIT_QUAL_MANIFEST:-$SCRIPT_DIR/pwnkit-qualification-variants.json}}"
MATRIX_DIR="${2:-${EIDOLON_PWNKIT_QUAL_DIR:-}}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/collect-pwnkit-qualification-matrix.sh [manifest] <matrix-dir>

Collects a pwnkit qualification matrix summary from a hypothesis manifest and a
matrix output directory produced by run-pwnkit-qualification-matrix.sh.

The summary is independent from M3 closeout. It records which qualification
hypotheses ran, which are still blocked, which VM profiles are required, and
what high-level scanner signal each executed variant produced.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

absolute_input_path() {
  local path="$1"

  if [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s/%s' "$CALLER_PWD" "$path"
  fi
}

canonical_file_path() {
  local path="$1"
  local dir
  local base

  dir="$(dirname "$path")"
  base="$(basename "$path")"
  (
    cd "$dir"
    printf '%s/%s' "$(pwd -P)" "$base"
  )
}

validate_manifest() {
  jq -e '
    .schema_version == 1
    and .run_kind == "pwnkit_qualification_matrix_manifest"
    and .boundary == "scanner_qualification"
    and (.variants | type == "array")
    and (.variants | length > 0)
    and all(.variants[]; (
      (.variant_id | type == "string")
      and (.control_kind | type == "string")
      and (
        .control_kind == "positive_control"
        or .control_kind == "negative_control"
        or .control_kind == "transfer_control"
        or .control_kind == "stock_vs_patched"
      )
      and (.hypothesis_id | type == "string")
      and (.hypothesis | type == "string")
      and (.expected_observation | type == "string")
      and (.runner_kind | type == "string")
    ))
  ' "$MANIFEST" >/dev/null || fail "invalid pwnkit qualification manifest: $MANIFEST"
}

emit_variant_summary() {
  local index="$1"
  local variant_id
  local variant_dir
  local summary_file
  local sample_plan
  local meta_json
  local sample_json="null"

  variant_id="$(jq -r ".variants[$index].variant_id" "$MANIFEST")"
  variant_dir="$MATRIX_DIR/$variant_id"
  summary_file="$variant_dir/pwnkit-stability-sample.json"
  sample_plan="$variant_dir/sample-plan.txt"
  meta_json="$(jq -c ".variants[$index] + {enabled: (if has(\"enabled\") then .enabled else true end)}" "$MANIFEST")"

  if [[ "$(jq -r "if (.variants[$index] | has(\"enabled\")) then .variants[$index].enabled else true end" "$MANIFEST")" == "false" ]]; then
    jq -cn \
      --argjson meta "$meta_json" \
      --arg variant_dir "$variant_dir" \
      '{
        variant_id: $meta.variant_id,
        enabled: false,
        control_kind: $meta.control_kind,
        hypothesis_id: $meta.hypothesis_id,
        hypothesis: $meta.hypothesis,
        expected_observation: $meta.expected_observation,
        runner_kind: $meta.runner_kind,
        vm_profile: ($meta.vm_profile // null),
        run_count: ($meta.run_count // null),
        blocked_reason: ($meta.blocked_reason // "disabled"),
        notes: ($meta.notes // null),
        execution_state: "blocked",
        sample_dir: $variant_dir,
        sample_plan_path: (
          if ($variant_dir | endswith("/")) then
            ($variant_dir + "sample-plan.txt")
          else
            ($variant_dir + "/sample-plan.txt")
          end
        )
      }'
    return
  fi

  if [[ -f "$summary_file" ]]; then
    sample_json="$(jq -c '.' "$summary_file")"
    jq -cn \
      --argjson meta "$meta_json" \
      --arg variant_dir "$variant_dir" \
      --argjson sample "$sample_json" \
      '{
        variant_id: $meta.variant_id,
        enabled: true,
        control_kind: $meta.control_kind,
        hypothesis_id: $meta.hypothesis_id,
        hypothesis: $meta.hypothesis,
        expected_observation: $meta.expected_observation,
        runner_kind: $meta.runner_kind,
        vm_profile: ($meta.vm_profile // null),
        run_count: ($meta.run_count // null),
        notes: ($meta.notes // null),
        execution_state: "completed",
        sample_dir: $variant_dir,
        strongest_claim_level: ($sample.strongest_claim_level // null),
        weakest_claim_level: ($sample.weakest_claim_level // null),
        valid_summary_count: ($sample.valid_summary_count // 0),
        artifact_count: ($sample.artifact_count // 0),
        evidence_tracks: ($sample.evidence_tracks // []),
        runner_environments: ($sample.runner_environments // []),
        runner_network_topologies: ($sample.runner_network_topologies // []),
        stock_vs_patched_parity_status: ($sample.comparison.parity_status // null),
        stock_vs_patched_parity_reproduced: ($sample.comparison.parity_reproduced // null),
        stock_vs_patched_next_question: ($sample.comparison.next_question // null),
        no_signal_likely_cause: ($sample.no_signal_diagnostics.likely_cause // null),
        strict_ready_for_stability_claim: ($sample.strict_stability.ready_for_stability_claim // false),
        direct_finding_count_total: (($sample.artifacts // []) | map(.direct_finding_count // 0) | add // 0),
        eidolon_finding_count_total: (($sample.artifacts // []) | map(.eidolon_finding_count // 0) | add // 0)
      }'
    return
  fi

  if [[ -f "$sample_plan" ]]; then
    jq -cn \
      --argjson meta "$meta_json" \
      --arg variant_dir "$variant_dir" \
      --arg sample_plan "$sample_plan" \
      '{
        variant_id: $meta.variant_id,
        enabled: true,
        control_kind: $meta.control_kind,
        hypothesis_id: $meta.hypothesis_id,
        hypothesis: $meta.hypothesis,
        expected_observation: $meta.expected_observation,
        runner_kind: $meta.runner_kind,
        vm_profile: ($meta.vm_profile // null),
        run_count: ($meta.run_count // null),
        notes: ($meta.notes // null),
        execution_state: "planned",
        sample_dir: $variant_dir,
        sample_plan_path: $sample_plan
      }'
    return
  fi

  jq -cn \
    --argjson meta "$meta_json" \
    --arg variant_dir "$variant_dir" \
    '{
      variant_id: $meta.variant_id,
      enabled: true,
      control_kind: $meta.control_kind,
      hypothesis_id: $meta.hypothesis_id,
      hypothesis: $meta.hypothesis,
      expected_observation: $meta.expected_observation,
      runner_kind: $meta.runner_kind,
      vm_profile: ($meta.vm_profile // null),
      run_count: ($meta.run_count // null),
      notes: ($meta.notes // null),
      execution_state: "missing",
      sample_dir: $variant_dir,
      missing_reason: "variant output not found"
    }'
}

main() {
  local variant_count

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if ! command -v jq >/dev/null 2>&1; then
    fail "missing required tool: jq"
  fi

  MANIFEST="$(absolute_input_path "$MANIFEST")"
  if [[ ! -f "$MANIFEST" ]]; then
    fail "manifest not found: $MANIFEST"
  fi
  MANIFEST="$(canonical_file_path "$MANIFEST")"
  validate_manifest

  if [[ -z "$MATRIX_DIR" ]]; then
    fail "pass a matrix directory"
  fi
  MATRIX_DIR="$(absolute_input_path "$MATRIX_DIR")"
  if [[ ! -d "$MATRIX_DIR" ]]; then
    fail "matrix directory not found: $MATRIX_DIR"
  fi
  MATRIX_DIR="$(cd "$MATRIX_DIR" && pwd -P)"

  variant_count="$(jq '.variants | length' "$MANIFEST")"
  for ((index = 0; index < variant_count; index++)); do
    emit_variant_summary "$index"
  done | jq -s \
    --arg manifest "$MANIFEST" \
    --arg matrix_dir "$MATRIX_DIR" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_qualification_matrix_summary",
      boundary: "scanner_qualification",
      generated_at: (now | todateiso8601),
      manifest_path: $manifest,
      matrix_dir: $matrix_dir,
      variant_count: length,
      enabled_variant_count: ([.[] | select(.enabled == true)] | length),
      completed_variant_count: ([.[] | select(.execution_state == "completed")] | length),
      planned_variant_count: ([.[] | select(.execution_state == "planned")] | length),
      blocked_variant_count: ([.[] | select(.execution_state == "blocked")] | length),
      missing_variant_count: ([.[] | select(.execution_state == "missing")] | length),
      control_kind_counts: (
        map(.control_kind)
        | sort
        | group_by(.)
        | map({control_kind: .[0], count: length})
      ),
      runner_kind_counts: (
        map(.runner_kind)
        | sort
        | group_by(.)
        | map({runner_kind: .[0], count: length})
      ),
      vm_profiles: (
        map(.vm_profile)
        | map(select(. != null and . != ""))
        | unique
      ),
      acceptance_coverage: {
        positive_control_completed: any(.[]; .control_kind == "positive_control" and .execution_state == "completed"),
        negative_control_completed: any(.[]; .control_kind == "negative_control" and .execution_state == "completed"),
        transfer_control_completed: any(.[]; .control_kind == "transfer_control" and .execution_state == "completed"),
        stock_vs_patched_completed: any(.[]; .control_kind == "stock_vs_patched" and .execution_state == "completed")
      },
      variants: .
    }'
}

main "$@"
