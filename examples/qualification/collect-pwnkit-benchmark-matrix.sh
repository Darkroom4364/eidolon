#!/usr/bin/env bash
set -euo pipefail

CALLER_PWD="$(pwd -P)"
MANIFEST="${1:-${EIDOLON_PWNKIT_BENCHMARK_MANIFEST:-}}"
MATRIX_DIR="${2:-${EIDOLON_PWNKIT_BENCHMARK_MATRIX_DIR:-}}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/collect-pwnkit-benchmark-matrix.sh <manifest> <matrix-dir>

Collects a benchmark-only pwnkit matrix summary from a benchmark manifest and
the output directory produced by run-pwnkit-benchmark-matrix.sh.
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

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  shasum -a 256 "$path" | awk '{print $1}'
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
    jq -cn --argjson meta "$meta_json" --arg variant_dir "$variant_dir" '{
      variant_id: $meta.variant_id,
      enabled: false,
      lane: "xbow_benchmark",
      benchmark_family: $meta.benchmark_family,
      benchmark_task_id: $meta.benchmark_task_id,
      benchmark_snapshot_id: $meta.benchmark_snapshot_id,
      benchmark_model_id: ($meta.benchmark_model_id // null),
      benchmark_prompt_bundle_hash: ($meta.benchmark_prompt_bundle_hash // null),
      benchmark_validation_rule: $meta.benchmark_validation_rule,
      substrate: ($meta.substrate // "unspecified"),
      defense_mode: ($meta.defense_mode // "unspecified"),
      runner_kind: $meta.runner_kind,
      run_count: ($meta.run_count // null),
      blocked_reason: ($meta.blocked_reason // "disabled"),
      notes: ($meta.notes // null),
      execution_state: "blocked",
      result_class: "inconclusive",
      validation_status: "blocked",
      interpretation_basis: (
        if ($meta.blocked_reason // null) != null then
          ("blocked:" + $meta.blocked_reason)
        else
          "blocked:disabled"
        end
      ),
      budget: {
        planned_run_count: ($meta.run_count // null),
        benchmark_action_budget: ($meta.benchmark_action_budget // null),
        benchmark_token_budget: ($meta.benchmark_token_budget // null),
        benchmark_wall_clock_budget_seconds: ($meta.benchmark_wall_clock_budget_seconds // null)
      },
      sample_dir: $variant_dir
    }'
    return
  fi

  if [[ -f "$summary_file" ]]; then
    sample_json="$(jq -c '.' "$summary_file")"
    jq -cn --argjson meta "$meta_json" --arg variant_dir "$variant_dir" --argjson sample "$sample_json" '
      {
        variant_id: $meta.variant_id,
        enabled: true,
        lane: "xbow_benchmark",
        benchmark_family: $meta.benchmark_family,
        benchmark_task_id: $meta.benchmark_task_id,
        benchmark_snapshot_id: $meta.benchmark_snapshot_id,
        benchmark_model_id: ($meta.benchmark_model_id // null),
        benchmark_prompt_bundle_hash: ($meta.benchmark_prompt_bundle_hash // null),
        benchmark_validation_rule: $meta.benchmark_validation_rule,
        substrate: ($sample.substrate // ($meta.substrate // "unspecified")),
        defense_mode: ($sample.defense_mode // ($meta.defense_mode // "unspecified")),
        runner_kind: $meta.runner_kind,
        run_count: ($meta.run_count // null),
        notes: ($meta.notes // null),
        execution_state: "completed",
        result_class: (
          if ($sample.validation.status // "inconclusive") == "validated" then
            "pass"
          elif ($sample.validation.status // "inconclusive") == "invalidated" then
            "fail"
          else
            "inconclusive"
          end
        ),
        validation_status: ($sample.validation.status // "inconclusive"),
        interpretation_basis: (
          "benchmark_validation:" + ($sample.validation.status // "inconclusive")
        ),
        budget: {
          planned_run_count: ($meta.run_count // null),
          benchmark_action_budget: ($sample.budget.benchmark_action_budget // $meta.benchmark_action_budget // null),
          benchmark_token_budget: ($sample.budget.benchmark_token_budget // $meta.benchmark_token_budget // null),
          benchmark_wall_clock_budget_seconds: ($sample.budget.benchmark_wall_clock_budget_seconds // $meta.benchmark_wall_clock_budget_seconds // null),
          observed_artifact_count: ($sample.budget.observed_artifact_count // 0),
          observed_valid_summary_count: ($sample.budget.observed_valid_summary_count // 0)
        },
        counts: ($sample.counts // {}),
        validation: ($sample.validation // {}),
        raw_sample: ($sample.raw_sample // {}),
        sample_dir: $variant_dir
      }'
    return
  fi

  if [[ -f "$sample_plan" ]]; then
    jq -cn --argjson meta "$meta_json" --arg variant_dir "$variant_dir" --arg sample_plan "$sample_plan" '{
      variant_id: $meta.variant_id,
      enabled: true,
      lane: "xbow_benchmark",
      benchmark_family: $meta.benchmark_family,
      benchmark_task_id: $meta.benchmark_task_id,
      benchmark_snapshot_id: $meta.benchmark_snapshot_id,
      benchmark_model_id: ($meta.benchmark_model_id // null),
      benchmark_prompt_bundle_hash: ($meta.benchmark_prompt_bundle_hash // null),
      benchmark_validation_rule: $meta.benchmark_validation_rule,
      substrate: ($meta.substrate // "unspecified"),
      defense_mode: ($meta.defense_mode // "unspecified"),
      runner_kind: $meta.runner_kind,
      run_count: ($meta.run_count // null),
      notes: ($meta.notes // null),
      execution_state: "planned",
      result_class: "inconclusive",
      validation_status: "planned",
      interpretation_basis: "planned_only",
      budget: {
        planned_run_count: ($meta.run_count // null),
        benchmark_action_budget: ($meta.benchmark_action_budget // null),
        benchmark_token_budget: ($meta.benchmark_token_budget // null),
        benchmark_wall_clock_budget_seconds: ($meta.benchmark_wall_clock_budget_seconds // null)
      },
      sample_dir: $variant_dir,
      sample_plan_path: $sample_plan
    }'
    return
  fi

  jq -cn --argjson meta "$meta_json" --arg variant_dir "$variant_dir" '{
    variant_id: $meta.variant_id,
    enabled: true,
    lane: "xbow_benchmark",
    benchmark_family: $meta.benchmark_family,
    benchmark_task_id: $meta.benchmark_task_id,
    benchmark_snapshot_id: $meta.benchmark_snapshot_id,
    benchmark_model_id: ($meta.benchmark_model_id // null),
    benchmark_prompt_bundle_hash: ($meta.benchmark_prompt_bundle_hash // null),
    benchmark_validation_rule: $meta.benchmark_validation_rule,
    substrate: ($meta.substrate // "unspecified"),
    defense_mode: ($meta.defense_mode // "unspecified"),
    runner_kind: $meta.runner_kind,
    run_count: ($meta.run_count // null),
    notes: ($meta.notes // null),
    execution_state: "missing",
    result_class: "inconclusive",
    validation_status: "missing",
    interpretation_basis: "missing_output",
    budget: {
      planned_run_count: ($meta.run_count // null),
      benchmark_action_budget: ($meta.benchmark_action_budget // null),
      benchmark_token_budget: ($meta.benchmark_token_budget // null),
      benchmark_wall_clock_budget_seconds: ($meta.benchmark_wall_clock_budget_seconds // null)
    },
    sample_dir: $variant_dir,
    missing_reason: "variant output not found"
  }'
}

main() {
  local variant_count
  local import_metadata_json

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
  fi

  [[ -n "$MANIFEST" ]] || fail "pass a manifest"
  [[ -n "$MATRIX_DIR" ]] || fail "pass a matrix directory"

  MANIFEST="$(absolute_input_path "$MANIFEST")"
  [[ -f "$MANIFEST" ]] || fail "manifest not found: $MANIFEST"
  MANIFEST="$(canonical_file_path "$MANIFEST")"

  MATRIX_DIR="$(absolute_input_path "$MATRIX_DIR")"
  [[ -d "$MATRIX_DIR" ]] || fail "matrix directory not found: $MATRIX_DIR"
  MATRIX_DIR="$(cd "$MATRIX_DIR" && pwd -P)"

  import_metadata_json="$(jq -c '.import_metadata // null' "$MANIFEST")"

  variant_count="$(jq '.variants | length' "$MANIFEST")"
  for ((index = 0; index < variant_count; index++)); do
    emit_variant_summary "$index"
  done | jq -s \
    --arg manifest "$MANIFEST" \
    --arg matrix_dir "$MATRIX_DIR" \
    --arg manifest_sha256 "$(sha256_file "$MANIFEST")" \
    --argjson import_metadata "$import_metadata_json" '
    . as $variants
    | {
      schema_version: 1,
      run_kind: "pwnkit_benchmark_matrix_summary",
      boundary: "scanner_qualification",
      claim_posture: "benchmark_capability_only",
      evaluation_contract_version: 1,
      generated_at: (now | todateiso8601),
      manifest_path: $manifest,
      manifest_sha256: $manifest_sha256,
      import_metadata: $import_metadata,
      matrix_dir: $matrix_dir,
      variant_count: ($variants | length),
      completed_variant_count: ([$variants[] | select(.execution_state == "completed")] | length),
      planned_variant_count: ([$variants[] | select(.execution_state == "planned")] | length),
      blocked_variant_count: ([$variants[] | select(.execution_state == "blocked")] | length),
      missing_variant_count: ([$variants[] | select(.execution_state == "missing")] | length),
      result_counts: ($variants | map(.result_class) | sort | group_by(.) | map({result_class: .[0], count: length})),
      validation_status_counts: ($variants | map(.validation_status) | sort | group_by(.) | map({validation_status: .[0], count: length})),
      benchmark_family_counts: ($variants | map(.benchmark_family) | sort | group_by(.) | map({benchmark_family: .[0], count: length})),
      defense_mode_counts: ($variants | map(.defense_mode) | sort | group_by(.) | map({defense_mode: .[0], count: length})),
      substrate_counts: ($variants | map(.substrate) | sort | group_by(.) | map({substrate: .[0], count: length})),
      benchmark_summary: {
        task_count: ($variants | length),
        validated_count: ([$variants[] | select(.validation_status == "validated")] | length),
        invalidated_count: ([$variants[] | select(.validation_status == "invalidated")] | length),
        inconclusive_count: ([$variants[] | select(.validation_status != "validated" and .validation_status != "invalidated")] | length),
        validated_rate: (
          if ($variants | length) == 0 then
            0
          else
            (([$variants[] | select(.validation_status == "validated")] | length) / ($variants | length))
          end
        )
      },
      rerun_identity: {
        evaluation_contract_version: 1,
        manifest_sha256: $manifest_sha256,
        comparison_scope: "benchmark_lane_only",
        lane_set: ["xbow_benchmark"],
        task_export_sha256: ($import_metadata.task_export_sha256 // null),
        task_export_format: ($import_metadata.task_export_format // null),
        imported_task_count: ($import_metadata.imported_task_count // null),
        benchmark_family_set: ($variants | map(.benchmark_family) | unique),
        benchmark_task_id_set: ($variants | map(.benchmark_task_id) | unique),
        benchmark_snapshot_id_set: ($variants | map(.benchmark_snapshot_id) | unique),
        benchmark_model_id_set: ($variants | map(.benchmark_model_id) | map(select(. != null and . != "")) | unique),
        benchmark_prompt_bundle_hash_set: (
          $variants
          | map(.benchmark_prompt_bundle_hash)
          | map(select(. != null and . != ""))
          | unique
        ),
        benchmark_validation_rule_set: ($variants | map(.benchmark_validation_rule) | unique),
        benchmark_action_budget_set: (
          $variants
          | map(.budget.benchmark_action_budget)
          | map(select(. != null))
          | unique
        ),
        benchmark_token_budget_set: (
          $variants
          | map(.budget.benchmark_token_budget)
          | map(select(. != null))
          | unique
        ),
        benchmark_wall_clock_budget_seconds_set: (
          $variants
          | map(.budget.benchmark_wall_clock_budget_seconds)
          | map(select(. != null))
          | unique
        ),
        substrate_set: ($variants | map(.substrate) | unique),
        defense_mode_set: ($variants | map(.defense_mode) | unique),
        runner_kind_set: ($variants | map(.runner_kind) | unique)
      },
      variants: $variants
    }'
}

main "$@"
