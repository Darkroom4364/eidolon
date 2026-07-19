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

sha256_file() {
  local path="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi

  shasum -a 256 "$path" | awk '{print $1}'
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
      and (.lane == null or (.lane | type == "string"))
      and (.benchmark_family == null or (.benchmark_family | type == "string"))
      and (.benchmark_task_id == null or (.benchmark_task_id | type == "string"))
      and (.benchmark_snapshot_id == null or (.benchmark_snapshot_id | type == "string"))
      and (.benchmark_model_id == null or (.benchmark_model_id | type == "string"))
      and (.benchmark_prompt_bundle_hash == null or (.benchmark_prompt_bundle_hash | type == "string"))
      and (.benchmark_validation_rule == null or (.benchmark_validation_rule | type == "string"))
      and (.benchmark_action_budget == null or (.benchmark_action_budget | type == "number" and floor == . and . > 0))
      and (.benchmark_token_budget == null or (.benchmark_token_budget | type == "number" and floor == . and . > 0))
      and (.benchmark_wall_clock_budget_seconds == null or (.benchmark_wall_clock_budget_seconds | type == "number" and floor == . and . > 0))
      and (.substrate == null or (.substrate | type == "string"))
      and (.defense_mode == null or (.defense_mode | type == "string"))
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
        lane: ($meta.lane // "unspecified"),
        benchmark_family: ($meta.benchmark_family // null),
        benchmark_task_id: ($meta.benchmark_task_id // null),
        benchmark_snapshot_id: ($meta.benchmark_snapshot_id // null),
        benchmark_model_id: ($meta.benchmark_model_id // null),
        benchmark_prompt_bundle_hash: ($meta.benchmark_prompt_bundle_hash // null),
        benchmark_validation_rule: ($meta.benchmark_validation_rule // null),
        substrate: ($meta.substrate // "unspecified"),
        defense_mode: ($meta.defense_mode // "unspecified"),
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
        result_class: "inconclusive",
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
        artifact_identity: {
          boundary: "scanner_qualification",
          matrix_variant_id: $meta.variant_id,
          sample_dir: $variant_dir
        },
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
      '
      def direct_total: (($sample.artifacts // []) | map(.direct_finding_count // 0) | add // 0);
      def eidolon_total: (($sample.artifacts // []) | map(.eidolon_finding_count // 0) | add // 0);
      def any_signal: ((direct_total + eidolon_total) > 0) or (($sample.strongest_claim_level // null) != null);
      {
        variant_id: $meta.variant_id,
        enabled: true,
        lane: ($meta.lane // "unspecified"),
        benchmark_family: ($meta.benchmark_family // null),
        benchmark_task_id: ($meta.benchmark_task_id // null),
        benchmark_snapshot_id: ($meta.benchmark_snapshot_id // null),
        benchmark_model_id: ($meta.benchmark_model_id // null),
        benchmark_prompt_bundle_hash: ($meta.benchmark_prompt_bundle_hash // null),
        benchmark_validation_rule: ($meta.benchmark_validation_rule // null),
        substrate: ($meta.substrate // "unspecified"),
        defense_mode: ($meta.defense_mode // "unspecified"),
        control_kind: $meta.control_kind,
        hypothesis_id: $meta.hypothesis_id,
        hypothesis: $meta.hypothesis,
        expected_observation: $meta.expected_observation,
        runner_kind: $meta.runner_kind,
        vm_profile: ($meta.vm_profile // null),
        run_count: ($meta.run_count // null),
        notes: ($meta.notes // null),
        execution_state: "completed",
        result_class: (
          if ($sample.valid_summary_count // 0) == 0 and ($sample.artifact_count // 0) == 0 then
            "inconclusive"
          elif $meta.control_kind == "positive_control" then
            if (direct_total > 0) then "pass" else "fail" end
          elif $meta.control_kind == "negative_control" then
            if (direct_total == 0 and eidolon_total == 0) then "pass" else "fail" end
          elif $meta.control_kind == "transfer_control" then
            if any_signal then "pass" else "fail" end
          elif $meta.control_kind == "stock_vs_patched" then
            if (($sample.comparison.parity_reproduced // false) == true
                or (($sample.comparison.parity_status // null) == "parity_reproduced")) then
              "pass"
            elif ($sample.comparison.parity_status // null) == null then
              "inconclusive"
            else
              "fail"
            end
          else
            "inconclusive"
          end
        ),
        interpretation_basis: (
          if ($sample.valid_summary_count // 0) == 0 and ($sample.artifact_count // 0) == 0 then
            "completed_without_valid_summary"
          elif $meta.control_kind == "positive_control" then
            if (direct_total > 0) then
              "positive_control:direct_findings_present"
            else
              "positive_control:no_direct_findings"
            end
          elif $meta.control_kind == "negative_control" then
            if (direct_total == 0 and eidolon_total == 0) then
              "negative_control:quiet_result"
            else
              "negative_control:unexpected_findings"
            end
          elif $meta.control_kind == "transfer_control" then
            if any_signal then
              "transfer_control:signal_present"
            else
              "transfer_control:no_material_signal"
            end
          elif $meta.control_kind == "stock_vs_patched" then
            if (($sample.comparison.parity_reproduced // false) == true
                or (($sample.comparison.parity_status // null) == "parity_reproduced")) then
              "stock_vs_patched:parity_reproduced"
            elif ($sample.comparison.parity_status // null) == null then
              "stock_vs_patched:parity_missing"
            else
              ("stock_vs_patched:" + ($sample.comparison.parity_status // "parity_not_reproduced"))
            end
          else
            "unsupported_control_kind"
          end
        ),
        budget: {
          planned_run_count: ($meta.run_count // null),
          benchmark_action_budget: ($meta.benchmark_action_budget // null),
          benchmark_token_budget: ($meta.benchmark_token_budget // null),
          benchmark_wall_clock_budget_seconds: ($meta.benchmark_wall_clock_budget_seconds // null),
          observed_valid_summary_count: ($sample.valid_summary_count // 0),
          observed_artifact_count: ($sample.artifact_count // 0)
        },
        artifact_identity: {
          boundary: "scanner_qualification",
          matrix_variant_id: $meta.variant_id,
          sample_dir: $variant_dir
        },
        sample_dir: $variant_dir,
        strongest_claim_level: ($sample.strongest_claim_level // null),
        weakest_claim_level: ($sample.weakest_claim_level // null),
        valid_summary_count: ($sample.valid_summary_count // 0),
        artifact_count: ($sample.artifact_count // 0),
        evidence_tracks: ($sample.evidence_tracks // []),
        runner_pwnkit_fixture_ids: ($sample.runner_pwnkit_fixture_ids // []),
        runner_environments: ($sample.runner_environments // []),
        runner_network_topologies: ($sample.runner_network_topologies // []),
        stock_vs_patched_parity_status: ($sample.comparison.parity_status // null),
        stock_vs_patched_parity_reproduced: ($sample.comparison.parity_reproduced // null),
        stock_vs_patched_next_question: ($sample.comparison.next_question // null),
        no_signal_likely_cause: ($sample.no_signal_diagnostics.likely_cause // null),
        strict_ready_for_stability_claim: ($sample.strict_stability.ready_for_stability_claim // false),
        direct_finding_count_total: direct_total,
        eidolon_finding_count_total: eidolon_total
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
        lane: ($meta.lane // "unspecified"),
        benchmark_family: ($meta.benchmark_family // null),
        benchmark_task_id: ($meta.benchmark_task_id // null),
        benchmark_snapshot_id: ($meta.benchmark_snapshot_id // null),
        benchmark_model_id: ($meta.benchmark_model_id // null),
        benchmark_prompt_bundle_hash: ($meta.benchmark_prompt_bundle_hash // null),
        benchmark_validation_rule: ($meta.benchmark_validation_rule // null),
        substrate: ($meta.substrate // "unspecified"),
        defense_mode: ($meta.defense_mode // "unspecified"),
        control_kind: $meta.control_kind,
        hypothesis_id: $meta.hypothesis_id,
        hypothesis: $meta.hypothesis,
        expected_observation: $meta.expected_observation,
        runner_kind: $meta.runner_kind,
        vm_profile: ($meta.vm_profile // null),
        run_count: ($meta.run_count // null),
        notes: ($meta.notes // null),
        execution_state: "planned",
        result_class: "inconclusive",
        interpretation_basis: "planned_only",
        budget: {
          planned_run_count: ($meta.run_count // null),
          benchmark_action_budget: ($meta.benchmark_action_budget // null),
          benchmark_token_budget: ($meta.benchmark_token_budget // null),
          benchmark_wall_clock_budget_seconds: ($meta.benchmark_wall_clock_budget_seconds // null)
        },
        artifact_identity: {
          boundary: "scanner_qualification",
          matrix_variant_id: $meta.variant_id,
          sample_dir: $variant_dir
        },
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
      lane: ($meta.lane // "unspecified"),
      benchmark_family: ($meta.benchmark_family // null),
      benchmark_task_id: ($meta.benchmark_task_id // null),
      benchmark_snapshot_id: ($meta.benchmark_snapshot_id // null),
      benchmark_model_id: ($meta.benchmark_model_id // null),
      benchmark_prompt_bundle_hash: ($meta.benchmark_prompt_bundle_hash // null),
      benchmark_validation_rule: ($meta.benchmark_validation_rule // null),
      substrate: ($meta.substrate // "unspecified"),
      defense_mode: ($meta.defense_mode // "unspecified"),
      control_kind: $meta.control_kind,
      hypothesis_id: $meta.hypothesis_id,
      hypothesis: $meta.hypothesis,
      expected_observation: $meta.expected_observation,
      runner_kind: $meta.runner_kind,
      vm_profile: ($meta.vm_profile // null),
      run_count: ($meta.run_count // null),
      notes: ($meta.notes // null),
      execution_state: "missing",
      result_class: "inconclusive",
      interpretation_basis: "missing_output",
      budget: {
        planned_run_count: ($meta.run_count // null),
        benchmark_action_budget: ($meta.benchmark_action_budget // null),
        benchmark_token_budget: ($meta.benchmark_token_budget // null),
        benchmark_wall_clock_budget_seconds: ($meta.benchmark_wall_clock_budget_seconds // null)
      },
      artifact_identity: {
        boundary: "scanner_qualification",
        matrix_variant_id: $meta.variant_id,
        sample_dir: $variant_dir
      },
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
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
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
    --arg manifest_sha256 "$(sha256_file "$MANIFEST")" \
    '
    . as $variants
    | (["positive_control", "negative_control", "transfer_control", "stock_vs_patched"]) as $required_controls
    | (map(.control_kind) | unique) as $present_controls
    | {
      schema_version: 1,
      run_kind: "pwnkit_qualification_matrix_summary",
      boundary: "scanner_qualification",
      claim_posture: (
        if any($variants[]; .lane == "xbow_benchmark") and any($variants[]; .lane != "xbow_benchmark") then
          "mixed_lane_contract"
        elif any($variants[]; .lane == "xbow_benchmark") then
          "benchmark_capability_only"
        else
          "scanner_qualification_only"
        end
      ),
      evaluation_contract_version: 1,
      generated_at: (now | todateiso8601),
      manifest_path: $manifest,
      manifest_sha256: $manifest_sha256,
      matrix_dir: $matrix_dir,
      variant_count: ($variants | length),
      enabled_variant_count: ([$variants[] | select(.enabled == true)] | length),
      completed_variant_count: ([$variants[] | select(.execution_state == "completed")] | length),
      planned_variant_count: ([$variants[] | select(.execution_state == "planned")] | length),
      blocked_variant_count: ([$variants[] | select(.execution_state == "blocked")] | length),
      missing_variant_count: ([$variants[] | select(.execution_state == "missing")] | length),
      control_kind_counts: (
        $variants
        | map(.control_kind)
        | sort
        | group_by(.)
        | map({control_kind: .[0], count: length})
      ),
      lane_counts: (
        $variants
        | map(.lane)
        | sort
        | group_by(.)
        | map({lane: .[0], count: length})
      ),
      substrate_counts: (
        $variants
        | map(.substrate)
        | sort
        | group_by(.)
        | map({substrate: .[0], count: length})
      ),
      defense_mode_counts: (
        $variants
        | map(.defense_mode)
        | sort
        | group_by(.)
        | map({defense_mode: .[0], count: length})
      ),
      runner_kind_counts: (
        $variants
        | map(.runner_kind)
        | sort
        | group_by(.)
        | map({runner_kind: .[0], count: length})
      ),
      result_counts: (
        $variants
        | map(.result_class)
        | sort
        | group_by(.)
        | map({result_class: .[0], count: length})
      ),
      benchmark_contract: {
        benchmark_variant_count: ([$variants[] | select(.lane == "xbow_benchmark")] | length),
        nonbenchmark_variant_count: ([$variants[] | select(.lane != "xbow_benchmark")] | length),
        mixed_benchmark_and_nonbenchmark: (
          any($variants[]; .lane == "xbow_benchmark") and any($variants[]; .lane != "xbow_benchmark")
        ),
        benchmark_families: (
          $variants
          | map(select(.lane == "xbow_benchmark") | .benchmark_family)
          | map(select(. != null and . != ""))
          | unique
        ),
        benchmark_task_ids: (
          $variants
          | map(select(.lane == "xbow_benchmark") | .benchmark_task_id)
          | map(select(. != null and . != ""))
          | unique
        )
      },
      vm_profiles: (
        $variants
        | map(.vm_profile)
        | map(select(. != null and . != ""))
        | unique
      ),
      acceptance_coverage: {
        positive_control_completed: any($variants[]; .control_kind == "positive_control" and .execution_state == "completed"),
        negative_control_completed: any($variants[]; .control_kind == "negative_control" and .execution_state == "completed"),
        transfer_control_completed: any($variants[]; .control_kind == "transfer_control" and .execution_state == "completed"),
        stock_vs_patched_completed: any($variants[]; .control_kind == "stock_vs_patched" and .execution_state == "completed")
      },
      acceptance_results: {
        positive_control: (
          if any($variants[]; .control_kind == "positive_control" and .result_class == "pass") then
            "pass"
          elif any($variants[]; .control_kind == "positive_control" and .result_class == "fail") then
            "fail"
          elif any($variants[]; .control_kind == "positive_control") then
            "inconclusive"
          else
            "not_present"
          end
        ),
        negative_control: (
          if any($variants[]; .control_kind == "negative_control" and .result_class == "pass") then
            "pass"
          elif any($variants[]; .control_kind == "negative_control" and .result_class == "fail") then
            "fail"
          elif any($variants[]; .control_kind == "negative_control") then
            "inconclusive"
          else
            "not_present"
          end
        ),
        transfer_control: (
          if any($variants[]; .control_kind == "transfer_control" and .result_class == "pass") then
            "pass"
          elif any($variants[]; .control_kind == "transfer_control" and .result_class == "fail") then
            "fail"
          elif any($variants[]; .control_kind == "transfer_control") then
            "inconclusive"
          else
            "not_present"
          end
        ),
        stock_vs_patched: (
          if any($variants[]; .control_kind == "stock_vs_patched" and .result_class == "pass") then
            "pass"
          elif any($variants[]; .control_kind == "stock_vs_patched" and .result_class == "fail") then
            "fail"
          elif any($variants[]; .control_kind == "stock_vs_patched") then
            "inconclusive"
          else
            "not_present"
          end
        )
      },
      qualification_contract: {
        required_control_kinds: $required_controls,
        present_control_kinds: $present_controls,
        missing_control_kinds: (
          $required_controls
          - $present_controls
        ),
        incomplete_control_kinds: (
          $required_controls
          | map(select(. as $kind | any($variants[]; .control_kind == $kind and .execution_state != "completed")))
        ),
        failed_control_kinds: (
          $required_controls
          | map(select(. as $kind | any($variants[]; .control_kind == $kind and .result_class == "fail")))
        ),
        inconclusive_control_kinds: (
          $required_controls
          | map(select(. as $kind | any($variants[]; .control_kind == $kind and .result_class == "inconclusive")))
        ),
        qualification_status: (
          if any($variants[]; .lane == "xbow_benchmark") and any($variants[]; .lane != "xbow_benchmark") then
            "mixed_lane_invalid"
          elif any($variants[]; .lane == "xbow_benchmark") then
            "benchmark_only"
          elif any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .result_class == "fail")) then
            "failed"
          elif (($required_controls - $present_controls) | length) > 0 then
            "not_ready"
          elif any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .execution_state != "completed")) then
            "not_ready"
          elif any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .result_class == "inconclusive")) then
            "not_ready"
          else
            "ready"
          end
        ),
        qualification_reasons: (
          if any($variants[]; .lane == "xbow_benchmark") and any($variants[]; .lane != "xbow_benchmark") then
            ["mixed_benchmark_and_nonbenchmark_lanes"]
          elif any($variants[]; .lane == "xbow_benchmark") then
            ["benchmark_lane_only"]
          else
            (
              (($required_controls - $present_controls) | map("missing_control:" + .))
              + ($required_controls | map(select(. as $kind | any($variants[]; .control_kind == $kind and .execution_state != "completed")) | "incomplete_control:" + .))
              + ($required_controls | map(select(. as $kind | any($variants[]; .control_kind == $kind and .result_class == "fail")) | "failed_control:" + .))
              + ($required_controls | map(select(. as $kind | any($variants[]; .control_kind == $kind and .result_class == "inconclusive")) | "inconclusive_control:" + .))
              | if length == 0 then ["all_required_controls_passed"] else . end
            )
          end
        ),
        ready_for_qualification_claim: (
          (if any($variants[]; .lane == "xbow_benchmark") and any($variants[]; .lane != "xbow_benchmark") then true else false end) == false
          and (if any($variants[]; .lane == "xbow_benchmark") then true else false end) == false
          and (($required_controls - $present_controls) | length) == 0
          and any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .result_class == "fail")) == false
          and any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .execution_state != "completed")) == false
          and any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .result_class == "inconclusive")) == false
        )
      },
      rerun_identity: {
        evaluation_contract_version: 1,
        manifest_sha256: $manifest_sha256,
        lane_set: ($variants | map(.lane) | map(select(. != null and . != "")) | unique),
        substrate_set: ($variants | map(.substrate) | map(select(. != null and . != "")) | unique),
        defense_mode_set: ($variants | map(.defense_mode) | map(select(. != null and . != "")) | unique),
        runner_kind_set: ($variants | map(.runner_kind) | map(select(. != null and . != "")) | unique),
        control_kind_set: ($variants | map(.control_kind) | map(select(. != null and . != "")) | unique),
        vm_profile_set: ($variants | map(.vm_profile) | map(select(. != null and . != "")) | unique),
        evidence_track_set: ($variants | map(.evidence_tracks // []) | add | map(select(. != null and . != "")) | unique),
        fixture_id_set: ($variants | map(.runner_pwnkit_fixture_ids // []) | add | map(select(. != null and . != "")) | unique),
        benchmark_family_set: ($variants | map(.benchmark_family) | map(select(. != null and . != "")) | unique),
        benchmark_task_id_set: ($variants | map(.benchmark_task_id) | map(select(. != null and . != "")) | unique),
        benchmark_model_id_set: ($variants | map(.benchmark_model_id) | map(select(. != null and . != "")) | unique),
        qualification_status: (
          if any($variants[]; .lane == "xbow_benchmark") and any($variants[]; .lane != "xbow_benchmark") then
            "mixed_lane_invalid"
          elif any($variants[]; .lane == "xbow_benchmark") then
            "benchmark_only"
          elif any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .result_class == "fail")) then
            "failed"
          elif (($required_controls - $present_controls) | length) > 0 then
            "not_ready"
          elif any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .execution_state != "completed")) then
            "not_ready"
          elif any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .result_class == "inconclusive")) then
            "not_ready"
          else
            "ready"
          end
        ),
        comparison_scope: (
          if any($variants[]; .lane == "xbow_benchmark") and any($variants[]; .lane != "xbow_benchmark") then
            "mixed_lane_invalid"
          elif any($variants[]; .lane == "xbow_benchmark") then
            "benchmark_lane_only"
          elif (($required_controls - $present_controls) | length) > 0
            or any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .execution_state != "completed"))
            or any($required_controls[]; . as $kind | any($variants[]; .control_kind == $kind and .result_class == "inconclusive")) then
            "partial_qualification_matrix"
          else
            "full_qualification_matrix"
          end
        )
      },
      variants: $variants
    }'
}

main "$@"
