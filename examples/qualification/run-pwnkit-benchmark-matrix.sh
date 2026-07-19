#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
CALLER_PWD="$(pwd -P)"

MANIFEST="${1:-${EIDOLON_PWNKIT_BENCHMARK_MANIFEST:-$SCRIPT_DIR/pwnkit-benchmark-variants.json}}"
MATRIX_DIR="${2:-${EIDOLON_PWNKIT_BENCHMARK_MATRIX_DIR:-/tmp/eidolon-pwnkit-benchmark-matrix-$(date +%Y%m%d-%H%M%S)}}"
DEFAULT_RUN_COUNT="${EIDOLON_PWNKIT_BENCHMARK_RUNS:-1}"
EIDOLON_PWNKIT_BENCHMARK_MATRIX_DRY_RUN="${EIDOLON_PWNKIT_BENCHMARK_MATRIX_DRY_RUN:-0}"
RUNNER_BENCHMARK_SAMPLE="${EIDOLON_PWNKIT_BENCHMARK_MATRIX_RUNNER:-$REPO_ROOT/examples/qualification/run-pwnkit-benchmark-sample.sh}"
BENCHMARK_MATRIX_CHECKER="${EIDOLON_PWNKIT_BENCHMARK_MATRIX_CHECKER:-$SCRIPT_DIR/check-pwnkit-benchmark-matrix.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/run-pwnkit-benchmark-matrix.sh [manifest] [matrix-dir]

Runs a benchmark-only pwnkit matrix for XBow-style tasks.

The output stays separate from scanner qualification and Eidolon defensive
claims. Each variant is expected to run through the benchmark sample wrapper.

Environment:
  EIDOLON_PWNKIT_BENCHMARK_MANIFEST
  EIDOLON_PWNKIT_BENCHMARK_MATRIX_DIR
  EIDOLON_PWNKIT_BENCHMARK_RUNS
  EIDOLON_PWNKIT_BENCHMARK_MATRIX_DRY_RUN
  EIDOLON_PWNKIT_BENCHMARK_MATRIX_RUNNER
  EIDOLON_PWNKIT_BENCHMARK_MATRIX_CHECKER

Outputs:
  <matrix-dir>/benchmark-plan.json
  <matrix-dir>/pwnkit-benchmark-variants.json
  <matrix-dir>/pwnkit-benchmark-matrix.json
  <matrix-dir>/<variant-id>/...
USAGE
}

truthy() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || fail "$name must be a positive integer, got: $value"
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

validate_variant_id() {
  local variant_id="$1"
  [[ "$variant_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || fail "invalid variant_id: $variant_id"
}

validate_manifest() {
  jq -e '
    .schema_version == 1
    and .run_kind == "pwnkit_benchmark_matrix_manifest"
    and .boundary == "scanner_qualification"
    and (.claim_posture // "benchmark_capability_only") == "benchmark_capability_only"
    and (
      .import_metadata == null
      or (
        (.import_metadata | type == "object")
        and ((.import_metadata.import_contract_version // 1) == 1)
        and (.import_metadata.task_export_format == null or (.import_metadata.task_export_format | IN("json_array", "jsonl")))
        and (.import_metadata.task_export_sha256 == null or (.import_metadata.task_export_sha256 | type == "string"))
        and (.import_metadata.imported_task_count == null or (.import_metadata.imported_task_count | type == "number" and floor == . and . > 0))
      )
    )
    and (.variants | type == "array")
    and (.variants | length > 0)
    and all(.variants[]; (
      (.variant_id | type == "string")
      and (.enabled == null or (.enabled | type == "boolean"))
      and (.lane == null or .lane == "xbow_benchmark")
      and (.benchmark_family | type == "string")
      and (.benchmark_task_id | type == "string")
      and (.benchmark_snapshot_id | type == "string")
      and (.benchmark_model_id == null or (.benchmark_model_id | type == "string"))
      and (.benchmark_prompt_bundle_hash == null or (.benchmark_prompt_bundle_hash | type == "string"))
      and (.benchmark_validation_rule | type == "string")
      and (.benchmark_action_budget == null or (.benchmark_action_budget | type == "number" and floor == . and . > 0))
      and (.benchmark_token_budget == null or (.benchmark_token_budget | type == "number" and floor == . and . > 0))
      and (.benchmark_wall_clock_budget_seconds == null or (.benchmark_wall_clock_budget_seconds | type == "number" and floor == . and . > 0))
      and (.substrate == null or (.substrate | type == "string"))
      and (.defense_mode == null or (.defense_mode | type == "string"))
      and (.runner_kind | type == "string")
      and .runner_kind == "qualification_benchmark_sample"
      and (.run_count == null or (.run_count | type == "number" and floor == . and . > 0))
      and (.blocked_reason == null or (.blocked_reason | type == "string"))
      and (.notes == null or (.notes | type == "string"))
      and (
        .env == null
        or (
          .env | type == "object"
          and all(to_entries[]; (
            (.key | type == "string")
            and (
              (.value | type) == "string"
              or (.value | type) == "number"
              or (.value | type) == "boolean"
            )
          ))
        )
      )
    ))
  ' "$MANIFEST" >/dev/null || fail "invalid pwnkit benchmark manifest: $MANIFEST"
}

write_benchmark_plan() {
  local dry_run_json="false"
  if truthy "$EIDOLON_PWNKIT_BENCHMARK_MATRIX_DRY_RUN"; then
    dry_run_json="true"
  fi

  jq -n \
    --arg manifest "$MANIFEST" \
    --arg matrix_dir "$MATRIX_DIR" \
    --argjson default_run_count "$DEFAULT_RUN_COUNT" \
    --argjson dry_run "$dry_run_json" \
    --slurpfile manifest_json "$MANIFEST" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_benchmark_matrix_plan",
      boundary: "scanner_qualification",
      claim_posture: "benchmark_capability_only",
      generated_at: (now | todateiso8601),
      manifest_path: $manifest,
      matrix_dir: $matrix_dir,
      default_run_count: $default_run_count,
      dry_run: $dry_run,
      variants: $manifest_json[0].variants
    }' > "$MATRIX_DIR/benchmark-plan.json"
}

write_blocked_variant_note() {
  local index="$1"
  local variant_id
  local variant_dir
  local blocked_reason

  variant_id="$(jq -r ".variants[$index].variant_id" "$MANIFEST")"
  variant_dir="$MATRIX_DIR/$variant_id"
  blocked_reason="$(jq -r ".variants[$index].blocked_reason // \"disabled\"" "$MANIFEST")"

  mkdir -p "$variant_dir"
  {
    printf 'enabled=false\n'
    printf 'variant_id=%s\n' "$variant_id"
    printf 'blocked_reason=%s\n' "$blocked_reason"
  } > "$variant_dir/variant-status.txt"
}

run_variant() {
  local index="$1"
  local variant_id
  local variant_dir
  local run_count
  local env_args=()
  local line
  local key
  local value

  variant_id="$(jq -r ".variants[$index].variant_id" "$MANIFEST")"
  validate_variant_id "$variant_id"

  if [[ "$(jq -r "if (.variants[$index] | has(\"enabled\")) then .variants[$index].enabled else true end" "$MANIFEST")" == "false" ]]; then
    write_blocked_variant_note "$index"
    return
  fi

  [[ -x "$RUNNER_BENCHMARK_SAMPLE" ]] || fail "benchmark runner is not executable: $RUNNER_BENCHMARK_SAMPLE"

  run_count="$(jq -r ".variants[$index].run_count // $DEFAULT_RUN_COUNT" "$MANIFEST")"
  require_positive_integer "run_count for $variant_id" "$run_count"

  variant_dir="$MATRIX_DIR/$variant_id"
  mkdir -p "$variant_dir"

  env_args+=("EIDOLON_PWNKIT_BENCHMARK_FAMILY=$(jq -r ".variants[$index].benchmark_family" "$MANIFEST")")
  env_args+=("EIDOLON_PWNKIT_BENCHMARK_TASK_ID=$(jq -r ".variants[$index].benchmark_task_id" "$MANIFEST")")
  env_args+=("EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID=$(jq -r ".variants[$index].benchmark_snapshot_id" "$MANIFEST")")
  env_args+=("EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE=$(jq -r ".variants[$index].benchmark_validation_rule" "$MANIFEST")")

  while IFS= read -r line; do
    key="${line%%$'\t'*}"
    value="${line#*$'\t'}"
    env_args+=("$key=$value")
  done < <(
    jq -r '
      .variants['"$index"']
      | {
          EIDOLON_PWNKIT_BENCHMARK_MODEL_ID: (.benchmark_model_id // empty),
          EIDOLON_PWNKIT_BENCHMARK_PROMPT_BUNDLE_HASH: (.benchmark_prompt_bundle_hash // empty),
          EIDOLON_PWNKIT_BENCHMARK_ACTION_BUDGET: (.benchmark_action_budget // empty),
          EIDOLON_PWNKIT_BENCHMARK_TOKEN_BUDGET: (.benchmark_token_budget // empty),
          EIDOLON_PWNKIT_BENCHMARK_WALL_CLOCK_BUDGET_SECONDS: (.benchmark_wall_clock_budget_seconds // empty),
          EIDOLON_PWNKIT_BENCHMARK_DEFENSE_MODE: (.defense_mode // empty)
        }
      | with_entries(select(.value != "" and .value != null))
      | to_entries[]
      | [.key, (.value | tostring)]
      | @tsv
    ' "$MANIFEST"
  )

  while IFS= read -r line; do
    key="${line%%$'\t'*}"
    value="${line#*$'\t'}"
    env_args+=("$key=$value")
  done < <(
    jq -r ".variants[$index].env // {} | to_entries[] | [.key, (.value | tostring)] | @tsv" "$MANIFEST"
  )

  if truthy "$EIDOLON_PWNKIT_BENCHMARK_MATRIX_DRY_RUN"; then
    env_args+=("EIDOLON_PWNKIT_BENCHMARK_DRY_RUN=1")
  fi

  echo "pwnkit benchmark variant $((index + 1))/$VARIANT_COUNT: $variant_id -> $variant_dir" >&2
  env "${env_args[@]}" "$RUNNER_BENCHMARK_SAMPLE" "$run_count" "$variant_dir"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"
  require_positive_integer "EIDOLON_PWNKIT_BENCHMARK_RUNS" "$DEFAULT_RUN_COUNT"
  [[ -x "$BENCHMARK_MATRIX_CHECKER" ]] || fail "benchmark matrix checker is not executable: $BENCHMARK_MATRIX_CHECKER"

  MANIFEST="$(absolute_input_path "$MANIFEST")"
  [[ -f "$MANIFEST" ]] || fail "manifest not found: $MANIFEST"
  MANIFEST="$(canonical_file_path "$MANIFEST")"
  validate_manifest

  mkdir -p "$MATRIX_DIR"
  MATRIX_DIR="$(cd "$MATRIX_DIR" && pwd -P)"
  cp "$MANIFEST" "$MATRIX_DIR/pwnkit-benchmark-variants.json"
  write_benchmark_plan

  VARIANT_COUNT="$(jq '.variants | length' "$MANIFEST")"
  for ((index = 0; index < VARIANT_COUNT; index++)); do
    run_variant "$index"
  done

  "$SCRIPT_DIR/collect-pwnkit-benchmark-matrix.sh" "$MANIFEST" "$MATRIX_DIR" \
    > "$MATRIX_DIR/pwnkit-benchmark-matrix.json"
  "$BENCHMARK_MATRIX_CHECKER" "$MATRIX_DIR/pwnkit-benchmark-matrix.json"

  echo "pwnkit benchmark matrix summary: $MATRIX_DIR/pwnkit-benchmark-matrix.json"
}

main "$@"
