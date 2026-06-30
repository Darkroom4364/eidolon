#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
CALLER_PWD="$(pwd -P)"

MANIFEST="${1:-${EIDOLON_PWNKIT_QUAL_MANIFEST:-$SCRIPT_DIR/pwnkit-qualification-variants.json}}"
MATRIX_DIR="${2:-${EIDOLON_PWNKIT_QUAL_DIR:-/tmp/eidolon-pwnkit-qualification-$(date +%Y%m%d-%H%M%S)}}"
DEFAULT_RUN_COUNT="${EIDOLON_PWNKIT_QUAL_RUNS:-1}"
EIDOLON_PWNKIT_QUAL_DRY_RUN="${EIDOLON_PWNKIT_QUAL_DRY_RUN:-0}"

RUNNER_M3_LOCAL_SAMPLE="${EIDOLON_PWNKIT_QUAL_RUNNER_M3_LOCAL_SAMPLE:-$REPO_ROOT/examples/m3/run-pwnkit-sample.sh}"
RUNNER_M3_KALI_SAME_VM="${EIDOLON_PWNKIT_QUAL_RUNNER_M3_KALI_SAME_VM:-$REPO_ROOT/examples/m3/run-pwnkit-kali-vm.sh}"
RUNNER_SHIELD_LAB_KALI_ORBSTACK="${EIDOLON_PWNKIT_QUAL_RUNNER_SHIELD_LAB_KALI_ORBSTACK:-$REPO_ROOT/examples/shield-lab/run-pwnkit-kali-vm.sh}"
RUNNER_QUAL_DIRECT_SAMPLE="${EIDOLON_PWNKIT_QUAL_RUNNER_DIRECT_SAMPLE:-$REPO_ROOT/examples/qualification/run-pwnkit-direct-qualification-sample.sh}"
RUNNER_QUAL_STOCK_VS_PATCHED_SAMPLE="${EIDOLON_PWNKIT_QUAL_RUNNER_STOCK_VS_PATCHED_SAMPLE:-$REPO_ROOT/examples/qualification/run-pwnkit-stock-vs-patched-qualification-sample.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/run-pwnkit-qualification-matrix.sh [manifest] [matrix-dir]

Runs the pwnkit scanner-qualification matrix outside the M3 closeout path.

The manifest records qualification hypotheses, control kinds, runner topology,
and optional VM profile requirements. VM-backed variants are queued into a
separate vm-spool plan so the matrix can be reviewed honestly before any real
provisioning backend exists.

Environment:
  EIDOLON_PWNKIT_QUAL_MANIFEST   Manifest path if [manifest] is omitted.
  EIDOLON_PWNKIT_QUAL_DIR        Matrix root if [matrix-dir] is omitted.
  EIDOLON_PWNKIT_QUAL_RUNS       Default run count per enabled variant.
                                 Defaults to 1.
  EIDOLON_PWNKIT_QUAL_DRY_RUN    If true, only write per-variant sample plans
                                 and the VM spool plan.
  EIDOLON_PWNKIT_QUAL_RUNNER_M3_LOCAL_SAMPLE
                                 Override the host-local runner command.
  EIDOLON_PWNKIT_QUAL_RUNNER_M3_KALI_SAME_VM
                                 Override the Kali same-VM loopback runner.
  EIDOLON_PWNKIT_QUAL_RUNNER_SHIELD_LAB_KALI_ORBSTACK
                                 Override the Kali -> OrbStack NodePort runner.
  EIDOLON_PWNKIT_QUAL_RUNNER_DIRECT_SAMPLE
                                 Override the direct-only qualification runner.
  EIDOLON_PWNKIT_QUAL_RUNNER_STOCK_VS_PATCHED_SAMPLE
                                 Override the local stock-vs-patched runner.

Outputs:
  <matrix-dir>/matrix-plan.json
  <matrix-dir>/vm-spool-plan.json
  <matrix-dir>/pwnkit-qualification-matrix.json
  <matrix-dir>/<variant-id>/...
USAGE
}

truthy() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_positive_integer() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be a positive integer, got: $value"
  fi
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

  if [[ ! "$variant_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
    fail "invalid variant_id: $variant_id"
  fi
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
      and (.enabled == null or (.enabled | type == "boolean"))
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
      and (
        .runner_kind == "m3_local_sample"
        or .runner_kind == "m3_kali_same_vm"
        or .runner_kind == "shield_lab_kali_orbstack"
        or .runner_kind == "qualification_direct_sample"
        or .runner_kind == "qualification_stock_vs_patched_sample"
      )
      and (.run_count == null or (.run_count | type == "number" and floor == . and . > 0))
      and (.vm_profile == null or (.vm_profile | type == "string"))
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
  ' "$MANIFEST" >/dev/null || fail "invalid pwnkit qualification manifest: $MANIFEST"
}

resolve_runner_path() {
  local runner_kind="$1"

  case "$runner_kind" in
    m3_local_sample)
      printf '%s' "$RUNNER_M3_LOCAL_SAMPLE"
      ;;
    m3_kali_same_vm)
      printf '%s' "$RUNNER_M3_KALI_SAME_VM"
      ;;
    shield_lab_kali_orbstack)
      printf '%s' "$RUNNER_SHIELD_LAB_KALI_ORBSTACK"
      ;;
    qualification_direct_sample)
      printf '%s' "$RUNNER_QUAL_DIRECT_SAMPLE"
      ;;
    qualification_stock_vs_patched_sample)
      printf '%s' "$RUNNER_QUAL_STOCK_VS_PATCHED_SAMPLE"
      ;;
    *)
      fail "unsupported runner_kind: $runner_kind"
      ;;
  esac
}

write_matrix_plan() {
  local dry_run_json="false"

  if truthy "$EIDOLON_PWNKIT_QUAL_DRY_RUN"; then
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
      run_kind: "pwnkit_qualification_matrix_plan",
      boundary: "scanner_qualification",
      generated_at: (now | todateiso8601),
      manifest_path: $manifest,
      matrix_dir: $matrix_dir,
      default_run_count: $default_run_count,
      dry_run: $dry_run,
      variants: $manifest_json[0].variants
    }' > "$MATRIX_DIR/matrix-plan.json"
}

write_vm_spool_plan() {
  jq -n \
    --arg manifest "$MANIFEST" \
    --arg matrix_dir "$MATRIX_DIR" \
    --slurpfile manifest_json "$MANIFEST" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_qualification_vm_spool_plan",
      boundary: "scanner_qualification",
      generated_at: (now | todateiso8601),
      manifest_path: $manifest,
      matrix_dir: $matrix_dir,
      vm_profiles: (
        $manifest_json[0].variants
        | map(select(((if has("enabled") then .enabled else true end) == true) and (.vm_profile // null) != null))
        | sort_by(.vm_profile)
        | group_by(.vm_profile)
        | map({
            vm_profile: .[0].vm_profile,
            runner_kinds: ([.[].runner_kind] | unique),
            control_kinds: ([.[].control_kind] | unique),
            variant_ids: [.[].variant_id],
            hypothesis_ids: [.[].hypothesis_id]
          })
      )
    }' > "$MATRIX_DIR/vm-spool-plan.json"
}

write_blocked_variant_note() {
  local index="$1"
  local variant_id
  local variant_dir
  local blocked_reason
  local vm_profile

  variant_id="$(jq -r ".variants[$index].variant_id" "$MANIFEST")"
  variant_dir="$MATRIX_DIR/$variant_id"
  blocked_reason="$(jq -r ".variants[$index].blocked_reason // \"disabled\"" "$MANIFEST")"
  vm_profile="$(jq -r ".variants[$index].vm_profile // \"none\"" "$MANIFEST")"

  mkdir -p "$variant_dir"
  {
    printf 'enabled=false\n'
    printf 'variant_id=%s\n' "$variant_id"
    printf 'blocked_reason=%s\n' "$blocked_reason"
    printf 'vm_profile=%s\n' "$vm_profile"
  } > "$variant_dir/variant-status.txt"
}

run_variant() {
  local index="$1"
  local variant_id
  local variant_dir
  local runner_kind
  local runner_path
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

  runner_kind="$(jq -r ".variants[$index].runner_kind" "$MANIFEST")"
  runner_path="$(resolve_runner_path "$runner_kind")"
  if [[ ! -x "$runner_path" ]]; then
    fail "runner command is not executable for $variant_id: $runner_path"
  fi

  run_count="$(jq -r ".variants[$index].run_count // $DEFAULT_RUN_COUNT" "$MANIFEST")"
  require_positive_integer "run_count for $variant_id" "$run_count"

  variant_dir="$MATRIX_DIR/$variant_id"
  mkdir -p "$variant_dir"

  while IFS= read -r line; do
    key="${line%%$'\t'*}"
    value="${line#*$'\t'}"
    env_args+=("$key=$value")
  done < <(
    jq -r ".variants[$index].env // {} | to_entries[] | [.key, (.value | tostring)] | @tsv" \
      "$MANIFEST"
  )

  case "$runner_kind" in
    m3_local_sample)
      if truthy "$EIDOLON_PWNKIT_QUAL_DRY_RUN"; then
        env_args+=("EIDOLON_M3_SAMPLE_DRY_RUN=1")
      fi
      ;;
    m3_kali_same_vm)
      if truthy "$EIDOLON_PWNKIT_QUAL_DRY_RUN"; then
        env_args+=("EIDOLON_M3_KALI_VM_DRY_RUN=1")
        env_args+=("EIDOLON_M3_ALLOW_NON_KALI_VM=1")
      fi
      ;;
    shield_lab_kali_orbstack)
      if truthy "$EIDOLON_PWNKIT_QUAL_DRY_RUN"; then
        env_args+=("EIDOLON_SHIELD_KALI_VM_DRY_RUN=1")
        env_args+=("EIDOLON_SHIELD_ALLOW_NON_KALI_VM=1")
      fi
      ;;
    qualification_direct_sample)
      if truthy "$EIDOLON_PWNKIT_QUAL_DRY_RUN"; then
        env_args+=("EIDOLON_PWNKIT_QUAL_DIRECT_DRY_RUN=1")
      fi
      ;;
    qualification_stock_vs_patched_sample)
      if truthy "$EIDOLON_PWNKIT_QUAL_DRY_RUN"; then
        env_args+=("EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DRY_RUN=1")
      fi
      ;;
  esac

  echo "pwnkit qualification variant $((index + 1))/$VARIANT_COUNT: $variant_id -> $variant_dir" >&2
  if [[ "${#env_args[@]}" -gt 0 ]]; then
    env "${env_args[@]}" "$runner_path" "$run_count" "$variant_dir"
  else
    "$runner_path" "$run_count" "$variant_dir"
  fi
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if ! command -v jq >/dev/null 2>&1; then
    fail "missing required tool: jq"
  fi

  require_positive_integer "EIDOLON_PWNKIT_QUAL_RUNS" "$DEFAULT_RUN_COUNT"

  MANIFEST="$(absolute_input_path "$MANIFEST")"
  if [[ ! -f "$MANIFEST" ]]; then
    fail "manifest not found: $MANIFEST"
  fi
  MANIFEST="$(canonical_file_path "$MANIFEST")"
  validate_manifest

  mkdir -p "$MATRIX_DIR"
  MATRIX_DIR="$(cd "$MATRIX_DIR" && pwd -P)"
  cp "$MANIFEST" "$MATRIX_DIR/pwnkit-qualification-variants.json"

  write_matrix_plan
  write_vm_spool_plan

  VARIANT_COUNT="$(jq '.variants | length' "$MANIFEST")"
  for ((index = 0; index < VARIANT_COUNT; index++)); do
    run_variant "$index"
  done

  "$SCRIPT_DIR/collect-pwnkit-qualification-matrix.sh" "$MANIFEST" "$MATRIX_DIR" \
    > "$MATRIX_DIR/pwnkit-qualification-matrix.json"

  echo "pwnkit qualification matrix summary: $MATRIX_DIR/pwnkit-qualification-matrix.json"
}

main "$@"
