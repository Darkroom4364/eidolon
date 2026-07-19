#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

MATRIX_DIR="${1:-${EIDOLON_PWNKIT_QUAL_DIR:-}}"
VARIANT_ID="${2:-${EIDOLON_PWNKIT_QUAL_VM_VARIANT_ID:-}}"
SPOOL_DIR="${3:-${EIDOLON_PWNKIT_QUAL_VM_SPOOL_DIR:-}}"

SPOOLER="${EIDOLON_PWNKIT_QUAL_VM_SPOOLER:-$SCRIPT_DIR/spool-pwnkit-qualification-orbstack-vms.sh}"
COLLECTOR="${EIDOLON_PWNKIT_QUAL_VM_COLLECTOR:-$REPO_ROOT/examples/shield-lab/collect-kali-vm-sample.sh}"
MATRIX_COLLECTOR="${EIDOLON_PWNKIT_QUAL_MATRIX_COLLECTOR:-$SCRIPT_DIR/collect-pwnkit-qualification-matrix.sh}"
HOST_BUNDLE_DIR="${EIDOLON_PWNKIT_QUAL_HOST_BUNDLE_DIR:-}"
EDGE_DECISIONS_PATH="${EIDOLON_PWNKIT_QUAL_EDGE_DECISIONS_PATH:-}"
OVERWRITE="${EIDOLON_PWNKIT_QUAL_VM_OVERWRITE:-0}"
VM_SAMPLE_DIR_OVERRIDE="${EIDOLON_PWNKIT_QUAL_VM_SAMPLE_DIR:-}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/run-pwnkit-qualification-orbstack-vm-variant.sh <matrix-dir> <variant-id> [spool-dir]

Runs one VM-backed pwnkit qualification variant from the macOS host by using
the OrbStack spool manifest/helper path, then copies the resulting VM sample
back into the matrix variant directory and refreshes the matrix summary.

Inputs:
  <matrix-dir>/pwnkit-qualification-variants.json
  <matrix-dir>/vm-spool-plan.json
  [spool-dir]/vm-spool-manifest.json

Outputs:
  <matrix-dir>/<variant-id>/...
  <matrix-dir>/<variant-id>/vm-run-manifest.json
  <matrix-dir>/pwnkit-qualification-matrix.json

Environment:
  EIDOLON_PWNKIT_QUAL_VM_SPOOLER         Override the OrbStack spooler path.
  EIDOLON_PWNKIT_QUAL_VM_COLLECTOR       Override the VM sample collector path.
  EIDOLON_PWNKIT_QUAL_MATRIX_COLLECTOR   Override the matrix collector path.
  EIDOLON_PWNKIT_QUAL_HOST_BUNDLE_DIR    Optional host bundle linked into the
                                         copied VM sample manifest.
  EIDOLON_PWNKIT_QUAL_EDGE_DECISIONS_PATH
                                         Optional edge export linked into the
                                         copied VM sample manifest.
  EIDOLON_PWNKIT_QUAL_VM_OVERWRITE       Replace an existing completed variant
                                         directory when true.
  EIDOLON_PWNKIT_QUAL_VM_SAMPLE_DIR      Override the VM-local sample dir used
                                         by the generated helper.

If [spool-dir] is omitted, the script uses:
  <matrix-dir>/orbstack-vm-spool

If that spool directory does not already contain vm-spool-manifest.json, the
OrbStack spooler is run automatically against <matrix-dir>/vm-spool-plan.json.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
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

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

canonical_dir_path() {
  local path="$1"
  (
    cd "$path"
    pwd -P
  )
}

ensure_spool_manifest() {
  local spool_plan="$MATRIX_DIR/vm-spool-plan.json"
  local spool_manifest="$SPOOL_DIR/vm-spool-manifest.json"

  [[ -f "$spool_plan" ]] || fail "vm-spool-plan.json not found in matrix dir: $spool_plan"
  [[ -x "$SPOOLER" ]] || fail "OrbStack spooler is not executable: $SPOOLER"

  mkdir -p "$SPOOL_DIR"
  if [[ ! -f "$spool_manifest" ]]; then
    "$SPOOLER" "$spool_plan" "$SPOOL_DIR"
  fi

  [[ -f "$spool_manifest" ]] || fail "vm-spool-manifest.json not found after spooling: $spool_manifest"
}

validate_matrix_manifest() {
  jq -e '
    .schema_version == 1
    and .run_kind == "pwnkit_qualification_matrix_manifest"
    and .boundary == "scanner_qualification"
    and (.variants | type == "array")
  ' "$MANIFEST_FILE" >/dev/null || fail "invalid qualification manifest: $MANIFEST_FILE"
}

validate_spool_manifest() {
  jq -e '
    .schema_version == 1
    and .run_kind == "pwnkit_qualification_orbstack_vm_spool_manifest"
    and .boundary == "scanner_qualification"
    and .provider == "orbstack"
    and (.profiles | type == "array")
  ' "$SPOOL_MANIFEST" >/dev/null || fail "invalid OrbStack spool manifest: $SPOOL_MANIFEST"
}

load_variant_metadata() {
  VARIANT_META="$(jq -c --arg variant_id "$VARIANT_ID" '.variants[] | select(.variant_id == $variant_id)' "$MANIFEST_FILE")"
  [[ -n "$VARIANT_META" ]] || fail "variant_id not found in manifest: $VARIANT_ID"

  VARIANT_ENABLED="$(jq -r 'if has("enabled") then .enabled else true end' <<<"$VARIANT_META")"
  [[ "$VARIANT_ENABLED" == "true" ]] || fail "variant is disabled or blocked: $VARIANT_ID"

  VARIANT_LANE="$(jq -r '.lane // "unspecified"' <<<"$VARIANT_META")"
  VARIANT_BENCHMARK_FAMILY="$(jq -r '.benchmark_family // empty' <<<"$VARIANT_META")"
  VARIANT_SUBSTRATE="$(jq -r '.substrate // "unspecified"' <<<"$VARIANT_META")"
  VARIANT_DEFENSE_MODE="$(jq -r '.defense_mode // "unspecified"' <<<"$VARIANT_META")"
  VARIANT_RUNNER_KIND="$(jq -r '.runner_kind' <<<"$VARIANT_META")"
  VARIANT_VM_PROFILE="$(jq -r '.vm_profile // empty' <<<"$VARIANT_META")"
  VARIANT_RUN_COUNT="$(jq -r '.run_count // 1' <<<"$VARIANT_META")"

  [[ -n "$VARIANT_VM_PROFILE" ]] || fail "variant is not VM-backed: $VARIANT_ID"
  case "$VARIANT_RUNNER_KIND" in
    m3_kali_same_vm|shield_lab_kali_orbstack)
      ;;
    *)
      fail "variant runner_kind is not OrbStack VM-backed: $VARIANT_RUNNER_KIND"
      ;;
  esac
}

load_profile_metadata() {
  PROFILE_META="$(jq -c --arg vm_profile "$VARIANT_VM_PROFILE" '.profiles[] | select(.vm_profile == $vm_profile)' "$SPOOL_MANIFEST")"
  [[ -n "$PROFILE_META" ]] || fail "vm_profile not found in spool manifest: $VARIANT_VM_PROFILE"

  MACHINE_NAME="$(jq -r '.machine_name' <<<"$PROFILE_META")"
  VM_SAMPLE_DIR="$(jq -r '.sample_dir' <<<"$PROFILE_META")"
  HELPER_SCRIPT="$(jq -r '.helper_script' <<<"$PROFILE_META")"

  if [[ -n "$VM_SAMPLE_DIR_OVERRIDE" ]]; then
    VM_SAMPLE_DIR="$VM_SAMPLE_DIR_OVERRIDE"
  fi

  [[ -x "$HELPER_SCRIPT" ]] || fail "spooled helper script is not executable: $HELPER_SCRIPT"
  [[ "$VM_SAMPLE_DIR" = /* ]] || fail "vm sample dir must be absolute: $VM_SAMPLE_DIR"
}

prepare_variant_dir() {
  VARIANT_DIR="$MATRIX_DIR/$VARIANT_ID"
  if [[ -d "$VARIANT_DIR" ]]; then
    if [[ -f "$VARIANT_DIR/pwnkit-stability-sample.json" ]] && ! truthy "$OVERWRITE"; then
      fail "variant already has a completed sample; set EIDOLON_PWNKIT_QUAL_VM_OVERWRITE=1 to replace it: $VARIANT_DIR"
    fi
    if truthy "$OVERWRITE"; then
      rm -rf "$VARIANT_DIR"
    fi
  fi
  mkdir -p "$VARIANT_DIR"
}

run_helper() {
  "$HELPER_SCRIPT" "$VARIANT_RUN_COUNT" "$VM_SAMPLE_DIR"
}

collect_vm_sample() {
  local collector_args=()

  [[ -x "$COLLECTOR" ]] || fail "VM sample collector is not executable: $COLLECTOR"

  collector_args+=(--vm "$MACHINE_NAME")
  if [[ -n "$HOST_BUNDLE_DIR" ]]; then
    [[ -d "$HOST_BUNDLE_DIR" ]] || fail "host bundle dir does not exist: $HOST_BUNDLE_DIR"
    collector_args+=(--host-bundle-dir "$HOST_BUNDLE_DIR")
  fi
  if [[ -n "$EDGE_DECISIONS_PATH" ]]; then
    [[ -f "$EDGE_DECISIONS_PATH" ]] || fail "edge decisions file does not exist: $EDGE_DECISIONS_PATH"
    collector_args+=(--edge-decisions "$EDGE_DECISIONS_PATH")
  fi
  collector_args+=("$VM_SAMPLE_DIR" "$VARIANT_DIR")

  "$COLLECTOR" "${collector_args[@]}"
}

write_vm_run_manifest() {
  jq -n \
    --arg variant_id "$VARIANT_ID" \
    --arg matrix_dir "$MATRIX_DIR" \
    --arg spool_manifest "$SPOOL_MANIFEST" \
    --arg helper_script "$HELPER_SCRIPT" \
    --arg machine_name "$MACHINE_NAME" \
    --arg vm_profile "$VARIANT_VM_PROFILE" \
    --arg runner_kind "$VARIANT_RUNNER_KIND" \
    --arg lane "$VARIANT_LANE" \
    --arg benchmark_family "$VARIANT_BENCHMARK_FAMILY" \
    --arg substrate "$VARIANT_SUBSTRATE" \
    --arg defense_mode "$VARIANT_DEFENSE_MODE" \
    --arg run_count "$VARIANT_RUN_COUNT" \
    --arg vm_sample_dir "$VM_SAMPLE_DIR" \
    --arg host_bundle_dir "$HOST_BUNDLE_DIR" \
    --arg edge_decisions_path "$EDGE_DECISIONS_PATH" \
    --arg watcher_script "$REPO_ROOT/examples/qualification/watch-pwnkit-qualification-vm-run.sh" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_qualification_orbstack_vm_variant_run",
      boundary: "scanner_qualification",
      claim_posture: "scanner_qualification_only",
      evaluation_lane_version: 1,
      generated_at: (now | todateiso8601),
      variant_id: $variant_id,
      lane: $lane,
      benchmark_family: (if $benchmark_family == "" then null else $benchmark_family end),
      substrate: $substrate,
      defense_mode: $defense_mode,
      artifact_identity: {
        artifact_kind: "pwnkit_qualification_orbstack_vm_variant_run",
        variant_id: $variant_id,
        vm_profile: $vm_profile,
        machine_name: $machine_name,
        vm_sample_dir: $vm_sample_dir
      },
      budget: {
        planned_run_count: ($run_count | tonumber)
      },
      matrix_dir: $matrix_dir,
      spool_manifest: $spool_manifest,
      helper_script: $helper_script,
      machine_name: $machine_name,
      vm_profile: $vm_profile,
      runner_kind: $runner_kind,
      run_count: ($run_count | tonumber),
      vm_sample_dir: $vm_sample_dir,
      observability: {
        watcher_script: $watcher_script,
        vm_sample_dir: $vm_sample_dir
      },
      host_bundle_dir: (if $host_bundle_dir == "" then null else $host_bundle_dir end),
      edge_decisions_path: (if $edge_decisions_path == "" then null else $edge_decisions_path end)
    }' > "$VARIANT_DIR/vm-run-manifest.json"
}

refresh_matrix_summary() {
  [[ -x "$MATRIX_COLLECTOR" ]] || fail "matrix collector is not executable: $MATRIX_COLLECTOR"
  "$MATRIX_COLLECTOR" "$MANIFEST_FILE" "$MATRIX_DIR" > "$MATRIX_DIR/pwnkit-qualification-matrix.json"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  [[ -n "$MATRIX_DIR" ]] || fail "missing matrix-dir"
  [[ -n "$VARIANT_ID" ]] || fail "missing variant-id"

  require_command jq

  [[ -d "$MATRIX_DIR" ]] || fail "matrix dir not found: $MATRIX_DIR"
  MATRIX_DIR="$(canonical_dir_path "$MATRIX_DIR")"
  MANIFEST_FILE="$MATRIX_DIR/pwnkit-qualification-variants.json"
  [[ -f "$MANIFEST_FILE" ]] || fail "matrix manifest not found: $MANIFEST_FILE"
  validate_matrix_manifest

  if [[ -z "$SPOOL_DIR" ]]; then
    SPOOL_DIR="$MATRIX_DIR/orbstack-vm-spool"
  fi

  load_variant_metadata

  mkdir -p "$SPOOL_DIR"
  SPOOL_DIR="$(canonical_dir_path "$SPOOL_DIR")"

  ensure_spool_manifest
  SPOOL_MANIFEST="$SPOOL_DIR/vm-spool-manifest.json"
  validate_spool_manifest

  load_profile_metadata
  prepare_variant_dir
  run_helper
  collect_vm_sample
  write_vm_run_manifest
  refresh_matrix_summary

  echo "completed OrbStack qualification variant: $VARIANT_ID -> $VARIANT_DIR"
}

main "$@"
