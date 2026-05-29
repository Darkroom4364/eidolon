#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
CALLER_PWD="$(pwd -P)"

MANIFEST="${1:-${EIDOLON_M3_PROMOTION_MANIFEST:-$SCRIPT_DIR/bait-promotion-variants.json}}"
MATRIX_DIR="${2:-${EIDOLON_M3_PROMOTION_DIR:-/tmp/eidolon-m3-pwnkit-promotion-$(date +%Y%m%d-%H%M%S)}}"
RUN_COUNT="${EIDOLON_M3_PROMOTION_RUNS:-1}"
EIDOLON_M3_PROMOTION_DRY_RUN="${EIDOLON_M3_PROMOTION_DRY_RUN:-0}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/run-pwnkit-promotion-matrix.sh [manifest] [matrix-dir]

Runs each variant in the M3 pwnkit bait-promotion manifest through
run-pwnkit-sample.sh, varying only the optional lab-only bait profile.

Environment:
  EIDOLON_M3_PROMOTION_MANIFEST  Manifest path if [manifest] is omitted.
  EIDOLON_M3_PROMOTION_DIR       Matrix root if [matrix-dir] is omitted.
  EIDOLON_M3_PROMOTION_RUNS      Per-variant sample run count. Defaults to 1.
  EIDOLON_M3_PROMOTION_DRY_RUN   If true, create the planned layout only.
  EIDOLON_LAB_TARGET_URL         Passed through to run-pwnkit-sample.sh.
  EIDOLON_LAB_PROXY_URL          Passed through to run-pwnkit-sample.sh.
  EIDOLON_M3_ALLOW_AGENT_ERRORS  Passed through to run-pwnkit-sample.sh.
  EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE
                                  Passed through to run-pwnkit-sample.sh.
  PWNKIT_SOURCE_DIR              Passed through to run-pwnkit-sample.sh.
                                  Defaults to ~/Projects/pwnkit.
  PWNKIT_NODE_ENTRY/PWNKIT_BIN   Explicit pwnkit runner overrides passed
                                  through for diagnostics.

Use only against the owned loopback Lab target. Sync and rebuild pwnkit before
running when using a source checkout.
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

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
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

resolve_profile_path() {
  local profile="$1"
  local resolved

  if [[ "$profile" == /* ]]; then
    resolved="$profile"
  else
    resolved="$REPO_ROOT/$profile"
  fi

  if [[ ! -f "$resolved" ]]; then
    fail "bait_profile must point to an existing file: $profile"
  fi

  canonical_file_path "$resolved"
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
    and .run_kind == "m3_pwnkit_promotion_matrix_manifest"
    and .boundary == "owned_loopback_lab"
    and (.variants | type == "array")
    and (.variants | length > 0)
    and all(.variants[]; (
      (.variant_id | type == "string")
      and (.bait_profile == null or (.bait_profile | type == "string"))
      and (.expected_observation | type == "string")
    ))
  ' "$MANIFEST" >/dev/null || fail "invalid M3 pwnkit promotion manifest: $MANIFEST"
}

write_matrix_plan() {
  local dry_run_json="false"
  local plan_file="$MATRIX_DIR/matrix-plan.json"

  if truthy "$EIDOLON_M3_PROMOTION_DRY_RUN"; then
    dry_run_json="true"
  fi

  jq -n \
    --arg manifest "$MANIFEST" \
    --arg matrix_dir "$MATRIX_DIR" \
    --argjson run_count "$RUN_COUNT" \
    --argjson dry_run "$dry_run_json" \
    --slurpfile manifest_json "$MANIFEST" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_promotion_matrix_plan",
      generated_at: (now | todateiso8601),
      manifest_path: $manifest,
      matrix_dir: $matrix_dir,
      run_count: $run_count,
      dry_run: $dry_run,
      variants: $manifest_json[0].variants
    }' > "$plan_file"
}

run_variant() {
  local index="$1"
  local variant_id
  local bait_profile
  local profile_path
  local variant_dir

  variant_id="$(jq -r ".variants[$index].variant_id" "$MANIFEST")"
  validate_variant_id "$variant_id"

  bait_profile="$(jq -r ".variants[$index].bait_profile // empty" "$MANIFEST")"
  variant_dir="$MATRIX_DIR/$variant_id"
  mkdir -p "$variant_dir"

  echo "m3 pwnkit promotion variant $((index + 1))/$VARIANT_COUNT: $variant_id -> $variant_dir" >&2

  if [[ -n "$bait_profile" ]]; then
    profile_path="$(resolve_profile_path "$bait_profile")"
    EIDOLON_M3_SAMPLE_DRY_RUN="$EIDOLON_M3_PROMOTION_DRY_RUN" \
      EIDOLON_M3_BAIT_PROFILE="$profile_path" \
      "$SCRIPT_DIR/run-pwnkit-sample.sh" "$RUN_COUNT" "$variant_dir"
  else
    EIDOLON_M3_SAMPLE_DRY_RUN="$EIDOLON_M3_PROMOTION_DRY_RUN" \
      "$SCRIPT_DIR/run-pwnkit-sample.sh" "$RUN_COUNT" "$variant_dir"
  fi
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_command jq
  require_positive_integer "EIDOLON_M3_PROMOTION_RUNS" "$RUN_COUNT"

  MANIFEST="$(absolute_input_path "$MANIFEST")"
  if [[ ! -f "$MANIFEST" ]]; then
    fail "manifest not found: $MANIFEST"
  fi
  MANIFEST="$(canonical_file_path "$MANIFEST")"
  validate_manifest

  mkdir -p "$MATRIX_DIR"
  MATRIX_DIR="$(cd "$MATRIX_DIR" && pwd -P)"
  cp "$MANIFEST" "$MATRIX_DIR/bait-promotion-variants.json"
  write_matrix_plan

  VARIANT_COUNT="$(jq '.variants | length' "$MANIFEST")"
  for ((index = 0; index < VARIANT_COUNT; index++)); do
    run_variant "$index"
  done

  if truthy "$EIDOLON_M3_PROMOTION_DRY_RUN"; then
    echo "dry-run promotion matrix plan: $MATRIX_DIR/matrix-plan.json"
    exit 0
  fi

  "$SCRIPT_DIR/collect-pwnkit-promotion-matrix.sh" "$MANIFEST" "$MATRIX_DIR" \
    > "$MATRIX_DIR/pwnkit-promotion-matrix.json"

  echo "m3 pwnkit promotion matrix summary: $MATRIX_DIR/pwnkit-promotion-matrix.json"
}

main "$@"
