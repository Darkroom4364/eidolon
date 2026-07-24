#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

MATRIX_DIR="${1:-}"
FINAL_BUNDLE_DIR="${2:-}"
BUNDLE_DIR=""
STAGING_DIR=""
MATRIX_MANIFEST=""
MATRIX_SUMMARY=""
INPUT_SNAPSHOT_DIR=""

usage() {
  cat <<'USAGE'
Usage: examples/m3/package-pwnkit-promotion-matrix.sh <matrix-dir> <bundle-dir>

Packages a completed pwnkit promotion matrix into a commit-safe bundle
reconstructed from typed public allowlists.

Environment:
  EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX
    If set to 1, allow packaging a matrix that fails its interpretation gate.
    Use only for diagnostic bundles, not commit-ready evidence claims.

Unknown fields, raw artifacts, commands, URLs, scope values, session/proof
identifiers, free-form notes, and unsafe matrix metadata are not exported.
USAGE
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

sha256_file() {
  local path="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path"
    return
  fi

  shasum -a 256 "$path"
}

validate_single_json_object() {
  local path="$1"
  local label="$2"

  jq -e -s '
    length == 1
    and (.[0] | type == "object")
  ' "$path" >/dev/null || fail "$label must contain exactly one JSON object: $path"
}

validate_variant_id() {
  local variant_id="$1"

  if [[ ! "$variant_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]]; then
    fail "invalid variant_id: $variant_id"
  fi
}

validate_run_name() {
  local run_name="$1"

  if [[ ! "$run_name" =~ ^run-[1-9][0-9]*$ ]]; then
    fail "invalid run directory name: $run_name"
  fi
}

ensure_bundle_target_available() {
  if [[ -L "$FINAL_BUNDLE_DIR" ]]; then
    fail "bundle path must not be a symlink: $FINAL_BUNDLE_DIR"
  fi
  if [[ -e "$FINAL_BUNDLE_DIR" && ! -d "$FINAL_BUNDLE_DIR" ]]; then
    fail "bundle path exists and is not a directory: $FINAL_BUNDLE_DIR"
  fi
  if [[ -d "$FINAL_BUNDLE_DIR" ]] \
    && [[ -n "$(find "$FINAL_BUNDLE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    fail "bundle directory must be empty: $FINAL_BUNDLE_DIR"
  fi
}

cleanup_stage() {
  if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
    rm -rf -- "$STAGING_DIR"
  fi
}

begin_staging() {
  local parent_dir
  parent_dir="$(dirname "$FINAL_BUNDLE_DIR")"
  mkdir -p "$parent_dir"
  STAGING_DIR="$(mktemp -d "$parent_dir/.eidolon-pwnkit-matrix.XXXXXX")"
  BUNDLE_DIR="$STAGING_DIR"
  trap cleanup_stage EXIT INT TERM
}

snapshot_matrix_contract() {
  local source_manifest="$MATRIX_MANIFEST"
  local source_summary="$MATRIX_SUMMARY"

  [[ ! -L "$source_manifest" ]] \
    || fail "matrix manifest must not be a symlink: $source_manifest"
  [[ ! -L "$source_summary" ]] \
    || fail "matrix summary must not be a symlink: $source_summary"

  INPUT_SNAPSHOT_DIR="$BUNDLE_DIR/.source"
  mkdir -p "$INPUT_SNAPSHOT_DIR"
  cp "$source_manifest" "$INPUT_SNAPSHOT_DIR/bait-promotion-variants.json"
  cp "$source_summary" "$INPUT_SNAPSHOT_DIR/pwnkit-promotion-matrix.json"
  MATRIX_MANIFEST="$INPUT_SNAPSHOT_DIR/bait-promotion-variants.json"
  MATRIX_SUMMARY="$INPUT_SNAPSHOT_DIR/pwnkit-promotion-matrix.json"
}

snapshot_variant_inputs() {
  local variant_count

  variant_count="$(jq '.variants | length' "$MATRIX_SUMMARY")"
  for ((index = 0; index < variant_count; index++)); do
    local variant_id
    local present
    local source_variant_dir
    local snapshot_variant_dir
    local source_run_dir
    local found_run=false

    variant_id="$(jq -r ".variants[$index].variant_id" "$MATRIX_SUMMARY")"
    present="$(jq -r ".variants[$index].present" "$MATRIX_SUMMARY")"
    validate_variant_id "$variant_id"
    [[ "$present" == "true" ]] || continue

    source_variant_dir="$MATRIX_DIR/$variant_id"
    snapshot_variant_dir="$INPUT_SNAPSHOT_DIR/variants/$variant_id"
    [[ -d "$source_variant_dir" ]] \
      || fail "missing observed variant directory: $source_variant_dir"
    [[ ! -L "$source_variant_dir" ]] \
      || fail "variant directory must not be a symlink: $source_variant_dir"
    [[ -f "$source_variant_dir/pwnkit-stability-sample.json" ]] \
      || fail "missing variant sample summary: $source_variant_dir/pwnkit-stability-sample.json"
    [[ ! -L "$source_variant_dir/pwnkit-stability-sample.json" ]] \
      || fail "variant sample summary must not be a symlink: $source_variant_dir/pwnkit-stability-sample.json"

    mkdir -p "$snapshot_variant_dir"
    cp \
      "$source_variant_dir/pwnkit-stability-sample.json" \
      "$snapshot_variant_dir/pwnkit-stability-sample.json"

    for source_run_dir in "$source_variant_dir"/run-*; do
      [[ -d "$source_run_dir" ]] || continue
      local run_name
      local snapshot_run_dir
      found_run=true
      run_name="$(basename "$source_run_dir")"
      validate_run_name "$run_name"
      [[ ! -L "$source_run_dir" ]] \
        || fail "variant run directory must not be a symlink: $source_run_dir"
      [[ -f "$source_run_dir/pwnkit-summary.json" ]] \
        || fail "missing variant run summary: $source_run_dir/pwnkit-summary.json"
      [[ -f "$source_run_dir/agent-replay-trace-summary.json" ]] \
        || fail "missing variant agent trace: $source_run_dir/agent-replay-trace-summary.json"
      [[ ! -L "$source_run_dir/pwnkit-summary.json" ]] \
        || fail "variant run summary must not be a symlink: $source_run_dir/pwnkit-summary.json"
      [[ ! -L "$source_run_dir/agent-replay-trace-summary.json" ]] \
        || fail "variant agent trace must not be a symlink: $source_run_dir/agent-replay-trace-summary.json"

      snapshot_run_dir="$snapshot_variant_dir/$run_name"
      mkdir -p "$snapshot_run_dir"
      cp \
        "$source_run_dir/pwnkit-summary.json" \
        "$snapshot_run_dir/pwnkit-summary.json"
      cp \
        "$source_run_dir/agent-replay-trace-summary.json" \
        "$snapshot_run_dir/agent-replay-trace-summary.json"
    done

    [[ "$found_run" == true ]] \
      || fail "variant contains no run-* directories: $source_variant_dir"
  done
}

discard_input_snapshot() {
  rm -rf -- "$INPUT_SNAPSHOT_DIR"
  INPUT_SNAPSHOT_DIR=""
}

publish_bundle() {
  if [[ -d "$FINAL_BUNDLE_DIR" ]]; then
    rmdir "$FINAL_BUNDLE_DIR"
  fi
  mv "$STAGING_DIR" "$FINAL_BUNDLE_DIR"
  STAGING_DIR=""
  BUNDLE_DIR="$FINAL_BUNDLE_DIR"
  trap - EXIT INT TERM
}

redact_json() {
  local constructor="$1"
  local input="$2"
  local output="$3"
  local temp_output="${output}.tmp"

  jq -e -L "$SCRIPT_DIR" \
    "include \"public-evidence-contract\"; $constructor" \
    "$input" > "$temp_output"
  [[ -s "$temp_output" ]] || fail "redaction produced no output for: $input"
  mv "$temp_output" "$output"
}

validate_public_contract() {
  local constructor="$1"
  local input="$2"
  local label="$3"

  jq -e -L "$SCRIPT_DIR" \
    "include \"public-evidence-contract\"; $constructor | true" \
    "$input" >/dev/null || fail "invalid $label public contract: $input"
}

validate_manifest_summary_agreement() {
  jq -e -n \
    --slurpfile manifest "$MATRIX_MANIFEST" \
    --slurpfile summary "$MATRIX_SUMMARY" '
      ($manifest[0].variants // []) as $manifest_variants
      | ($summary[0].variants // []) as $summary_variants
      | ($manifest_variants | map(.variant_id)) as $manifest_ids
      | ($summary_variants | map(.variant_id)) as $summary_ids
      | ($manifest_ids | length) > 0
      and ($manifest_ids | unique | length) == ($manifest_ids | length)
      and ($summary_ids | unique | length) == ($summary_ids | length)
      and $summary_ids == $manifest_ids
      and all(
        range(0; $manifest_variants | length);
        ($manifest_variants[.] | {
          variant_id,
          bait_profile,
          hypothesis,
          knobs,
          expected_observation
        })
        == ($summary_variants[.] | {
          variant_id,
          bait_profile,
          hypothesis,
          knobs,
          expected_observation
        })
      )
    ' >/dev/null || fail "matrix summary metadata does not match its manifest"
}

check_matrix_health() {
  local checker="$SCRIPT_DIR/check-pwnkit-promotion-matrix-health.sh"

  [[ -x "$checker" ]] \
    || fail "promotion matrix health checker is not executable: $checker"
  "$checker" "$MATRIX_SUMMARY"
}

matrix_value() {
  local filter="$1"
  jq -r "$filter // \"unknown\"" "$BUNDLE_DIR/pwnkit-promotion-matrix.json"
}

write_readme() {
  local collected_on
  local variant_count
  local observed_count
  local class_counts
  local differential_variants
  local stability_variants

  collected_on="$(date -u +%F)"
  variant_count="$(matrix_value '.variant_count')"
  observed_count="$(matrix_value '.observed_variant_count')"
  class_counts="$(jq -r '(.observation_class_counts // []) | map("`" + .observation_class + "`: `" + (.count|tostring) + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-promotion-matrix.json")"
  differential_variants="$(jq -r '(.ready_for_differential_finding_claim_variants // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-promotion-matrix.json")"
  stability_variants="$(jq -r '(.ready_for_stability_claim_variants // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-promotion-matrix.json")"

  {
    printf '# M3 pwnkit Promotion Matrix Evidence\n\n'
    printf 'Lab-only evidence bundle packaged on %s.\n\n' "$collected_on"
    printf '## Scope\n\n'
    printf -- '- Boundary: owned loopback lab.\n'
    printf -- '- Source matrix directory: omitted from the committed bundle.\n'
    printf -- '- Matrix variants: `%s` total, `%s` observed.\n\n' "$variant_count" "$observed_count"
    printf '## Disclosure Contract\n\n'
    printf 'Every JSON object is reconstructed from a typed public allowlist. Matrix hypotheses are bounded text; knobs and observations use strict token contracts. Unknown fields and sensitive runtime material are omitted, and invalid retained types fail packaging.\n\n'
    printf 'Checksums protect the packaged bytes against accidental change. Redaction and checksums do not establish semantic truth.\n\n'
    printf '## Contents\n\n'
    printf -- '- `bait-promotion-variants.json`: narrowed validated manifest.\n'
    printf -- '- `pwnkit-promotion-matrix.json`: narrowed matrix aggregate.\n'
    printf -- '- `variants/<variant-id>/`: typed public sample bundle per observed variant.\n'
    printf -- '- `SHA256SUMS`: checksums for packaged evidence files.\n\n'
    printf '## Result\n\n'
    printf -- '- observation classes: %s\n' "${class_counts:-unknown}"
    printf -- '- differential-finding-ready variants: %s\n' "${differential_variants:-none}"
    printf -- '- stability-claim-ready variants: %s\n\n' "${stability_variants:-none}"
    printf 'This remains Lab-only evidence and does not establish production readiness, attacker identity, semantic truth, or stability beyond the recorded samples.\n'
  } > "$BUNDLE_DIR/README.md"
}

write_checksums() {
  (
    cd "$BUNDLE_DIR"
    find . -type f ! -name SHA256SUMS | sort | while read -r path; do
      sha256_file "${path#./}"
    done
  ) > "$BUNDLE_DIR/SHA256SUMS"
}

package_variant() {
  local variant_id="$1"
  local source_variant_dir="$INPUT_SNAPSHOT_DIR/variants/$variant_id"
  local output_variant_dir="$BUNDLE_DIR/variants/$variant_id"

  validate_variant_id "$variant_id"
  [[ -d "$source_variant_dir" ]] \
    || fail "missing observed variant directory: $source_variant_dir"
  "$SCRIPT_DIR/package-pwnkit-sample.sh" \
    "$source_variant_dir" \
    "$output_variant_dir" >/dev/null
}

preflight_inputs() {
  validate_single_json_object "$MATRIX_MANIFEST" "matrix manifest"
  validate_single_json_object "$MATRIX_SUMMARY" "matrix summary"
  validate_public_contract public_matrix_manifest "$MATRIX_MANIFEST" "matrix manifest"
  validate_public_contract public_matrix_summary "$MATRIX_SUMMARY" "matrix summary"
  validate_manifest_summary_agreement
  check_matrix_health
}

package_bundle() {
  local variant_count

  redact_json \
    public_matrix_manifest \
    "$MATRIX_MANIFEST" \
    "$BUNDLE_DIR/bait-promotion-variants.json"
  redact_json \
    public_matrix_summary \
    "$MATRIX_SUMMARY" \
    "$BUNDLE_DIR/pwnkit-promotion-matrix.json"

  variant_count="$(jq '.variants | length' "$MATRIX_SUMMARY")"
  for ((index = 0; index < variant_count; index++)); do
    local variant_id
    local present
    variant_id="$(jq -r ".variants[$index].variant_id" "$MATRIX_SUMMARY")"
    present="$(jq -r ".variants[$index].present" "$MATRIX_SUMMARY")"
    validate_variant_id "$variant_id"
    if [[ "$present" == "true" ]]; then
      package_variant "$variant_id"
    fi
  done

  discard_input_snapshot
  write_readme
  write_checksums
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ -z "$MATRIX_DIR" || -z "$FINAL_BUNDLE_DIR" ]]; then
    usage >&2
    exit 2
  fi

  require_command jq
  if ! command -v sha256sum >/dev/null 2>&1 \
    && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
  fi
  [[ -d "$MATRIX_DIR" ]] \
    || fail "matrix directory does not exist: $MATRIX_DIR"

  MATRIX_MANIFEST="$MATRIX_DIR/bait-promotion-variants.json"
  MATRIX_SUMMARY="$MATRIX_DIR/pwnkit-promotion-matrix.json"
  [[ -f "$MATRIX_MANIFEST" ]] \
    || fail "missing matrix manifest: $MATRIX_MANIFEST"
  [[ -f "$MATRIX_SUMMARY" ]] \
    || fail "missing matrix summary: $MATRIX_SUMMARY"

  ensure_bundle_target_available
  begin_staging
  snapshot_matrix_contract
  preflight_inputs
  snapshot_variant_inputs
  package_bundle
  publish_bundle

  echo "packaged pwnkit promotion matrix bundle: $FINAL_BUNDLE_DIR"
}

main "$@"
