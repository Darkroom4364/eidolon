#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
MATRIX_DIR="${1:-}"
BUNDLE_DIR="${2:-}"
SUMMARY_FILE=""
MANIFEST_FILE=""
PLAN_FILE=""
SPOOL_FILE=""

usage() {
  cat <<'USAGE'
Usage: examples/qualification/package-pwnkit-qualification-matrix.sh <matrix-dir> <bundle-dir>

Packages a completed pwnkit qualification matrix into a commit-safe bundle.

Inputs:
  <matrix-dir>/pwnkit-qualification-variants.json
  <matrix-dir>/matrix-plan.json
  <matrix-dir>/vm-spool-plan.json
  <matrix-dir>/pwnkit-qualification-matrix.json
  <matrix-dir>/<variant-id>/...

Outputs:
  <bundle-dir>/README.md
  <bundle-dir>/qualification-report.md
  <bundle-dir>/pwnkit-qualification-variants.json
  <bundle-dir>/matrix-plan.json
  <bundle-dir>/vm-spool-plan.json
  <bundle-dir>/pwnkit-qualification-matrix.json
  <bundle-dir>/variants/<variant-id>/...
  <bundle-dir>/SHA256SUMS

Completed variants are re-packaged through examples/m3/package-pwnkit-sample.sh
so the qualification bundle stays separate from raw pwnkit artifacts.
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

ensure_empty_bundle_dir() {
  if [[ -e "$BUNDLE_DIR" && ! -d "$BUNDLE_DIR" ]]; then
    fail "bundle path exists and is not a directory: $BUNDLE_DIR"
  fi

  if [[ -d "$BUNDLE_DIR" ]] && [[ -n "$(find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    fail "bundle directory must be empty: $BUNDLE_DIR"
  fi

  mkdir -p "$BUNDLE_DIR"
}

validate_summary() {
  jq -e '
    .schema_version == 1
    and .run_kind == "pwnkit_qualification_matrix_summary"
    and .boundary == "scanner_qualification"
    and (.variants | type == "array")
  ' "$SUMMARY_FILE" >/dev/null || fail "invalid qualification matrix summary: $SUMMARY_FILE"
}

copy_top_level_files() {
  cp "$MANIFEST_FILE" "$BUNDLE_DIR/pwnkit-qualification-variants.json"
  cp "$PLAN_FILE" "$BUNDLE_DIR/matrix-plan.json"
  cp "$SPOOL_FILE" "$BUNDLE_DIR/vm-spool-plan.json"
  cp "$SUMMARY_FILE" "$BUNDLE_DIR/pwnkit-qualification-matrix.json"
  "$SCRIPT_DIR/report-pwnkit-qualification-matrix.sh" "$SUMMARY_FILE" \
    > "$BUNDLE_DIR/qualification-report.md"
}

package_variants() {
  local count
  local index
  local variant_id
  local execution_state
  local run_kind
  local source_dir
  local dest_dir

  count="$(jq '.variants | length' "$SUMMARY_FILE")"
  mkdir -p "$BUNDLE_DIR/variants"

  for ((index = 0; index < count; index++)); do
    variant_id="$(jq -r ".variants[$index].variant_id" "$SUMMARY_FILE")"
    execution_state="$(jq -r ".variants[$index].execution_state" "$SUMMARY_FILE")"
    source_dir="$MATRIX_DIR/$variant_id"
    dest_dir="$BUNDLE_DIR/variants/$variant_id"

    case "$execution_state" in
      completed)
        run_kind="$(jq -r '.run_kind' "$source_dir/pwnkit-stability-sample.json")"
        case "$run_kind" in
          m3_pwnkit_codex_sample)
            "$SCRIPT_DIR/../m3/package-pwnkit-sample.sh" "$source_dir" "$dest_dir"
            ;;
          pwnkit_direct_qualification_sample)
            "$SCRIPT_DIR/package-pwnkit-direct-qualification-sample.sh" "$source_dir" "$dest_dir"
            ;;
          *)
            fail "unsupported completed sample run_kind for $variant_id: $run_kind"
            ;;
        esac
        ;;
      planned)
        mkdir -p "$dest_dir"
        if [[ ! -f "$source_dir/sample-plan.txt" ]]; then
          fail "planned variant missing sample-plan.txt: $source_dir"
        fi
        cp "$source_dir/sample-plan.txt" "$dest_dir/sample-plan.txt"
        ;;
      blocked|missing)
        mkdir -p "$dest_dir"
        if [[ -f "$source_dir/variant-status.txt" ]]; then
          cp "$source_dir/variant-status.txt" "$dest_dir/variant-status.txt"
        elif [[ -f "$source_dir/sample-plan.txt" ]]; then
          cp "$source_dir/sample-plan.txt" "$dest_dir/sample-plan.txt"
        else
          jq -n \
            --arg variant_id "$variant_id" \
            --arg execution_state "$execution_state" \
            '{variant_id: $variant_id, execution_state: $execution_state}' \
            > "$dest_dir/variant-status.json"
        fi
        ;;
      *)
        fail "unsupported execution_state for $variant_id: $execution_state"
        ;;
    esac
  done
}

write_readme() {
  local completed planned blocked missing positive_done negative_done transfer_done stock_done

  completed="$(jq -r '.completed_variant_count' "$SUMMARY_FILE")"
  planned="$(jq -r '.planned_variant_count' "$SUMMARY_FILE")"
  blocked="$(jq -r '.blocked_variant_count' "$SUMMARY_FILE")"
  missing="$(jq -r '.missing_variant_count' "$SUMMARY_FILE")"
  positive_done="$(jq -r '.acceptance_coverage.positive_control_completed' "$SUMMARY_FILE")"
  negative_done="$(jq -r '.acceptance_coverage.negative_control_completed' "$SUMMARY_FILE")"
  transfer_done="$(jq -r '.acceptance_coverage.transfer_control_completed' "$SUMMARY_FILE")"
  stock_done="$(jq -r '.acceptance_coverage.stock_vs_patched_completed' "$SUMMARY_FILE")"

  {
    printf '# pwnkit Qualification Bundle\n\n'
    printf 'scanner-qualification evidence bundle packaged from the independent `#174` track.\n\n'
    printf '## Scope\n\n'
    printf -- '- boundary: `scanner_qualification`\n'
    printf -- '- completed variants: `%s`\n' "$completed"
    printf -- '- planned variants: `%s`\n' "$planned"
    printf -- '- blocked variants: `%s`\n' "$blocked"
    printf -- '- missing variants: `%s`\n' "$missing"
    printf -- '- positive control completed: `%s`\n' "$positive_done"
    printf -- '- negative control completed: `%s`\n' "$negative_done"
    printf -- '- transfer control completed: `%s`\n' "$transfer_done"
    printf -- '- stock-vs-patched completed: `%s`\n\n' "$stock_done"
    printf '## Contents\n\n'
    printf -- '- `qualification-report.md`: markdown review summary for the matrix.\n'
    printf -- '- `pwnkit-qualification-matrix.json`: collected machine-readable matrix summary.\n'
    printf -- '- `matrix-plan.json`: original planned qualification run layout.\n'
    printf -- '- `vm-spool-plan.json`: VM-backed topology spool requirements.\n'
    printf -- '- `variants/<variant-id>/...`: packaged completed samples or preserved plan/status files.\n'
    printf -- '- `SHA256SUMS`: checksums for committed bundle files.\n\n'
    printf 'Completed variants are packaged through the appropriate sample packager so raw pwnkit DBs, auth files, stdout/stderr logs, proxy JSONL, and private debug logs do not enter the qualification bundle.\n'
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

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ -z "$MATRIX_DIR" || -z "$BUNDLE_DIR" ]]; then
    usage >&2
    exit 2
  fi

  require_command jq
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
  fi

  if [[ ! -d "$MATRIX_DIR" ]]; then
    fail "matrix directory does not exist: $MATRIX_DIR"
  fi

  SUMMARY_FILE="$MATRIX_DIR/pwnkit-qualification-matrix.json"
  MANIFEST_FILE="$MATRIX_DIR/pwnkit-qualification-variants.json"
  PLAN_FILE="$MATRIX_DIR/matrix-plan.json"
  SPOOL_FILE="$MATRIX_DIR/vm-spool-plan.json"

  for required_file in "$SUMMARY_FILE" "$MANIFEST_FILE" "$PLAN_FILE" "$SPOOL_FILE"; do
    if [[ ! -f "$required_file" ]]; then
      fail "missing required matrix file: $required_file"
    fi
  done

  validate_summary
  ensure_empty_bundle_dir
  copy_top_level_files
  package_variants
  write_readme
  write_checksums

  echo "packaged pwnkit qualification bundle: $BUNDLE_DIR"
}

main "$@"
