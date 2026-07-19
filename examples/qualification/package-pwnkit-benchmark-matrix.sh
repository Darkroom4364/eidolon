#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
MATRIX_DIR="${1:-}"
BUNDLE_DIR="${2:-}"
CHECKER="${EIDOLON_PWNKIT_BENCHMARK_MATRIX_CHECKER:-$SCRIPT_DIR/check-pwnkit-benchmark-matrix.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/package-pwnkit-benchmark-matrix.sh <matrix-dir> <bundle-dir>
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
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

write_readme() {
  local manifest_sha256 comparison_scope validated_rate task_export_sha256 task_export_format imported_task_count
  manifest_sha256="$(jq -r '.rerun_identity.manifest_sha256' "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
  comparison_scope="$(jq -r '.rerun_identity.comparison_scope' "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
  validated_rate="$(jq -r '.benchmark_summary.validated_rate' "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
  task_export_sha256="$(jq -r '.rerun_identity.task_export_sha256 // "none"' "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
  task_export_format="$(jq -r '.rerun_identity.task_export_format // "none"' "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
  imported_task_count="$(jq -r '.rerun_identity.imported_task_count // "none"' "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
  {
    printf '# pwnkit Benchmark Matrix Bundle\n\n'
    printf 'benchmark-only bundle kept separate from scanner qualification and Eidolon defensive claims.\n\n'
    printf '## Scope\n\n'
    printf -- '- claim posture: `benchmark_capability_only`\n'
    printf -- '- comparison scope: `%s`\n' "$comparison_scope"
    printf -- '- manifest sha256: `%s`\n' "$manifest_sha256"
    printf -- '- task export sha256: `%s`\n' "$task_export_sha256"
    printf -- '- task export format: `%s`\n' "$task_export_format"
    printf -- '- imported task count: `%s`\n' "$imported_task_count"
    printf -- '- validated rate: `%s`\n\n' "$validated_rate"
    printf '## Contents\n\n'
    printf -- '- `benchmark-report.md`: markdown benchmark scoreboard.\n'
    printf -- '- `pwnkit-benchmark-matrix.json`: machine-readable benchmark matrix summary.\n'
    printf -- '- `benchmark-plan.json`: original benchmark plan.\n'
    printf -- '- `variants/<variant-id>/...`: packaged benchmark samples or preserved plan/status files.\n'
    printf -- '- `SHA256SUMS`: checksums for committed bundle files.\n'
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
  local count index variant_id execution_state source_dir dest_dir

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  [[ -n "$MATRIX_DIR" && -n "$BUNDLE_DIR" ]] || { usage >&2; exit 2; }
  command -v jq >/dev/null 2>&1 || fail "missing required tool: jq"
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
  fi
  [[ -x "$CHECKER" ]] || fail "benchmark matrix checker is not executable: $CHECKER"
  [[ -d "$MATRIX_DIR" ]] || fail "matrix directory does not exist: $MATRIX_DIR"
  [[ -f "$MATRIX_DIR/pwnkit-benchmark-matrix.json" ]] || fail "missing benchmark matrix summary"
  "$CHECKER" "$MATRIX_DIR/pwnkit-benchmark-matrix.json"

  ensure_empty_bundle_dir
  cp "$MATRIX_DIR/pwnkit-benchmark-variants.json" "$BUNDLE_DIR/pwnkit-benchmark-variants.json"
  cp "$MATRIX_DIR/benchmark-plan.json" "$BUNDLE_DIR/benchmark-plan.json"
  cp "$MATRIX_DIR/pwnkit-benchmark-matrix.json" "$BUNDLE_DIR/pwnkit-benchmark-matrix.json"
  "$SCRIPT_DIR/report-pwnkit-benchmark-matrix.sh" "$MATRIX_DIR/pwnkit-benchmark-matrix.json" > "$BUNDLE_DIR/benchmark-report.md"

  count="$(jq '.variants | length' "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
  mkdir -p "$BUNDLE_DIR/variants"
  for ((index = 0; index < count; index++)); do
    variant_id="$(jq -r ".variants[$index].variant_id" "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
    execution_state="$(jq -r ".variants[$index].execution_state" "$MATRIX_DIR/pwnkit-benchmark-matrix.json")"
    source_dir="$MATRIX_DIR/$variant_id"
    dest_dir="$BUNDLE_DIR/variants/$variant_id"
    case "$execution_state" in
      completed)
        "$SCRIPT_DIR/package-pwnkit-benchmark-sample.sh" "$source_dir" "$dest_dir"
        ;;
      planned)
        mkdir -p "$dest_dir"
        cp "$source_dir/sample-plan.txt" "$dest_dir/sample-plan.txt"
        ;;
      blocked|missing)
        mkdir -p "$dest_dir"
        if [[ -f "$source_dir/variant-status.txt" ]]; then
          cp "$source_dir/variant-status.txt" "$dest_dir/variant-status.txt"
        elif [[ -f "$source_dir/sample-plan.txt" ]]; then
          cp "$source_dir/sample-plan.txt" "$dest_dir/sample-plan.txt"
        fi
        ;;
      *)
        fail "unsupported execution_state for $variant_id: $execution_state"
        ;;
    esac
  done

  write_readme
  write_checksums
}

main "$@"
