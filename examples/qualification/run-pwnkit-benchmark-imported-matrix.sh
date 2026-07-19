#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TASK_EXPORT_PATH="${1:-}"
RUN_DIR="${2:-${EIDOLON_PWNKIT_BENCHMARK_IMPORTED_DIR:-/tmp/eidolon-pwnkit-benchmark-imported-$(date +%Y%m%d-%H%M%S)}}"

TASK_REPORTER="${EIDOLON_PWNKIT_BENCHMARK_TASK_REPORTER:-$SCRIPT_DIR/report-pwnkit-benchmark-task-export.sh}"
IMPORTER="${EIDOLON_PWNKIT_BENCHMARK_IMPORTER:-$SCRIPT_DIR/import-pwnkit-benchmark-tasks.sh}"
RUNNER="${EIDOLON_PWNKIT_BENCHMARK_IMPORTED_RUNNER:-$SCRIPT_DIR/run-pwnkit-benchmark-matrix.sh}"
REPORTER="${EIDOLON_PWNKIT_BENCHMARK_MATRIX_REPORTER:-$SCRIPT_DIR/report-pwnkit-benchmark-matrix.sh}"
PACKAGER="${EIDOLON_PWNKIT_BENCHMARK_MATRIX_PACKAGER:-$SCRIPT_DIR/package-pwnkit-benchmark-matrix.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/run-pwnkit-benchmark-imported-matrix.sh <tasks.json|tasks.jsonl> [run-dir]

Preflights an external benchmark task export, imports it into a benchmark-only
manifest, runs the pwnkit benchmark matrix, emits a benchmark report, and
packages the resulting bundle.

Outputs:
  <run-dir>/task-export-report.md
  <run-dir>/imported-manifest.json
  <run-dir>/matrix/...
  <run-dir>/benchmark-report.md
  <run-dir>/bundle/...
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ -n "$TASK_EXPORT_PATH" ]] || { usage >&2; exit 2; }
[[ -f "$TASK_EXPORT_PATH" ]] || fail "task export not found: $TASK_EXPORT_PATH"
[[ -x "$TASK_REPORTER" ]] || fail "task reporter is not executable: $TASK_REPORTER"
[[ -x "$IMPORTER" ]] || fail "importer is not executable: $IMPORTER"
[[ -x "$RUNNER" ]] || fail "matrix runner is not executable: $RUNNER"
[[ -x "$REPORTER" ]] || fail "matrix reporter is not executable: $REPORTER"
[[ -x "$PACKAGER" ]] || fail "matrix packager is not executable: $PACKAGER"

mkdir -p "$RUN_DIR"
MANIFEST_PATH="$RUN_DIR/imported-manifest.json"
MATRIX_DIR="$RUN_DIR/matrix"
BUNDLE_DIR="$RUN_DIR/bundle"
TASK_REPORT_PATH="$RUN_DIR/task-export-report.md"
MATRIX_REPORT_PATH="$RUN_DIR/benchmark-report.md"

"$TASK_REPORTER" "$TASK_EXPORT_PATH" > "$TASK_REPORT_PATH"
"$IMPORTER" "$TASK_EXPORT_PATH" "$MANIFEST_PATH"
"$RUNNER" "$MANIFEST_PATH" "$MATRIX_DIR" >/dev/null
"$REPORTER" "$MATRIX_DIR" > "$MATRIX_REPORT_PATH"
"$PACKAGER" "$MATRIX_DIR" "$BUNDLE_DIR" >/dev/null

printf 'task export report: %s\n' "$TASK_REPORT_PATH"
printf 'imported manifest: %s\n' "$MANIFEST_PATH"
printf 'benchmark matrix dir: %s\n' "$MATRIX_DIR"
printf 'benchmark bundle dir: %s\n' "$BUNDLE_DIR"

