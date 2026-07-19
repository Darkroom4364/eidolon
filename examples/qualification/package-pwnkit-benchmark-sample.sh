#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SAMPLE_DIR="${1:-}"
BUNDLE_DIR="${2:-}"
CHECKER="${EIDOLON_PWNKIT_BENCHMARK_CHECKER:-$SCRIPT_DIR/check-pwnkit-benchmark-sample.sh}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/package-pwnkit-benchmark-sample.sh <sample-dir> <bundle-dir>

Packages a completed benchmark-capability pwnkit sample into a commit-safe
bundle, keeping it separate from qualification and Eidolon-defensive bundles.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || fail "missing required tool: $command_name"
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

redact_benchmark_summary() {
  local input="$1"
  local output="$2"

  jq '
    def omitted_source_path: "<source-artifact-path-omitted>";
    .artifact_identity = (
      if (.artifact_identity // null) == null then
        null
      else
        (.artifact_identity + {
          raw_sample_summary_path: omitted_source_path,
          validation_artifact_path: (
            if (.artifact_identity.validation_artifact_path // null) == null then
              null
            else
              omitted_source_path
            end
          )
        })
      end
    )
    | .artifacts |= [
        .[] | . + {
          artifact_identity: (
            if (.artifact_identity // null) == null then
              null
            else
              (.artifact_identity + {raw_sample_summary_path: omitted_source_path})
            end
          )
        }
      ]
    | .redaction = {
        raw_sample_paths_omitted: true,
        raw_benchmark_artifacts_omitted: true
      }
  ' "$input" > "$output"
}

write_readme() {
  {
    printf '# pwnkit Benchmark Sample\n\n'
    printf 'benchmark-capability bundle kept separate from scanner qualification and Eidolon defensive claims.\n\n'
    printf '## Contents\n\n'
    printf -- '- `pwnkit-stability-sample.json`: benchmark-only summary.\n'
    printf -- '- `raw-sample/...`: packaged raw sample evidence.\n'
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
  local benchmark_summary raw_sample_dir

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ -z "$SAMPLE_DIR" || -z "$BUNDLE_DIR" ]]; then
    usage >&2
    exit 2
  fi

  require_command jq
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
  fi
  [[ -x "$CHECKER" ]] || fail "benchmark checker is not executable: $CHECKER"

  [[ -d "$SAMPLE_DIR" ]] || fail "sample directory does not exist: $SAMPLE_DIR"
  benchmark_summary="$SAMPLE_DIR/pwnkit-stability-sample.json"
  raw_sample_dir="$SAMPLE_DIR/raw-sample"
  [[ -f "$benchmark_summary" ]] || fail "missing benchmark summary: $benchmark_summary"
  [[ -d "$raw_sample_dir" ]] || fail "missing raw sample dir: $raw_sample_dir"
  "$CHECKER" "$benchmark_summary"

  ensure_empty_bundle_dir
  redact_benchmark_summary "$benchmark_summary" "$BUNDLE_DIR/pwnkit-stability-sample.json"
  "$SCRIPT_DIR/../m3/package-pwnkit-sample.sh" "$raw_sample_dir" "$BUNDLE_DIR/raw-sample"
  write_readme
  write_checksums
}

main "$@"
