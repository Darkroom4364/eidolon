#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SAMPLE_DIR="${1:-}"
BUNDLE_DIR="${2:-}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/package-pwnkit-stock-vs-patched-qualification-sample.sh <sample-dir> <bundle-dir>

Packages a completed stock-vs-patched pwnkit qualification sample into a
commit-safe bundle.
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

redact_parity_json() {
  local input="$1"
  local output="$2"

  jq '
    def omitted_sample_path: "<sample-path-omitted>";
    .tracks.upstream_current.sample_path = omitted_sample_path
    | .tracks.local_patched_pwnkit.sample_path = omitted_sample_path
    | .artifact_identity = (
        if (.artifact_identity // null) == null then
          null
        else
          (.artifact_identity
            + {
                upstream_sample_source: omitted_sample_path,
                local_patched_sample_source: omitted_sample_path,
                parity_source: "<parity-source-omitted>"
              })
        end
      )
    | .redaction = {
        sample_paths_omitted: true
      }
  ' "$input" > "$output"
}

redact_sample_summary() {
  local input="$1"
  local output="$2"

  jq '
    def omitted_sample_path: "<sample-path-omitted>";
    .tracks.upstream_current.sample_path = omitted_sample_path
    | .tracks.local_patched_pwnkit.sample_path = omitted_sample_path
    | .artifact_identity = (
        if (.artifact_identity // null) == null then
          null
        else
          (.artifact_identity
            + {
                upstream_sample_source: omitted_sample_path,
                local_patched_sample_source: omitted_sample_path,
                parity_source: "<parity-source-omitted>"
              })
        end
      )
    | .artifacts |= [
        .[] |
        if (.sample_path // null) == null then
          .
        else
          . + {
            sample_path: omitted_sample_path,
            artifact_identity: (
              if (.artifact_identity // null) == null then
                null
              else
                (.artifact_identity + {sample_path: omitted_sample_path})
              end
            )
          }
        end
      ]
    | .redaction = {
        sample_paths_omitted: true,
        raw_pwnkit_artifacts_omitted: true,
        raw_proxy_events_omitted: true,
        private_debug_logs_omitted: true
      }
  ' "$input" > "$output"
}

write_readme() {
  {
    printf '# pwnkit Stock-vs-Patched Qualification Sample\n\n'
    printf 'scanner-qualification stock-vs-patched comparison bundle.\n\n'
    printf 'lane: `eidolon_owned_target`; defense: `comparison`.\n\n'
    printf '## Contents\n\n'
    printf -- '- `pwnkit-stability-sample.json`: top-level stock-vs-patched qualification summary.\n'
    printf -- '- `pwnkit-parity.json`: redacted parity comparison between the upstream-current and canonical local-patched tracks.\n'
    printf -- '- `tracks/upstream-current/...`: packaged upstream-current local sample.\n'
    printf -- '- `tracks/local-patched/...`: packaged canonical local-patched sample.\n'
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
  local top_level_summary
  local parity_summary
  local upstream_dir
  local local_dir

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

  [[ -d "$SAMPLE_DIR" ]] || fail "sample directory does not exist: $SAMPLE_DIR"

  top_level_summary="$SAMPLE_DIR/pwnkit-stability-sample.json"
  parity_summary="$SAMPLE_DIR/pwnkit-parity.json"
  upstream_dir="$SAMPLE_DIR/upstream-current"
  local_dir="$SAMPLE_DIR/local-patched"

  [[ -f "$top_level_summary" ]] || fail "missing sample summary: $top_level_summary"
  [[ -f "$parity_summary" ]] || fail "missing parity summary: $parity_summary"
  [[ -d "$upstream_dir" ]] || fail "missing upstream-current sample directory: $upstream_dir"
  [[ -d "$local_dir" ]] || fail "missing local-patched sample directory: $local_dir"

  jq -e '.run_kind == "pwnkit_stock_vs_patched_qualification_sample"' "$top_level_summary" >/dev/null \
    || fail "unexpected top-level run_kind in sample summary"

  ensure_empty_bundle_dir
  redact_sample_summary "$top_level_summary" "$BUNDLE_DIR/pwnkit-stability-sample.json"
  redact_parity_json "$parity_summary" "$BUNDLE_DIR/pwnkit-parity.json"

  mkdir -p "$BUNDLE_DIR/tracks"
  "$SCRIPT_DIR/../m3/package-pwnkit-sample.sh" "$upstream_dir" "$BUNDLE_DIR/tracks/upstream-current"
  "$SCRIPT_DIR/../m3/package-pwnkit-sample.sh" "$local_dir" "$BUNDLE_DIR/tracks/local-patched"

  write_readme
  write_checksums
}

main "$@"
