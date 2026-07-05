#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/microvm/collect-microvm-sample.sh [--host-bundle-dir <dir>] [--edge-decisions <file>] <sample-dir> <host-output-dir>

Copies a host-side mirrored microVM sample tree into a collected evidence
directory and writes a manifest that links scanner-side hashes to host-side
deployment artifacts.

This scaffold only supports already mirrored host paths. Future microVM guest
collection transports should feed into the same sample tree shape before this
collector runs.

Arguments:
  sample-dir         Absolute host path containing the mirrored sample tree
  host-output-dir    Destination directory on the host

Options:
  --host-bundle-dir <dir>
                     Link a host-side evidence bundle into the generated
                     manifest by path and hash.
  --edge-decisions <file>
                     Link a host-side edge decisions JSON export into the
                     generated manifest by path and hash.
  -h, --help         Show this help text.
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

copy_sample_tree() {
  local sample_dir="$1"
  local host_output_dir="$2"
  local manifest

  mkdir -p "$host_output_dir"
  manifest="$(mktemp)"
  trap 'rm -f "$manifest"' RETURN
  (
    cd "$sample_dir"
    printf '%s\0' './sample-plan.json' './pwnkit-stability-sample.json' > "$manifest"
    find . -maxdepth 2 -type f \
      \( -path './run-*/agent-summary.json' \
      -o -path './run-*/hypotheses.jsonl' \
      -o -path './run-*/actions.jsonl' \
      -o -path './run-*/guest-trace.jsonl' \
      -o -path './run-*/heartbeat.jsonl' \
      -o -path './run-*/exit-status.json' \
      -o -path './run-*/stdout.log' \
      -o -path './run-*/stderr.log' \
      -o -path './run-*/serial-console.log' \
      -o -path './run-*/vm-metadata.json' \) \
      -print0 >> "$manifest"
    find . -maxdepth 3 -type f -path './run-*/tool-results/*.json' -print0 >> "$manifest"
    tar --null -T "$manifest" -cf -
  ) | tar -xf - -C "$host_output_dir"
  rm -f "$manifest"
}

write_manifest() {
  local output_dir="$1"
  local sample_dir="$2"
  local host_bundle_dir="$3"
  local edge_decisions_path="$4"

  {
    printf '# MicroVM Sample Copy\n\n'
    printf -- '- copied_at_utc: `%s`\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf -- '- sample_dir: `%s`\n\n' "$sample_dir"
    printf '## Files\n\n'
    while IFS= read -r file; do
      [[ -n "$file" ]] || continue
      printf -- '- `%s` `%s`\n' \
        "${file#$output_dir/}" \
        "$(shasum -a 256 "$file" | awk '{print $1}')"
    done < <(find "$output_dir" -type f ! -name README.md | sort)

    if [[ -n "$host_bundle_dir" || -n "$edge_decisions_path" ]]; then
      printf '\n## Linked host artifacts\n\n'
      if [[ -n "$host_bundle_dir" ]]; then
        printf -- '- host_bundle_dir: `%s`\n' "$host_bundle_dir"
        if [[ -f "$host_bundle_dir/README.md" ]]; then
          printf -- '- host_bundle_readme_sha256: `%s`\n' \
            "$(shasum -a 256 "$host_bundle_dir/README.md" | awk '{print $1}')"
        fi
      fi
      if [[ -n "$edge_decisions_path" ]]; then
        printf -- '- edge_decisions_path: `%s`\n' "$edge_decisions_path"
        printf -- '- edge_decisions_sha256: `%s`\n' \
          "$(shasum -a 256 "$edge_decisions_path" | awk '{print $1}')"
      fi
    fi
  } > "$output_dir/README.md"
}

SAMPLE_DIR=""
HOST_OUTPUT_DIR=""
HOST_BUNDLE_DIR=""
EDGE_DECISIONS_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-bundle-dir)
      [[ $# -ge 2 ]] || fail "missing value for --host-bundle-dir"
      HOST_BUNDLE_DIR="$2"
      shift 2
      ;;
    --edge-decisions)
      [[ $# -ge 2 ]] || fail "missing value for --edge-decisions"
      EDGE_DECISIONS_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      fail "unknown option: $1"
      ;;
    *)
      if [[ -z "$SAMPLE_DIR" ]]; then
        SAMPLE_DIR="$1"
      elif [[ -z "$HOST_OUTPUT_DIR" ]]; then
        HOST_OUTPUT_DIR="$1"
      else
        fail "unexpected positional argument: $1"
      fi
      shift
      ;;
  esac
done

[[ -n "$SAMPLE_DIR" ]] || fail "missing sample-dir"
[[ -n "$HOST_OUTPUT_DIR" ]] || fail "missing host-output-dir"
[[ "$SAMPLE_DIR" = /* ]] || fail "sample-dir must be an absolute host path"
[[ -d "$SAMPLE_DIR" ]] || fail "sample-dir does not exist: $SAMPLE_DIR"
[[ -f "$SAMPLE_DIR/pwnkit-stability-sample.json" ]] || fail "missing pwnkit-stability-sample.json in sample-dir: $SAMPLE_DIR"
[[ -f "$SAMPLE_DIR/sample-plan.json" ]] || fail "missing sample-plan.json in sample-dir: $SAMPLE_DIR"

if [[ -n "$HOST_BUNDLE_DIR" && ! -d "$HOST_BUNDLE_DIR" ]]; then
  fail "host-bundle-dir does not exist: $HOST_BUNDLE_DIR"
fi
if [[ -n "$EDGE_DECISIONS_PATH" && ! -f "$EDGE_DECISIONS_PATH" ]]; then
  fail "edge-decisions file does not exist: $EDGE_DECISIONS_PATH"
fi

require_command shasum
mkdir -p "$HOST_OUTPUT_DIR"
copy_sample_tree "$SAMPLE_DIR" "$HOST_OUTPUT_DIR"
write_manifest "$HOST_OUTPUT_DIR" "$SAMPLE_DIR" "$HOST_BUNDLE_DIR" "$EDGE_DECISIONS_PATH"

echo "copied microVM sample to $HOST_OUTPUT_DIR"
