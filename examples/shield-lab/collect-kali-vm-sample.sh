#!/usr/bin/env bash
set -euo pipefail

ORB_BIN="${ORB_BIN:-orb}"
VM_NAME="${EIDOLON_KALI_VM_NAME:-kali}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/collect-kali-vm-sample.sh [--vm <name>] [--host-bundle-dir <dir>] [--edge-decisions <file>] <vm-sample-dir> <host-output-dir>

Copies the scanner-side summary for an OrbStack Kali sample onto the macOS host
so host-side M4 evidence remains auditable after the VM run finishes. If the
sample tree is already mirrored on the host, the script can relink it locally
without touching the VM again.

Arguments:
  vm-sample-dir     Absolute sample directory inside the Kali VM, or an
                    absolute host path containing an already mirrored sample
  host-output-dir   Absolute or relative destination directory on the host

Options:
  --vm <name>       OrbStack VM name. Defaults to `kali`.
  --host-bundle-dir <dir>
                     Link a host-side evidence bundle into the generated
                     manifest by path and hash.
  --edge-decisions <file>
                     Link a host-side edge decisions JSON export into the
                     generated manifest by path and hash.
  -h, --help        Show this help text.

Environment:
  ORB_BIN                 orb command override.
  EIDOLON_KALI_VM_NAME    Default VM name if --vm is omitted.
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

orb_cmd() {
  "$ORB_BIN" -m "$VM_NAME" bash -lc "$1"
}

copy_sample_tree() {
  local sample_dir="$1"
  local host_output_dir="$2"
  local quoted_sample_dir
  local manifest

  if [[ -f "$sample_dir/pwnkit-stability-sample.json" ]]; then
    mkdir -p "$host_output_dir"
    manifest="$(mktemp)"
    trap 'rm -f "$manifest"' RETURN
    (
      cd "$sample_dir"
      printf '%s\0' './pwnkit-stability-sample.json' > "$manifest"
      find . -maxdepth 2 -type f \
        \( -path './run-*/pwnkit-summary.json' \
        -o -path './run-*/pwnkit-direct.json' \
        -o -path './run-*/pwnkit-eidolon.json' \) \
        -print0 >> "$manifest"
      tar --null -T "$manifest" -cf -
    ) | tar -xf - -C "$host_output_dir"
    rm -f "$manifest"
    return
  fi

  quoted_sample_dir="$(printf '%q' "$sample_dir")"
  mkdir -p "$host_output_dir"

  orb_cmd "
set -euo pipefail
sample_dir=$quoted_sample_dir
test -f \"\$sample_dir/pwnkit-stability-sample.json\"
cd \"\$sample_dir\"
manifest=\$(mktemp)
trap 'rm -f \"\$manifest\"' EXIT
printf '%s\0' './pwnkit-stability-sample.json' > \"\$manifest\"
find . -maxdepth 2 -type f \\
  \\( -path './run-*/pwnkit-summary.json' \\
  -o -path './run-*/pwnkit-direct.json' \\
  -o -path './run-*/pwnkit-eidolon.json' \\) \\
  -print0 >> \"\$manifest\"
tar --null -T \"\$manifest\" -cf -
" | tar -xf - -C "$host_output_dir"
}

write_manifest() {
  local output_dir="$1"
  local sample_dir="$2"
  local host_bundle_dir="$3"
  local edge_decisions_path="$4"

  {
    printf '# OrbStack Kali Sample Copy\n\n'
    printf -- '- copied_at_utc: `%s`\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf -- '- vm_name: `%s`\n' "$VM_NAME"
    printf -- '- vm_sample_dir: `%s`\n\n' "$sample_dir"
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
        if [[ -f "$host_bundle_dir/cluster-status.json" ]]; then
          printf -- '- host_bundle_cluster_status_sha256: `%s`\n' \
            "$(shasum -a 256 "$host_bundle_dir/cluster-status.json" | awk '{print $1}')"
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

VM_SAMPLE_DIR=""
HOST_OUTPUT_DIR=""
HOST_BUNDLE_DIR=""
EDGE_DECISIONS_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm)
      [[ $# -ge 2 ]] || fail "missing value for --vm"
      VM_NAME="$2"
      shift 2
      ;;
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
      if [[ -z "$VM_SAMPLE_DIR" ]]; then
        VM_SAMPLE_DIR="$1"
      elif [[ -z "$HOST_OUTPUT_DIR" ]]; then
        HOST_OUTPUT_DIR="$1"
      else
        fail "unexpected positional argument: $1"
      fi
      shift
      ;;
  esac
done

[[ -n "$VM_SAMPLE_DIR" ]] || fail "missing vm-sample-dir"
[[ -n "$HOST_OUTPUT_DIR" ]] || fail "missing host-output-dir"
[[ "$VM_SAMPLE_DIR" = /* ]] || fail "vm-sample-dir must be an absolute path"
if [[ -n "$HOST_BUNDLE_DIR" && ! -d "$HOST_BUNDLE_DIR" ]]; then
  fail "host-bundle-dir does not exist: $HOST_BUNDLE_DIR"
fi
if [[ -n "$EDGE_DECISIONS_PATH" && ! -f "$EDGE_DECISIONS_PATH" ]]; then
  fail "edge-decisions file does not exist: $EDGE_DECISIONS_PATH"
fi

require_command "$ORB_BIN"
require_command shasum

mkdir -p "$HOST_OUTPUT_DIR"

copy_sample_tree "$VM_SAMPLE_DIR" "$HOST_OUTPUT_DIR"

if [[ ! -f "$HOST_OUTPUT_DIR/pwnkit-stability-sample.json" ]]; then
  fail "missing pwnkit-stability-sample.json in VM sample dir: $VM_SAMPLE_DIR"
fi

write_manifest "$HOST_OUTPUT_DIR" "$VM_SAMPLE_DIR" "$HOST_BUNDLE_DIR" "$EDGE_DECISIONS_PATH"

echo "copied Kali sample to $HOST_OUTPUT_DIR"
