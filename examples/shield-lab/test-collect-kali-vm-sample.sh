#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-kali-copy-test.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

VM_SAMPLE_DIR="$TMP_ROOT/vm-sample"
HOST_OUTPUT_DIR="$TMP_ROOT/host-output"
HOST_BUNDLE_DIR="$TMP_ROOT/host-bundle"
EDGE_DECISIONS_PATH="$TMP_ROOT/edge-decisions.json"
mkdir -p "$VM_SAMPLE_DIR/run-1"
mkdir -p "$HOST_BUNDLE_DIR"

cat > "$VM_SAMPLE_DIR/pwnkit-stability-sample.json" <<'JSON'
{"strict_stability":{"sample_size":1},"aggregate_counts":{"eidolon_findings":1}}
JSON

cat > "$VM_SAMPLE_DIR/run-1/pwnkit-summary.json" <<'JSON'
{"run_id":"run-1","eidolon_findings":1}
JSON

cat > "$HOST_BUNDLE_DIR/README.md" <<'MD'
# Host bundle
MD

cat > "$HOST_BUNDLE_DIR/cluster-status.json" <<'JSON'
{"context":"orbstack"}
JSON

cat > "$EDGE_DECISIONS_PATH" <<'JSON'
[{"session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}]
JSON

ORB_STUB="$TMP_ROOT/orb"
cat > "$ORB_STUB" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "-m" ]]; then
  echo "expected -m" >&2
  exit 2
fi
shift 2

if [[ "${1:-}" != "bash" || "${2:-}" != "-lc" ]]; then
  echo "expected bash -lc" >&2
  exit 2
fi
shift 2

/bin/bash -lc "$1"
SH
chmod +x "$ORB_STUB"

ORB_BIN="$ORB_STUB" \
  "$REPO_ROOT/examples/shield-lab/collect-kali-vm-sample.sh" \
  --host-bundle-dir "$HOST_BUNDLE_DIR" \
  --edge-decisions "$EDGE_DECISIONS_PATH" \
  "$VM_SAMPLE_DIR" \
  "$HOST_OUTPUT_DIR"

test -f "$HOST_OUTPUT_DIR/pwnkit-stability-sample.json"
test -f "$HOST_OUTPUT_DIR/run-1/pwnkit-summary.json"
test -f "$HOST_OUTPUT_DIR/README.md"
grep -q 'pwnkit-stability-sample.json' "$HOST_OUTPUT_DIR/README.md"
grep -q 'run-1/pwnkit-summary.json' "$HOST_OUTPUT_DIR/README.md"
grep -q 'host_bundle_dir' "$HOST_OUTPUT_DIR/README.md"
grep -q 'host_bundle_readme_sha256' "$HOST_OUTPUT_DIR/README.md"
grep -q 'edge_decisions_sha256' "$HOST_OUTPUT_DIR/README.md"

LOCAL_OUTPUT_DIR="$TMP_ROOT/host-output-local"
"$REPO_ROOT/examples/shield-lab/collect-kali-vm-sample.sh" \
  --host-bundle-dir "$HOST_BUNDLE_DIR" \
  --edge-decisions "$EDGE_DECISIONS_PATH" \
  "$HOST_OUTPUT_DIR" \
  "$LOCAL_OUTPUT_DIR"

test -f "$LOCAL_OUTPUT_DIR/pwnkit-stability-sample.json"
test -f "$LOCAL_OUTPUT_DIR/run-1/pwnkit-summary.json"
grep -q 'host_bundle_dir' "$LOCAL_OUTPUT_DIR/README.md"
