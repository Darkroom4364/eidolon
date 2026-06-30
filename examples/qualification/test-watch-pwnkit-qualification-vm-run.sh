#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
WATCHER="$SCRIPT_DIR/watch-pwnkit-qualification-vm-run.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-watch-pwnkit-vm-run.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

RUN_ROOT="$TMP_ROOT/sample"
RUN_DIR="$RUN_ROOT/run-1"
mkdir -p "$RUN_DIR/tool-results"

cat > "$RUN_DIR/agent-summary.json" <<'JSON'
{"status":"running","current_leg":"eidolon","artifact_counts":{"hypotheses":1,"actions":1,"tool_results":1}}
JSON

cat > "$RUN_DIR/hypotheses.jsonl" <<'JSONL'
{"hypothesis":"signal survives transfer"}
JSONL

cat > "$RUN_DIR/actions.jsonl" <<'JSONL'
{"action":"launch_pwnkit_scan","outcome":"started"}
JSONL

cat > "$RUN_DIR/tool-results/pwnkit-eidolon-attempt-1.json" <<'JSON'
{"tool":"pwnkit","label":"eidolon","status":"running"}
JSON

cat > "$RUN_DIR/pwnkit-eidolon.stderr.log" <<'LOG'
heartbeat line
LOG

cat > "$RUN_DIR/pwnkit-eidolon.stdout.log" <<'LOG'
stdout line
LOG

output="$("$WATCHER" --once "$RUN_ROOT")"

grep -q 'run_dir: ' <<<"$output"
grep -q 'agent-summary' <<<"$output"
grep -q 'signal survives transfer' <<<"$output"
grep -q 'launch_pwnkit_scan' <<<"$output"
grep -q 'tool-results/pwnkit-eidolon-attempt-1.json' <<<"$output"
grep -q 'heartbeat line' <<<"$output"
grep -q 'stdout line' <<<"$output"

printf 'watch pwnkit qualification VM run fixture tests passed\n'
