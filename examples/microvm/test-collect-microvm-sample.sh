#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECT_SCRIPT="$SCRIPT_DIR/collect-microvm-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-microvm-collect-test.XXXXXX"
}

write_sample_tree() {
  local dir="$1"

  mkdir -p "$dir/run-1/tool-results" "$dir/host-bundle"
  cat > "$dir/sample-plan.json" <<'JSON'
{"schema_version":1,"mode":"dry_run","runner_environment":"microvm","run_count":1}
JSON
  cat > "$dir/pwnkit-stability-sample.json" <<'JSON'
{"schema_version":1,"runs":[{"run_index":1,"status":"planned"}]}
JSON
  cat > "$dir/run-1/agent-summary.json" <<'JSON'
{"status":"planned"}
JSON
  cat > "$dir/run-1/hypotheses.jsonl" <<'TXT'
{"hypothesis":"example"}
TXT
  cat > "$dir/run-1/actions.jsonl" <<'TXT'
{"action":"example"}
TXT
  cat > "$dir/run-1/guest-trace.jsonl" <<'TXT'
{"event":"vm_booted"}
TXT
  cat > "$dir/run-1/heartbeat.jsonl" <<'TXT'
{"event":"heartbeat"}
TXT
  cat > "$dir/run-1/exit-status.json" <<'JSON'
{"exit_code":0}
JSON
  cat > "$dir/run-1/stdout.log" <<'TXT'
stdout
TXT
  cat > "$dir/run-1/stderr.log" <<'TXT'
stderr
TXT
  cat > "$dir/run-1/serial-console.log" <<'TXT'
serial
TXT
  cat > "$dir/run-1/vm-metadata.json" <<'JSON'
{"guest_profile":"microvm_min"}
JSON
  cat > "$dir/run-1/tool-results/probe.json" <<'JSON'
{"tool":"probe"}
JSON
  cat > "$dir/host-bundle/README.md" <<'TXT'
host bundle
TXT
  cat > "$dir/edge-decisions.json" <<'JSON'
[]
JSON
}

test_collector_copies_files_and_links_host_artifacts() {
  local temp_dir sample_dir output_dir output
  temp_dir="$(new_temp_dir)"
  sample_dir="$temp_dir/sample"
  output_dir="$temp_dir/collected"

  write_sample_tree "$sample_dir"

  output="$(
    bash "$COLLECT_SCRIPT" \
      --host-bundle-dir "$sample_dir/host-bundle" \
      --edge-decisions "$sample_dir/edge-decisions.json" \
      "$sample_dir" \
      "$output_dir"
  )"

  rg -q 'copied microVM sample to' <<<"$output"
  [[ -f "$output_dir/sample-plan.json" ]]
  [[ -f "$output_dir/pwnkit-stability-sample.json" ]]
  [[ -f "$output_dir/run-1/agent-summary.json" ]]
  [[ -f "$output_dir/run-1/tool-results/probe.json" ]]
  [[ -f "$output_dir/run-1/serial-console.log" ]]
  [[ -f "$output_dir/README.md" ]]
  rg -q 'host_bundle_dir' "$output_dir/README.md"
  rg -q 'edge_decisions_path' "$output_dir/README.md"
}

test_collector_copies_files_and_links_host_artifacts

printf 'microvm collect scaffold checks passed\n'
