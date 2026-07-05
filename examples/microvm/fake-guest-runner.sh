#!/usr/bin/env bash
set -euo pipefail

PLAN_PATH="${1:-}"

usage() {
  cat <<'USAGE'
Usage: examples/microvm/fake-guest-runner.sh <sample-plan.json>

Consumes a dry-run microVM sample plan and materializes the expected host-side
artifact skeleton without booting a real guest. This is a control-plane test
shim only.
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

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

[[ -n "$PLAN_PATH" ]] || fail "missing sample-plan.json path"
[[ -f "$PLAN_PATH" ]] || fail "plan file does not exist: $PLAN_PATH"

require_command jq

jq -e '
  .schema_version == 1
  and .run_kind == "pwnkit_microvm_sample_plan"
  and .mode == "dry_run"
  and .implemented == false
  and (.sample_dir | type == "string")
  and (.runs | type == "array")
' "$PLAN_PATH" >/dev/null || fail "invalid microVM sample plan: $PLAN_PATH"

sample_dir="$(jq -r '.sample_dir' "$PLAN_PATH")"
run_count="$(jq -r '.run_count' "$PLAN_PATH")"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for ((run_index = 1; run_index <= run_count; run_index++)); do
  run_dir="$sample_dir/run-$run_index"
  tool_dir="$run_dir/tool-results"
  mkdir -p "$tool_dir"

  cat > "$run_dir/agent-summary.json" <<JSON
{"schema_version":1,"status":"simulated","run_index":$run_index,"runner_environment":"microvm","generated_at_utc":"$generated_at"}
JSON
  cat > "$run_dir/hypotheses.jsonl" <<JSON
{"event":"hypothesis_generated","run_index":$run_index,"summary":"Simulated microVM hypothesis"}
JSON
  cat > "$run_dir/actions.jsonl" <<JSON
{"event":"action_selected","run_index":$run_index,"action":"simulate_guest_execution"}
JSON
  cat > "$run_dir/guest-trace.jsonl" <<JSON
{"event":"vm_booted","run_index":$run_index}
{"event":"plan_loaded","run_index":$run_index}
{"event":"runner_exited","run_index":$run_index,"status":"simulated"}
JSON
  cat > "$run_dir/heartbeat.jsonl" <<JSON
{"event":"heartbeat","run_index":$run_index,"status":"alive"}
JSON
  cat > "$run_dir/exit-status.json" <<JSON
{"schema_version":1,"run_index":$run_index,"exit_code":0,"status":"simulated"}
JSON
  printf 'simulated stdout for run %s\n' "$run_index" > "$run_dir/stdout.log"
  printf 'simulated stderr for run %s\n' "$run_index" > "$run_dir/stderr.log"
  printf 'serial console for run %s\n' "$run_index" > "$run_dir/serial-console.log"
  cat > "$run_dir/vm-metadata.json" <<JSON
{"schema_version":1,"run_index":$run_index,"guest_profile":"$(jq -r '.guest_profile' "$PLAN_PATH")","hypervisor":"$(jq -r '.hypervisor' "$PLAN_PATH")","simulated":true}
JSON
  cat > "$tool_dir/probe.json" <<JSON
{"schema_version":1,"run_index":$run_index,"tool":"probe","status":"simulated"}
JSON
done

jq -n \
  --arg generated_at "$generated_at" \
  --arg sample_dir "$sample_dir" \
  --arg runner_environment "$(jq -r '.runner_environment' "$PLAN_PATH")" \
  --arg network_topology "$(jq -r '.network_topology' "$PLAN_PATH")" \
  --arg hypervisor "$(jq -r '.hypervisor' "$PLAN_PATH")" \
  --arg guest_profile "$(jq -r '.guest_profile' "$PLAN_PATH")" \
  --argjson run_count "$run_count" '
  {
    schema_version: 1,
    generated_at_utc: $generated_at,
    sample_dir: $sample_dir,
    status: "simulated",
    runner_environment: $runner_environment,
    network_topology: $network_topology,
    hypervisor: $hypervisor,
    guest_profile: $guest_profile,
    runs: [range(1; $run_count + 1) | {
      run_index: .,
      status: "simulated",
      artifact_dir: ("run-" + (. | tostring))
    }]
  }' > "$sample_dir/pwnkit-stability-sample.json"

echo "simulated microVM guest run wrote artifacts to $sample_dir"
