#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUN_SCRIPT="$SCRIPT_DIR/run-pwnkit-microvm.sh"
FAKE_GUEST_RUNNER="$SCRIPT_DIR/fake-guest-runner.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-microvm-fake-runner-test.XXXXXX"
}

test_fake_guest_runner_materializes_artifacts() {
  local temp_dir output
  temp_dir="$(new_temp_dir)"

  bash "$RUN_SCRIPT" 2 "$temp_dir/sample" >/dev/null

  output="$(
    bash "$FAKE_GUEST_RUNNER" "$temp_dir/sample/sample-plan.json"
  )"

  rg -q 'simulated microVM guest run wrote artifacts to' <<<"$output"
  [[ -f "$temp_dir/sample/pwnkit-stability-sample.json" ]]
  [[ -f "$temp_dir/sample/run-1/serial-console.log" ]]
  [[ -f "$temp_dir/sample/run-2/tool-results/probe.json" ]]
  jq -e '
    .schema_version == 1
    and .status == "simulated"
    and .runner_environment == "microvm"
    and (.runs | length) == 2
  ' "$temp_dir/sample/pwnkit-stability-sample.json" >/dev/null
}

test_fake_guest_runner_materializes_artifacts

printf 'microvm fake guest runner checks passed\n'
