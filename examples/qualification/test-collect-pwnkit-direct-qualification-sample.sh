#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-direct-qualification-sample.sh"
CHECKER="$SCRIPT_DIR/check-pwnkit-direct-qualification-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-direct-collect-test.XXXXXX"
}

write_summary() {
  local dir="$1"
  local finding_count="$2"
  local request_artifacts="$3"
  local agent_error_count="${4:-0}"

  cat > "$dir/pwnkit-summary.json" <<JSON
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_comparison",
  "boundary": "owned_loopback_lab",
  "artifact_dir": "$dir",
  "runner": {
    "environment": {
      "runner_environment": "host_mac",
      "runner_environment_source": "env_override",
      "network_topology": "same_host_loopback",
      "os": {"kernel_name": "Darwin"},
      "tool_fingerprint": []
    },
    "pwnkit": {
      "git_head": "fixture-head",
      "package_version": "fixture-version",
      "git_dirty": false,
      "origin_main": {"ahead": 0, "behind": 0, "in_sync": true},
      "fixture": {"id": "fixture-id", "pinned": true},
      "stale_dist_guard_bypassed": false,
      "evidence_track": "local_patched_pwnkit"
    }
  },
  "runs": {
    "direct": {
      "artifact_status": "present",
      "finding_count": $finding_count,
      "final_json_finding_count": $finding_count,
      "db_saved_finding_count": $finding_count,
      "db_active_finding_count": $finding_count,
      "pwnkit_events": {"tool_artifacts": $request_artifacts},
      "target_evidence_diagnostics": {"request_artifact_count": $request_artifacts},
      "agent_error_diagnostics": {
        "count": $agent_error_count,
        "class_counts": [
          {"error_class": "codex_backend_api_error", "count": $agent_error_count}
        ]
      }
    }
  }
}
JSON
}

test_collects_quiet_and_noisy_runs() {
  local temp_dir quiet_dir noisy_dir summary
  temp_dir="$(new_temp_dir)"
  quiet_dir="$temp_dir/run-1"
  noisy_dir="$temp_dir/run-2"
  mkdir -p "$quiet_dir" "$noisy_dir"
  write_summary "$quiet_dir" 0 3
  write_summary "$noisy_dir" 2 4

  summary="$("$COLLECTOR" "$quiet_dir" "$noisy_dir")"
  jq -e '
    .run_kind == "pwnkit_direct_qualification_sample"
    and .counts.quiet_runs == 1
    and .counts.noisy_runs == 1
    and .counts.target_interaction_observed == 2
    and .qualification_result.ready_for_negative_control_claim == false
    and .strongest_claim_level == "direct_findings_present"
    and .weakest_claim_level == "no_direct_findings"
  ' <<<"$summary" >/dev/null
}

test_checker_rejects_agent_errors() {
  local temp_dir run_dir summary_file output status=0
  temp_dir="$(new_temp_dir)"
  run_dir="$temp_dir/run-1"
  mkdir -p "$run_dir"
  write_summary "$run_dir" 0 2 1

  "$COLLECTOR" "$run_dir" > "$temp_dir/pwnkit-stability-sample.json"
  summary_file="$temp_dir/pwnkit-stability-sample.json"
  output="$("$CHECKER" "$summary_file" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'pwnkit agent errors detected' <<<"$output"
}

test_collects_quiet_and_noisy_runs
test_checker_rejects_agent_errors

printf 'direct qualification collector fixture tests passed\n'
