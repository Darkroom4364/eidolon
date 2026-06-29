#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-qualification-matrix.sh"
PACKAGER="$SCRIPT_DIR/package-pwnkit-qualification-matrix.sh"
REPORTER="$SCRIPT_DIR/report-pwnkit-qualification-matrix.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-qualification-package-test.XXXXXX"
}

write_stub_runner() {
  local path="$1"

  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"
runner_env="${EIDOLON_M3_RUNNER_ENVIRONMENT:-kali_vm}"
network_topology="${EIDOLON_M3_NETWORK_TOPOLOGY:-kali_vm_to_orbstack_nodeport}"
evidence_track="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-upstream_current}"
fixture_id="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-fixture-id}"

mkdir -p "$sample_dir/run-1/private"
{
  printf 'run_count=%s\n' "$run_count"
  printf 'dry_run=%s\n' "${EIDOLON_M3_SAMPLE_DRY_RUN:-${EIDOLON_M3_KALI_VM_DRY_RUN:-${EIDOLON_SHIELD_KALI_VM_DRY_RUN:-0}}}"
} > "$sample_dir/sample-plan.txt"

if [[ "${EIDOLON_M3_SAMPLE_DRY_RUN:-0}" == "1" \
   || "${EIDOLON_M3_KALI_VM_DRY_RUN:-0}" == "1" \
   || "${EIDOLON_SHIELD_KALI_VM_DRY_RUN:-0}" == "1" ]]; then
  exit 0
fi

cat > "$sample_dir/pwnkit-stability-sample.json" <<JSON
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_sample",
  "boundary": "owned_loopback_lab",
  "generated_at": "2026-06-29T00:00:00Z",
  "artifact_count": 1,
  "valid_summary_count": 1,
  "strongest_claim_level": "controlled_reality_entered",
  "weakest_claim_level": "controlled_reality_entered",
  "runner_git_heads": ["fixture-head"],
  "runner_package_versions": ["fixture-version"],
  "runner_pwnkit_fixture_ids": ["$fixture_id"],
  "evidence_track_counts": [{"evidence_track": "$evidence_track", "count": 1}],
  "evidence_tracks": ["$evidence_track"],
  "single_evidence_track": true,
  "mixed_evidence_tracks": false,
  "unknown_evidence_track_count": 0,
  "runner_environments": ["$runner_env"],
  "runner_network_topologies": ["$network_topology"],
  "tool_fingerprint_summary": [],
  "source_checkout": {
    "all_runners_clean": true,
    "all_runners_origin_main_synced": true
  },
  "finding_reconciliation": {
    "direct_final_json_finding_total": 1,
    "eidolon_final_json_finding_total": 1,
    "direct_db_saved_finding_total": 1,
    "eidolon_db_saved_finding_total": 1,
    "direct_db_active_finding_total": 1,
    "eidolon_db_active_finding_total": 1,
    "any_db_saved_findings_omitted_from_final_json": false,
    "final_json_counts_still_drive_finding_claims": true
  },
  "no_signal_diagnostics": {
    "likely_cause": null,
    "next_questions": []
  },
  "differential_findings": {
    "ready_for_differential_finding_claim": false
  },
  "strict_stability": {
    "ready_for_stability_claim": false
  },
  "artifacts": [
    {
      "artifact_dir": "/private/tmp/fixture-source",
      "present": true,
      "evidence_track": "$evidence_track",
      "runner_git_head": "fixture-head",
      "runner_package_version": "fixture-version",
      "runner_git_dirty": false,
      "runner_origin_main": {"ahead": 0, "behind": 0, "in_sync": true},
      "runner_origin_main_in_sync": true,
      "runner_pwnkit_fixture": {"id": "$fixture_id", "pinned": true},
      "runner_pwnkit_fixture_id": "$fixture_id",
      "stale_dist_guard_bypassed": false,
      "runner_environment": "$runner_env",
      "runner_environment_source": "env_override",
      "runner_network_topology": "$network_topology",
      "runner_os": {"kernel_name": "Linux"},
      "runner_tool_fingerprint": [],
      "claim_level": "same_session_bait_action_confirmed",
      "conclusion": "bait_action_observed",
      "target_interaction_observed": true,
      "bait_reached": true,
      "bait_action_observed": true,
      "same_session_confirmed_bait_action": true,
      "controlled_reality_entered": false,
      "direct_finding_count": 1,
      "eidolon_finding_count": 1,
      "direct_final_json_finding_count": 1,
      "eidolon_final_json_finding_count": 1,
      "direct_db_saved_finding_count": 1,
      "eidolon_db_saved_finding_count": 1,
      "direct_db_active_finding_count": 1,
      "eidolon_db_active_finding_count": 1,
      "pwnkit_events": {"eidolon": {"tool_artifacts": 1}, "direct": {"tool_artifacts": 1}},
      "target_evidence_diagnostics": {"eidolon": {"request_artifact_count": 1}, "direct": {"request_artifact_count": 1}},
      "agent_error_diagnostics": {"eidolon": {"count": 0, "class_counts": []}, "direct": {"count": 0, "class_counts": []}},
      "eidolon_proxy": {"request_count": 1, "request_path_counts": [{"value": "/docs?secret=value", "count": 1}]},
      "target_correlation_diagnostics": {"pwnkit_eidolon_request_artifact_count": 1, "eidolon_proxy_request_count": 1, "correlated_target_request_count": 1},
      "correlated_counts": {"target_requests": 1, "bait_exposures": 1, "bait_actions": 1, "same_session_confirmed_bait_actions": 1, "controlled_reality_entries": 0},
      "pinned_session": {"present": true, "cookie_preserved": true},
      "metrics": {"bait_follow_rate": 1, "same_session_confirmed_bait_follow_rate": 1},
      "agent_trace": {"claim_level": "same_session_bait_action_confirmed"},
      "trace_gap": {"controlled_reality_entered": false}
    }
  ]
}
JSON

cat > "$sample_dir/run-1/pwnkit-summary.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_comparison",
  "boundary": "owned_loopback_lab",
  "artifact_dir": "/private/tmp/fixture-source",
  "runner": {
    "schema_version": 1,
    "run_kind": "m3_pwnkit_codex_runner",
    "created_at": "2026-06-29T00:00:00Z",
    "mode": "all",
    "urls": {"target": "http://127.0.0.1:9001", "proxy": "http://127.0.0.1:8080"},
    "environment": {"runner_environment": "host_mac", "network_topology": "same_host_loopback"},
    "pwnkit": {
      "package_version": "fixture-version",
      "git_head": "fixture-head",
      "git_head_short": "fixture-head",
      "git_head_time_seconds": 1770000000,
      "git_dirty": false,
      "origin_main": {"ahead": 0, "behind": 0, "in_sync": true},
      "evidence_track": "upstream_current",
      "fixture": {"id": null, "pinned": false},
      "stale_dist_guard_bypassed": false
    }
  },
  "runs": {
    "direct": {
      "artifact_status": "present",
      "finding_count": 0,
      "final_json_finding_count": 0,
      "db_saved_finding_count": 0,
      "db_active_finding_count": 0,
      "pwnkit_events": {"tool_artifacts": 1},
      "target_evidence_diagnostics": {"request_artifact_count": 1},
      "agent_error_diagnostics": {"count": 0, "class_counts": []}
    },
    "eidolon": {
      "artifact_status": "present",
      "finding_count": 1,
      "final_json_finding_count": 1,
      "db_saved_finding_count": 1,
      "db_active_finding_count": 1,
      "pwnkit_events": {"tool_artifacts": 1},
      "target_evidence_diagnostics": {"request_artifact_count": 1},
      "agent_error_diagnostics": {"count": 0, "class_counts": []}
    }
  }
}
JSON

cat > "$sample_dir/run-1/agent-replay-trace-summary.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "agent_replay_trace_summary",
  "boundary": "owned_loopback_lab",
  "claim_level": "controlled_reality_entered"
}
JSON
SH
  chmod +x "$path"
}

write_stock_stub_runner() {
  local path="$1"

  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"

mkdir -p "$sample_dir/upstream-current/run-1/private" "$sample_dir/local-patched/run-1/private"
printf 'run_count=%s\n' "$run_count" > "$sample_dir/sample-plan.txt"

if [[ "${EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DRY_RUN:-0}" == "1" ]]; then
  exit 0
fi

cat > "$sample_dir/pwnkit-stability-sample.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "pwnkit_stock_vs_patched_qualification_sample",
  "boundary": "scanner_qualification",
  "generated_at": "2026-06-29T00:00:00Z",
  "artifact_count": 2,
  "valid_summary_count": 2,
  "strongest_claim_level": "controlled_reality_entered",
  "weakest_claim_level": "controlled_reality_entered",
  "runner_git_heads": ["upstream-head", "local-head"],
  "runner_package_versions": ["fixture-version"],
  "runner_pwnkit_fixture_ids": ["fixture-id"],
  "evidence_track_counts": [
    {"evidence_track": "local_patched_pwnkit", "count": 1},
    {"evidence_track": "upstream_current", "count": 1}
  ],
  "evidence_tracks": ["local_patched_pwnkit", "upstream_current"],
  "single_evidence_track": false,
  "mixed_evidence_tracks": true,
  "unknown_evidence_track_count": 0,
  "runner_environments": ["host_mac"],
  "runner_network_topologies": ["same_host_loopback"],
  "tool_fingerprint_summary": [],
  "source_checkout": {
    "all_runners_clean": true,
    "all_runners_origin_main_synced": true
  },
  "no_signal_diagnostics": {
    "likely_cause": null,
    "next_question": "parity_reproduced",
    "next_questions": ["parity_reproduced"]
  },
  "differential_findings": {
    "ready_for_differential_finding_claim": true,
    "parity_reproduced": true,
    "parity_status": "parity_reproduced",
    "positive_differential_run_count_delta": 0
  },
  "strict_stability": {
    "ready_for_stability_claim": true
  },
  "comparison": {
    "parity_status": "parity_reproduced",
    "parity_reproduced": true,
    "next_question": "parity_reproduced"
  },
  "tracks": {
    "upstream_current": {
      "sample_path": "/private/tmp/upstream-current",
      "runner_git_head": "upstream-head",
      "runner_package_version": "fixture-version",
      "runner_pwnkit_fixture_id": null
    },
    "local_patched_pwnkit": {
      "sample_path": "/private/tmp/local-patched",
      "runner_git_head": "local-head",
      "runner_package_version": "fixture-version",
      "runner_pwnkit_fixture_id": "fixture-id"
    }
  },
  "artifacts": [
    {
      "artifact_id": "upstream-current",
      "parity_role": "candidate",
      "evidence_track": "upstream_current",
      "sample_path": "/private/tmp/upstream-current",
      "runner_git_head": "upstream-head",
      "runner_package_version": "fixture-version",
      "runner_pwnkit_fixture_id": null,
      "claim_level": "controlled_reality_entered",
      "direct_finding_count": 0,
      "eidolon_finding_count": 1,
      "positive_differential_findings": 1,
      "strict_stability_ready_for_stability_claim": true,
      "differential_findings_ready_for_differential_finding_claim": true
    },
    {
      "artifact_id": "local-patched",
      "parity_role": "canonical",
      "evidence_track": "local_patched_pwnkit",
      "sample_path": "/private/tmp/local-patched",
      "runner_git_head": "local-head",
      "runner_package_version": "fixture-version",
      "runner_pwnkit_fixture_id": "fixture-id",
      "claim_level": "controlled_reality_entered",
      "direct_finding_count": 0,
      "eidolon_finding_count": 1,
      "positive_differential_findings": 1,
      "strict_stability_ready_for_stability_claim": true,
      "differential_findings_ready_for_differential_finding_claim": true
    }
  ]
}
JSON

cat > "$sample_dir/pwnkit-parity.json" <<'JSON'
{
  "schema_version": 1,
  "generated_at": "2026-06-29T00:00:00Z",
  "canonical_track": "local_patched_pwnkit",
  "tracks": {
    "upstream_current": {
      "sample_path": "/private/tmp/upstream-current",
      "runner_git_head": "upstream-head",
      "runner_package_version": "fixture-version",
      "runner_pwnkit_fixture_id": null
    },
    "local_patched_pwnkit": {
      "sample_path": "/private/tmp/local-patched",
      "runner_git_head": "local-head",
      "runner_package_version": "fixture-version",
      "runner_pwnkit_fixture_id": "fixture-id"
    }
  },
  "comparison": {
    "upstream_matches_local_patched_stability": true,
    "upstream_matches_local_patched_differential_findings": true,
    "upstream_matches_local_patched_claim_level": true,
    "positive_differential_run_count_delta": 0,
    "upstream_direct_finding_run_count": 0,
    "local_patched_direct_finding_run_count": 0,
    "parity_reproduced": true,
    "parity_status": "parity_reproduced",
    "next_question": "parity_reproduced"
  }
}
JSON

for track_dir in "$sample_dir/upstream-current" "$sample_dir/local-patched"; do
  cat > "$track_dir/pwnkit-stability-sample.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_sample",
  "generated_at": "2026-06-29T00:00:00Z",
  "artifact_count": 1,
  "valid_summary_count": 1,
  "counts": {
    "bait_reached": 1,
    "bait_action_observed": 1,
    "same_session_confirmed_bait_action": 1,
    "controlled_reality_entered": 1,
    "direct_quiet": 1,
    "direct_findings": 0,
    "eidolon_findings": 1,
    "positive_differential_findings": 1
  },
  "rates": {
    "target_interaction_rate": 1,
    "bait_reach_rate": 1,
    "bait_action_rate": 1,
    "same_session_confirmed_bait_action_rate": 1,
    "controlled_reality_entry_rate": 1,
    "direct_quiet_rate": 1,
    "eidolon_finding_rate": 1,
    "positive_differential_finding_rate": 1
  },
  "claim_level_counts": [{"claim_level": "controlled_reality_entered", "count": 1}],
  "weakest_claim_level": "controlled_reality_entered",
  "strongest_claim_level": "controlled_reality_entered",
  "runner_git_heads": ["fixture-head"],
  "runner_package_versions": ["fixture-version"],
  "runner_pwnkit_fixture_ids": [],
  "evidence_track_counts": [{"evidence_track": "upstream_current", "count": 1}],
  "evidence_tracks": ["upstream_current"],
  "single_evidence_track": true,
  "mixed_evidence_tracks": false,
  "unknown_evidence_track_count": 0,
  "runner_environments": ["host_mac"],
  "runner_network_topologies": ["same_host_loopback"],
  "tool_fingerprint_summary": [],
  "source_checkout": {"all_runners_clean": true, "all_runners_origin_main_synced": true},
  "finding_reconciliation": {
    "direct_final_json_finding_total": 0,
    "eidolon_final_json_finding_total": 1,
    "direct_db_saved_finding_total": 0,
    "eidolon_db_saved_finding_total": 1,
    "direct_db_active_finding_total": 0,
    "eidolon_db_active_finding_total": 1,
    "any_db_saved_findings_omitted_from_final_json": false,
    "final_json_counts_still_drive_finding_claims": true
  },
  "no_signal_diagnostics": {"likely_cause": null, "next_questions": []},
  "differential_findings": {"ready_for_differential_finding_claim": true, "positive_differential_run_count": 1, "direct_finding_run_count": 0, "eidolon_finding_run_count": 1, "controlled_reality_without_eidolon_finding_run_count": 0},
  "strict_stability": {"ready_for_stability_claim": true},
  "artifacts": [{
    "artifact_dir": "/private/tmp/fixture-source",
    "present": true,
    "evidence_track": "upstream_current",
    "runner_git_head": "fixture-head",
    "runner_package_version": "fixture-version",
    "runner_git_dirty": false,
    "runner_origin_main": {"ahead": 0, "behind": 0, "in_sync": true},
    "runner_origin_main_in_sync": true,
    "runner_pwnkit_fixture": null,
    "runner_pwnkit_fixture_id": null,
    "stale_dist_guard_bypassed": false,
    "runner_environment": "host_mac",
    "runner_environment_source": "env_override",
    "runner_network_topology": "same_host_loopback",
    "runner_os": {"kernel_name": "Darwin"},
    "runner_tool_fingerprint": [],
    "claim_level": "controlled_reality_entered",
    "conclusion": "bait_action_observed",
    "target_interaction_observed": true,
    "bait_reached": true,
    "bait_action_observed": true,
    "same_session_confirmed_bait_action": true,
    "controlled_reality_entered": true,
    "direct_finding_count": 0,
    "eidolon_finding_count": 1,
    "direct_final_json_finding_count": 0,
    "eidolon_final_json_finding_count": 1,
    "direct_db_saved_finding_count": 0,
    "eidolon_db_saved_finding_count": 1,
    "direct_db_active_finding_count": 0,
    "eidolon_db_active_finding_count": 1,
    "pwnkit_events": {"eidolon": {"tool_artifacts": 1}, "direct": {"tool_artifacts": 1}},
    "target_evidence_diagnostics": {"eidolon": {"request_artifact_count": 1}, "direct": {"request_artifact_count": 1}},
    "agent_error_diagnostics": {"eidolon": {"count": 0, "class_counts": []}, "direct": {"count": 0, "class_counts": []}},
    "eidolon_proxy": {"request_count": 1, "request_path_counts": [{"value": "/docs?secret=value", "count": 1}]},
    "target_correlation_diagnostics": {"pwnkit_eidolon_request_artifact_count": 1, "eidolon_proxy_request_count": 1, "correlated_target_request_count": 1},
    "correlated_counts": {"target_requests": 1, "bait_exposures": 1, "bait_actions": 1, "same_session_confirmed_bait_actions": 1, "controlled_reality_entries": 1},
    "pinned_session": {"present": true, "cookie_preserved": true},
    "metrics": {"bait_follow_rate": 1, "same_session_confirmed_bait_follow_rate": 1},
    "agent_trace": {"claim_level": "controlled_reality_entered"},
    "trace_gap": {"controlled_reality_entered": false}
  }]
}
JSON

  cat > "$track_dir/run-1/pwnkit-summary.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_comparison",
  "boundary": "owned_loopback_lab",
  "artifact_dir": "/private/tmp/fixture-source",
  "runner": {
    "schema_version": 1,
    "run_kind": "m3_pwnkit_codex_runner",
    "created_at": "2026-06-29T00:00:00Z",
    "mode": "all",
    "urls": {"target": "http://127.0.0.1:9001", "proxy": "http://127.0.0.1:8080"},
    "environment": {"runner_environment": "host_mac", "network_topology": "same_host_loopback"},
    "pwnkit": {
      "package_version": "fixture-version",
      "git_head": "fixture-head",
      "git_head_short": "fixture-head",
      "git_head_time_seconds": 1770000000,
      "git_dirty": false,
      "origin_main": {"ahead": 0, "behind": 0, "in_sync": true},
      "evidence_track": "upstream_current",
      "fixture": {"id": null, "pinned": false},
      "stale_dist_guard_bypassed": false
    }
  },
  "runs": {
    "direct": {
      "artifact_status": "present",
      "finding_count": 0,
      "final_json_finding_count": 0,
      "db_saved_finding_count": 0,
      "db_active_finding_count": 0,
      "pwnkit_events": {"tool_artifacts": 1},
      "target_evidence_diagnostics": {"request_artifact_count": 1},
      "agent_error_diagnostics": {"count": 0, "class_counts": []}
    },
    "eidolon": {
      "artifact_status": "present",
      "finding_count": 1,
      "final_json_finding_count": 1,
      "db_saved_finding_count": 1,
      "db_active_finding_count": 1,
      "pwnkit_events": {"tool_artifacts": 1},
      "target_evidence_diagnostics": {"request_artifact_count": 1},
      "agent_error_diagnostics": {"count": 0, "class_counts": []}
    }
  }
}
JSON

  cat > "$track_dir/run-1/agent-replay-trace-summary.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "agent_replay_trace_summary",
  "boundary": "owned_loopback_lab",
  "claim_level": "controlled_reality_entered"
}
JSON
done
SH
  chmod +x "$path"
}

write_manifest() {
  local manifest="$1"

  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_matrix_manifest",
    boundary: "scanner_qualification",
    variants: [
      {
        variant_id: "local_positive",
        enabled: true,
        control_kind: "positive_control",
        hypothesis_id: "host_positive",
        hypothesis: "local positive control",
        expected_observation: "direct_findings_present",
        runner_kind: "m3_local_sample",
        run_count: 1
      },
      {
        variant_id: "kali_transfer",
        enabled: true,
        control_kind: "transfer_control",
        hypothesis_id: "kali_transfer",
        hypothesis: "kali transfer control",
        expected_observation: "signal_survives_transfer",
        runner_kind: "shield_lab_kali_orbstack",
        vm_profile: "kali_vm_to_orbstack_nodeport"
      },
      {
        variant_id: "negative_blocked",
        enabled: false,
        control_kind: "negative_control",
        hypothesis_id: "negative_blocked",
        hypothesis: "negative control placeholder",
        expected_observation: "quiet_result",
        runner_kind: "m3_local_sample",
        blocked_reason: "waiting on hardened target"
      }
    ]
  }' > "$manifest"
}

write_stock_manifest() {
  local manifest="$1"

  jq -n '{
    schema_version: 1,
    run_kind: "pwnkit_qualification_matrix_manifest",
    boundary: "scanner_qualification",
    variants: [
      {
        variant_id: "stock_compare",
        enabled: true,
        control_kind: "stock_vs_patched",
        hypothesis_id: "stock_compare",
        hypothesis: "stock compare",
        expected_observation: "parity_reproduced",
        runner_kind: "qualification_stock_vs_patched_sample",
        run_count: 1
      }
    ]
  }' > "$manifest"
}

test_report_renders_markdown() {
  local temp_dir
  local manifest
  local matrix_dir
  local stub
  local output

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  stub="$temp_dir/stub-runner.sh"
  write_manifest "$manifest"
  write_stub_runner "$stub"

  EIDOLON_PWNKIT_QUAL_RUNNER_M3_LOCAL_SAMPLE="$stub" \
    EIDOLON_PWNKIT_QUAL_RUNNER_SHIELD_LAB_KALI_ORBSTACK="$stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  output="$("$REPORTER" "$matrix_dir")"
  rg -q '^# pwnkit Qualification Matrix' <<<"$output"
  rg -q 'positive control completed: `yes`' <<<"$output"
  rg -q 'negative control completed: `no`' <<<"$output"
  rg -q '`negative_blocked` \[negative_control\] state=`blocked`' <<<"$output"
}

test_packager_creates_bundle() {
  local temp_dir
  local manifest
  local matrix_dir
  local bundle_dir
  local stub

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  bundle_dir="$temp_dir/bundle"
  stub="$temp_dir/stub-runner.sh"
  write_manifest "$manifest"
  write_stub_runner "$stub"

  EIDOLON_PWNKIT_QUAL_RUNNER_M3_LOCAL_SAMPLE="$stub" \
    EIDOLON_PWNKIT_QUAL_RUNNER_SHIELD_LAB_KALI_ORBSTACK="$stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]]
  [[ -f "$bundle_dir/qualification-report.md" ]]
  [[ -f "$bundle_dir/pwnkit-qualification-matrix.json" ]]
  [[ -f "$bundle_dir/matrix-plan.json" ]]
  [[ -f "$bundle_dir/vm-spool-plan.json" ]]
  [[ -f "$bundle_dir/SHA256SUMS" ]]
  [[ -f "$bundle_dir/variants/local_positive/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/variants/local_positive/run-1/pwnkit-summary.redacted.json" ]]
  [[ -f "$bundle_dir/variants/local_positive/run-1/agent-replay-trace-summary.json" ]]
  [[ -f "$bundle_dir/variants/kali_transfer/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/variants/negative_blocked/variant-status.txt" ]]

  rg -q 'scanner-qualification evidence bundle' "$bundle_dir/README.md"
  rg -q 'state=`completed`' "$bundle_dir/qualification-report.md"
  rg -q 'state=`blocked`' "$bundle_dir/qualification-report.md"
  rg -q '<source-artifact-path-omitted>' \
    "$bundle_dir/variants/local_positive/pwnkit-stability-sample.json"
  rg -q 'negative_blocked/variant-status.txt' "$bundle_dir/SHA256SUMS"
}

test_packager_routes_stock_vs_patched_variant() {
  local temp_dir manifest matrix_dir bundle_dir stock_stub

  temp_dir="$(new_temp_dir)"
  manifest="$temp_dir/manifest.json"
  matrix_dir="$temp_dir/matrix"
  bundle_dir="$temp_dir/bundle"
  stock_stub="$temp_dir/stock-stub.sh"
  write_stock_manifest "$manifest"
  write_stock_stub_runner "$stock_stub"

  EIDOLON_PWNKIT_QUAL_RUNNER_STOCK_VS_PATCHED_SAMPLE="$stock_stub" \
    "$RUNNER" "$manifest" "$matrix_dir" >/dev/null

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/variants/stock_compare/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/variants/stock_compare/pwnkit-parity.json" ]]
  [[ -f "$bundle_dir/variants/stock_compare/tracks/upstream-current/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/variants/stock_compare/tracks/local-patched/pwnkit-stability-sample.json" ]]
  rg -q 'parity_status=`parity_reproduced`' "$bundle_dir/qualification-report.md"
}

test_report_renders_markdown
test_packager_creates_bundle
test_packager_routes_stock_vs_patched_variant

printf 'pwnkit qualification package fixture tests passed\n'
