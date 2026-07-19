#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGER="$SCRIPT_DIR/package-pwnkit-direct-qualification-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-direct-package-test.XXXXXX"
}

write_sample() {
  local sample_dir="$1"
  mkdir -p "$sample_dir/run-1"

  cat > "$sample_dir/pwnkit-stability-sample.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "pwnkit_direct_qualification_sample",
  "boundary": "scanner_qualification",
  "claim_posture": "scanner_qualification_only",
  "evaluation_lane_version": 1,
  "lane": "eidolon_owned_target",
  "benchmark_family": null,
  "defense_mode": "none",
  "substrate": "host_local",
  "artifact_identity": {
    "artifact_kind": "pwnkit_direct_qualification_sample",
    "source_artifact_count": 1
  },
  "budget": {
    "observed_artifact_count": 1,
    "observed_valid_summary_count": 1
  },
  "generated_at": "2026-06-29T00:00:00Z",
  "artifact_count": 1,
  "valid_summary_count": 1,
  "counts": {
    "target_interaction_observed": 1,
    "quiet_runs": 1,
    "noisy_runs": 0
  },
  "rates": {
    "quiet_run_rate": 1
  },
  "claim_level_counts": [
    {"claim_level": "no_direct_findings", "count": 1}
  ],
  "weakest_claim_level": "no_direct_findings",
  "strongest_claim_level": "no_direct_findings",
  "runner_git_heads": ["fixture-head"],
  "runner_package_versions": ["fixture-version"],
  "runner_pwnkit_fixture_ids": ["fixture-id"],
  "evidence_track_counts": [
    {"evidence_track": "local_patched_pwnkit", "count": 1}
  ],
  "evidence_tracks": ["local_patched_pwnkit"],
  "single_evidence_track": true,
  "mixed_evidence_tracks": false,
  "unknown_evidence_track_count": 0,
  "runner_environments": ["host_mac"],
  "substrate_counts": [
    {"substrate": "host_local", "count": 1}
  ],
  "runner_network_topologies": ["same_host_loopback"],
  "tool_fingerprint_summary": [],
  "source_checkout": {
    "all_runners_clean": true,
    "all_runners_origin_main_synced": true
  },
  "finding_reconciliation": {
    "direct_final_json_finding_total": 0,
    "direct_db_saved_finding_total": 0,
    "direct_db_active_finding_total": 0
  },
  "no_signal_diagnostics": {
    "sample_size": 1,
    "no_target_interaction_run_count": 0,
    "all_runs_no_target_interaction": false,
    "totals": {
      "direct_pwnkit_agent_errors": 0,
      "direct_request_artifacts": 2
    },
    "direct_agent_error_class_counts": [],
    "likely_cause": null,
    "next_questions": []
  },
  "qualification_result": {
    "ready_for_negative_control_claim": true,
    "quiet_run_count": 1,
    "noisy_run_count": 0,
    "target_interaction_run_count": 1
  },
  "strict_stability": {
    "ready_for_stability_claim": false
  },
  "artifacts": [
    {
      "artifact_dir": "/private/tmp/direct-source",
      "present": true,
      "lane": "eidolon_owned_target",
      "benchmark_family": null,
      "defense_mode": "none",
      "substrate": "host_local",
      "artifact_identity": {
        "artifact_kind": "pwnkit_direct_qualification_run",
        "artifact_dir": "/private/tmp/direct-source"
      },
      "evidence_track": "local_patched_pwnkit",
      "runner_git_head": "fixture-head",
      "runner_package_version": "fixture-version",
      "runner_git_dirty": false,
      "runner_origin_main": {"ahead": 0, "behind": 0, "in_sync": true},
      "runner_origin_main_in_sync": true,
      "runner_pwnkit_fixture": {"id": "fixture-id", "pinned": true},
      "runner_pwnkit_fixture_id": "fixture-id",
      "stale_dist_guard_bypassed": false,
      "runner_environment": "host_mac",
      "runner_environment_source": "env_override",
      "runner_network_topology": "same_host_loopback",
      "runner_os": {"kernel_name": "Darwin"},
      "runner_tool_fingerprint": [],
      "claim_level": "no_direct_findings",
      "target_interaction_observed": true,
      "direct_finding_count": 0,
      "direct_final_json_finding_count": 0,
      "direct_db_saved_finding_count": 0,
      "direct_db_active_finding_count": 0,
      "finding_diagnostics": null,
      "finding_reconciliation": null,
      "pwnkit_events": {"tool_artifacts": 2},
      "target_evidence_diagnostics": {"request_artifact_count": 2},
      "agent_error_diagnostics": {"count": 0, "class_counts": []}
    }
  ]
}
JSON

  cat > "$sample_dir/run-1/pwnkit-summary.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_comparison",
  "boundary": "owned_loopback_lab",
  "artifact_dir": "/private/tmp/direct-source",
  "runner": {
    "schema_version": 1,
    "run_kind": "m3_pwnkit_codex_runner",
    "created_at": "2026-06-29T00:00:00Z",
    "mode": "direct",
    "urls": {
      "target": "http://127.0.0.1:9101",
      "proxy": "http://127.0.0.1:8080"
    },
    "environment": {
      "runner_environment": "host_mac",
      "network_topology": "same_host_loopback"
    },
    "pwnkit": {
      "depth": "quick",
      "mode": "web",
      "runtime": "codex",
      "rate_limit": "2",
      "command_source": "fixture",
      "package_version": "fixture-version",
      "git_head": "fixture-head",
      "git_head_short": "fixture-head",
      "git_head_time_seconds": 1770000000,
      "git_dirty": false,
      "origin_main": {"ahead": 0, "behind": 0, "in_sync": true},
      "evidence_track": "local_patched_pwnkit",
      "fixture": {"id": "fixture-id", "pinned": true},
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
      "pwnkit_events": {"tool_artifacts": 2},
      "target_evidence_diagnostics": {"request_artifact_count": 2},
      "agent_error_diagnostics": {"count": 0, "class_counts": []}
    },
    "eidolon": {
      "artifact_status": "missing"
    }
  }
}
JSON
}

test_packager_creates_bundle() {
  local temp_dir sample_dir bundle_dir
  temp_dir="$(new_temp_dir)"
  sample_dir="$temp_dir/sample"
  bundle_dir="$temp_dir/bundle"
  write_sample "$sample_dir"

  "$PACKAGER" "$sample_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]]
  [[ -f "$bundle_dir/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/run-1/pwnkit-summary.redacted.json" ]]
  [[ -f "$bundle_dir/SHA256SUMS" ]]
  rg -q 'scanner-qualification direct-only negative-control bundle' "$bundle_dir/README.md"
  rg -q 'lane: `eidolon_owned_target`; defense: `none`.' "$bundle_dir/README.md"
  rg -q '<source-artifact-path-omitted>' "$bundle_dir/pwnkit-stability-sample.json"
  jq -e '
    .lane == "eidolon_owned_target"
    and .defense_mode == "none"
    and .substrate == "host_local"
    and .artifact_identity.artifact_kind == "pwnkit_direct_qualification_sample"
    and .artifacts[0].artifact_identity.artifact_dir == "<source-artifact-path-omitted>"
  ' "$bundle_dir/pwnkit-stability-sample.json" >/dev/null
}

test_packager_creates_bundle

printf 'direct qualification package fixture tests passed\n'
