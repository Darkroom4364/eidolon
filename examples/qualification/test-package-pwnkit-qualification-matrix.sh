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

cat > "$sample_dir/pwnkit-stability-sample.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_sample",
  "generated_at": "2026-06-29T00:00:00Z",
  "artifact_count": 1,
  "valid_summary_count": 1,
  "counts": {
    "target_interaction_observed": 1,
    "bait_reached": 1,
    "bait_action_observed": 1,
    "same_session_confirmed_bait_action": 1,
    "controlled_reality_entered": 1,
    "direct_quiet": 1,
    "direct_findings": 1,
    "eidolon_findings": 1,
    "positive_differential_findings": 0,
    "pinned_session_present": 1,
    "pinned_cookie_preserved": 1
  },
  "rates": {
    "target_interaction_rate": 1,
    "bait_reach_rate": 1,
    "bait_action_rate": 1,
    "same_session_confirmed_bait_action_rate": 1,
    "controlled_reality_entry_rate": 1,
    "direct_quiet_rate": 1,
    "eidolon_finding_rate": 1,
    "positive_differential_finding_rate": 0,
    "pinned_cookie_preservation_rate": 1
  },
  "claim_level_counts": [
    {"claim_level": "same_session_bait_action_confirmed", "count": 1}
  ],
  "weakest_claim_level": "same_session_bait_action_confirmed",
  "strongest_claim_level": "same_session_bait_action_confirmed",
  "runner_git_heads": ["fixture-head"],
  "runner_package_versions": ["fixture-version"],
  "runner_pwnkit_fixture_ids": ["fixture-id"],
  "evidence_track_counts": [
    {"evidence_track": "upstream_current", "count": 1}
  ],
  "evidence_tracks": ["upstream_current"],
  "single_evidence_track": true,
  "mixed_evidence_tracks": false,
  "unknown_evidence_track_count": 0,
  "runner_environments": ["kali_vm"],
  "runner_network_topologies": ["kali_vm_to_orbstack_nodeport"],
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
    "totals": {
      "direct_pwnkit_agent_errors": 0,
      "eidolon_pwnkit_agent_errors": 0
    },
    "eidolon_agent_error_class_counts": [],
    "proxy_path_counts": [],
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
      "evidence_track": "upstream_current",
      "runner_git_head": "fixture-head",
      "runner_package_version": "fixture-version",
      "runner_git_dirty": false,
      "runner_origin_main": {
        "ahead": 0,
        "behind": 0,
        "in_sync": true
      },
      "runner_origin_main_in_sync": true,
      "runner_pwnkit_fixture": {
        "id": "fixture-id",
        "pinned": true
      },
      "runner_pwnkit_fixture_id": "fixture-id",
      "stale_dist_guard_bypassed": false,
      "runner_environment": "kali_vm",
      "runner_environment_source": "env_override",
      "runner_network_topology": "kali_vm_to_orbstack_nodeport",
      "runner_os": {
        "kernel_name": "Linux"
      },
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
      "finding_reconciliation": {
        "direct": {
          "final_json_finding_count": 1,
          "db_saved_finding_count": 1,
          "db_active_finding_count": 1,
          "counts_match": true,
          "db_saved_findings_omitted_from_final_json": false
        },
        "eidolon": {
          "final_json_finding_count": 1,
          "db_saved_finding_count": 1,
          "db_active_finding_count": 1,
          "counts_match": true,
          "db_saved_findings_omitted_from_final_json": false
        }
      },
      "pwnkit_events": {
        "eidolon": {"tool_artifacts": 1},
        "direct": {"tool_artifacts": 1}
      },
      "target_evidence_diagnostics": {
        "eidolon": {"request_artifact_count": 1},
        "direct": {"request_artifact_count": 1}
      },
      "agent_error_diagnostics": {
        "eidolon": {
          "count": 0,
          "stage_counts": [],
          "class_counts": [],
          "has_agent_error": false,
          "has_codex_token_refresh_failure": false,
          "has_codex_authentication_failure": false,
          "has_codex_backend_api_error": false
        },
        "direct": {
          "count": 0,
          "stage_counts": [],
          "class_counts": [],
          "has_agent_error": false,
          "has_codex_token_refresh_failure": false,
          "has_codex_authentication_failure": false,
          "has_codex_backend_api_error": false
        }
      },
      "eidolon_proxy": {
        "request_count": 1,
        "request_path_counts": [
          {"value": "/docs?secret=value", "count": 1}
        ]
      },
      "target_correlation_diagnostics": {
        "pwnkit_eidolon_request_artifact_count": 1,
        "eidolon_proxy_request_count": 1,
        "correlated_target_request_count": 1
      },
      "finding_gap": {
        "positive_differential_findings": false
      },
      "finding_export_gap": {
        "direct_db_saved_findings_omitted_from_final_json": false,
        "eidolon_db_saved_findings_omitted_from_final_json": false
      },
      "strict_correlation_gap": {
        "same_session_confirmed_bait_action_without_findings": false
      },
      "correlated_counts": {
        "target_requests": 1,
        "bait_exposures": 1,
        "bait_actions": 1,
        "same_session_confirmed_bait_actions": 1,
        "controlled_reality_entries": 0
      },
      "pinned_session": {
        "present": true,
        "cookie_preserved": true
      },
      "metrics": {
        "bait_follow_rate": 1,
        "same_session_confirmed_bait_follow_rate": 1
      },
      "agent_trace": {
        "claim_level": "same_session_bait_action_confirmed"
      },
      "trace_gap": {
        "controlled_reality_entered": false
      }
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
    "urls": {
      "target": "http://127.0.0.1:9001",
      "proxy": "http://127.0.0.1:8080"
    },
    "environment": {
      "runner_environment": "kali_vm",
      "network_topology": "kali_vm_to_orbstack_nodeport"
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
      "origin_main": {
        "ahead": 0,
        "behind": 0,
        "in_sync": true
      },
      "evidence_track": "upstream_current",
      "fixture": {
        "id": "fixture-id",
        "pinned": true
      },
      "stale_dist_guard_bypassed": false,
      "scopes": {
        "eidolon": {
          "path": "/private/tmp/eidolon-scope.json",
          "in_scope": ["127.0.0.1"],
          "out_of_scope": []
        },
        "direct": {
          "path": "/private/tmp/direct-scope.json",
          "in_scope": ["127.0.0.1"],
          "out_of_scope": []
        }
      }
    },
    "eidolon": {
      "pinned_session_enabled": true
    }
  },
  "runs": {
    "eidolon": {
      "target": "http://127.0.0.1:8080",
      "scan_depth": "quick",
      "duration_ms": 10,
      "finding_count": 1,
      "final_json_finding_count": 1,
      "db_saved_finding_count": 1,
      "db_active_finding_count": 1,
      "warnings": [],
      "pwnkit_events": {"tool_artifacts": 1}
    },
    "direct": {
      "target": "http://127.0.0.1:9001",
      "scan_depth": "quick",
      "duration_ms": 10,
      "finding_count": 1,
      "final_json_finding_count": 1,
      "db_saved_finding_count": 1,
      "db_active_finding_count": 1,
      "warnings": [],
      "pwnkit_events": {"tool_artifacts": 1}
    }
  },
  "eidolon_proxy": {
    "present": true,
    "event_count": 5,
    "request_count": 1,
    "kind_counts": {"request_seen": 1},
    "routing_counts": {"protected_upstream": 1},
    "counts": {"bait_exposed": 1}
  },
  "comparison": {
    "target_interaction_observed": true,
    "bait_reached": true,
    "bait_action_observed": true,
    "same_session_confirmed_bait_action": true,
    "controlled_reality_entered": false,
    "conclusion": "bait_action_observed",
    "claim_level": "same_session_bait_action_confirmed",
    "correlated_bait_events": {
      "matrix": [
        {
          "bait_id": "rel_2025_04_b7f2",
          "surfaces": ["/docs?secret=value"],
          "action_paths": ["/api/v2/import/reconcile"],
          "exposure_count": 1,
          "action_count": 1,
          "same_session_confirmed_action_count": 1
        }
      ]
    },
    "target_correlation_diagnostics": {
      "eidolon_request_artifact_count": 1
    },
    "finding_gap": {
      "positive_differential_findings": false
    },
    "finding_export_gap": {
      "eidolon_db_saved_findings_omitted_from_final_json": false
    },
    "strict_correlation_gap": {
      "same_session_confirmed_bait_action_without_findings": false
    }
  },
  "metrics": {
    "bait_follow_rate": 1
  },
  "pinned_session": {
    "present": true,
    "cookie_preserved": true
  },
  "notes": [
    "fixture note"
  ]
}
JSON

cat > "$sample_dir/run-1/agent-replay-trace-summary.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "agent_replay_trace_summary",
  "boundary": "owned_loopback_lab",
  "evidence_source": "fixture",
  "artifact_dir": "/private/tmp/fixture-source",
  "claim_level": "same_session_bait_action_confirmed",
  "counts": {
    "exposures": 1,
    "actions": 1
  },
  "metrics": {
    "same_session_confirmed_bait_follow_rate": 1
  },
  "pinned_session": {
    "present": true,
    "cookie_preserved": true
  },
  "sessions": {
    "eidolon": "session-1"
  },
  "bait_events": {
    "exposures": [
      {
        "bait_id": "rel_2025_04_b7f2",
        "surface": "/docs?secret=value"
      }
    ],
    "actions": [
      {
        "bait_id": "rel_2025_04_b7f2",
        "path": "/api/v2/import/reconcile"
      }
    ],
    "same_session_confirmed_actions": [
      {
        "bait_id": "rel_2025_04_b7f2",
        "path": "/api/v2/import/reconcile"
      }
    ],
    "controlled_reality_entries_after_confirmed_action": []
  },
  "notes": []
}
JSON
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

test_report_renders_markdown
test_packager_creates_bundle

printf 'pwnkit qualification package fixture tests passed\n'
