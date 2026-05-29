#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGER="$SCRIPT_DIR/package-pwnkit-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-package-test.XXXXXX"
}

write_fixture_sample() {
  local sample_dir="$1"
  local run_dir="$sample_dir/run-1"

  mkdir -p "$run_dir/private"
  cat > "$sample_dir/pwnkit-stability-sample.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_sample",
  "generated_at": "2026-05-20T00:00:00Z",
  "artifact_count": 1,
  "valid_summary_count": 1,
  "counts": {
    "target_interaction_observed": 1,
    "bait_reached": 1,
    "bait_action_observed": 1,
    "same_session_confirmed_bait_action": 1,
    "controlled_reality_entered": 1,
    "direct_quiet": 1,
    "direct_findings": 0,
    "eidolon_findings": 0,
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
    "eidolon_finding_rate": 0,
    "positive_differential_finding_rate": 0,
    "pinned_cookie_preservation_rate": 1
  },
  "claim_level_counts": [
    {"claim_level": "controlled_reality_entered", "count": 1}
  ],
  "weakest_claim_level": "controlled_reality_entered",
  "strongest_claim_level": "controlled_reality_entered",
  "runner_git_heads": ["abc123"],
  "runner_package_versions": ["v0.test"],
  "runner_pwnkit_fixture_ids": ["pwnkit-v0.12.0-private"],
  "evidence_track_counts": [
    {"evidence_track": "upstream_current", "count": 1}
  ],
  "evidence_tracks": ["upstream_current"],
  "single_evidence_track": true,
  "mixed_evidence_tracks": false,
  "unknown_evidence_track_count": 0,
  "runner_environments": ["kali_vm"],
  "runner_network_topologies": ["same_vm_loopback"],
  "tool_fingerprint_summary": [
    {"name": "bash", "present_count": 1, "missing_count": 0, "versions": ["GNU bash fixture"]},
    {"name": "nmap", "present_count": 0, "missing_count": 1, "versions": ["unknown"]}
  ],
  "source_checkout": {
    "all_runners_clean": true,
    "all_runners_origin_main_synced": true
  },
  "finding_reconciliation": {
    "sample_size": 1,
    "direct_final_json_finding_total": 0,
    "eidolon_final_json_finding_total": 0,
    "direct_db_saved_finding_total": 0,
    "eidolon_db_saved_finding_total": 1,
    "direct_db_active_finding_total": 0,
    "eidolon_db_active_finding_total": 1,
    "direct_db_saved_findings_omitted_run_count": 0,
    "eidolon_db_saved_findings_omitted_run_count": 1,
    "positive_eidolon_db_saved_finding_delta_run_count": 1,
    "positive_eidolon_db_active_finding_delta_run_count": 1,
    "any_db_saved_findings_omitted_from_final_json": true,
    "final_json_counts_still_drive_finding_claims": true
  },
  "no_signal_diagnostics": {
    "sample_size": 1,
    "no_target_interaction_run_count": 0,
    "all_runs_no_target_interaction": false,
    "totals": {
      "eidolon_proxy_requests": 1,
      "correlated_target_requests": 1,
      "eidolon_pwnkit_agent_errors": 1
    },
    "runs_with_eidolon_agent_errors": 1,
    "runs_with_eidolon_codex_token_refresh_failure": 0,
    "eidolon_agent_error_class_counts": [
      {"error_class": "codex_backend_api_error", "count": 1}
    ],
    "proxy_path_counts": [
      {"path": "/docs?token=secret-token", "count": 1}
    ],
    "likely_cause": null,
    "next_questions": []
  },
  "differential_findings": {
    "ready_for_differential_finding_claim": false,
    "next_questions": ["why_controlled_reality_chain_was_not_promoted_to_finding"]
  },
  "evidence_gap_diagnostics": {
    "sample_size": 1,
    "proxy_trace_present_run_count": 1,
    "proxy_trace_controlled_reality_run_count": 1,
    "proxy_trace_real_surface_quiet_run_count": 1,
    "pwnkit_strict_controlled_reality_run_count": 1,
    "pwnkit_strict_same_session_run_count": 1,
    "proxy_trace_without_strict_controlled_reality_run_count": 0,
    "strict_controlled_reality_without_eidolon_finding_run_count": 1,
    "positive_differential_without_strict_controlled_reality_run_count": 0,
    "all_proxy_trace_contained": true,
    "all_strict_pwnkit_controlled_reality": true,
    "all_strict_controlled_reality_promoted_to_findings": false,
    "observed_gaps": ["strict_controlled_reality_without_eidolon_findings"],
    "next_questions": ["why_controlled_reality_chain_was_not_promoted_to_finding"]
  },
  "strict_stability": {
    "ready_for_stability_claim": false
  },
  "artifacts": [
    {
      "artifact_dir": "/private/tmp/eidolon-fixture",
      "present": true,
      "evidence_track": "upstream_current",
      "runner_git_head": "abc123",
      "runner_package_version": "v0.test",
      "runner_git_dirty": false,
      "runner_origin_main_in_sync": true,
      "runner_pwnkit_fixture": {
        "id": "pwnkit-v0.12.0-private",
        "pinned": true
      },
      "runner_pwnkit_fixture_id": "pwnkit-v0.12.0-private",
      "runner_command": "node /tmp/pwnkit/dist/pwnkit.js",
      "stale_dist_guard_bypassed": false,
      "runner_environment": "kali_vm",
      "runner_environment_source": "env_override",
      "runner_network_topology": "same_vm_loopback",
      "runner_os": {
        "kernel_name": "Linux",
        "machine_arch": "x86_64"
      },
      "runner_tool_fingerprint": [
        {"name": "bash", "present": true, "version": "GNU bash fixture"},
        {"name": "nmap", "present": false, "version": null}
      ],
      "claim_level": "controlled_reality_entered",
      "conclusion": "bait_action_observed",
      "target_interaction_observed": true,
      "bait_reached": true,
      "bait_action_observed": true,
      "same_session_confirmed_bait_action": true,
      "controlled_reality_entered": true,
      "direct_finding_count": 0,
      "eidolon_finding_count": 0,
      "direct_final_json_finding_count": 0,
      "eidolon_final_json_finding_count": 0,
      "direct_db_saved_finding_count": 0,
      "eidolon_db_saved_finding_count": 1,
      "direct_db_active_finding_count": 0,
      "eidolon_db_active_finding_count": 1,
      "finding_reconciliation": {
        "direct": {
          "final_json_finding_count": 0,
          "db_saved_finding_count": 0,
          "db_active_finding_count": 0,
          "counts_match": true,
          "db_saved_findings_omitted_from_final_json": false
        },
        "eidolon": {
          "final_json_finding_count": 0,
          "db_saved_finding_count": 1,
          "db_active_finding_count": 1,
          "counts_match": false,
          "db_saved_findings_omitted_from_final_json": true
        }
      },
      "pwnkit_events": {
        "eidolon": {
          "tool_artifacts": 1,
          "crawl_artifacts": [
            {"timestamp_ms": 1767225601000, "start_path": "/docs", "depth": 2, "pages_visited": 5}
          ]
        },
        "direct": {"tool_artifacts": 1}
      },
      "target_evidence_diagnostics": {
        "eidolon": {
          "request_artifact_count": 1,
          "crawl_artifact_count": 1,
          "crawl_start_paths": ["/docs"]
        },
        "direct": {"request_artifact_count": 1}
      },
      "agent_error_diagnostics": {
        "eidolon": {
          "count": 1,
          "stage_counts": [{"stage": "attack", "agentRole": "attack", "count": 1}],
          "class_counts": [{"error_class": "codex_backend_api_error", "count": 1}],
          "has_agent_error": true,
          "has_codex_token_refresh_failure": false,
          "has_codex_authentication_failure": false,
          "has_codex_backend_api_error": true
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
          {"value": "/docs?token=secret-token", "count": 1}
        ]
      },
      "target_correlation_diagnostics": {
        "pwnkit_eidolon_request_artifact_count": 1,
        "eidolon_proxy_request_count": 1,
        "correlated_target_request_count": 1
      },
      "finding_gap": {
        "positive_differential_findings": false,
        "next_question": "why_controlled_reality_chain_was_not_promoted_to_finding"
      },
      "finding_export_gap": {
        "direct_final_json_finding_count": 0,
        "eidolon_final_json_finding_count": 0,
        "direct_db_saved_finding_count": 0,
        "eidolon_db_saved_finding_count": 1,
        "direct_db_active_finding_count": 0,
        "eidolon_db_active_finding_count": 1,
        "direct_db_saved_findings_omitted_from_final_json": false,
        "eidolon_db_saved_findings_omitted_from_final_json": true,
        "any_db_saved_findings_omitted_from_final_json": true,
        "positive_eidolon_db_saved_finding_delta": true,
        "positive_eidolon_db_active_finding_delta": true,
        "final_json_counts_still_drive_finding_gap": true,
        "next_question": "why_db_saved_findings_were_omitted_from_final_json"
      },
      "strict_correlation_gap": {
        "proxy_confirmed_action_count": 1,
        "strict_correlated_action_count": 1,
        "strict_confirmed_action_count": 0,
        "unconfirmed_strict_action_count": 1,
        "proxy_confirmed_action_not_strict_count": 1,
        "matching_proxy_exposure_not_pwnkit_correlated_count": 1,
        "unconfirmed_actions": [
          {
            "bait_id": "openapi_reconcile_trace",
            "action_path": "/api/v2/import/reconcile?token=<redacted>",
            "has_exposure_id": true,
            "matching_proxy_exposure_count": 1,
            "matching_strict_exposure_count": 0,
            "matching_proxy_exposure_surfaces": ["/docs/legacy-import"],
            "matching_proxy_exposure_crawl_start_paths": ["/docs"],
            "reason": "matching_proxy_exposure_not_pwnkit_correlated"
          }
        ],
        "crawl_artifact_count": 1,
        "crawl_artifact_start_paths": ["/docs"],
        "matching_proxy_exposure_crawl_start_path_count": 1,
        "matching_proxy_exposure_crawl_start_paths": ["/docs"],
        "likely_cause": "matching_proxy_exposure_not_pwnkit_correlated",
        "likely_missing_artifact_class": "crawl_page_request_artifact",
        "next_questions": [
          "why_pwnkit_did_not_emit_request_artifact_for_exposure_surface",
          "whether_pwnkit_crawl_persisted_per_page_request_artifacts"
        ]
      },
      "correlated_counts": {
        "target_requests": 1,
        "bait_exposures": 1,
        "bait_actions": 1,
        "same_session_confirmed_bait_actions": 1,
        "controlled_reality_entries": 1
      },
      "pinned_session": {
        "present": true,
        "session_id": "00000000-0000-0000-0000-000000000001",
        "cookie_preserved": true
      },
      "metrics": {
        "bait_follow_rate": 1,
        "same_session_confirmed_bait_follow_rate": 1
      },
      "agent_trace": {
        "claim_level": "controlled_reality_entered",
        "real_surface_requests_after_containment": 0
      },
      "trace_gap": {
        "proxy_trace_present": true,
        "proxy_trace_claim_level": "controlled_reality_entered",
        "proxy_trace_controlled_reality_entered": true,
        "proxy_trace_real_surface_quiet": true,
        "pwnkit_strict_claim_level": "controlled_reality_entered",
        "pwnkit_strict_same_session_confirmed": true,
        "pwnkit_strict_controlled_reality_entered": true,
        "proxy_trace_controlled_reality_without_strict_confirmation": false,
        "strict_controlled_reality_without_eidolon_finding": true,
        "positive_differential_without_strict_controlled_reality": false,
        "next_question": "why_controlled_reality_chain_was_not_promoted_to_finding"
      }
    }
  ],
  "raw_future_field": "must-not-survive"
}
JSON

  cat > "$run_dir/pwnkit-summary.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_comparison",
  "boundary": "owned_loopback_lab",
  "artifact_dir": "/private/tmp/eidolon-fixture",
  "runner": {
    "schema_version": 1,
    "run_kind": "m3_pwnkit_codex_runner",
    "created_at": "2026-05-20T00:00:00Z",
    "mode": "all",
    "urls": {
      "target": "http://127.0.0.1:9001",
      "proxy": "http://127.0.0.1:8080"
    },
    "environment": {
      "runner_environment": "kali_vm",
      "runner_environment_source": "env_override",
      "network_topology": "same_vm_loopback",
      "os": {
        "kernel_name": "Linux",
        "machine_arch": "x86_64"
      },
      "tool_fingerprint": [
        {"name": "bash", "present": true, "version": "GNU bash fixture"},
        {"name": "nmap", "present": false, "version": null}
      ]
    },
    "pwnkit": {
      "depth": "quick",
      "mode": "web",
      "runtime": "codex",
      "rate_limit": "2",
      "command": "node /tmp/pwnkit/dist/pwnkit.js",
      "entry_path": "/tmp/pwnkit/dist/pwnkit.js",
      "source_dir": "/tmp/pwnkit",
      "command_source": "fixture",
      "package_version": "v0.test",
      "evidence_track": "upstream_current",
      "git_head": "abc123",
      "git_head_short": "abc123",
      "git_head_time_seconds": 1770000000,
      "git_dirty": false,
      "origin_main": {"in_sync": true},
      "fixture": {
        "id": "pwnkit-v0.12.0-private",
        "pinned": true
      },
      "stale_dist_guard_bypassed": false,
      "scopes": {
        "eidolon": {
          "path": "/private/tmp/eidolon-fixture/pwnkit-eidolon-scope.json",
          "in_scope": ["127.0.0.1"],
          "out_of_scope": []
        },
        "direct": {
          "path": "/private/tmp/eidolon-fixture/pwnkit-direct-scope.json",
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
      "finding_count": 0,
      "final_json_finding_count": 0,
      "db_saved_finding_count": 1,
      "db_active_finding_count": 1,
      "finding_reconciliation": {
        "final_json_finding_count": 0,
        "db_saved_finding_count": 1,
        "db_active_finding_count": 1,
        "counts_match": false,
        "db_saved_findings_omitted_from_final_json": true
      },
      "warnings": ["raw warning with secret-token"],
      "pwnkit_events": {
        "pipeline_events": 1,
        "tool_artifacts": 1,
        "tool_counts": [{"tool": "http_request", "count": 1}],
        "crawl_artifacts": [
          {"timestamp_ms": 1767225601000, "start_path": "/docs", "depth": 2, "pages_visited": 5}
        ]
      },
      "requested_paths": [
        {"method": "GET", "path": "/docs?token=secret-token", "tool_evidence_label": "secret-label"}
      ],
      "finding_diagnostics": {
        "severity_counts": [],
        "field_presence": {"title": 0}
      },
      "target_evidence_diagnostics": {
        "request_artifact_count": 1,
        "crawl_artifact_count": 1,
        "crawl_start_paths": ["/docs"],
        "observed_request_evidence_without_findings": true
      },
      "agent_error_diagnostics": {
        "count": 1,
        "stage_counts": [{"stage": "attack", "agentRole": "attack", "count": 1}],
        "class_counts": [{"error_class": "codex_backend_api_error", "count": 1}],
        "has_agent_error": true,
        "has_codex_token_refresh_failure": false,
        "has_codex_authentication_failure": false,
        "has_codex_backend_api_error": true
      }
    },
    "direct": {
      "target": "http://127.0.0.1:9001",
      "scan_depth": "quick",
      "duration_ms": 10,
      "finding_count": 0,
      "final_json_finding_count": 0,
      "db_saved_finding_count": 0,
      "db_active_finding_count": 0,
      "finding_reconciliation": {
        "final_json_finding_count": 0,
        "db_saved_finding_count": 0,
        "db_active_finding_count": 0,
        "counts_match": true,
        "db_saved_findings_omitted_from_final_json": false
      },
      "warnings": [],
      "pwnkit_events": {
        "pipeline_events": 1,
        "tool_artifacts": 1,
        "tool_counts": [{"tool": "http_request", "count": 1}]
      },
      "agent_error_diagnostics": {
        "count": 0,
        "stage_counts": [],
        "class_counts": [],
        "has_agent_error": false,
        "has_codex_token_refresh_failure": false,
        "has_codex_authentication_failure": false,
        "has_codex_backend_api_error": false
      },
      "requested_paths": [
        {"method": "GET", "path": "/health?token=direct-secret", "tool_evidence_label": "direct-secret-label"}
      ]
    }
  },
  "eidolon_proxy": {
    "present": true,
    "event_count": 5,
    "request_count": 2,
    "kind_counts": [{"kind": "request_seen", "count": 2}],
    "routing_counts": [{"routing_decision": "controlled_reality", "count": 1}],
    "counts": {
      "bait_exposures": 1,
      "bait_actions": 1,
      "same_session_confirmed_bait_actions": 1,
      "controlled_reality_entries": 1
    }
  },
  "pinned_session": {
    "present": true,
    "session_id": "00000000-0000-0000-0000-000000000001",
    "cookie_preserved": true
  },
  "comparison": {
    "direct_requested_paths": ["/health?token=direct-secret"],
    "eidolon_requested_paths": ["/docs?token=secret-token"],
    "paths_only_direct": ["/health?token=direct-secret"],
    "paths_only_eidolon": ["/docs?token=secret-token"],
    "correlated_target_requests": [
      {
        "method": "GET",
        "path": "/docs?token=secret-token",
        "tool_evidence_label": "secret-label"
      }
    ],
    "correlated_bait_events": {
      "exposures": [
        {"bait_id": "openapi_reconcile_trace", "surface": "/openapi.json?token=secret-token"}
      ],
      "actions": [
        {"bait_id": "openapi_reconcile_trace", "path": "/api/v2/import/reconcile?token=secret-token"}
      ],
      "same_session_confirmed_actions": [
        {"bait_id": "openapi_reconcile_trace", "path": "/api/v2/import/reconcile?token=secret-token"}
      ],
      "controlled_reality_entries": [
        {"reason": "controlled"}
      ],
      "matrix": [
        {
          "bait_id": "openapi_reconcile_trace",
          "exposure_count": 1,
          "action_count": 1,
          "same_session_confirmed_action_count": 1,
          "surfaces": ["/openapi.json?token=secret-token"],
          "action_paths": ["/api/v2/import/reconcile?token=secret-token"]
        }
      ]
    },
    "target_interaction_observed": true,
    "bait_reached": true,
    "bait_action_observed": true,
    "same_session_confirmed_bait_action": true,
    "controlled_reality_entered": true,
    "claim_level": "controlled_reality_entered",
    "conclusion": "bait_action_observed",
    "target_correlation_diagnostics": {
      "pwnkit_eidolon_request_artifact_count": 1,
      "eidolon_proxy_request_count": 2,
      "correlated_target_request_count": 1
    },
    "finding_gap": {
      "positive_differential_findings": false,
      "eidolon_controlled_reality_without_findings": true,
      "next_question": "why_controlled_reality_chain_was_not_promoted_to_finding"
    },
    "finding_export_gap": {
      "direct_final_json_finding_count": 0,
      "eidolon_final_json_finding_count": 0,
      "direct_db_saved_finding_count": 0,
      "eidolon_db_saved_finding_count": 1,
      "direct_db_active_finding_count": 0,
      "eidolon_db_active_finding_count": 1,
      "direct_db_saved_findings_omitted_from_final_json": false,
      "eidolon_db_saved_findings_omitted_from_final_json": true,
      "any_db_saved_findings_omitted_from_final_json": true,
      "positive_eidolon_db_saved_finding_delta": true,
      "positive_eidolon_db_active_finding_delta": true,
      "final_json_counts_still_drive_finding_gap": true,
      "next_question": "why_db_saved_findings_were_omitted_from_final_json"
    },
    "strict_correlation_gap": {
      "proxy_confirmed_action_count": 1,
      "strict_correlated_action_count": 1,
      "strict_confirmed_action_count": 0,
      "unconfirmed_strict_action_count": 1,
      "proxy_confirmed_action_not_strict_count": 1,
      "matching_proxy_exposure_not_pwnkit_correlated_count": 1,
      "unconfirmed_actions": [
        {
          "bait_id": "openapi_reconcile_trace",
          "action_path": "/api/v2/import/reconcile?token=<redacted>",
          "has_exposure_id": true,
          "matching_proxy_exposure_count": 1,
          "matching_strict_exposure_count": 0,
          "matching_proxy_exposure_surfaces": ["/docs/legacy-import"],
          "matching_proxy_exposure_crawl_start_paths": ["/docs"],
          "reason": "matching_proxy_exposure_not_pwnkit_correlated"
        }
      ],
      "crawl_artifact_count": 1,
      "crawl_artifact_start_paths": ["/docs"],
      "matching_proxy_exposure_crawl_start_path_count": 1,
      "matching_proxy_exposure_crawl_start_paths": ["/docs"],
      "likely_cause": "matching_proxy_exposure_not_pwnkit_correlated",
      "likely_missing_artifact_class": "crawl_page_request_artifact",
      "next_questions": [
        "why_pwnkit_did_not_emit_request_artifact_for_exposure_surface",
        "whether_pwnkit_crawl_persisted_per_page_request_artifacts"
      ]
    }
  },
  "metrics": {
    "bait_follow_rate": 1,
    "same_session_confirmed_bait_follow_rate": 1,
    "real_surface_requests_after_containment": null,
    "controlled_reality_action_depth": null,
    "controlled_reality_branch_count": null
  },
  "notes": ["fixture note"],
  "raw_future_field": "must-not-survive"
}
JSON

  cat > "$run_dir/agent-replay-trace-summary.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_agent_replay_trace",
  "boundary": "owned_loopback_lab",
  "evidence_source": "authorized_agent_proxy_trace",
  "artifact_dir": "/private/tmp/eidolon-fixture",
  "claim_level": "controlled_reality_entered",
  "counts": {
    "events": 5,
    "requests": 2,
    "bait_exposures": 1,
    "bait_actions": 1,
    "same_session_confirmed_bait_actions": 1,
    "controlled_reality_entries_after_confirmed_action": 1
  },
  "metrics": {
    "real_surface_requests_after_containment": 0,
    "controlled_reality_action_depth": 1,
    "controlled_reality_branch_count": 1
  },
  "pinned_session": {
    "present": true,
    "session_id": "00000000-0000-0000-0000-000000000001"
  },
  "sessions": [
    {"session_id": "00000000-0000-0000-0000-000000000001", "claim_level": "controlled_reality_entered"}
  ],
  "bait_events": {
    "exposures": [
      {"surface": "/openapi.json?token=secret-token"}
    ],
    "actions": [
      {"path": "/api/v2/import/reconcile?token=secret-token"}
    ],
    "same_session_confirmed_actions": [
      {"path": "/api/v2/import/reconcile?token=secret-token"}
    ],
    "controlled_reality_entries_after_confirmed_action": [
      {"reason": "controlled"}
    ]
  },
  "notes": ["fixture note"]
}
JSON

  cat > "$run_dir/private/eidolon-debug.jsonl" <<'EOF_DEBUG'
{"secret":"debug-secret"}
EOF_DEBUG
  cat > "$run_dir/pwnkit-eidolon.stdout.log" <<'EOF_STDOUT'
secret-token
EOF_STDOUT
  cat > "$run_dir/pwnkit-eidolon.db" <<'EOF_DB'
not a real sqlite db
EOF_DB
}

test_packager_redacts_raw_artifacts_and_query_values() {
  local sample_dir
  local bundle_dir
  sample_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_sample "$sample_dir"

  EIDOLON_M3_ALLOW_AGENT_ERRORS=1 "$PACKAGER" "$sample_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]]
  [[ -f "$bundle_dir/SHA256SUMS" ]]
  [[ -f "$bundle_dir/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/run-1/pwnkit-summary.redacted.json" ]]
  [[ -f "$bundle_dir/run-1/agent-replay-trace-summary.json" ]]

  ! find "$bundle_dir" -type f -name '*.db' | rg -q .
  ! find "$bundle_dir" -type f -name '*.log' | rg -q .
  ! find "$bundle_dir" -type f -path '*/private/*' | rg -q .
  ! rg -q 'secret-token|direct-secret|secret-label|debug-secret|must-not-survive|raw warning' "$bundle_dir"
  ! rg -q '/private/tmp|/tmp/pwnkit|node /tmp|eidolon-fixture' "$bundle_dir"

  jq -e '
    .source_artifact_dir == "<source-artifact-path-omitted>"
    and .comparison.correlated_target_request_count == 1
    and .comparison.eidolon_requested_path_count == 1
    and .comparison.correlated_bait_matrix[0].surfaces == ["/openapi.json"]
    and .comparison.correlated_bait_matrix[0].action_paths == ["/api/v2/import/reconcile"]
    and .comparison.target_correlation_diagnostics.correlated_target_request_count == 1
    and .comparison.strict_correlation_gap.likely_cause == "matching_proxy_exposure_not_pwnkit_correlated"
    and .comparison.strict_correlation_gap.likely_missing_artifact_class == "crawl_page_request_artifact"
    and .comparison.strict_correlation_gap.matching_proxy_exposure_crawl_start_paths == ["/docs"]
    and .comparison.strict_correlation_gap.unconfirmed_actions[0].action_path == "/api/v2/import/reconcile?token=<redacted>"
    and .runs.eidolon.warning_count == 1
    and .runs.eidolon.final_json_finding_count == 0
    and .runs.eidolon.db_saved_finding_count == 1
    and .runs.eidolon.finding_reconciliation.db_saved_findings_omitted_from_final_json == true
    and .comparison.finding_export_gap.eidolon_db_saved_findings_omitted_from_final_json == true
    and .comparison.finding_export_gap.final_json_counts_still_drive_finding_gap == true
    and .runs.eidolon.pwnkit_events.crawl_artifacts[0].start_path == "/docs"
    and .runs.eidolon.target_evidence_diagnostics.crawl_start_paths == ["/docs"]
    and .runs.eidolon.agent_error_diagnostics.class_counts == [
      {error_class: "codex_backend_api_error", count: 1}
    ]
    and .runner.environment.runner_environment == "kali_vm"
    and .runner.environment.network_topology == "same_vm_loopback"
    and .runner.environment.tool_fingerprint[0].name == "bash"
    and .runner.pwnkit.fixture == {
      id: "pwnkit-v0.12.0-private",
      pinned: true
    }
    and .runner.pwnkit.evidence_track == "upstream_current"
    and .redaction.raw_agent_error_text_omitted == true
    and (.runner.pwnkit | has("command") | not)
    and (.runner.pwnkit | has("entry_path") | not)
    and (.runner.pwnkit | has("source_dir") | not)
    and (.runner.pwnkit.scopes.eidolon | has("path") | not)
    and (.runner.pwnkit.scopes.direct | has("path") | not)
    and .redaction.source_artifact_path_omitted == true
    and .redaction.runner_command_paths_omitted == true
    and .redaction.pwnkit_scope_paths_omitted == true
    and .redaction.raw_requested_paths_omitted == true
  ' "$bundle_dir/run-1/pwnkit-summary.redacted.json" >/dev/null

  jq -e '
    .artifact_dir == "<source-artifact-path-omitted>"
    and .bait_events.exposures[0].surface == "/openapi.json"
    and .bait_events.actions[0].path == "/api/v2/import/reconcile"
    and .redaction.private_debug_logs_omitted == true
    and .redaction.source_artifact_path_omitted == true
  ' "$bundle_dir/run-1/agent-replay-trace-summary.json" >/dev/null

  jq -e '
    .redaction.raw_pwnkit_artifacts_omitted == true
    and .redaction.source_artifact_paths_omitted == true
    and .redaction.runner_command_paths_omitted == true
    and .no_signal_diagnostics.proxy_path_counts == [{path: "/docs", count: 1}]
    and .no_signal_diagnostics.eidolon_agent_error_class_counts == [
      {error_class: "codex_backend_api_error", count: 1}
    ]
    and .runner_environments == ["kali_vm"]
    and .runner_pwnkit_fixture_ids == ["pwnkit-v0.12.0-private"]
    and .evidence_tracks == ["upstream_current"]
    and .evidence_track_counts == [{evidence_track: "upstream_current", count: 1}]
    and .single_evidence_track == true
    and .mixed_evidence_tracks == false
    and .unknown_evidence_track_count == 0
    and .runner_network_topologies == ["same_vm_loopback"]
    and .tool_fingerprint_summary[0].name == "bash"
    and .finding_reconciliation.eidolon_db_saved_finding_total == 1
    and .finding_reconciliation.any_db_saved_findings_omitted_from_final_json == true
    and .evidence_gap_diagnostics.observed_gaps == [
      "strict_controlled_reality_without_eidolon_findings"
    ]
    and .evidence_gap_diagnostics.strict_controlled_reality_without_eidolon_finding_run_count == 1
    and .artifacts[0].agent_error_diagnostics.eidolon.count == 1
    and .artifacts[0].artifact_dir == "<source-artifact-path-omitted>"
    and .artifacts[0].evidence_track == "upstream_current"
    and (.artifacts[0] | has("runner_command") | not)
    and .artifacts[0].runner_environment == "kali_vm"
    and .artifacts[0].runner_pwnkit_fixture_id == "pwnkit-v0.12.0-private"
    and .artifacts[0].runner_pwnkit_fixture == {
      id: "pwnkit-v0.12.0-private",
      pinned: true
    }
    and .artifacts[0].runner_tool_fingerprint[0].name == "bash"
    and .artifacts[0].finding_export_gap.eidolon_db_saved_findings_omitted_from_final_json == true
    and .artifacts[0].eidolon_proxy.request_path_counts == [{value: "/docs", count: 1}]
    and .artifacts[0].target_correlation_diagnostics.correlated_target_request_count == 1
    and .artifacts[0].strict_correlation_gap.likely_cause == "matching_proxy_exposure_not_pwnkit_correlated"
    and .artifacts[0].strict_correlation_gap.likely_missing_artifact_class == "crawl_page_request_artifact"
    and .artifacts[0].strict_correlation_gap.matching_proxy_exposure_crawl_start_paths == ["/docs"]
    and .artifacts[0].strict_correlation_gap.unconfirmed_actions[0].action_path == "/api/v2/import/reconcile?token=<redacted>"
    and .artifacts[0].pwnkit_events.eidolon.crawl_artifacts[0].start_path == "/docs"
    and .artifacts[0].target_evidence_diagnostics.eidolon.crawl_start_paths == ["/docs"]
    and .artifacts[0].trace_gap.strict_controlled_reality_without_eidolon_finding == true
    and (. | has("raw_future_field") | not)
  ' "$bundle_dir/pwnkit-stability-sample.json" >/dev/null

  rg -q 'pwnkit-stability-sample.json' "$bundle_dir/SHA256SUMS"
  rg -q 'run-1/pwnkit-summary.redacted.json' "$bundle_dir/SHA256SUMS"
  rg -q 'evidence gaps: `strict_controlled_reality_without_eidolon_findings`' "$bundle_dir/README.md"
  rg -Fq 'runner environment(s): `kali_vm`' "$bundle_dir/README.md"
  rg -Fq 'pwnkit pinned fixture id(s): `pwnkit-v0.12.0-private`' "$bundle_dir/README.md"
  rg -Fq 'evidence track(s): `upstream_current`' "$bundle_dir/README.md"
  rg -q 'DB-saved findings direct/Eidolon: `0/1`' "$bundle_dir/README.md"
  rg -q '`strict_stability.ready_for_stability_claim`: `false`' "$bundle_dir/README.md"
}

test_packager_refuses_non_empty_bundle_dir() {
  local sample_dir
  local bundle_dir
  local output
  local status=0
  sample_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_sample "$sample_dir"
  mkdir -p "$bundle_dir"
  printf 'existing\n' > "$bundle_dir/existing.txt"

  output="$("$PACKAGER" "$sample_dir" "$bundle_dir" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'bundle directory must be empty' <<<"$output"
}

test_packager_rejects_agent_error_sample_by_default() {
  local sample_dir
  local bundle_dir
  local output
  local status=0
  sample_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_sample "$sample_dir"

  output="$("$PACKAGER" "$sample_dir" "$bundle_dir" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'pwnkit agent errors detected in sample' <<<"$output"
  rg -q 'eidolon classes=codex_backend_api_error=1' <<<"$output"
  ! rg -q 'secret-token|debug-secret|raw warning' <<<"$output"
}

test_packager_redacts_raw_artifacts_and_query_values
test_packager_refuses_non_empty_bundle_dir
test_packager_rejects_agent_error_sample_by_default

printf 'package-pwnkit-sample fixture tests passed\n'
