#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGER="$SCRIPT_DIR/package-pwnkit-promotion-matrix.sh"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-promotion-matrix.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-promotion-package-test.XXXXXX"
}

write_manifest() {
  local manifest="$1"

  jq -n '{
    schema_version: 1,
    run_kind: "m3_pwnkit_promotion_matrix_manifest",
    boundary: "owned_loopback_lab",
    variants: [
      {
        variant_id: "default_m3_catalog",
        bait_profile: null,
        hypothesis: "baseline",
        knobs: [],
        expected_observation: "behavior_only"
      },
      {
        variant_id: "promoted_probe",
        bait_profile: "examples/m3/bait-profiles/openapi-promotion-probe.json",
        hypothesis: "finding promotion",
        knobs: ["openapi.summary"],
        expected_observation: "diagnostic_delta_or_promoted_finding"
      }
    ]
  }' > "$manifest"
}

write_variant_sample() {
  local sample_dir="$1"
  local eidolon_findings="$2"
  local positive_differential="$3"
  local run_dir="$sample_dir/run-1"

  mkdir -p "$run_dir/private"

  jq -n \
    --argjson eidolon_findings "$eidolon_findings" \
    --argjson positive_differential "$positive_differential" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_codex_sample",
      generated_at: "2026-05-21T00:00:00Z",
      artifact_count: 1,
      valid_summary_count: 1,
      counts: {
        missing_summary: 0,
        target_interaction_observed: 1,
        bait_reached: 1,
        bait_action_observed: 1,
        same_session_confirmed_bait_action: 1,
        controlled_reality_entered: 1,
        direct_quiet: 1,
        direct_findings: 0,
        eidolon_findings: (if $eidolon_findings > 0 then 1 else 0 end),
        positive_differential_findings: (
          if $positive_differential then 1 else 0 end
        ),
        bait_reached_without_eidolon_findings: (
          if $eidolon_findings == 0 then 1 else 0 end
        ),
        bait_action_without_eidolon_findings: (
          if $eidolon_findings == 0 then 1 else 0 end
        ),
        controlled_reality_without_eidolon_findings: (
          if $eidolon_findings == 0 then 1 else 0 end
        ),
        pinned_session_present: 1,
        pinned_cookie_preserved: 1
      },
      rates: {
        target_interaction_rate: 1,
        bait_reach_rate: 1,
        bait_action_rate: 1,
        same_session_confirmed_bait_action_rate: 1,
        controlled_reality_entry_rate: 1,
        direct_quiet_rate: 1,
        eidolon_finding_rate: (if $eidolon_findings > 0 then 1 else 0 end),
        positive_differential_finding_rate: (
          if $positive_differential then 1 else 0 end
        ),
        pinned_cookie_preservation_rate: 1
      },
      claim_level_counts: [
        {
          claim_level: "controlled_reality_entered",
          count: 1
        }
      ],
      weakest_claim_level: "controlled_reality_entered",
      strongest_claim_level: "controlled_reality_entered",
      runner_git_heads: ["abc123"],
      runner_package_versions: ["0.11.1"],
      source_checkout: {
        all_runners_clean: true,
        all_runners_origin_main_synced: true
      },
      differential_findings: {
        ready_for_differential_finding_claim: $positive_differential,
        direct_finding_run_count: 0,
        eidolon_finding_run_count: (if $eidolon_findings > 0 then 1 else 0 end),
        positive_differential_run_count: (
          if $positive_differential then 1 else 0 end
        )
      },
      strict_stability: {
        ready_for_stability_claim: true
      },
      artifacts: [
        {
          artifact_dir: "/private/tmp/eidolon-secret-source",
          present: true,
          claim_level: "controlled_reality_entered",
          conclusion: "bait_action_observed",
          target_interaction_observed: true,
          bait_reached: true,
          bait_action_observed: true,
          same_session_confirmed_bait_action: true,
          controlled_reality_entered: true,
          direct_finding_count: 0,
          eidolon_finding_count: $eidolon_findings,
          finding_gap: {
            positive_differential_findings: $positive_differential
          },
          correlated_counts: {
            target_requests: 1,
            bait_exposures: 1,
            bait_actions: 1,
            same_session_confirmed_bait_actions: 1,
            controlled_reality_entries: 1
          },
          pinned_session: {
            present: true,
            cookie_preserved: true
          },
          metrics: {
            bait_follow_rate: 1,
            same_session_confirmed_bait_follow_rate: 1
          }
        }
      ],
      raw_future_field: "must-not-survive"
    }' > "$sample_dir/pwnkit-stability-sample.json"

  jq -n '{
    schema_version: 1,
    run_kind: "m3_pwnkit_codex_comparison",
    boundary: "owned_loopback_lab",
    artifact_dir: "/private/tmp/eidolon-secret-source",
    runner: {
      schema_version: 1,
      run_kind: "m3_pwnkit_codex_runner",
      created_at: "2026-05-21T00:00:00Z",
      mode: "all",
      urls: {
        target: "http://127.0.0.1:9001",
        proxy: "http://127.0.0.1:8080"
      },
      pwnkit: {
        depth: "quick",
        mode: "web",
        runtime: "codex",
        rate_limit: "2",
        command: "node /tmp/pwnkit/dist/pwnkit.js",
        entry_path: "/tmp/pwnkit/dist/pwnkit.js",
        command_source: "fixture",
        package_version: "0.11.1",
        git_head: "abc123",
        git_head_short: "abc123",
        git_head_time_seconds: 1770000000,
        git_dirty: false,
        origin_main: {
          in_sync: true
        },
        stale_dist_guard_bypassed: false,
        scopes: {
          eidolon: {
            in_scope: ["127.0.0.1"],
            out_of_scope: []
          },
          direct: {
            in_scope: ["127.0.0.1"],
            out_of_scope: []
          }
        }
      },
      eidolon: {
        pinned_session_enabled: true
      }
    },
    runs: {
      eidolon: {
        target: "http://127.0.0.1:8080",
        scan_depth: "quick",
        duration_ms: 10,
        finding_count: 0,
        warnings: ["raw warning secret-token"],
        requested_paths: [
          {
            method: "GET",
            path: "/docs?token=secret-token",
            tool_evidence_label: "secret-label"
          }
        ]
      },
      direct: {
        target: "http://127.0.0.1:9001",
        scan_depth: "quick",
        duration_ms: 10,
        finding_count: 0,
        warnings: []
      }
    },
    eidolon_proxy: {
      present: true,
      event_count: 5,
      request_count: 2,
      kind_counts: [],
      routing_counts: [],
      counts: {}
    },
    comparison: {
      target_interaction_observed: true,
      bait_reached: true,
      bait_action_observed: true,
      same_session_confirmed_bait_action: true,
      controlled_reality_entered: true,
      claim_level: "controlled_reality_entered",
      conclusion: "bait_action_observed",
      correlated_target_requests: [
        {
          method: "GET",
          path: "/docs?token=secret-token",
          tool_evidence_label: "secret-label"
        }
      ],
      eidolon_requested_paths: ["/docs?token=secret-token"],
      direct_requested_paths: ["/health?token=direct-secret"],
      paths_only_eidolon: ["/docs?token=secret-token"],
      paths_only_direct: ["/health?token=direct-secret"],
      correlated_bait_events: {
        exposures: [
          {
            bait_id: "openapi_reconcile_trace",
            surface: "/openapi.json?token=secret-token"
          }
        ],
        actions: [
          {
            bait_id: "openapi_reconcile_trace",
            path: "/api/v2/import/reconcile?token=secret-token"
          }
        ],
        same_session_confirmed_actions: [],
        controlled_reality_entries: [],
        matrix: [
          {
            bait_id: "openapi_reconcile_trace",
            exposure_count: 1,
            action_count: 1,
            same_session_confirmed_action_count: 1,
            surfaces: ["/openapi.json?token=secret-token"],
            action_paths: ["/api/v2/import/reconcile?token=secret-token"]
          }
        ]
      },
      finding_gap: {
        positive_differential_findings: false
      }
    },
    metrics: {
      bait_follow_rate: 1,
      same_session_confirmed_bait_follow_rate: 1
    },
    pinned_session: {
      present: true,
      cookie_preserved: true
    },
    notes: []
  }' > "$run_dir/pwnkit-summary.json"

  jq -n '{
    schema_version: 1,
    run_kind: "m3_agent_replay_trace",
    boundary: "owned_loopback_lab",
    evidence_source: "authorized_agent_proxy_trace",
    artifact_dir: "/private/tmp/eidolon-secret-source",
    claim_level: "controlled_reality_entered",
    counts: {
      events: 5
    },
    metrics: {
      real_surface_requests_after_containment: 0
    },
    pinned_session: {
      present: true
    },
    sessions: [],
    bait_events: {
      exposures: [
        {
          surface: "/openapi.json?token=secret-token"
        }
      ],
      actions: [
        {
          path: "/api/v2/import/reconcile?token=secret-token"
        }
      ],
      same_session_confirmed_actions: [],
      controlled_reality_entries_after_confirmed_action: []
    },
    notes: []
  }' > "$run_dir/agent-replay-trace-summary.json"

  printf '{"secret":"private-debug-secret"}\n' > "$run_dir/private/eidolon-debug.jsonl"
  printf 'secret-token\n' > "$run_dir/pwnkit-eidolon.stdout.log"
  printf 'not sqlite\n' > "$run_dir/pwnkit-eidolon.db"
}

write_fixture_matrix() {
  local matrix_dir="$1"

  mkdir -p "$matrix_dir/default_m3_catalog" "$matrix_dir/promoted_probe"
  write_manifest "$matrix_dir/bait-promotion-variants.json"
  write_variant_sample "$matrix_dir/default_m3_catalog" 0 false
  write_variant_sample "$matrix_dir/promoted_probe" 1 true
  "$COLLECTOR" "$matrix_dir/bait-promotion-variants.json" "$matrix_dir" \
    > "$matrix_dir/pwnkit-promotion-matrix.json"
}

test_packager_redacts_matrix_and_variant_artifacts() {
  local matrix_dir
  local bundle_dir
  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_matrix "$matrix_dir"

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]]
  [[ -f "$bundle_dir/SHA256SUMS" ]]
  [[ -f "$bundle_dir/bait-promotion-variants.json" ]]
  [[ -f "$bundle_dir/pwnkit-promotion-matrix.json" ]]
  [[ -f "$bundle_dir/variants/default_m3_catalog/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/variants/default_m3_catalog/run-1/pwnkit-summary.redacted.json" ]]
  [[ -f "$bundle_dir/variants/default_m3_catalog/SHA256SUMS" ]]
  [[ -f "$bundle_dir/variants/promoted_probe/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/variants/promoted_probe/run-1/agent-replay-trace-summary.json" ]]
  [[ -f "$bundle_dir/variants/promoted_probe/SHA256SUMS" ]]

  ! find "$bundle_dir" -type f -name '*.db' | rg -q .
  ! find "$bundle_dir" -type f -name '*.log' | rg -q .
  ! find "$bundle_dir" -type f -path '*/private/*' | rg -q .
  ! rg -q 'secret-token|direct-secret|secret-label|private-debug-secret|must-not-survive|raw warning' "$bundle_dir"

  jq -e '
    .run_kind == "m3_pwnkit_promotion_matrix"
    and .redaction.source_variant_sample_dirs_omitted == true
    and (.variants[] | select(.variant_id == "default_m3_catalog") | .sample_dir | not)
    and (.variants[] | select(.variant_id == "default_m3_catalog") | .variant_bundle_dir == "variants/default_m3_catalog")
    and (.variants[] | select(.variant_id == "promoted_probe") | .observation_class == "promoted_finding")
    and (.ready_for_differential_finding_claim_variants == ["promoted_probe"])
  ' "$bundle_dir/pwnkit-promotion-matrix.json" >/dev/null

  jq -e '
    .redaction.absolute_bait_profile_paths_omitted == true
    and (.variants | length == 2)
  ' "$bundle_dir/bait-promotion-variants.json" >/dev/null

  jq -e '
    .comparison.correlated_bait_matrix[0].surfaces == ["/openapi.json"]
    and .comparison.correlated_bait_matrix[0].action_paths == ["/api/v2/import/reconcile"]
    and .runs.eidolon.warning_count == 1
  ' "$bundle_dir/variants/default_m3_catalog/run-1/pwnkit-summary.redacted.json" >/dev/null

  rg -q 'pwnkit-promotion-matrix.json' "$bundle_dir/SHA256SUMS"
  rg -q 'variants/default_m3_catalog/pwnkit-stability-sample.json' "$bundle_dir/SHA256SUMS"
  rg -q 'variants/promoted_probe/run-1/agent-replay-trace-summary.json' "$bundle_dir/SHA256SUMS"
}

test_packager_refuses_non_empty_bundle_dir() {
  local matrix_dir
  local bundle_dir
  local output
  local status=0
  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_matrix "$matrix_dir"
  mkdir -p "$bundle_dir"
  printf 'existing\n' > "$bundle_dir/existing.txt"

  output="$("$PACKAGER" "$matrix_dir" "$bundle_dir" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'bundle directory must be empty' <<<"$output"
}

test_packager_rejects_invalid_summary_variant_id() {
  local matrix_dir
  local bundle_dir
  local output
  local status=0
  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  mkdir -p "$matrix_dir"
  write_manifest "$matrix_dir/bait-promotion-variants.json"
  jq -n '{
    schema_version: 1,
    run_kind: "m3_pwnkit_promotion_matrix",
    boundary: "owned_loopback_lab",
    variants: [
      {
        variant_id: "../bad",
        present: true
      }
    ]
  }' > "$matrix_dir/pwnkit-promotion-matrix.json"

  output="$("$PACKAGER" "$matrix_dir" "$bundle_dir" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'invalid variant_id' <<<"$output"
}

test_packager_redacts_matrix_and_variant_artifacts
test_packager_refuses_non_empty_bundle_dir
test_packager_rejects_invalid_summary_variant_id

printf 'package-pwnkit-promotion-matrix fixture tests passed\n'
