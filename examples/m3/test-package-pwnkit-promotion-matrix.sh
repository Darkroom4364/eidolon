#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PACKAGER="$SCRIPT_DIR/package-pwnkit-promotion-matrix.sh"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-promotion-matrix.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-promotion-package-test.XXXXXX"
}

rewrite_json() {
  local path="$1"
  local filter="$2"
  local temp_file="${path}.tmp"

  jq "$filter" "$path" > "$temp_file"
  mv "$temp_file" "$path"
}

inject_matrix_sentinels() {
  local matrix_dir="$1"
  local path
  local filter='
    walk(
      if type == "object" then
        . + {
          unexpected_nested_secret: "EIDOLON_MATRIX_SENTINEL_228",
          headers: {authorization: "EIDOLON_MATRIX_SENTINEL_228"},
          cookies: {session: "EIDOLON_MATRIX_SENTINEL_228"},
          body: "EIDOLON_MATRIX_SENTINEL_228",
          token: "EIDOLON_MATRIX_SENTINEL_228",
          url: "https://sentinel.invalid/?token=EIDOLON_MATRIX_SENTINEL_228"
        }
      else
        .
      end
    )
  '

  for path in \
    "$matrix_dir/bait-promotion-variants.json" \
    "$matrix_dir/pwnkit-promotion-matrix.json"; do
    rewrite_json "$path" "$filter"
  done
}

schema_digest() {
  local path="$1"
  local schema

  schema="$(jq -cS '
    [
      paths as $value_path
      | (getpath($value_path)) as $value
      | if ($value | type) == "object" then
          {
            path: $value_path,
            type: "object",
            keys: ($value | keys)
          }
        elif ($value | type) == "array" then
          {
            path: $value_path,
            type: "array",
            length: ($value | length),
            item_types: ($value | map(type))
          }
        else
          {
            path: $value_path,
            type: ($value | type)
          }
        end
    ]
  ' "$path")"

  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "$schema" | sha256sum | awk '{print $1}'
  else
    printf '%s\n' "$schema" | shasum -a 256 | awk '{print $1}'
  fi
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
      runner_pwnkit_fixture_ids: ["eidolon-m3-fixture-2026-05-21"],
      evidence_track_counts: [
        {evidence_track: "upstream_current", count: 1}
      ],
      evidence_tracks: ["upstream_current"],
      single_evidence_track: true,
      mixed_evidence_tracks: false,
      unknown_evidence_track_count: 0,
      source_checkout: {
        all_runners_clean: true,
        all_runners_origin_main_synced: true
      },
      finding_reconciliation: {
        direct_final_json_finding_total: 0,
        eidolon_final_json_finding_total: $eidolon_findings,
        direct_db_saved_finding_total: 0,
        eidolon_db_saved_finding_total: $eidolon_findings,
        direct_db_active_finding_total: 0,
        eidolon_db_active_finding_total: $eidolon_findings,
        any_db_saved_findings_omitted_from_final_json: false,
        final_json_counts_still_drive_finding_claims: true
      },
      no_signal_diagnostics: {
        sample_size: 1,
        no_target_interaction_run_count: 0,
        all_runs_no_target_interaction: false,
        totals: {
          eidolon_proxy_requests: 1,
          correlated_target_requests: 1
        },
        proxy_path_counts: [
          {
            path: "/docs?token=secret-token",
            count: 1
          }
        ],
        likely_cause: null,
        next_questions: []
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
          evidence_track: "upstream_current",
          runner_git_head: "abc123",
          runner_git_dirty: false,
          runner_origin_main_in_sync: true,
          runner_origin_main: {
            ahead: 0,
            behind: 0,
            in_sync: true
          },
          runner_pwnkit_fixture: {
            id: "eidolon-m3-fixture-2026-05-21",
            pinned: true
          },
          claim_level: "controlled_reality_entered",
          conclusion: "bait_action_observed",
          target_interaction_observed: true,
          bait_reached: true,
          bait_action_observed: true,
          same_session_confirmed_bait_action: true,
          controlled_reality_entered: true,
          direct_finding_count: 0,
          eidolon_finding_count: $eidolon_findings,
          direct_final_json_finding_count: 0,
          eidolon_final_json_finding_count: $eidolon_findings,
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
        source_dir: "/tmp/pwnkit",
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
            path: "/private/tmp/eidolon-secret-source/pwnkit-eidolon-scope.json",
            in_scope: ["127.0.0.1"],
            out_of_scope: []
          },
          direct: {
            path: "/private/tmp/eidolon-secret-source/pwnkit-direct-scope.json",
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
  rewrite_json "$matrix_dir/pwnkit-promotion-matrix.json" '
    .no_signal_diagnostics = {
      variant_count: 1,
      likely_cause_counts: [
        {likely_cause: "behavior_only", count: 1}
      ],
      variants: [
        {
          variant_id: "default_m3_catalog",
          likely_cause: "behavior_only",
          totals: {
            eidolon_proxy_requests: 1,
            correlated_target_requests: 1
          },
          proxy_path_counts: [
            {path: "/docs?token=matrix-secret", count: 1}
          ]
        }
      ]
    }
  '
}

mark_fixture_matrix_unhealthy() {
  local matrix_dir="$1"
  local matrix_file="$matrix_dir/pwnkit-promotion-matrix.json"
  local tmp_file="$matrix_file.tmp"

  jq '
    .matrix_health.ready_for_matrix_interpretation = false
    | .matrix_health.total_pwnkit_agent_errors = 1
    | .matrix_health.all_observed_samples_agent_error_free = false
    | .no_signal_diagnostics.variant_count = 1
  ' "$matrix_file" > "$tmp_file"
  mv "$tmp_file" "$matrix_file"
}

test_packager_redacts_matrix_and_variant_artifacts() {
  local matrix_dir
  local bundle_dir
  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_matrix "$matrix_dir"
  inject_matrix_sentinels "$matrix_dir"

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]] || return 1
  [[ -f "$bundle_dir/SHA256SUMS" ]] || return 1
  [[ -f "$bundle_dir/bait-promotion-variants.json" ]] || return 1
  [[ -f "$bundle_dir/pwnkit-promotion-matrix.json" ]] || return 1
  [[ -f "$bundle_dir/variants/default_m3_catalog/pwnkit-stability-sample.json" ]] || return 1
  [[ -f "$bundle_dir/variants/default_m3_catalog/run-1/pwnkit-summary.redacted.json" ]] || return 1
  [[ -f "$bundle_dir/variants/default_m3_catalog/SHA256SUMS" ]] || return 1
  [[ -f "$bundle_dir/variants/promoted_probe/pwnkit-stability-sample.json" ]] || return 1
  [[ -f "$bundle_dir/variants/promoted_probe/run-1/agent-replay-trace-summary.json" ]] || return 1
  [[ -f "$bundle_dir/variants/promoted_probe/SHA256SUMS" ]] || return 1

  ! find "$bundle_dir" -type f -name '*.db' | rg -q . || return 1
  ! find "$bundle_dir" -type f -name '*.log' | rg -q . || return 1
  ! find "$bundle_dir" -type f -path '*/private/*' | rg -q . || return 1
  ! rg -q 'secret-token|direct-secret|secret-label|private-debug-secret|must-not-survive|raw warning' "$bundle_dir" || return 1
  ! rg -q 'EIDOLON_MATRIX_SENTINEL_228' "$bundle_dir" || return 1
  ! rg -q 'matrix-secret' "$bundle_dir" || return 1
  ! rg -q '/private/tmp|/tmp/pwnkit|node /tmp|eidolon-secret-source' "$bundle_dir" || return 1

  [[ "$(schema_digest "$bundle_dir/bait-promotion-variants.json")" \
    == "07d25ef7db69b46088e758d22cd73116336b22ea7ec8d657da7fbf7cd0ead6ae" ]] || return 1
  [[ "$(schema_digest "$bundle_dir/pwnkit-promotion-matrix.json")" \
    == "43d4c0eaa680ac4524d8c9f92b12f309389c51cbcd05ac83fe1bb2d3252845a9" ]] || return 1

  jq -e '
    .run_kind == "m3_pwnkit_promotion_matrix"
    and .redaction.source_variant_sample_dirs_omitted == true
    and .redaction.raw_agent_error_text_omitted == true
    and .matrix_health.ready_for_matrix_interpretation == true
    and .matrix_health.total_pwnkit_agent_errors == 0
    and .matrix_health.runner_pwnkit_fixture_ids == ["eidolon-m3-fixture-2026-05-21"]
    and .no_signal_diagnostics.variant_count == 1
    and .no_signal_diagnostics.likely_cause_counts == [
      {likely_cause: "behavior_only", count: 1}
    ]
    and .no_signal_diagnostics.variants[0].variant_id == "default_m3_catalog"
    and .no_signal_diagnostics.variants[0].proxy_path_counts == [
      {path: "/docs", count: 1}
    ]
    and (.variants[] | select(.variant_id == "default_m3_catalog") | .sample_dir | not)
    and (.variants[] | select(.variant_id == "default_m3_catalog") | .variant_bundle_dir == "variants/default_m3_catalog")
    and (.variants[] | select(.variant_id == "default_m3_catalog") | .runner_pwnkit_fixture_ids == ["eidolon-m3-fixture-2026-05-21"])
    and (.variants[] | select(.variant_id == "default_m3_catalog") | .no_signal_diagnostics.proxy_path_counts == [{path: "/docs", count: 1}])
    and (.variants[] | select(.variant_id == "promoted_probe") | .observation_class == "promoted_finding")
    and (.ready_for_differential_finding_claim_variants == ["promoted_probe"])
  ' "$bundle_dir/pwnkit-promotion-matrix.json" >/dev/null

  jq -e '
    .redaction.absolute_bait_profile_paths_omitted == true
    and (.variants | length == 2)
  ' "$bundle_dir/bait-promotion-variants.json" >/dev/null

  jq -e '
    .source_artifact_dir == "<source-artifact-path-omitted>"
    and (.runner.pwnkit | has("source_dir") | not)
    and (.runner.pwnkit.scopes.eidolon | has("path") | not)
    and (.runner.pwnkit.scopes.direct | has("path") | not)
    and .comparison.correlated_bait_matrix[0].surfaces == ["/openapi.json"]
    and .comparison.correlated_bait_matrix[0].action_paths == ["/api/v2/import/reconcile"]
    and .runs.eidolon.warning_count == 1
  ' "$bundle_dir/variants/default_m3_catalog/run-1/pwnkit-summary.redacted.json" >/dev/null

  rg -q 'pwnkit-promotion-matrix.json' "$bundle_dir/SHA256SUMS"
  rg -q 'variants/default_m3_catalog/pwnkit-stability-sample.json' "$bundle_dir/SHA256SUMS"
  rg -q 'variants/promoted_probe/run-1/agent-replay-trace-summary.json' "$bundle_dir/SHA256SUMS"
}

test_packager_rejects_unhealthy_matrix_by_default() {
  local matrix_dir
  local bundle_dir
  local output
  local status=0
  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_matrix "$matrix_dir"
  mark_fixture_matrix_unhealthy "$matrix_dir"

  output="$("$PACKAGER" "$matrix_dir" "$bundle_dir" 2>&1)" || status="$?"

  [[ "$status" -eq 1 ]] || return 1
  rg -q 'matrix.*health|not ready|ready_for_matrix_interpretation' <<<"$output"
  [[ ! -f "$bundle_dir/pwnkit-promotion-matrix.json" ]] || return 1
}

test_packager_allows_unhealthy_matrix_with_diagnostic_bypass() {
  local matrix_dir
  local bundle_dir
  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_matrix "$matrix_dir"
  mark_fixture_matrix_unhealthy "$matrix_dir"

  EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX=1 "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/pwnkit-promotion-matrix.json" ]] || return 1
  [[ -f "$bundle_dir/variants/promoted_probe/run-1/pwnkit-summary.redacted.json" ]] || return 1
  ! rg -q 'secret-token|direct-secret|secret-label|private-debug-secret|must-not-survive|raw warning' "$bundle_dir" || return 1
  ! rg -q '/private/tmp|/tmp/pwnkit|node /tmp|eidolon-secret-source' "$bundle_dir" || return 1

  jq -e '
    .matrix_health.ready_for_matrix_interpretation == false
    and .matrix_health.total_pwnkit_agent_errors == 1
    and .redaction.raw_agent_error_text_omitted == true
    and (.variants[] | select(.variant_id == "promoted_probe") | .variant_bundle_dir == "variants/promoted_probe")
  ' "$bundle_dir/pwnkit-promotion-matrix.json" >/dev/null
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

  [[ "$status" -eq 2 ]] || return 1
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
    generated_at: "2026-05-21T00:00:00Z",
    boundary: "owned_loopback_lab",
    matrix_health: {
      ready_for_matrix_interpretation: true,
      all_variants_observed: true,
      all_observed_samples_agent_error_free: true,
      all_observed_source_checkouts_clean: true,
      all_observed_source_checkouts_synced: true,
      missing_variant_count: 0,
      total_pwnkit_agent_errors: 0,
      source_checkout_clean_variant_count: 1,
      source_checkout_synced_variant_count: 1,
      runner_git_heads: ["abc123"],
      runner_package_versions: ["0.11.1"],
      runner_pwnkit_fixture_ids: ["eidolon-m3-fixture-2026-05-21"]
    },
    variants: [
      {
        variant_id: "../bad",
        present: true
      }
    ]
  }' > "$matrix_dir/pwnkit-promotion-matrix.json"

  output="$("$PACKAGER" "$matrix_dir" "$bundle_dir" 2>&1)" || status="$?"

  [[ "$status" -eq 2 ]] || return 1
  rg -q 'invalid variant_id' <<<"$output"
}

test_packager_rejects_invalid_matrix_metadata_atomically() {
  local filter
  local filters=(
    '.variants[1].hypothesis = {secret: "metadata-secret"}'
    '.variants[1].hypothesis = "line one\nline two"'
    '.variants[1].hypothesis = "see /private/tmp/metadata-secret"'
    '.variants[1].hypothesis = "see https://sentinel.invalid/metadata-secret"'
    '.variants[1].knobs = {}'
    '.variants[1].knobs = ["openapi.summary", "openapi.summary"]'
    '.variants[1].knobs = ["../secret"]'
    '.variants[1].expected_observation = "unknown_observation"'
    '.variants[1].bait_profile = "../secret.json"'
    '.variants[1].bait_profile = {path: "secret"}'
    '.variants[1].missing_reason = "missing at /private/tmp/secret"'
    'if .run_kind == "m3_pwnkit_promotion_matrix" then .variants[1].observation_class = "unknown_class" else . end'
    'if .run_kind == "m3_pwnkit_promotion_matrix" then .observation_class_counts[0].observation_class = "unknown_class" else . end'
    '.schema_version = 999'
    '.boundary = "other_boundary"'
    'if .run_kind == "m3_pwnkit_promotion_matrix" then .run_kind = "future_matrix" else . end'
    'if .run_kind == "m3_pwnkit_promotion_matrix_manifest" then .run_kind = "future_manifest" else . end'
    'if .run_kind == "m3_pwnkit_promotion_matrix" then .variants[1].present = null else . end'
    'if .run_kind == "m3_pwnkit_promotion_matrix" then .matrix_health.runner_package_versions[0] = "/private/tmp/secret" else . end'
    'if .run_kind == "m3_pwnkit_promotion_matrix" then .matrix_health.runner_pwnkit_fixture_ids[0] = "/private/tmp/secret" else . end'
    'if .run_kind == "m3_pwnkit_promotion_matrix" then .matrix_health.runner_package_versions[0] = "EIDOLON_PUBLIC_SECRET_228" else . end'
    'if .run_kind == "m3_pwnkit_promotion_matrix" then .matrix_health.runner_pwnkit_fixture_ids[0] = "EIDOLON_PUBLIC_SECRET_228" else . end'
  )

  for filter in "${filters[@]}"; do
    local matrix_dir
    local bundle_parent
    local bundle_dir
    local status=0

    matrix_dir="$(new_temp_dir)"
    bundle_parent="$(new_temp_dir)"
    bundle_dir="$bundle_parent/bundle"
    write_fixture_matrix "$matrix_dir"
    rewrite_json "$matrix_dir/bait-promotion-variants.json" "$filter"
    rewrite_json "$matrix_dir/pwnkit-promotion-matrix.json" "$filter"

    "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null 2>&1 \
      || status="$?"

    [[ "$status" -ne 0 ]] || return 1
    [[ ! -e "$bundle_dir" ]] || return 1
    ! find "$bundle_parent" -maxdepth 1 \
      -name '.eidolon-pwnkit-matrix.*' | rg -q . || return 1
  done
}

test_packager_rejects_manifest_summary_disagreement() {
  local matrix_dir
  local bundle_dir
  local status=0

  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_matrix "$matrix_dir"
  rewrite_json \
    "$matrix_dir/pwnkit-promotion-matrix.json" \
    '.variants[1].hypothesis = "different bounded hypothesis"'

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null 2>&1 \
    || status="$?"

  [[ "$status" -eq 2 ]] || return 1
  [[ ! -e "$bundle_dir" ]] || return 1
}

test_packager_rejects_duplicate_variant_ids() {
  local matrix_dir
  local bundle_dir
  local status=0
  local filter='.variants[1].variant_id = .variants[0].variant_id'

  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_matrix "$matrix_dir"
  rewrite_json "$matrix_dir/bait-promotion-variants.json" "$filter"
  rewrite_json "$matrix_dir/pwnkit-promotion-matrix.json" "$filter"

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null 2>&1 \
    || status="$?"

  [[ "$status" -eq 2 ]] || return 1
  [[ ! -e "$bundle_dir" ]] || return 1
}

test_packager_rejects_non_string_matrix_path() {
  local matrix_dir
  local bundle_dir
  local status=0

  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  write_fixture_matrix "$matrix_dir"
  rewrite_json \
    "$matrix_dir/pwnkit-promotion-matrix.json" \
    '.variants[0].no_signal_diagnostics.proxy_path_counts[0].path = {}'

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null 2>&1 \
    || status="$?"

  [[ "$status" -ne 0 ]] || return 1
  [[ ! -e "$bundle_dir" ]] || return 1
}

test_packager_rejects_invalid_matrix_json_streams() {
  local test_case

  for test_case in empty whitespace multiple malformed array; do
    local matrix_dir
    local bundle_dir
    local summary_file
    local status=0

    matrix_dir="$(new_temp_dir)"
    bundle_dir="$(new_temp_dir)/bundle"
    write_fixture_matrix "$matrix_dir"
    summary_file="$matrix_dir/pwnkit-promotion-matrix.json"

    case "$test_case" in
      empty)
        : > "$summary_file"
        ;;
      whitespace)
        printf '  \n' > "$summary_file"
        ;;
      multiple)
        printf '{}\n{}\n' > "$summary_file"
        ;;
      malformed)
        printf '{"schema_version":\n' > "$summary_file"
        ;;
      array)
        printf '[]\n' > "$summary_file"
        ;;
    esac

    "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null 2>&1 \
      || status="$?"

    [[ "$status" -ne 0 ]] || return 1
    [[ ! -e "$bundle_dir" ]] || return 1
  done
}

test_packager_uses_one_input_snapshot() {
  local matrix_dir
  local bundle_dir
  local fake_bin
  local real_cp

  matrix_dir="$(new_temp_dir)"
  bundle_dir="$(new_temp_dir)/bundle"
  fake_bin="$(new_temp_dir)"
  real_cp="$(command -v cp)"
  write_fixture_matrix "$matrix_dir"

  cat > "$fake_bin/cp" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

"$REAL_CP" "$@"
source_path="${@: -2:1}"
destination_path="${@: -1}"
if [[ "$source_path" != *"/.source/"* \
  && "$(basename "$source_path")" == "pwnkit-promotion-matrix.json" ]]; then
  jq '.schema_version = 999' "$source_path" > "$source_path.tmp"
  mv "$source_path.tmp" "$source_path"
elif [[ "$source_path" != *"/.source/"* \
  && "$(basename "$source_path")" == "pwnkit-stability-sample.json" ]]; then
  jq '.schema_version = 999' "$source_path" > "$source_path.tmp"
  mv "$source_path.tmp" "$source_path"
fi
SH
  chmod +x "$fake_bin/cp"

  REAL_CP="$real_cp" \
    PATH="$fake_bin:$PATH" \
    "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null

  jq -e '.schema_version == 999' \
    "$matrix_dir/pwnkit-promotion-matrix.json" >/dev/null
  jq -e '.schema_version == 999' \
    "$matrix_dir/default_m3_catalog/pwnkit-stability-sample.json" >/dev/null
  jq -e '.schema_version == 1' \
    "$bundle_dir/pwnkit-promotion-matrix.json" >/dev/null
  jq -e '.schema_version == 1' \
    "$bundle_dir/variants/default_m3_catalog/pwnkit-stability-sample.json" \
    >/dev/null
}

test_packager_discards_late_variant_failure() {
  local matrix_dir
  local bundle_parent
  local bundle_dir
  local status=0

  matrix_dir="$(new_temp_dir)"
  bundle_parent="$(new_temp_dir)"
  bundle_dir="$bundle_parent/bundle"
  write_fixture_matrix "$matrix_dir"
  printf '{"schema_version":\n' \
    > "$matrix_dir/promoted_probe/run-1/agent-replay-trace-summary.json"

  "$PACKAGER" "$matrix_dir" "$bundle_dir" >/dev/null 2>&1 \
    || status="$?"

  [[ "$status" -ne 0 ]] || return 1
  [[ ! -e "$bundle_dir" ]] || return 1
  ! find "$bundle_parent" -maxdepth 1 \
    -name '.eidolon-pwnkit-matrix.*' | rg -q . || return 1
}

test_packager_redacts_matrix_and_variant_artifacts
test_packager_rejects_unhealthy_matrix_by_default
test_packager_allows_unhealthy_matrix_with_diagnostic_bypass
test_packager_refuses_non_empty_bundle_dir
test_packager_rejects_invalid_summary_variant_id
test_packager_rejects_invalid_matrix_metadata_atomically
test_packager_rejects_manifest_summary_disagreement
test_packager_rejects_duplicate_variant_ids
test_packager_rejects_non_string_matrix_path
test_packager_rejects_invalid_matrix_json_streams
test_packager_uses_one_input_snapshot
test_packager_discards_late_variant_failure

printf 'package-pwnkit-promotion-matrix fixture tests passed\n'
