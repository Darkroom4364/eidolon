#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-stock-vs-patched-qualification-sample.sh"
PACKAGER="$SCRIPT_DIR/package-pwnkit-stock-vs-patched-qualification-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-stock-package-test.XXXXXX"
}

write_fake_pwnkit_repo() {
  local repo_dir="$1"
  local patched_worktree="$2"
  local patched_head

  git init -q "$repo_dir"
  git -C "$repo_dir" config user.email fixture@example.com
  git -C "$repo_dir" config user.name "Fixture User"

  printf 'patched\n' > "$repo_dir/pwnkit.txt"
  git -C "$repo_dir" add pwnkit.txt
  git -C "$repo_dir" commit -q -m "patched fixture"
  patched_head="$(git -C "$repo_dir" rev-parse HEAD)"
  git -C "$repo_dir" worktree add -q --detach "$patched_worktree" "$patched_head"

  printf 'upstream\n' > "$repo_dir/pwnkit.txt"
  git -C "$repo_dir" commit -q -am "upstream current"
  git -C "$repo_dir" update-ref refs/remotes/origin/main "$(git -C "$repo_dir" rev-parse HEAD)"

  printf '%s\n' "$patched_head"
}

write_stub_runner() {
  local path="$1"

  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"
track="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-unknown}"
fixture_id="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"

mkdir -p "$sample_dir/run-1/private"
printf 'run_count=%s\ntrack=%s\n' "$run_count" "$track" > "$sample_dir/sample-plan.txt"

if [[ "${EIDOLON_M3_SAMPLE_DRY_RUN:-0}" == "1" ]]; then
  exit 0
fi

if [[ "$track" == "upstream_current" ]]; then
  git_head="upstream-head"
else
  git_head="local-patched-head"
fi

jq -n \
  --arg evidence_track "$track" \
  --arg git_head "$git_head" \
  --arg fixture_id "$fixture_id" \
  '{
    schema_version: 1,
    run_kind: "m3_pwnkit_codex_sample",
    generated_at: "2026-06-29T00:00:00Z",
    artifact_count: 1,
    valid_summary_count: 1,
    counts: {
      bait_reached: 1,
      bait_action_observed: 1,
      same_session_confirmed_bait_action: 1,
      controlled_reality_entered: 1,
      direct_quiet: 1,
      direct_findings: 0,
      eidolon_findings: 1,
      positive_differential_findings: 1
    },
    rates: {
      target_interaction_rate: 1,
      bait_reach_rate: 1,
      bait_action_rate: 1,
      same_session_confirmed_bait_action_rate: 1,
      controlled_reality_entry_rate: 1,
      direct_quiet_rate: 1,
      eidolon_finding_rate: 1,
      positive_differential_finding_rate: 1
    },
    claim_level_counts: [
      {claim_level: "controlled_reality_entered", count: 1}
    ],
    weakest_claim_level: "controlled_reality_entered",
    strongest_claim_level: "controlled_reality_entered",
    runner_git_heads: [$git_head],
    runner_package_versions: ["fixture-version"],
    runner_pwnkit_fixture_ids: (if $fixture_id == "" then [] else [$fixture_id] end),
    evidence_track_counts: [{evidence_track: $evidence_track, count: 1}],
    evidence_tracks: [$evidence_track],
    single_evidence_track: true,
    mixed_evidence_tracks: false,
    unknown_evidence_track_count: 0,
    runner_environments: ["host_mac"],
    runner_network_topologies: ["same_host_loopback"],
    tool_fingerprint_summary: [],
    source_checkout: {
      all_runners_clean: true,
      all_runners_origin_main_synced: true
    },
    finding_reconciliation: {
      direct_final_json_finding_total: 0,
      eidolon_final_json_finding_total: 1,
      direct_db_saved_finding_total: 0,
      eidolon_db_saved_finding_total: 1,
      direct_db_active_finding_total: 0,
      eidolon_db_active_finding_total: 1,
      any_db_saved_findings_omitted_from_final_json: false,
      final_json_counts_still_drive_finding_claims: true
    },
    no_signal_diagnostics: {
      likely_cause: null,
      next_questions: []
    },
    differential_findings: {
      ready_for_differential_finding_claim: true,
      positive_differential_run_count: 1,
      direct_finding_run_count: 0,
      eidolon_finding_run_count: 1,
      controlled_reality_without_eidolon_finding_run_count: 0
    },
    strict_stability: {
      ready_for_stability_claim: true,
      sample_size: 1,
      all_same_session_confirmed_bait_action: true,
      all_controlled_reality_entered: true,
      all_direct_quiet: true
    },
    artifacts: [
      {
        artifact_dir: "/private/tmp/fixture-source",
        present: true,
        evidence_track: $evidence_track,
        runner_git_head: $git_head,
        runner_package_version: "fixture-version",
        runner_git_dirty: false,
        runner_origin_main: {"ahead": 0, "behind": 0, "in_sync": true},
        runner_origin_main_in_sync: true,
        runner_pwnkit_fixture: {
          id: (if $fixture_id == "" then null else $fixture_id end),
          pinned: ($fixture_id != "")
        },
        runner_pwnkit_fixture_id: (if $fixture_id == "" then null else $fixture_id end),
        stale_dist_guard_bypassed: false,
        runner_environment: "host_mac",
        runner_environment_source: "env_override",
        runner_network_topology: "same_host_loopback",
        runner_os: {"kernel_name": "Darwin"},
        runner_tool_fingerprint: [],
        claim_level: "controlled_reality_entered",
        conclusion: "bait_action_observed",
        target_interaction_observed: true,
        bait_reached: true,
        bait_action_observed: true,
        same_session_confirmed_bait_action: true,
        controlled_reality_entered: true,
        direct_finding_count: 0,
        eidolon_finding_count: 1,
        direct_final_json_finding_count: 0,
        eidolon_final_json_finding_count: 1,
        direct_db_saved_finding_count: 0,
        eidolon_db_saved_finding_count: 1,
        direct_db_active_finding_count: 0,
        eidolon_db_active_finding_count: 1,
        pwnkit_events: {
          eidolon: {"tool_artifacts": 1},
          direct: {"tool_artifacts": 1}
        },
        target_evidence_diagnostics: {
          eidolon: {"request_artifact_count": 1},
          direct: {"request_artifact_count": 1}
        },
        agent_error_diagnostics: {
          eidolon: {"count": 0, "class_counts": []},
          direct: {"count": 0, "class_counts": []}
        },
        eidolon_proxy: {
          request_count: 1,
          request_path_counts: [{"value": "/docs?secret=value", "count": 1}]
        },
        target_correlation_diagnostics: {
          pwnkit_eidolon_request_artifact_count: 1,
          eidolon_proxy_request_count: 1,
          correlated_target_request_count: 1
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
        },
        agent_trace: {
          claim_level: "controlled_reality_entered"
        },
        trace_gap: {
          controlled_reality_entered: false
        }
      }
    ]
  }' > "$sample_dir/pwnkit-stability-sample.json"

cat > "$sample_dir/run-1/pwnkit-summary.json" <<JSON
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
      "runner_environment": "host_mac",
      "network_topology": "same_host_loopback"
    },
    "pwnkit": {
      "package_version": "fixture-version",
      "git_head": "$git_head",
      "git_head_short": "$git_head",
      "git_head_time_seconds": 1770000000,
      "git_dirty": false,
      "origin_main": {"ahead": 0, "behind": 0, "in_sync": true},
      "evidence_track": "$track",
      "fixture": {
        "id": $(if [[ -n "$fixture_id" ]]; then printf '"%s"' "$fixture_id"; else printf 'null'; fi),
        "pinned": $(if [[ -n "$fixture_id" ]]; then printf 'true'; else printf 'false'; fi)
      },
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

test_packager_creates_bundle() {
  local temp_dir repo_dir patched_worktree runner_stub sample_dir bundle_dir patched_head

  temp_dir="$(new_temp_dir)"
  repo_dir="$temp_dir/pwnkit"
  patched_worktree="$temp_dir/pwnkit-patched"
  runner_stub="$temp_dir/stub-runner.sh"
  sample_dir="$temp_dir/sample"
  bundle_dir="$temp_dir/bundle"

  patched_head="$(write_fake_pwnkit_repo "$repo_dir" "$patched_worktree")"
  write_stub_runner "$runner_stub"

  PWNKIT_SOURCE_DIR="$repo_dir" \
    EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_HEAD="$patched_head" \
    EIDOLON_PWNKIT_QUAL_RUNNER_UPSTREAM_CURRENT_SAMPLE="$runner_stub" \
    EIDOLON_PWNKIT_QUAL_RUNNER_LOCAL_PATCHED_SAMPLE="$runner_stub" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  "$PACKAGER" "$sample_dir" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]]
  [[ -f "$bundle_dir/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/pwnkit-parity.json" ]]
  [[ -f "$bundle_dir/tracks/upstream-current/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/tracks/local-patched/pwnkit-stability-sample.json" ]]
  [[ -f "$bundle_dir/SHA256SUMS" ]]
  rg -q 'stock-vs-patched comparison bundle' "$bundle_dir/README.md"
  rg -q 'lane: `eidolon_owned_target`; defense: `comparison`.' "$bundle_dir/README.md"
  rg -q '<sample-path-omitted>' "$bundle_dir/pwnkit-stability-sample.json"
  rg -q '<sample-path-omitted>' "$bundle_dir/pwnkit-parity.json"
  jq -e '
    .lane == "eidolon_owned_target"
    and .defense_mode == "comparison"
    and .substrate == "host_local"
    and .artifact_identity.upstream_sample_source == "<sample-path-omitted>"
    and .artifact_identity.parity_source == "<parity-source-omitted>"
    and (.artifacts[] | .artifact_identity.sample_path == "<sample-path-omitted>")
  ' "$bundle_dir/pwnkit-stability-sample.json" >/dev/null
}

test_packager_creates_bundle

printf 'stock-vs-patched qualification package fixture tests passed\n'
