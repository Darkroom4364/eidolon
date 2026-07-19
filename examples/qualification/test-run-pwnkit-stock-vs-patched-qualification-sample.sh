#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-stock-vs-patched-qualification-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-stock-run-test.XXXXXX"
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
source_dir="${PWNKIT_SOURCE_DIR:-unknown}"
dry_run="${EIDOLON_M3_SAMPLE_DRY_RUN:-0}"

mkdir -p "$sample_dir/run-1/private"
{
  printf 'run_count=%s\n' "$run_count"
  printf 'track=%s\n' "$track"
  printf 'fixture_id=%s\n' "${fixture_id:-none}"
  printf 'source_dir=%s\n' "$source_dir"
  printf 'dry_run=%s\n' "$dry_run"
} > "$sample_dir/sample-plan.txt"

if [[ "$dry_run" == "1" ]]; then
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
        artifact_dir: "<fixture-artifact-dir>",
        evidence_track: $evidence_track,
        direct_finding_count: 0,
        eidolon_finding_count: 1
      }
    ]
  }' > "$sample_dir/pwnkit-stability-sample.json"

cat > "$sample_dir/run-1/pwnkit-summary.json" <<JSON
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_comparison",
  "boundary": "owned_loopback_lab",
  "artifact_dir": "$sample_dir",
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
      "fixture": {"id": $(if [[ -n "$fixture_id" ]]; then printf '"%s"' "$fixture_id"; else printf 'null'; fi), "pinned": $(if [[ -n "$fixture_id" ]]; then printf 'true'; else printf 'false'; fi)},
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

test_help_mentions_track_contracts() {
  "$RUNNER" --help | rg -q 'EIDOLON_PWNKIT_QUAL_UPSTREAM_CURRENT_REF'
  "$RUNNER" --help | rg -q 'EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_FIXTURE_ID'
}

test_dry_run_writes_both_track_plans() {
  local temp_dir repo_dir patched_worktree runner_stub sample_dir patched_head

  temp_dir="$(new_temp_dir)"
  repo_dir="$temp_dir/pwnkit"
  patched_worktree="$temp_dir/pwnkit-patched"
  runner_stub="$temp_dir/stub-runner.sh"
  sample_dir="$temp_dir/sample"

  patched_head="$(write_fake_pwnkit_repo "$repo_dir" "$patched_worktree")"
  write_stub_runner "$runner_stub"

  EIDOLON_PWNKIT_QUAL_STOCK_COMPARE_DRY_RUN=1 \
    PWNKIT_SOURCE_DIR="$repo_dir" \
    EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_HEAD="$patched_head" \
    EIDOLON_PWNKIT_QUAL_RUNNER_UPSTREAM_CURRENT_SAMPLE="$runner_stub" \
    EIDOLON_PWNKIT_QUAL_RUNNER_LOCAL_PATCHED_SAMPLE="$runner_stub" \
    "$RUNNER" 2 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/sample-plan.txt" ]]
  [[ -f "$sample_dir/upstream-current/sample-plan.txt" ]]
  [[ -f "$sample_dir/local-patched/sample-plan.txt" ]]
  rg -q '^upstream_current_dir=upstream-current$' "$sample_dir/sample-plan.txt"
  rg -q '^local_patched_fixture_id=eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02$' "$sample_dir/sample-plan.txt"
  rg -q '^track=upstream_current$' "$sample_dir/upstream-current/sample-plan.txt"
  rg -q '^track=local_patched_pwnkit$' "$sample_dir/local-patched/sample-plan.txt"
  rg -q '^dry_run=1$' "$sample_dir/upstream-current/sample-plan.txt"
  rg -q '^dry_run=1$' "$sample_dir/local-patched/sample-plan.txt"
}

test_execution_collects_parity_summary() {
  local temp_dir repo_dir patched_worktree runner_stub sample_dir patched_head

  temp_dir="$(new_temp_dir)"
  repo_dir="$temp_dir/pwnkit"
  patched_worktree="$temp_dir/pwnkit-patched"
  runner_stub="$temp_dir/stub-runner.sh"
  sample_dir="$temp_dir/sample"

  patched_head="$(write_fake_pwnkit_repo "$repo_dir" "$patched_worktree")"
  write_stub_runner "$runner_stub"

  PWNKIT_SOURCE_DIR="$repo_dir" \
    EIDOLON_PWNKIT_QUAL_LOCAL_PATCHED_HEAD="$patched_head" \
    EIDOLON_PWNKIT_QUAL_RUNNER_UPSTREAM_CURRENT_SAMPLE="$runner_stub" \
    EIDOLON_PWNKIT_QUAL_RUNNER_LOCAL_PATCHED_SAMPLE="$runner_stub" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/pwnkit-parity.json" ]]
  [[ -f "$sample_dir/pwnkit-stability-sample.json" ]]
  jq -e '.comparison.parity_status == "parity_reproduced"' "$sample_dir/pwnkit-parity.json" >/dev/null
  jq -e '
    .run_kind == "pwnkit_stock_vs_patched_qualification_sample"
    and .claim_posture == "scanner_qualification_only"
    and .lane == "eidolon_owned_target"
    and .defense_mode == "comparison"
    and .substrate == "host_local"
    and .substrate_counts == [{"substrate":"host_local","count":1}]
    and (.evidence_tracks | sort == ["local_patched_pwnkit", "upstream_current"])
    and .comparison.parity_status == "parity_reproduced"
    and (.artifacts | length == 2)
    and (.artifacts[] | .lane == "eidolon_owned_target")
    and (.artifacts[] | .substrate == "host_local")
    and .strict_stability.ready_for_stability_claim == true
  ' "$sample_dir/pwnkit-stability-sample.json" >/dev/null
}

test_help_mentions_track_contracts
test_dry_run_writes_both_track_plans
test_execution_collects_parity_summary

printf 'stock-vs-patched qualification runner fixture tests passed\n'
