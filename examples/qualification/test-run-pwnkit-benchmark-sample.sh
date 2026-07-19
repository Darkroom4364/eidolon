#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-benchmark-sample.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-pwnkit-benchmark-run-test.XXXXXX"
}

write_stub_raw_runner() {
  local path="$1"
  cat > "$path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

run_count="$1"
sample_dir="$2"
mkdir -p "$sample_dir/run-1/private"

if [[ "${EIDOLON_PWNKIT_BENCHMARK_DRY_RUN:-0}" == "1" ]]; then
  printf 'run_count=%s\n' "$run_count" > "$sample_dir/sample-plan.txt"
  exit 0
fi

cat > "$sample_dir/pwnkit-stability-sample.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "m3_pwnkit_codex_sample",
  "artifact_count": 1,
  "valid_summary_count": 1,
  "counts": {
    "direct_findings": 0,
    "eidolon_findings": 1,
    "positive_differential_findings": 1
  },
  "strongest_claim_level": "controlled_reality_entered",
  "weakest_claim_level": "controlled_reality_entered",
  "runner_git_heads": ["fixture-head"],
  "runner_package_versions": ["fixture-version"],
  "runner_environments": ["host_mac"],
  "runner_network_topologies": ["same_host_loopback"],
  "evidence_tracks": ["upstream_current"]
}
JSON

cat > "$sample_dir/benchmark-validation.json" <<'JSON'
{
  "schema_version": 1,
  "run_kind": "pwnkit_benchmark_validation",
  "validation_status": "validated",
  "validator_kind": "fixture_validator",
  "exploit_rule": "validated_exploit_required",
  "notes": ["fixture benchmark validation"]
}
JSON

cat > "$sample_dir/run-1/pwnkit-summary.json" <<'JSON'
{"schema_version":1,"run_kind":"m3_pwnkit_codex_comparison","boundary":"owned_loopback_lab","runner":{"schema_version":1,"run_kind":"m3_pwnkit_codex_runner","created_at":"2026-07-06T00:00:00Z","mode":"all","urls":{"target":"http://127.0.0.1:9001","proxy":"http://127.0.0.1:8080"},"environment":{"runner_environment":"host_mac","network_topology":"same_host_loopback"},"pwnkit":{"package_version":"fixture-version","git_head":"fixture-head","git_head_short":"fixture-head","git_head_time_seconds":1770000000,"git_dirty":false,"origin_main":{"ahead":0,"behind":0,"in_sync":true},"evidence_track":"upstream_current","fixture":{"id":null,"pinned":false},"stale_dist_guard_bypassed":false}},"runs":{"direct":{"artifact_status":"present","finding_count":0,"final_json_finding_count":0,"db_saved_finding_count":0,"db_active_finding_count":0,"pwnkit_events":{"tool_artifacts":1},"target_evidence_diagnostics":{"request_artifact_count":1},"agent_error_diagnostics":{"count":0,"class_counts":[]}},"eidolon":{"artifact_status":"present","finding_count":1,"final_json_finding_count":1,"db_saved_finding_count":1,"db_active_finding_count":1,"pwnkit_events":{"tool_artifacts":1},"target_evidence_diagnostics":{"request_artifact_count":1},"agent_error_diagnostics":{"count":0,"class_counts":[]}}}}
JSON

cat > "$sample_dir/run-1/agent-replay-trace-summary.json" <<'JSON'
{"schema_version":1,"run_kind":"agent_replay_trace_summary","boundary":"owned_loopback_lab","claim_level":"controlled_reality_entered"}
JSON
SH
  chmod +x "$path"
}

test_dry_run_writes_plan() {
  local temp_dir runner_stub sample_dir
  temp_dir="$(new_temp_dir)"
  runner_stub="$temp_dir/raw-runner.sh"
  sample_dir="$temp_dir/sample"
  write_stub_raw_runner "$runner_stub"

  EIDOLON_PWNKIT_BENCHMARK_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_TASK_ID=task-alpha \
    EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID=snap-001 \
    EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE=validated_exploit_required \
    EIDOLON_PWNKIT_BENCHMARK_DRY_RUN=1 \
    EIDOLON_PWNKIT_BENCHMARK_RAW_RUNNER="$runner_stub" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/sample-plan.txt" ]]
  rg -q '^benchmark_family=xbow_public$' "$sample_dir/sample-plan.txt"
  rg -q '^benchmark_task_id=task-alpha$' "$sample_dir/sample-plan.txt"
}

test_execution_collects_benchmark_summary() {
  local temp_dir runner_stub sample_dir
  temp_dir="$(new_temp_dir)"
  runner_stub="$temp_dir/raw-runner.sh"
  sample_dir="$temp_dir/sample"
  write_stub_raw_runner "$runner_stub"

  EIDOLON_PWNKIT_BENCHMARK_FAMILY=xbow_public \
    EIDOLON_PWNKIT_BENCHMARK_TASK_ID=task-alpha \
    EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID=snap-001 \
    EIDOLON_PWNKIT_BENCHMARK_MODEL_ID=gpt-5.4 \
    EIDOLON_PWNKIT_BENCHMARK_PROMPT_BUNDLE_HASH=sha256:benchprompt \
    EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE=validated_exploit_required \
    EIDOLON_PWNKIT_BENCHMARK_ACTION_BUDGET=40 \
    EIDOLON_PWNKIT_BENCHMARK_TOKEN_BUDGET=120000 \
    EIDOLON_PWNKIT_BENCHMARK_WALL_CLOCK_BUDGET_SECONDS=900 \
    EIDOLON_PWNKIT_BENCHMARK_RAW_RUNNER="$runner_stub" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  jq -e '
    .run_kind == "pwnkit_benchmark_sample"
    and .claim_posture == "benchmark_capability_only"
    and .lane == "xbow_benchmark"
    and .benchmark_family == "xbow_public"
    and .benchmark_task_id == "task-alpha"
    and .benchmark_snapshot_id == "snap-001"
    and .benchmark_model_id == "gpt-5.4"
    and .benchmark_prompt_bundle_hash == "sha256:benchprompt"
    and .budget.benchmark_action_budget == 40
    and .budget.benchmark_token_budget == 120000
    and .budget.benchmark_wall_clock_budget_seconds == 900
    and .validation.status == "validated"
    and .validation.validator_kind == "fixture_validator"
  ' "$sample_dir/pwnkit-stability-sample.json" >/dev/null
}

test_rejects_missing_explicit_benchmark_executor() {
  local temp_dir sample_dir output status=0
  temp_dir="$(new_temp_dir)"
  sample_dir="$temp_dir/sample"

  output="$(
    EIDOLON_PWNKIT_BENCHMARK_FAMILY=xbow_public \
      EIDOLON_PWNKIT_BENCHMARK_TASK_ID=XBEN-005-24 \
      EIDOLON_PWNKIT_BENCHMARK_SNAPSHOT_ID=fixture-sha \
      EIDOLON_PWNKIT_BENCHMARK_VALIDATION_RULE=exact_flag_recovery \
      "$RUNNER" 1 "$sample_dir" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_PWNKIT_BENCHMARK_RAW_RUNNER is required' <<<"$output"
  rg -q "upstream XBow runner" <<<"$output"
}

test_dry_run_writes_plan
test_execution_collects_benchmark_summary
test_rejects_missing_explicit_benchmark_executor

printf 'benchmark sample runner fixture tests passed\n'
