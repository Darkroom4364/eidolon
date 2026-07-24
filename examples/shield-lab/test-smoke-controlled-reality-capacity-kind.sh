#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-controlled-reality-capacity-kind.sh"

new_fixture() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-capacity-fixture.XXXXXX"
}

write_valid_fixture() {
  local dir="$1"

  cat >"$dir/action.log" <<'LOG'
entry_status=202
entry_write_committed=false
followup_status=503
followup_synthetic=true
followup_write_committed=false
LOG
  cat >"$dir/probe-ids.meta" <<'META'
baseline_probe_id=shield-probe-baseline-fixture
capacity_probe_id=shield-probe-capacity-fixture
target_replica_count=2
META
  cat >"$dir/proxy-debug.jsonl" <<'JSONL'
{"event":"controlled_reality_backend_failed","fields":{"request_id":"request-followup","reason":"replay_cache_saturated","response_status":503,"local_fallback":false}}
JSONL
  cat >"$dir/proxy-events.jsonl" <<'JSONL'
{"session_id":"session-a","request_id":"request-exposure","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","exposure_id":"exposure-a"}}
{"session_id":"session-a","request_id":"request-action","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","exposure_id":"exposure-a","header_value_mint_status":"matched_session_value"}}
{"session_id":"session-a","request_id":"request-followup","policy_state":"controlled_reality","kind":{"type":"reality_escape_attempt","method":"POST","path":"/api/v1/imports","routing_decision":"controlled_reality"}}
{"session_id":"session-a","request_id":"request-followup","policy_state":"controlled_reality","kind":{"type":"response_served","status":503,"routing_decision":"eidolon_owned"}}
JSONL
  cat >"$dir/renderer-identity.meta" <<'META'
single_replica=true
pod_uid_stable=true
restart_count_stable=true
META
  cat >"$dir/renderer.jsonl" <<'JSONL'
{"schema_version":1,"component":"controlled_reality_renderer","event":"startup","request_id":null,"status":null,"reason":null,"peer":null,"dropped_audits_before":0,"counters":{"connection_queue_saturated_total":0,"audit_events_dropped_total":0,"replay_cache_saturated_total":0},"limits":{"connection_workers":1,"connection_queue_capacity":1,"audit_queue_capacity":1,"replay_cache_capacity":1}}
{"schema_version":1,"component":"controlled_reality_renderer","event":"served","request_id":"request-action","status":202,"reason":null,"peer":"10.244.1.8:41001","dropped_audits_before":2,"counters":{"connection_queue_saturated_total":3,"audit_events_dropped_total":2,"replay_cache_saturated_total":0},"limits":{"connection_workers":1,"connection_queue_capacity":1,"audit_queue_capacity":1,"replay_cache_capacity":1}}
{"schema_version":1,"component":"controlled_reality_renderer","event":"rejected","request_id":"request-followup","status":null,"reason":"replay_cache_saturated","peer":"10.244.1.8:41002","dropped_audits_before":0,"counters":{"connection_queue_saturated_total":3,"audit_events_dropped_total":2,"replay_cache_saturated_total":1},"limits":{"connection_workers":1,"connection_queue_capacity":1,"audit_queue_capacity":1,"replay_cache_capacity":1}}
JSONL
  cat >"$dir/restoration.meta" <<'META'
args_restored=true
renderer_ready=true
META
  printf '%s\n' 'stress_complete=true' >"$dir/stress.log"
  cat >"$dir/target-audit.log" <<'JSONL'
{"event":"protected_upstream_probe_observed","method":"POST","probe_id":"shield-probe-baseline-fixture","route":"api_v2_import_reconcile"}
{"event":"protected_upstream_probe_observed","method":"POST","probe_id":"shield-probe-baseline-fixture","route":"api_v2_import_reconcile"}
JSONL
}

expect_failure() {
  local dir="$1"
  if "$SMOKE_SCRIPT" --validate-fixture "$dir" >/dev/null 2>&1; then
    echo "fixture unexpectedly passed: $dir" >&2
    exit 1
  fi
}

[[ -x "$SMOKE_SCRIPT" ]] || {
  echo "capacity smoke is missing or not executable: $SMOKE_SCRIPT" >&2
  exit 1
}

grep -Fq 'config current-context' "$SMOKE_SCRIPT"
grep -Fq '[[ "$context" == "$EXPECTED_CONTEXT" ]]' "$SMOKE_SCRIPT"
for flag in \
  --connection-workers \
  --connection-queue-capacity \
  --audit-queue-capacity \
  --replay-cache-capacity
do
  grep -Fq -- "$flag" "$SMOKE_SCRIPT"
done
grep -Fq 'trap cleanup EXIT' "$SMOKE_SCRIPT"
cleanup_body="$(sed -n '/^cleanup() {/,/^}/p' "$SMOKE_SCRIPT")"
grep -Fq 'patch_renderer_args "$tmp_dir/original-renderer-args.json"' \
  <<<"$cleanup_body"
grep -Fq 'rollout status' <<<"$cleanup_body"

valid="$(new_fixture)"
bad_dirs=()
trap 'rm -rf "$valid" "${bad_dirs[@]:-}"' EXIT
write_valid_fixture "$valid"

"$SMOKE_SCRIPT" --validate-fixture "$valid" \
  | jq -e '
      .result == "passed"
      and .renderer.configured_limits.connection_workers == 1
      and .renderer.configured_limits.connection_queue_capacity == 1
      and .renderer.configured_limits.audit_queue_capacity == 1
      and .renderer.configured_limits.replay_cache_capacity == 1
      and .renderer.connection_queue_saturated == true
      and .renderer.audit_events_dropped == true
      and .renderer.replay_cache_saturated == true
      and .renderer.counters_monotonic == true
      and .fail_closed.followup_status == 503
      and .fail_closed.local_fallback == false
      and .deployment_restored == true
      and .protected_upstream.replicas_audited == 2
      and .protected_upstream.capacity_requests_observed == 0
    ' >/dev/null

for mutation in \
  stress_incomplete \
  entry_failed \
  followup_not_503 \
  followup_not_synthetic \
  followup_write_unknown \
  renderer_restarted \
  restoration_missing \
  renderer_not_ready \
  target_leak \
  markerless_target_leak \
  missing_baseline \
  duplicate_probe_id \
  broken_session_link \
  missing_followup \
  response_not_503 \
  response_wrong_route \
  debug_reason_wrong \
  debug_fallback_enabled \
  debug_request_mismatch \
  duplicate_debug_failure \
  worker_limit_wrong \
  connection_limit_wrong \
  audit_limit_wrong \
  replay_limit_wrong \
  startup_missing \
  served_missing \
  rejection_missing \
  queue_counter_zero \
  audit_counter_zero \
  replay_counter_zero \
  counters_decrease
do
  dir="$(new_fixture)"
  bad_dirs+=("$dir")
  cp -R "$valid/." "$dir/"
  case "$mutation" in
    stress_incomplete)
      sed -i.bak 's/stress_complete=true/stress_complete=false/' \
        "$dir/stress.log"
      rm "$dir/stress.log.bak"
      ;;
    entry_failed)
      sed -i.bak 's/entry_status=202/entry_status=503/' "$dir/action.log"
      rm "$dir/action.log.bak"
      ;;
    followup_not_503)
      sed -i.bak 's/followup_status=503/followup_status=202/' \
        "$dir/action.log"
      rm "$dir/action.log.bak"
      ;;
    followup_not_synthetic)
      sed -i.bak 's/followup_synthetic=true/followup_synthetic=false/' \
        "$dir/action.log"
      rm "$dir/action.log.bak"
      ;;
    followup_write_unknown)
      sed -i.bak \
        's/followup_write_committed=false/followup_write_committed=unknown/' \
        "$dir/action.log"
      rm "$dir/action.log.bak"
      ;;
    renderer_restarted)
      sed -i.bak 's/restart_count_stable=true/restart_count_stable=false/' \
        "$dir/renderer-identity.meta"
      rm "$dir/renderer-identity.meta.bak"
      ;;
    restoration_missing)
      sed -i.bak 's/args_restored=true/args_restored=false/' \
        "$dir/restoration.meta"
      rm "$dir/restoration.meta.bak"
      ;;
    renderer_not_ready)
      sed -i.bak 's/renderer_ready=true/renderer_ready=false/' \
        "$dir/restoration.meta"
      rm "$dir/restoration.meta.bak"
      ;;
    target_leak)
      printf '%s\n' \
        '{"event":"protected_upstream_probe_observed","method":"POST","probe_id":"shield-probe-capacity-fixture","route":"api_v2_import_reconcile"}' \
        >>"$dir/target-audit.log"
      ;;
    markerless_target_leak)
      printf '%s\n' \
        '{"event":"protected_upstream_probe_observed","method":"DELETE","route":"other_write"}' \
        >>"$dir/target-audit.log"
      ;;
    missing_baseline)
      sed -i.bak '1d' "$dir/target-audit.log"
      rm "$dir/target-audit.log.bak"
      ;;
    duplicate_probe_id)
      sed -i.bak \
        's/capacity_probe_id=shield-probe-capacity-fixture/capacity_probe_id=shield-probe-baseline-fixture/' \
        "$dir/probe-ids.meta"
      rm "$dir/probe-ids.meta.bak"
      ;;
    broken_session_link)
      sed -i.bak '3s/"session_id":"session-a"/"session_id":"session-b"/' \
        "$dir/proxy-events.jsonl"
      rm "$dir/proxy-events.jsonl.bak"
      ;;
    missing_followup)
      sed -i.bak '/"type":"reality_escape_attempt"/d' \
        "$dir/proxy-events.jsonl"
      rm "$dir/proxy-events.jsonl.bak"
      ;;
    response_not_503)
      sed -i.bak 's/"status":503/"status":202/' "$dir/proxy-events.jsonl"
      rm "$dir/proxy-events.jsonl.bak"
      ;;
    response_wrong_route)
      sed -i.bak \
        '4s/"routing_decision":"eidolon_owned"/"routing_decision":"protected_upstream"/' \
        "$dir/proxy-events.jsonl"
      rm "$dir/proxy-events.jsonl.bak"
      ;;
    debug_reason_wrong)
      sed -i.bak \
        's/"reason":"replay_cache_saturated"/"reason":"malformed_frame"/' \
        "$dir/proxy-debug.jsonl"
      rm "$dir/proxy-debug.jsonl.bak"
      ;;
    debug_fallback_enabled)
      sed -i.bak 's/"local_fallback":false/"local_fallback":true/' \
        "$dir/proxy-debug.jsonl"
      rm "$dir/proxy-debug.jsonl.bak"
      ;;
    debug_request_mismatch)
      sed -i.bak 's/request-followup/request-stale/' \
        "$dir/proxy-debug.jsonl"
      rm "$dir/proxy-debug.jsonl.bak"
      ;;
    duplicate_debug_failure)
      cat "$dir/proxy-debug.jsonl" >>"$dir/proxy-debug.jsonl.copy"
      cat "$dir/proxy-debug.jsonl.copy" >>"$dir/proxy-debug.jsonl"
      rm "$dir/proxy-debug.jsonl.copy"
      ;;
    worker_limit_wrong)
      sed -i.bak 's/"connection_workers":1/"connection_workers":2/g' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    connection_limit_wrong)
      sed -i.bak \
        's/"connection_queue_capacity":1/"connection_queue_capacity":2/g' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    audit_limit_wrong)
      sed -i.bak 's/"audit_queue_capacity":1/"audit_queue_capacity":2/g' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    replay_limit_wrong)
      sed -i.bak 's/"replay_cache_capacity":1/"replay_cache_capacity":2/g' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    startup_missing)
      sed -i.bak '1d' "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    served_missing)
      sed -i.bak '/"event":"served"/d' "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    rejection_missing)
      sed -i.bak \
        's/"reason":"replay_cache_saturated"/"reason":"malformed_frame"/' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    queue_counter_zero)
      sed -i.bak \
        's/"connection_queue_saturated_total":3/"connection_queue_saturated_total":0/g' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    audit_counter_zero)
      sed -i.bak \
        's/"audit_events_dropped_total":2/"audit_events_dropped_total":0/g' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    replay_counter_zero)
      sed -i.bak \
        's/"replay_cache_saturated_total":1/"replay_cache_saturated_total":0/' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
    counters_decrease)
      sed -i.bak \
        '3s/"connection_queue_saturated_total":3/"connection_queue_saturated_total":2/' \
        "$dir/renderer.jsonl"
      rm "$dir/renderer.jsonl.bak"
      ;;
  esac
  expect_failure "$dir"
done

echo "kind controlled-reality capacity fixture tests ok"
