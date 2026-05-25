#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTOR="$SCRIPT_DIR/collect-action-trace.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-action-trace-test.XXXXXX"
}

event() {
  local session_id="$1"
  local observed_at="$2"
  local policy_state="$3"
  local kind="$4"

  jq -cn \
    --arg session_id "$session_id" \
    --arg observed_at "$observed_at" \
    --arg policy_state "$policy_state" \
    --argjson kind "$kind" \
    '{
      schema_version: 2,
      id: ("evt-" + ($observed_at | gsub("[^0-9]"; ""))),
      session_id: $session_id,
      observed_at: $observed_at,
      source: "fixture",
      policy_state: $policy_state,
      kind: $kind
    }'
}

append_request_seen() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local method="$4"
  local path="$5"
  local routing_decision="$6"

  event "$session_id" "$observed_at" "observe" \
    "$(jq -cn \
      --arg method "$method" \
      --arg path "$path" \
      --arg routing_decision "$routing_decision" \
      '{type:"request_seen", method:$method, path:$path, routing_decision:$routing_decision}')" \
    >> "$dir/proxy-events.jsonl"
}

test_no_bait_activity_claim_for_non_bait_proxy_request() {
  local dir
  dir="$(new_temp_dir)"

  append_request_seen "$dir" "session-a" "2026-01-01T00:00:00Z" GET /wp-login.php protected_upstream

  "$COLLECTOR" "$dir" > "$dir/summary.json"

  jq -e '
    .schema_version == 1
    and .run_kind == "m3_scripted_action_trace"
    and .evidence_source == "proxy_trace"
    and .claim_level == "no_bait_activity"
    and .counts.events == 1
    and .counts.requests == 1
    and .counts.bait_exposures == 0
    and .counts.bait_actions == 0
    and .counts.same_session_confirmed_bait_actions == 0
    and .counts.controlled_reality_entries_after_confirmed_action == 0
    and .metrics.bait_follow_rate == 0
    and .metrics.same_session_confirmed_bait_follow_rate == 0
    and .metrics.real_surface_requests_after_containment == null
    and .metrics.controlled_reality_dwell_seconds == null
    and .metrics.controlled_reality_action_depth == 0
    and .metrics.controlled_reality_branch_count == 0
    and .pinned_session.present == false
    and (.sessions | length) == 0
    and (.bait_events.exposures | length) == 0
    and (.bait_events.actions | length) == 0
  ' "$dir/summary.json" >/dev/null
}

test_no_bait_activity_claim_for_non_bait_proxy_request

printf 'collect-action-trace fixture tests passed\n'
