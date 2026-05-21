#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-codex.sh"

new_artifact() {
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-collector-test.XXXXXX")"
  printf '%s\n' "$dir"
}

init_artifact() {
  local dir="$1"
  local session_id="$2"

  printf '%s\n' "$session_id" > "$dir/pinned-eidolon-session-id.txt"
  printf '{"findings":[]}\n' > "$dir/pwnkit-eidolon.json"
  sqlite3 "$dir/pwnkit-eidolon.db" '
    create table pipeline_events (
      id text primary key,
      scanId text not null,
      stage text not null,
      eventType text not null,
      findingId text,
      agentRole text,
      payload text not null default "{}",
      timestamp integer not null
    );
  '
  : > "$dir/proxy-events.jsonl"
}

sql_quote() {
  printf "%s" "$1" | sed "s/'/''/g"
}

insert_tool_artifact() {
  local dir="$1"
  local id="$2"
  local timestamp_ms="$3"
  local payload="$4"
  local escaped_payload
  escaped_payload="$(sql_quote "$payload")"

  sqlite3 "$dir/pwnkit-eidolon.db" "
    insert into pipeline_events
      (id, scanId, stage, eventType, findingId, agentRole, payload, timestamp)
    values
      ('$id', 'scan-1', 'attack', 'tool_artifact', null, null, '$escaped_payload', $timestamp_ms);
  "
}

insert_agent_error() {
  local dir="$1"
  local id="$2"
  local timestamp_ms="$3"
  local stage="$4"
  local role="$5"
  local error_text="$6"
  local payload
  local escaped_payload

  payload="$(jq -cn --arg error "$error_text" --argjson turn 1 '{turn:$turn,error:$error}')"
  escaped_payload="$(sql_quote "$payload")"

  sqlite3 "$dir/pwnkit-eidolon.db" "
    insert into pipeline_events
      (id, scanId, stage, eventType, findingId, agentRole, payload, timestamp)
    values
      ('$id', 'scan-1', '$stage', 'agent_error', null, '$role', '$escaped_payload', $timestamp_ms);
  "
}

insert_http_artifact() {
  local dir="$1"
  local id="$2"
  local timestamp_ms="$3"
  local method="$4"
  local path="$5"
  local status="$6"
  local payload

  payload="$(jq -cn \
    --arg method "$method" \
    --arg url "http://127.0.0.1:9102$path" \
    --argjson status "$status" \
    '{tool:"http_request", request:{method:$method, url:$url}, response:{status:$status}}')"
  insert_tool_artifact "$dir" "$id" "$timestamp_ms" "$payload"
}

insert_bash_http_artifact() {
  local dir="$1"
  local id="$2"
  local timestamp_ms="$3"
  local output
  local payload

  output=$'==== reconcile OpenAPI trace ====\nHTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{"status":"queued","synthetic":true,"write_committed":false,"path":"/api/v2/import/reconcile","action_depth":1}\n'
  payload="$(jq -cn --arg output "$output" '{tool:"bash", output:$output}')"
  insert_tool_artifact "$dir" "$id" "$timestamp_ms" "$payload"
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

append_bait_exposed() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local exposure_id="$4"

  event "$session_id" "$observed_at" "observe" \
    "$(jq -cn \
      --arg exposure_id "$exposure_id" \
      '{type:"bait_exposed", bait_id:"openapi_reconcile_trace", exposure_id:$exposure_id, surface:"/openapi.json"}')" \
    >> "$dir/proxy-events.jsonl"
}

append_bait_action() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local exposure_id="$4"

  event "$session_id" "$observed_at" "observe" \
    "$(jq -cn \
      --arg exposure_id "$exposure_id" \
      '{type:"bait_action_observed", bait_id:"openapi_reconcile_trace", exposure_id:$exposure_id, method:"POST", path:"/api/v2/import/reconcile"}')" \
    >> "$dir/proxy-events.jsonl"
}

append_controlled_reality() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"

  event "$session_id" "$observed_at" "controlled_reality" \
    "$(jq -cn '{type:"controlled_reality_entered", reason:"confirmed bait-derived action moved session into controlled reality"}')" \
    >> "$dir/proxy-events.jsonl"
}

seed_exposure() {
  local dir="$1"
  local session_id="$2"
  local exposure_id="$3"

  insert_http_artifact "$dir" "http-openapi" 1767225600000 GET /openapi.json 200
  append_request_seen "$dir" "$session_id" "2026-01-01T00:00:00Z" GET /openapi.json protected_upstream
  append_bait_exposed "$dir" "$session_id" "2026-01-01T00:00:01Z" "$exposure_id"
}

assert_claim() {
  local dir="$1"
  local expected="$2"

  "$COLLECTOR" "$dir" > "$dir/summary.json"
  jq -e --arg expected "$expected" '.comparison.claim_level == $expected' "$dir/summary.json" >/dev/null
}

test_exposure_only() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"

  assert_claim "$dir" "bait_exposed_without_action"
}

test_bash_http_output_upgrades_confirmed_action() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_bash_http_artifact "$dir" "bash-reconcile" 1767225603000
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:04Z" "exp-1"
  append_controlled_reality "$dir" "session-a" "2026-01-01T00:00:05Z"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '.comparison.correlated_bait_events.actions | length == 1' "$dir/summary.json" >/dev/null
}

test_wrong_session_action_does_not_confirm() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_bash_http_artifact "$dir" "bash-reconcile" 1767225603000
  append_request_seen "$dir" "session-b" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" "session-b" "2026-01-01T00:00:04Z" "exp-1"

  assert_claim "$dir" "bait_action_observed_without_same_session"
  jq -e '.comparison.correlated_bait_events.same_session_confirmed_actions | length == 0' "$dir/summary.json" >/dev/null
}

test_proxy_only_action_stays_exposure_only() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:04Z" "exp-1"
  append_controlled_reality "$dir" "session-a" "2026-01-01T00:00:05Z"

  assert_claim "$dir" "bait_exposed_without_action"
}

test_no_signal_diagnostics_classify_proxy_without_pwnkit_artifacts() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  append_request_seen "$dir" "session-b" "2026-01-01T00:00:00Z" GET /wp-login.php protected_upstream
  append_request_seen "$dir" "session-c" "2026-01-01T00:00:01Z" GET /readme.html protected_upstream

  assert_claim "$dir" "no_target_interaction"
  jq -e '
    .comparison.target_correlation_diagnostics.pwnkit_eidolon_tool_artifact_count == 0
    and .comparison.target_correlation_diagnostics.pwnkit_eidolon_request_artifact_count == 0
    and .comparison.target_correlation_diagnostics.eidolon_proxy_request_count == 2
    and .comparison.target_correlation_diagnostics.correlated_target_request_count == 0
    and .comparison.target_correlation_diagnostics.uncorrelated_proxy_request_count == 2
    and .comparison.target_correlation_diagnostics.likely_cause == "eidolon_proxy_saw_uncorrelated_requests_but_pwnkit_emitted_no_request_artifacts"
    and (.comparison.target_correlation_diagnostics.next_questions | index("why_pwnkit_emitted_no_request_artifacts"))
    and (.comparison.target_correlation_diagnostics.next_questions | index("which_runner_or_probe_generated_uncorrelated_proxy_requests"))
    and (.comparison.target_correlation_diagnostics.next_questions | index("why_pinned_session_cookie_was_not_reused_by_pwnkit"))
  ' "$dir/summary.json" >/dev/null
}

test_no_signal_diagnostics_classify_agent_auth_errors() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  append_request_seen "$dir" "session-b" "2026-01-01T00:00:00Z" GET /wp-login.php protected_upstream
  insert_agent_error \
    "$dir" \
    "err-refresh" \
    1767225600000 \
    attack \
    attack \
    "ChatGPT (Codex backend) API error: token refresh failed: 401 invalid_request_error sensitive-refresh-detail"

  assert_claim "$dir" "no_target_interaction"
  jq -e '
    .runs.eidolon.agent_error_diagnostics.count == 1
    and .runs.eidolon.agent_error_diagnostics.stage_counts == [
      {stage: "attack", agentRole: "attack", count: 1}
    ]
    and .runs.eidolon.agent_error_diagnostics.class_counts == [
      {error_class: "codex_token_refresh_failed", count: 1}
    ]
    and .runs.eidolon.agent_error_diagnostics.has_codex_token_refresh_failure == true
    and .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_count == 1
    and .comparison.target_correlation_diagnostics.likely_cause == "pwnkit_codex_token_refresh_failure_prevented_request_artifacts"
    and (.comparison.target_correlation_diagnostics.next_questions | index("refresh_pwnkit_codex_auth_before_rerun"))
    and (.comparison.target_correlation_diagnostics.next_questions | index("rerun_matrix_after_agent_error_free_scan"))
    and (. | tostring | contains("sensitive-refresh-detail") | not)
  ' "$dir/summary.json" >/dev/null
}

test_finding_diagnostics_are_shape_only() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  cat > "$dir/pwnkit-eidolon.json" <<'JSON'
{
  "findings": [
    {
      "id": "finding-1",
      "title": "do-not-emit-title",
      "description": "do-not-emit-description",
      "severity": "high",
      "category": "exposure",
      "confidence": "medium",
      "evidence": {
        "request": "do-not-emit-request",
        "analysis": "do-not-emit-analysis"
      }
    }
  ]
}
JSON

  "$COLLECTOR" "$dir" > "$dir/summary.json"

  jq -e '
    .runs.eidolon.finding_count == 1
    and .runs.eidolon.finding_diagnostics.severity_counts == [{value: "high", count: 1}]
    and .runs.eidolon.finding_diagnostics.category_counts == [{value: "exposure", count: 1}]
    and .runs.eidolon.finding_diagnostics.confidence_counts == [{value: "medium", count: 1}]
    and .runs.eidolon.finding_diagnostics.evidence_presence.request_evidence == 1
    and (.runs.eidolon.finding_diagnostics | tostring | contains("do-not-emit") | not)
  ' "$dir/summary.json" >/dev/null
}

test_finding_gap_marks_controlled_reality_without_findings() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_bash_http_artifact "$dir" "bash-reconcile" 1767225603000
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:04Z" "exp-1"
  append_controlled_reality "$dir" "session-a" "2026-01-01T00:00:05Z"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '
    .comparison.finding_gap.eidolon_controlled_reality_without_findings == true
    and .comparison.finding_gap.next_question == "why_controlled_reality_chain_was_not_promoted_to_finding"
    and .runs.eidolon.target_evidence_diagnostics.observed_request_evidence_without_findings == true
  ' "$dir/summary.json" >/dev/null
}

test_exposure_only
test_bash_http_output_upgrades_confirmed_action
test_wrong_session_action_does_not_confirm
test_proxy_only_action_stays_exposure_only
test_no_signal_diagnostics_classify_proxy_without_pwnkit_artifacts
test_no_signal_diagnostics_classify_agent_auth_errors
test_finding_diagnostics_are_shape_only
test_finding_gap_marks_controlled_reality_without_findings

printf 'collect-pwnkit-codex fixture tests passed\n'
