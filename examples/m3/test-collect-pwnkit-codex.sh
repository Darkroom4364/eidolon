#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-codex.sh"
MINT_AUDIT_JSON='{"header_name":"X-Minted-Trace","kind":"session_hmac_sha256_v1","prefix":"minted"}'

fixture_session_id() {
  case "$1" in
    session-a) printf '%s' 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' ;;
    session-b) printf '%s' 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' ;;
    session-c) printf '%s' 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' ;;
    *) printf '%s' "$1" ;;
  esac
}

fixture_event_id() {
  case "$1" in
    duplicate-exposure-id) printf '%s' '11111111-1111-4111-8111-111111111111' ;;
    conflicting-exposure-id) printf '%s' '22222222-2222-4222-8222-222222222222' ;;
    cross-session-action-id) printf '%s' '33333333-3333-4333-8333-333333333333' ;;
    duplicate-action-id) printf '%s' '44444444-4444-4444-8444-444444444444' ;;
    conflicting-action-id) printf '%s' '55555555-5555-4555-8555-555555555555' ;;
    conflict-id) printf '%s' '66666666-6666-4666-8666-666666666666' ;;
    *)
      local checksum
      checksum="$(printf '%s' "$1" | cksum | awk '{print $1}')"
      printf '00000000-0000-4000-8000-%012x' "$checksum"
      ;;
  esac
}

new_artifact() {
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-collector-test.XXXXXX")"
  printf '%s\n' "$dir"
}

init_artifact() {
  local dir="$1"
  local session_id="$2"

  fixture_session_id "$session_id" > "$dir/pinned-eidolon-session-id.txt"
  printf '\n' >> "$dir/pinned-eidolon-session-id.txt"
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

create_lifecycle_tables() {
  local dir="$1"

  sqlite3 "$dir/pwnkit-eidolon.db" '
    create table scans (
      id text primary key,
      target text not null,
      depth text not null,
      runtime text not null,
      mode text not null,
      status text not null,
      startedAt text not null,
      completedAt text,
      durationMs integer,
      summary text
    );
    create table agent_sessions (
      id text primary key,
      scanId text not null,
      agentRole text not null,
      turnCount integer not null,
      messages text not null default "[]",
      toolContext text not null default "{}",
      status text not null,
      createdAt text not null,
      updatedAt text not null
    );
  '
}

insert_scan_record() {
  local dir="$1"
  local status="$2"
  local total_findings="$3"
  local summary
  local completed_at=""

  summary="$(jq -cn --argjson total_findings "$total_findings" \
    '{totalAttacks: 9, totalFindings: $total_findings}')"
  if [[ "$status" == "completed" || "$status" == "failed" ]]; then
    completed_at="2026-01-01T00:10:00Z"
  fi

  sqlite3 "$dir/pwnkit-eidolon.db" "
    insert into scans
      (id, target, depth, runtime, mode, status, startedAt, completedAt, durationMs, summary)
    values
      (
        'scan-1',
        'http://127.0.0.1:8080',
        'quick',
        'codex',
        'web',
        '$(sql_quote "$status")',
        '2026-01-01T00:00:00Z',
        $(if [[ -n "$completed_at" ]]; then printf "'%s'" "$completed_at"; else printf 'null'; fi),
        600000,
        '$(sql_quote "$summary")'
      );
  "
}

insert_agent_session() {
  local dir="$1"
  local role="$2"
  local turn_count="$3"
  local status="$4"
  local session_id="${5:-session-$role}"
  local created_at="${6:-2026-01-01T00:00:00Z}"

  sqlite3 "$dir/pwnkit-eidolon.db" "
    insert into agent_sessions
      (id, scanId, agentRole, turnCount, messages, toolContext, status, createdAt, updatedAt)
    values
      (
        '$(sql_quote "$session_id")',
        'scan-1',
        '$(sql_quote "$role")',
        $turn_count,
        '[]',
        '{}',
        '$(sql_quote "$status")',
        '$(sql_quote "$created_at")',
        '2026-01-01T00:10:00Z'
      );
  "
}

insert_lifecycle_event() {
  local dir="$1"
  local id="$2"
  local event_type="$3"
  local timestamp_ms="$4"

  sqlite3 "$dir/pwnkit-eidolon.db" "
    insert into pipeline_events
      (id, scanId, stage, eventType, findingId, agentRole, payload, timestamp)
    values
      (
        '$(sql_quote "$id")',
        'scan-1',
        'report',
        '$(sql_quote "$event_type")',
        null,
        null,
        '{}',
        $timestamp_ms
      );
  "
}

create_findings_table() {
  local dir="$1"

  sqlite3 "$dir/pwnkit-eidolon.db" '
    create table findings (
      severity text,
      category text,
      status text,
      triageStatus text,
      workflowStatus text,
      triageNote text,
      confidence real,
      score integer,
      cvssScore real,
      layerVerdicts text,
      pocSteps text,
      verificationSpec text,
      pocExecution text,
      timestamp integer
    );
  '
}

insert_db_finding() {
  local dir="$1"
  local severity="$2"
  local category="$3"
  local status="$4"
  local triage_status="$5"
  local workflow_status="$6"
  local timestamp_ms="$7"

  sqlite3 "$dir/pwnkit-eidolon.db" "
    insert into findings
      (severity, category, status, triageStatus, workflowStatus, timestamp)
    values
      (
        '$(sql_quote "$severity")',
        '$(sql_quote "$category")',
        '$(sql_quote "$status")',
        '$(sql_quote "$triage_status")',
        '$(sql_quote "$workflow_status")',
        $timestamp_ms
      );
  "
}

set_latest_db_finding_metadata() {
  local dir="$1"
  local triage_note="$2"
  local confidence="$3"
  local score="$4"
  local cvss_score="$5"
  local layer_verdicts="$6"
  local poc_steps="$7"
  local triage_note_sql
  local score_sql
  local cvss_score_sql
  local layer_verdicts_sql
  local poc_steps_sql

  if [[ -z "$triage_note" ]]; then
    triage_note_sql="null"
  else
    triage_note_sql="'$(sql_quote "$triage_note")'"
  fi

  if [[ -z "$score" ]]; then
    score_sql="null"
  else
    score_sql="$score"
  fi

  if [[ -z "$cvss_score" ]]; then
    cvss_score_sql="null"
  else
    cvss_score_sql="$cvss_score"
  fi

  layer_verdicts_sql="'$(sql_quote "$layer_verdicts")'"
  poc_steps_sql="'$(sql_quote "$poc_steps")'"

  sqlite3 "$dir/pwnkit-eidolon.db" "
    update findings
       set triageNote = $triage_note_sql,
           confidence = $confidence,
           score = $score_sql,
           cvssScore = $cvss_score_sql,
           layerVerdicts = $layer_verdicts_sql,
           pocSteps = $poc_steps_sql
     where rowid = (select max(rowid) from findings);
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

insert_crawl_artifact() {
  local dir="$1"
  local id="$2"
  local timestamp_ms="$3"
  local start_url="$4"
  local depth="$5"
  local pages_visited="$6"
  local payload

  payload="$(jq -cn \
    --arg startUrl "$start_url" \
    --argjson depth "$depth" \
    --argjson pages_visited "$pages_visited" \
    '{tool:"crawl", startUrl:$startUrl, depth:$depth, pagesVisited:$pages_visited}')"
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

insert_large_bash_http_artifacts() {
  local dir="$1"
  local count="$2"
  local sql_file="$dir/large-bash-http-artifacts.sql"
  local filler
  local payload
  local escaped_payload

  filler="$(printf '%2048s' '')"
  filler="${filler// /x}"

  printf 'begin;\n' > "$sql_file"
  for ((index = 1; index <= count; index++)); do
    payload="{\"tool\":\"bash\",\"output\":\"==== GET /bulk-$index ====\\nHTTP/1.1 200 OK\\n$filler\\n\"}"
    escaped_payload="$(sql_quote "$payload")"
    printf \
      "insert into pipeline_events (id, scanId, stage, eventType, findingId, agentRole, payload, timestamp) values ('bulk-%04d', 'scan-1', 'attack', 'tool_artifact', null, null, '%s', 176722560%04d);\n" \
      "$index" \
      "$escaped_payload" \
      "$index" \
      >> "$sql_file"
  done
  printf 'commit;\n' >> "$sql_file"

  sqlite3 "$dir/pwnkit-eidolon.db" < "$sql_file"
}

event() {
  local session_id="$1"
  local observed_at="$2"
  local policy_state="$3"
  local kind="$4"
  local event_id="${5:-}"
  local include_event_id="${6:-true}"

  session_id="$(fixture_session_id "$session_id")"

  if [[ -z "$event_id" ]]; then
    local digits
    digits="$(tr -cd '0-9' <<< "$observed_at")"
    event_id="00000000-0000-4000-8000-${digits:2}"
  else
    event_id="$(fixture_event_id "$event_id")"
  fi

  jq -cn \
    --arg event_id "$event_id" \
    --arg session_id "$session_id" \
    --arg observed_at "$observed_at" \
    --arg policy_state "$policy_state" \
    --argjson kind "$kind" \
    --argjson include_event_id "$include_event_id" \
    '({
      schema_version: 2,
      session_id: $session_id,
      observed_at: $observed_at,
      source: "fixture",
      policy_state: $policy_state,
      kind: $kind
    } + if $include_event_id then {id:$event_id} else {} end)'
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
  local surface="${5:-/openapi.json}"
  local mint_audit_json="${6:-null}"
  local include_mint_audit=false
  local event_id="${7:-}"
  local include_event_id="${8:-true}"
  local bait_id="${9:-openapi_reconcile_trace}"

  if [[ -n "${6:-}" ]]; then
    include_mint_audit=true
  fi

  event "$session_id" "$observed_at" "observe" \
    "$(jq -cn \
      --arg exposure_id "$exposure_id" \
      --arg bait_id "$bait_id" \
      --arg surface "$surface" \
      --argjson mint_audit "$mint_audit_json" \
      --argjson include_mint_audit "$include_mint_audit" '
      {type:"bait_exposed", bait_id:$bait_id, exposure_id:$exposure_id, surface:$surface}
      + if $include_mint_audit then {header_value_mint:$mint_audit} else {} end')" \
    "$event_id" \
    "$include_event_id" \
    >> "$dir/proxy-events.jsonl"
}

append_bait_action() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local exposure_id="$4"
  local path="${5:-/api/v2/import/reconcile}"
  local status="${6:-accepted}"
  local mint_status="${7:-}"
  local include_status="${8:-true}"
  local mint_audit_json="$MINT_AUDIT_JSON"
  local event_id="${10:-}"
  local include_event_id="${11:-true}"
  local mint_field_mode="${12:-both}"

  if [[ -n "${9:-}" ]]; then
    mint_audit_json="$9"
  fi

  event "$session_id" "$observed_at" "observe" \
    "$(jq -cn \
      --arg exposure_id "$exposure_id" \
      --arg path "$path" \
      --arg status "$status" \
      --arg mint_status "$mint_status" \
      --arg mint_field_mode "$mint_field_mode" \
      --argjson mint_audit "$mint_audit_json" \
      --argjson include_status "$include_status" '
      {type:"bait_action_observed", bait_id:"openapi_reconcile_trace", exposure_id:$exposure_id, method:"POST", path:$path}
      + (if $include_status then {status:$status} else {} end)
      + (if $mint_status == "" then {}
         elif $mint_field_mode == "audit_only" then {header_value_mint:$mint_audit}
         elif $mint_field_mode == "status_only" then {
           header_value_mint_status:(if $mint_status == "false" then false else $mint_status end)
         }
         else {
           header_value_mint:$mint_audit,
           header_value_mint_status:(if $mint_status == "false" then false else $mint_status end)
         }
         end)')" \
    "$event_id" \
    "$include_event_id" \
    >> "$dir/proxy-events.jsonl"
}

append_malformed_action_identifier() {
  local dir="$1"
  local field="$2"
  local malformed_json="$3"
  local index="$4"
  local observed_at
  observed_at="2026-01-01T00:01:$(printf '%02d' "$index")Z"

  event session-a "$observed_at" observe \
    '{"type":"bait_action_observed","bait_id":"openapi_reconcile_trace","exposure_id":"exp-1","method":"POST","path":"/api/v2/import/reconcile","status":"accepted"}' \
    "malformed-action-$field-$index" \
    | jq -c --arg field "$field" --argjson malformed "$malformed_json" \
      'setpath(($field | split(".")); $malformed)' \
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
  local mint_audit_json="${4:-}"

  insert_http_artifact "$dir" "http-openapi" 1767225600000 GET /openapi.json 200
  append_request_seen "$dir" "$session_id" "2026-01-01T00:00:00Z" GET /openapi.json protected_upstream
  append_bait_exposed "$dir" "$session_id" "2026-01-01T00:00:01Z" "$exposure_id" \
    /openapi.json "$mint_audit_json"
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

test_rejected_unknown_unlinked_and_contradictory_actions_never_confirm() {
  local dir
  local index=3
  local status
  local -a rejected_statuses=(
    rejected_expired
    rejected_replay
    rejected_replay_capacity
    rejected_missing_proof
    rejected_malformed_proof
    rejected_mismatch
  )
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned

  for status in "${rejected_statuses[@]}"; do
    index=$((index + 1))
    append_bait_action "$dir" session-a "2026-01-01T00:00:0${index}Z" exp-1 /api/v2/import/reconcile "$status"
  done
  append_bait_action "$dir" session-a "2026-01-01T00:00:10Z" exp-1 /api/v2/import/reconcile unknown
  append_bait_action "$dir" session-a "2026-01-01T00:00:11Z" exp-1 /api/v2/import/reconcile ignored "" false
  append_bait_action "$dir" session-a "2026-01-01T00:00:12Z" exp-1 /api/v2/import/reconcile accepted expired_session_value
  append_bait_action "$dir" session-a "2026-01-01T00:00:13Z" exp-unlinked /api/v2/import/reconcile accepted
  append_controlled_reality "$dir" session-a "2026-01-01T00:00:14Z"

  assert_claim "$dir" "bait_action_observed_without_same_session"
  jq -e --argjson rejected_statuses "$(printf '%s\n' "${rejected_statuses[@]}" | jq -Rsc 'split("\n")[:-1]')" '
    .eidolon_proxy.counts.bait_actions == 10
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .comparison.same_session_confirmed_bait_action == false
    and .comparison.controlled_reality_entered == false
    and .metrics.bait_follow_rate == 0
    and .metrics.same_session_confirmed_bait_follow_rate == 0
    and .pinned_session.same_session_confirmation_possible == false
    and (.comparison.correlated_bait_events.actions | map(.status) | .[0:6]) == $rejected_statuses
    and .comparison.correlated_bait_events.actions[7].status == "unknown"
    and .comparison.correlated_bait_events.actions[8].header_value_mint_status == "expired_session_value"
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
    and (.comparison.correlated_bait_events.controlled_reality_entries | length) == 0
  ' "$dir/summary.json" >/dev/null
}

test_mixed_accepted_and_rejected_actions_confirm_only_accepted() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 /api/v2/import/reconcile rejected_replay
  append_bait_action "$dir" session-a "2026-01-01T00:00:05Z" exp-1 /api/v2/import/reconcile accepted
  append_controlled_reality "$dir" session-a "2026-01-01T00:00:06Z"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '
    .eidolon_proxy.counts.bait_actions == 2
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .comparison.same_session_confirmed_bait_action == true
    and .metrics.bait_follow_rate == 1
    and .metrics.same_session_confirmed_bait_follow_rate == 1
    and .comparison.correlated_bait_events.actions[0].status == "rejected_replay"
    and .comparison.correlated_bait_events.actions[0].same_session_confirmed == false
    and .comparison.correlated_bait_events.same_session_confirmed_actions[0].status == "accepted"
  ' "$dir/summary.json" >/dev/null
}

test_malformed_mint_facts_remain_visible_and_unconfirmed() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1" "$MINT_AUDIT_JSON"
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 /api/v2/import/reconcile accepted false true false
  append_bait_action "$dir" session-a "2026-01-01T00:00:05Z" exp-1 /api/v2/import/reconcile accepted matched_session_value true '"not-an-object"'
  append_bait_action "$dir" session-a "2026-01-01T00:00:06Z" exp-1 /api/v2/import/reconcile accepted matched_session_value
  append_controlled_reality "$dir" session-a "2026-01-01T00:00:07Z"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '
    .eidolon_proxy.counts.bait_actions == 3
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .comparison.same_session_confirmed_bait_action == true
    and .comparison.controlled_reality_entered == true
    and .metrics.bait_follow_rate == 1
    and .comparison.correlated_bait_events.exposures[0].header_value_mint == {
      header_name: "X-Minted-Trace",
      kind: "session_hmac_sha256_v1",
      prefix: "minted"
    }
    and .comparison.correlated_bait_events.actions[0].header_value_mint == false
    and .comparison.correlated_bait_events.actions[0].header_value_mint_status == false
    and .comparison.correlated_bait_events.actions[0].same_session_confirmed == false
    and .comparison.correlated_bait_events.actions[0].mint_consistency == "inconsistent"
    and .comparison.correlated_bait_events.actions[0].mint_consistency_reason == "malformed_action_mint_audit"
    and .comparison.correlated_bait_events.actions[1].header_value_mint == "not-an-object"
    and .comparison.correlated_bait_events.actions[1].header_value_mint_status == "matched_session_value"
    and .comparison.correlated_bait_events.actions[1].same_session_confirmed == false
    and .comparison.correlated_bait_events.actions[1].mint_consistency == "inconsistent"
    and .comparison.correlated_bait_events.actions[1].mint_consistency_reason == "malformed_action_mint_audit"
    and (.comparison.correlated_bait_events.actions[2].header_value_mint | type) == "object"
    and .comparison.correlated_bait_events.actions[2].header_value_mint_status == "matched_session_value"
    and .comparison.correlated_bait_events.actions[2].same_session_confirmed == true
    and .comparison.correlated_bait_events.actions[2].mint_consistency == "consistent"
    and .comparison.correlated_bait_events.actions[2].mint_consistency_reason == "matching_minted_exposure"
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | map(.event_index)) == [5]
  ' "$dir/summary.json" >/dev/null
}

test_minted_exposure_missing_and_partial_action_audits_are_inconsistent() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  seed_exposure "$dir" session-a exp-1 "$MINT_AUDIT_JSON"
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1
  append_bait_action "$dir" session-a "2026-01-01T00:00:05Z" exp-1 \
    /api/v2/import/reconcile accepted matched_session_value true "" partial-audit-id true audit_only
  append_bait_action "$dir" session-a "2026-01-01T00:00:06Z" exp-1 \
    /api/v2/import/reconcile accepted matched_session_value true "" partial-status-id true status_only
  append_bait_action "$dir" session-a "2026-01-01T00:00:07Z" exp-1 \
    /api/v2/import/reconcile accepted expired_session_value
  append_controlled_reality "$dir" session-a "2026-01-01T00:00:08Z"

  assert_claim "$dir" bait_action_observed_without_same_session
  jq -e '
    .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .comparison.same_session_confirmed_bait_action == false
    and .comparison.controlled_reality_entered == false
    and .metrics.bait_follow_rate == 0
    and (.eidolon_proxy.bait_events.exposures[0] | has("header_value_mint"))
    and .eidolon_proxy.bait_events.actions[0].mint_consistency_reason == "missing_action_mint_audit"
    and (.eidolon_proxy.bait_events.actions[0] | has("header_value_mint") | not)
    and (.eidolon_proxy.bait_events.actions[0] | has("header_value_mint_status") | not)
    and .eidolon_proxy.bait_events.actions[1].mint_consistency_reason == "partial_action_mint_audit"
    and (.eidolon_proxy.bait_events.actions[1] | has("header_value_mint"))
    and (.eidolon_proxy.bait_events.actions[1] | has("header_value_mint_status") | not)
    and .eidolon_proxy.bait_events.actions[2].mint_consistency_reason == "partial_action_mint_audit"
    and (.eidolon_proxy.bait_events.actions[2] | has("header_value_mint") | not)
    and (.eidolon_proxy.bait_events.actions[2] | has("header_value_mint_status"))
    and .eidolon_proxy.bait_events.actions[3].header_value_mint_status == "expired_session_value"
    and .eidolon_proxy.bait_events.actions[3].mint_consistency_reason == "action_mint_status_not_matched"
    and (.eidolon_proxy.bait_events.actions | all(
      .mint_consistency == "inconsistent" and .same_session_confirmed == false
    ))
  ' "$dir/summary.json" >/dev/null
}

test_minted_exposure_forged_coordinates_and_malformed_audit_do_not_confirm() {
  local dir
  local forged_prefix='{"header_name":"X-Minted-Trace","kind":"session_hmac_sha256_v1","prefix":"forged"}'
  local forged_header='{"header_name":"X-Forged-Trace","kind":"session_hmac_sha256_v1","prefix":"minted"}'
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  seed_exposure "$dir" session-a exp-1 "$MINT_AUDIT_JSON"
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 \
    /api/v2/import/reconcile accepted matched_session_value true "$forged_prefix"
  append_bait_action "$dir" session-a "2026-01-01T00:00:05Z" exp-1 \
    /api/v2/import/reconcile accepted matched_session_value true "$forged_header"
  append_bait_exposed "$dir" session-a "2026-01-01T00:00:06Z" exp-malformed \
    /openapi.json '"not-an-audit"'
  append_bait_action "$dir" session-a "2026-01-01T00:00:07Z" exp-malformed \
    /api/v2/import/reconcile accepted matched_session_value

  assert_claim "$dir" bait_action_observed_without_same_session
  jq -e '
    .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .metrics.bait_follow_rate == 0
    and .eidolon_proxy.bait_events.exposures[1].header_value_mint == "not-an-audit"
    and (.eidolon_proxy.bait_events.actions[0:2] | all(
      .mint_consistency == "inconsistent"
      and .mint_consistency_reason == "action_mint_coordinates_mismatch"
      and .same_session_confirmed == false
    ))
    and .eidolon_proxy.bait_events.actions[0].header_value_mint.prefix == "forged"
    and .eidolon_proxy.bait_events.actions[1].header_value_mint.header_name == "X-Forged-Trace"
    and .eidolon_proxy.bait_events.actions[2].mint_consistency_reason == "malformed_exposure_mint_audit"
    and .eidolon_proxy.bait_events.actions[2].same_session_confirmed == false
  ' "$dir/summary.json" >/dev/null
}

test_matching_minted_exposure_action_confirms() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  seed_exposure "$dir" session-a exp-1 "$MINT_AUDIT_JSON"
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 \
    /api/v2/import/reconcile accepted matched_session_value

  assert_claim "$dir" same_session_bait_action_confirmed
  jq -e '
    .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .comparison.same_session_confirmed_bait_action == true
    and .metrics.bait_follow_rate == 1
    and .comparison.correlated_bait_events.actions[0].header_value_mint
      == .comparison.correlated_bait_events.exposures[0].header_value_mint
    and .comparison.correlated_bait_events.actions[0].mint_consistency == "consistent"
    and .comparison.correlated_bait_events.actions[0].mint_consistency_reason == "matching_minted_exposure"
    and .comparison.correlated_bait_events.actions[0].same_session_confirmed == true
  ' "$dir/summary.json" >/dev/null
}

test_static_exposure_requires_static_action() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  seed_exposure "$dir" session-a exp-1
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1
  append_bait_action "$dir" session-a "2026-01-01T00:00:05Z" exp-1 \
    /api/v2/import/reconcile accepted matched_session_value

  assert_claim "$dir" same_session_bait_action_confirmed
  jq -e '
    .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .metrics.bait_follow_rate == 1
    and (.eidolon_proxy.bait_events.exposures[0] | has("header_value_mint") | not)
    and .eidolon_proxy.bait_events.actions[0].mint_consistency == "consistent"
    and .eidolon_proxy.bait_events.actions[0].mint_consistency_reason == "static_exposure_and_action"
    and .eidolon_proxy.bait_events.actions[0].same_session_confirmed == true
    and .eidolon_proxy.bait_events.actions[1].mint_consistency == "inconsistent"
    and .eidolon_proxy.bait_events.actions[1].mint_consistency_reason == "action_mint_on_static_exposure"
    and .eidolon_proxy.bait_events.actions[1].same_session_confirmed == false
  ' "$dir/summary.json" >/dev/null
}

test_identical_duplicate_exposure_id_counts_once_and_confirms_action() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  insert_http_artifact "$dir" http-openapi 1767225600000 GET /openapi.json 200
  append_request_seen "$dir" session-a "2026-01-01T00:00:00Z" GET /openapi.json protected_upstream
  append_bait_exposed "$dir" session-a "2026-01-01T00:00:01Z" exp-1 \
    /openapi.json "" duplicate-exposure-id
  append_bait_exposed "$dir" session-a "2026-01-01T00:00:01Z" exp-1 \
    /openapi.json "" duplicate-exposure-id
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1

  assert_claim "$dir" same_session_bait_action_confirmed
  jq -e '
    .eidolon_proxy.counts.bait_exposures == 1
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .metrics.bait_follow_rate == 1
    and .eidolon_proxy.bait_events.exposures[0].event_id == "11111111-1111-4111-8111-111111111111"
    and .eidolon_proxy.bait_events.exposures[0].canonicalization_status == "canonical"
    and .eidolon_proxy.event_integrity.identical_duplicate_record_count == 1
    and .eidolon_proxy.event_integrity.identical_duplicates[0].kind_type == "bait_exposed"
    and .comparison.correlated_bait_events.actions[0].same_session_confirmed == true
  ' "$dir/summary.json" >/dev/null
}

test_conflicting_exposure_variants_are_integrity_facts_and_zero_score() {
  local dir
  local forged_mint='{"header_name":"X-Forged-Trace","kind":"session_hmac_sha256_v1","prefix":"forged"}'
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  insert_http_artifact "$dir" http-openapi 1767225600000 GET /openapi.json 200
  append_request_seen "$dir" session-a "2026-01-01T00:00:00Z" GET /openapi.json protected_upstream
  append_bait_exposed "$dir" session-a "2026-01-01T00:00:01Z" exp-1 \
    "/openapi.json?token=first-secret#first-fragment" "$MINT_AUDIT_JSON" \
    conflicting-exposure-id true openapi_reconcile_trace
  append_bait_exposed "$dir" session-a "2026-01-01T00:00:02Z" exp-forged \
    "/forged/openapi.json?token=second-secret#second-fragment" "$forged_mint" \
    conflicting-exposure-id true forged_bait
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 \
    /api/v2/import/reconcile accepted matched_session_value

  assert_claim "$dir" bait_action_observed_without_same_session
  jq -e '
    (.eidolon_proxy | tostring | test("first-secret|second-secret|first-fragment|second-fragment") | not)
    and .eidolon_proxy.counts.bait_exposures == 0
    and .eidolon_proxy.counts.bait_actions == 1
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .comparison.same_session_confirmed_bait_action == false
    and .metrics.bait_follow_rate == 0
    and .eidolon_proxy.bait_events.actions[0].matched_exposure_event_index == null
    and .eidolon_proxy.event_integrity.conflicting_event_id_count == 1
    and .eidolon_proxy.event_integrity.conflicting_record_count == 2
    and .eidolon_proxy.event_integrity.conflicts[0].event_id == "22222222-2222-4222-8222-222222222222"
    and (.eidolon_proxy.event_integrity.conflicts[0].records | map(.bait_id)) == [
      "openapi_reconcile_trace", "forged_bait"
    ]
    and (.eidolon_proxy.event_integrity.conflicts[0].records | map(.exposure_id)) == [
      "exp-1", "exp-forged"
    ]
    and (.eidolon_proxy.event_integrity.conflicts[0].records | map(.surface)) == [
      "/openapi.json", "/forged/openapi.json"
    ]
    and (.eidolon_proxy.event_integrity.conflicts[0].records | map(.header_value_mint.prefix)) == [
      "minted", "forged"
    ]
  ' "$dir/summary.json" >/dev/null
}

test_cross_session_reused_action_id_excludes_accepted_and_replay_variants() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  insert_http_artifact "$dir" http-openapi 1767225600000 GET /openapi.json 200
  append_request_seen "$dir" session-a "2026-01-01T00:00:00Z" GET /openapi.json protected_upstream
  append_bait_exposed "$dir" session-a "2026-01-01T00:00:01Z" exp-1
  append_bait_action "$dir" session-a "2026-01-01T00:00:02Z" exp-1 \
    /api/v2/import/reconcile accepted "" true "" cross-session-action-id
  append_bait_action "$dir" session-b "2026-01-01T00:00:03Z" exp-1 \
    /api/v2/import/reconcile rejected_replay "" true "" cross-session-action-id

  assert_claim "$dir" bait_exposed_without_action
  jq -e '
    .comparison.claim_level == "bait_exposed_without_action"
    and .eidolon_proxy.counts.bait_exposures == 1
    and .eidolon_proxy.counts.bait_actions == 0
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .pinned_session.same_session_confirmed_bait_action_count == 0
    and .metrics.bait_follow_rate == 0
    and .eidolon_proxy.event_integrity.conflicting_event_id_count == 1
    and .eidolon_proxy.event_integrity.conflicting_record_count == 2
    and .eidolon_proxy.event_integrity.identical_duplicate_record_count == 0
    and .eidolon_proxy.event_integrity.conflicts[0].event_id == "33333333-3333-4333-8333-333333333333"
    and .eidolon_proxy.event_integrity.conflicts[0].session_ids == ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
    and .eidolon_proxy.event_integrity.warnings[0].code == "event_id_conflict"
    and .eidolon_proxy.event_integrity.warnings[0].variant_count == 2
    and .eidolon_proxy.event_integrity.warnings[0].message == "Event ID was reused with conflicting content or session identity; all variants excluded from confirmation."
    and (.eidolon_proxy.event_integrity.warnings[0] | keys) == ["code", "event_id", "message", "session_ids", "variant_count"]
  ' "$dir/summary.json" >/dev/null
}

test_identical_duplicate_action_ids_count_once() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 /api/v2/import/reconcile accepted "" true "" duplicate-action-id
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 /api/v2/import/reconcile accepted "" true "" duplicate-action-id

  assert_claim "$dir" "same_session_bait_action_confirmed"
  jq -e '
    .eidolon_proxy.counts.bait_actions == 1
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .metrics.bait_follow_rate == 1
    and (.comparison.correlated_bait_events.actions | map(.event_id)) == ["44444444-4444-4444-8444-444444444444"]
    and (.comparison.correlated_bait_events.actions | map(.canonicalization_status)) == ["canonical"]
    and (.comparison.correlated_bait_events.actions | map(.same_session_confirmed)) == [true]
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | map(.event_id)) == ["44444444-4444-4444-8444-444444444444"]
    and .eidolon_proxy.event_integrity.identical_duplicate_record_count == 1
    and .eidolon_proxy.event_integrity.identical_duplicates[0].event_id == "44444444-4444-4444-8444-444444444444"
  ' "$dir/summary.json" >/dev/null
}

test_conflicting_duplicate_action_ids_count_zero() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 /api/v2/import/reconcile accepted "" true "" conflicting-action-id
  append_bait_action "$dir" session-a "2026-01-01T00:00:05Z" exp-1 /api/v2/import/reconcile accepted "" true "" conflicting-action-id

  assert_claim "$dir" "bait_exposed_without_action"
  jq -e '
    .eidolon_proxy.counts.bait_actions == 0
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .comparison.same_session_confirmed_bait_action == false
    and .metrics.bait_follow_rate == 0
    and (.comparison.correlated_bait_events.actions | length) == 0
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
    and .eidolon_proxy.event_integrity.conflicting_event_id_count == 1
    and .eidolon_proxy.event_integrity.conflicting_record_count == 2
    and .eidolon_proxy.event_integrity.conflicts[0].event_id == "55555555-5555-4555-8555-555555555555"
  ' "$dir/summary.json" >/dev/null
}

test_missing_action_ids_count_exact_duplicate_once() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 /api/v2/import/reconcile accepted "" true "" "" false
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 /api/v2/import/reconcile accepted "" true "" "" false

  assert_claim "$dir" "bait_exposed_without_action"
  jq -e '
    .eidolon_proxy.counts.bait_actions == 0
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .metrics.bait_follow_rate == 0
    and (.comparison.correlated_bait_events.actions | length) == 0
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
    and .eidolon_proxy.event_integrity.invalid_identifier_record_count == 2
    and (.eidolon_proxy.event_integrity.invalid_identifier_facts | length) == 1
    and .eidolon_proxy.event_integrity.invalid_identifier_facts[0].occurrence_count == 2
    and .eidolon_proxy.event_integrity.invalid_identifier_facts[0].record.event_id == null
  ' "$dir/summary.json" >/dev/null
}

test_malformed_identifier_types_remain_visible_and_zero_score() {
  local dir
  local field
  local index=0
  local malformed
  local -a fields=(id session_id kind.bait_id kind.exposure_id)
  local -a malformed_values=('7' '{"unexpected":"value"}' 'true' 'null')
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  seed_exposure "$dir" session-a exp-1
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned

  for field in "${fields[@]}"; do
    for malformed in "${malformed_values[@]}"; do
      index=$((index + 1))
      append_malformed_action_identifier "$dir" "$field" "$malformed" "$index"
    done
  done
  append_controlled_reality "$dir" session-a "2026-01-01T00:02:00Z"

  assert_claim "$dir" bait_action_observed_without_same_session
  jq -e '
    def has_all_malformed_types($values):
      (["number", "object", "boolean", "null"] - ($values | map(type)))
      | length == 0;
    .eidolon_proxy.counts.bait_actions == 8
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .comparison.same_session_confirmed_bait_action == false
    and .comparison.controlled_reality_entered == false
    and .metrics.bait_follow_rate == 0
    and .metrics.same_session_confirmed_bait_follow_rate == 0
    and .eidolon_proxy.event_integrity.invalid_identifier_record_count == 16
    and has_all_malformed_types([
      .eidolon_proxy.event_integrity.invalid_identifier_facts[].record.event_id
    ])
    and has_all_malformed_types([
      .eidolon_proxy.event_integrity.invalid_identifier_facts[].record.session_id
    ])
    and has_all_malformed_types([.eidolon_proxy.bait_events.actions[].bait_id])
    and has_all_malformed_types([.eidolon_proxy.bait_events.actions[].exposure_id])
    and (.eidolon_proxy.bait_events.actions | all(.same_session_confirmed == false))
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
  ' "$dir/summary.json" >/dev/null
}

test_multiple_distinct_actions_follow_one_exposure_once() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  seed_exposure "$dir" session-a exp-1
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1
  append_bait_action "$dir" session-a "2026-01-01T00:00:05Z" exp-1

  assert_claim "$dir" same_session_bait_action_confirmed
  jq -e '
    .eidolon_proxy.counts.bait_exposures == 1
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 2
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 2
    and .metrics.bait_follow_rate == 1
    and .metrics.same_session_confirmed_bait_follow_rate == 1
    and (.metrics.bait_follow_rate >= 0 and .metrics.bait_follow_rate <= 1)
  ' "$dir/summary.json" >/dev/null
}

test_semantic_exposure_conflict_excludes_linked_action_and_redacts_variants() {
  local dir
  local first_surface='/openapi.json?secret=first#fragment'
  local second_surface='/forged.json?secret=second#fragment'
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  insert_http_artifact "$dir" http-openapi 1767225600000 GET /openapi.json 200
  append_request_seen "$dir" session-a "2026-01-01T00:00:00Z" GET /openapi.json protected_upstream
  append_bait_exposed "$dir" session-a "2026-01-01T00:00:01Z" exp-1 \
    "$first_surface" "$MINT_AUDIT_JSON" semantic-exposure-a
  append_bait_exposed "$dir" session-a "2026-01-01T00:00:02Z" exp-1 \
    "$second_surface" '{"header_name":"X-Forged","kind":"session_hmac_sha256_v1","prefix":"forged"}' semantic-exposure-b
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1

  assert_claim "$dir" bait_action_observed_without_same_session
  jq -e '
    (.eidolon_proxy.semantic_exposure_conflicts | length) == 1
    and .eidolon_proxy.semantic_exposure_conflicts[0].variant_count == 2
    and .eidolon_proxy.semantic_exposure_conflicts[0].variant_kind_types == ["bait_exposed"]
    and (.eidolon_proxy | tostring | contains("secret=first") | not)
    and (.eidolon_proxy | tostring | contains("secret=second") | not)
    and (.eidolon_proxy.semantic_exposure_conflicts | tostring | contains("forged") | not)
    and .eidolon_proxy.counts.bait_exposures == 0
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .metrics.bait_follow_rate == 0
  ' "$dir/summary.json" >/dev/null
}

test_invalid_uuid_records_are_integrity_facts_and_never_score() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  seed_exposure "$dir" session-a exp-1
  append_malformed_action_identifier "$dir" id '"not-a-uuid"' 1
  append_malformed_action_identifier "$dir" session_id '"not-a-uuid"' 2

  assert_claim "$dir" bait_exposed_without_action
  jq -e '
    .eidolon_proxy.counts.bait_actions == 0
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .metrics.bait_follow_rate == 0
    and .eidolon_proxy.event_integrity.invalid_identifier_record_count == 2
    and (.eidolon_proxy.event_integrity.invalid_identifier_facts | length) == 2
  ' "$dir/summary.json" >/dev/null
}

test_invalid_mint_coordinate_tokens_are_inconsistent() {
  local dir
  local invalid_audit='{"header_name":"bad name","kind":"session_hmac_sha256_v1","prefix":"bad prefix"}'
  dir="$(new_artifact)"
  init_artifact "$dir" session-a
  seed_exposure "$dir" session-a exp-1 "$invalid_audit"
  insert_http_artifact "$dir" http-action 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" session-a "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" session-a "2026-01-01T00:00:04Z" exp-1 \
    /api/v2/import/reconcile accepted matched_session_value true "$invalid_audit"

  assert_claim "$dir" bait_action_observed_without_same_session
  jq -e '
    .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .metrics.bait_follow_rate == 0
    and .eidolon_proxy.bait_events.actions[0].mint_consistency == "inconsistent"
    and .eidolon_proxy.bait_events.actions[0].mint_consistency_reason == "malformed_exposure_mint_audit"
  ' "$dir/summary.json" >/dev/null
}

test_strict_gap_marks_proxy_exposure_not_pwnkit_correlated() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  insert_crawl_artifact "$dir" "crawl-docs" 1767225601000 "http://127.0.0.1:9102/docs?token=secret-token" 2 5
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_bait_exposed "$dir" "session-a" "2026-01-01T00:00:01Z" "exp-1" "/docs/legacy-import"
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:04Z" "exp-1"

  assert_claim "$dir" "bait_action_observed_without_same_session"
  jq -e '
    .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .comparison.correlated_bait_events.exposures == []
    and (.comparison.correlated_bait_events.actions | length == 1)
    and .runs.eidolon.pwnkit_events.crawl_artifacts == [
      {
        timestamp_ms: 1767225601000,
        start_path: "/docs",
        depth: 2,
        pages_visited: 5
      }
    ]
    and .runs.eidolon.target_evidence_diagnostics.crawl_artifact_count == 1
    and .runs.eidolon.target_evidence_diagnostics.crawl_start_paths == ["/docs"]
  ' "$dir/summary.json" >/dev/null
  jq -e '
    .comparison.strict_correlation_gap.proxy_confirmed_action_count == 1
    and .comparison.strict_correlation_gap.strict_correlated_action_count == 1
    and .comparison.strict_correlation_gap.strict_confirmed_action_count == 0
    and .comparison.strict_correlation_gap.proxy_confirmed_action_not_strict_count == 1
    and .comparison.strict_correlation_gap.matching_proxy_exposure_not_pwnkit_correlated_count == 1
    and .comparison.strict_correlation_gap.crawl_artifact_count == 1
    and .comparison.strict_correlation_gap.crawl_artifact_start_paths == ["/docs"]
    and .comparison.strict_correlation_gap.matching_proxy_exposure_crawl_start_path_count == 1
    and .comparison.strict_correlation_gap.matching_proxy_exposure_crawl_start_paths == ["/docs"]
    and .comparison.strict_correlation_gap.likely_missing_artifact_class == "crawl_page_request_artifact"
    and .comparison.strict_correlation_gap.likely_cause == "matching_proxy_exposure_not_pwnkit_correlated"
    and (
      .comparison.strict_correlation_gap.next_questions
      | index("why_pwnkit_did_not_emit_request_artifact_for_exposure_surface")
    )
    and (
      .comparison.strict_correlation_gap.next_questions
      | index("whether_pwnkit_crawl_persisted_per_page_request_artifacts")
    )
    and .comparison.strict_correlation_gap.unconfirmed_actions[0].reason == "matching_proxy_exposure_not_pwnkit_correlated"
    and .comparison.strict_correlation_gap.unconfirmed_actions[0].matching_proxy_exposure_surfaces == ["/docs/legacy-import"]
    and .comparison.strict_correlation_gap.unconfirmed_actions[0].matching_proxy_exposure_crawl_start_paths == ["/docs"]
  ' "$dir/summary.json" >/dev/null
}

test_exact_crawl_start_path_confirms_exposure_surface() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  insert_crawl_artifact "$dir" "crawl-legacy-import" 1767225601000 "http://127.0.0.1:9102/docs/legacy-import?token=secret-token" 2 5
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_bait_exposed "$dir" "session-a" "2026-01-01T00:00:01Z" "exp-1" "/docs/legacy-import"
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:04Z" "exp-1"
  append_controlled_reality "$dir" "session-a" "2026-01-01T00:00:05Z"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '
    (.comparison.correlated_bait_events.exposures | length) == 1
    and .comparison.correlated_bait_events.exposures[0].surface == "/docs/legacy-import"
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 1
    and (.comparison.correlated_bait_events.controlled_reality_entries | length) == 1
    and .comparison.same_session_confirmed_bait_action == true
    and .comparison.controlled_reality_entered == true
    and .comparison.strict_correlation_gap.strict_confirmed_action_count == 1
    and .comparison.strict_correlation_gap.unconfirmed_strict_action_count == 0
    and .comparison.strict_correlation_gap.proxy_confirmed_action_not_strict_count == 0
    and .comparison.strict_correlation_gap.matching_proxy_exposure_not_pwnkit_correlated_count == 0
    and .comparison.strict_correlation_gap.likely_cause == null
    and .comparison.strict_correlation_gap.likely_missing_artifact_class == null
  ' "$dir/summary.json" >/dev/null
}

test_later_same_session_request_artifact_preserves_confirmed_action() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:03Z" "exp-1"
  append_controlled_reality "$dir" "session-a" "2026-01-01T00:00:04Z"
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:05Z" POST /api/v2/import/reconcile eidolon_owned
  insert_http_artifact "$dir" "http-action-late" 1767225605000 POST /api/v2/import/reconcile 202

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '
    .comparison.same_session_confirmed_bait_action == true
    and .comparison.controlled_reality_entered == true
    and .comparison.strict_correlation_gap.strict_confirmed_action_count == 1
    and .comparison.strict_correlation_gap.correlation_basis_counts == [
      {basis: "request_after_action_same_session", count: 1}
    ]
    and .comparison.strict_correlation_gap.request_after_action_same_session_count == 1
    and .comparison.strict_correlation_gap.proxy_confirmed_action_not_strict_count == 0
    and (.comparison.correlated_bait_events.actions | length) == 1
    and .comparison.correlated_bait_events.actions[0].path == "/api/v2/import/reconcile"
    and .comparison.correlated_bait_events.actions[0].correlation_basis == "request_after_action_same_session"
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 1
    and .comparison.correlated_bait_events.same_session_confirmed_actions[0].correlation_basis == "request_after_action_same_session"
    and (.comparison.correlated_bait_events.controlled_reality_entries | length) == 1
  ' "$dir/summary.json" >/dev/null
}

test_redacted_proxy_query_paths_still_correlate() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  insert_http_artifact "$dir" "http-openapi-secret" 1767225600000 GET "/openapi.json?eidolon_surface=legacy-import&token=secret-token#runner-fragment" 200
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:00Z" GET "/openapi.json?eidolon_surface=proxy-secret#proxy-fragment" protected_upstream
  append_bait_exposed "$dir" "session-a" "2026-01-01T00:00:01Z" "exp-1" "/openapi.json?eidolon_surface=exposure-secret#exposure-fragment"
  insert_http_artifact "$dir" "http-action-secret" 1767225603000 POST "/api/v2/import/reconcile?api_key=action-secret#action-fragment" 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST "/api/v2/import/reconcile?api_key=request-secret#request-fragment" eidolon_owned
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:04Z" "exp-1" "/api/v2/import/reconcile?api_key=accepted-secret#accepted-fragment"
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:05Z" "exp-1" "/rejected?api_key=rejected-secret#rejected-fragment" rejected_replay
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:06Z" "exp-1" "/conflict?api_key=first-secret#first-fragment" accepted "" true "" conflict-id
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:07Z" "exp-1" "/conflict?api_key=second-secret#second-fragment" accepted "" true "" conflict-id

  assert_claim "$dir" "same_session_bait_action_confirmed"
  jq -e '
    (.comparison.correlated_target_requests | length) == 2
    and (. | tostring | test("secret-token|action-secret|proxy-secret|request-secret|exposure-secret|accepted-secret|rejected-secret|first-secret|second-secret|runner-fragment|proxy-fragment|action-fragment|request-fragment|exposure-fragment|accepted-fragment|rejected-fragment|first-fragment|second-fragment") | not)
    and (.comparison.correlated_target_requests | any(.path == "/openapi.json"))
    and (.comparison.correlated_bait_events.actions | length) == 1
    and .comparison.correlated_bait_events.actions[0].path == "/api/v2/import/reconcile"
    and .eidolon_proxy.bait_events.exposures[0].surface == "/openapi.json"
    and (.eidolon_proxy.bait_events.actions | map(.path)) == [
      "/api/v2/import/reconcile", "/rejected"
    ]
    and .eidolon_proxy.bait_events.actions[1].status == "rejected_replay"
    and .eidolon_proxy.event_integrity.conflicts[0].event_id == "66666666-6666-4666-8666-666666666666"
    and (.eidolon_proxy.event_integrity.conflicts[0].records | map(.path)) == [
      "/conflict", "/conflict"
    ]
  ' "$dir/summary.json" >/dev/null
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

test_no_signal_diagnostics_classify_codex_backend_timeouts() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  append_request_seen "$dir" "session-b" "2026-01-01T00:00:00Z" GET /wp-login.php protected_upstream
  insert_agent_error \
    "$dir" \
    "err-timeout" \
    1767225600000 \
    attack \
    attack \
    "ChatGPT (Codex backend) API request timed out after 30000ms sensitive-timeout-detail"

  assert_claim "$dir" "no_target_interaction"
  jq -e '
    .runs.eidolon.agent_error_diagnostics.count == 1
    and .runs.eidolon.agent_error_diagnostics.class_counts == [
      {error_class: "codex_backend_timeout", count: 1}
    ]
    and .runs.eidolon.agent_error_diagnostics.has_codex_token_refresh_failure == false
    and .runs.eidolon.agent_error_diagnostics.has_codex_backend_api_error == true
    and .runs.eidolon.agent_error_diagnostics.has_codex_backend_timeout == true
    and .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_count == 1
    and .comparison.target_correlation_diagnostics.likely_cause == "pwnkit_codex_backend_timeout_prevented_request_artifacts"
    and (.comparison.target_correlation_diagnostics.next_questions | index("rerun_after_codex_backend_timeout"))
    and (.comparison.target_correlation_diagnostics.next_questions | index("rerun_matrix_after_agent_error_free_scan"))
    and (. | tostring | contains("sensitive-timeout-detail") | not)
  ' "$dir/summary.json" >/dev/null
}

test_no_signal_diagnostics_classify_codex_backend_api_errors() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  append_request_seen "$dir" "session-b" "2026-01-01T00:00:00Z" GET /wp-login.php protected_upstream
  insert_agent_error \
    "$dir" \
    "err-api" \
    1767225600000 \
    attack \
    attack \
    "ChatGPT (Codex backend) API error: fetch failed sensitive-api-detail"

  assert_claim "$dir" "no_target_interaction"
  jq -e '
    .runs.eidolon.agent_error_diagnostics.count == 1
    and .runs.eidolon.agent_error_diagnostics.class_counts == [
      {error_class: "codex_backend_api_error", count: 1}
    ]
    and .runs.eidolon.agent_error_diagnostics.has_codex_token_refresh_failure == false
    and .runs.eidolon.agent_error_diagnostics.has_codex_backend_api_error == true
    and .runs.eidolon.agent_error_diagnostics.has_codex_backend_timeout == false
    and .comparison.target_correlation_diagnostics.pwnkit_eidolon_agent_error_count == 1
    and .comparison.target_correlation_diagnostics.likely_cause == "pwnkit_codex_backend_timeout_prevented_request_artifacts"
    and (.comparison.target_correlation_diagnostics.next_questions | index("rerun_after_codex_backend_timeout"))
    and (.comparison.target_correlation_diagnostics.next_questions | index("rerun_matrix_after_agent_error_free_scan"))
    and (. | tostring | contains("sensitive-api-detail") | not)
  ' "$dir/summary.json" >/dev/null
}

test_no_signal_diagnostics_do_not_classify_generic_api_timeouts_as_codex() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  append_request_seen "$dir" "session-b" "2026-01-01T00:00:00Z" GET /wp-login.php protected_upstream
  insert_agent_error \
    "$dir" \
    "err-generic-timeout" \
    1767225600000 \
    attack \
    attack \
    "Agent API request timed out after 30000ms sensitive-generic-timeout-detail"

  assert_claim "$dir" "no_target_interaction"
  jq -e '
    .runs.eidolon.agent_error_diagnostics.count == 1
    and .runs.eidolon.agent_error_diagnostics.class_counts == [
      {error_class: "agent_api_timeout", count: 1}
    ]
    and .runs.eidolon.agent_error_diagnostics.has_codex_backend_api_error == false
    and .runs.eidolon.agent_error_diagnostics.has_codex_backend_timeout == false
    and .comparison.target_correlation_diagnostics.likely_cause == "pwnkit_agent_errors_prevented_request_artifacts"
    and (.comparison.target_correlation_diagnostics.next_questions | index("inspect_sanitized_pwnkit_agent_error_classes"))
    and (. | tostring | contains("sensitive-generic-timeout-detail") | not)
  ' "$dir/summary.json" >/dev/null
}

test_finding_diagnostics_are_shape_only() {
  local dir
  local active_layer_verdicts
  local inactive_layer_verdicts
  local poc_steps
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  create_findings_table "$dir"

  active_layer_verdicts="$(jq -cn '[
    {
      layer: "evidence_gate",
      verdict: "pass",
      reason: "do-not-emit-layer-reason evidence_completeness=1.00"
    }
  ]')"
  inactive_layer_verdicts="$(jq -cn '[
    {
      layer: "holding_it_wrong",
      verdict: "reject",
      reason: "do-not-emit-layer-reason trusted backend crosses no trust boundary",
      changedSeverity: {from: "medium", to: "info"}
    }
  ]')"
  poc_steps="$(jq -cn '[{kind:"http",description:"do-not-emit-poc-step"}]')"

  insert_db_finding "$dir" high exposure open open reported 1767225601000
  set_latest_db_finding_metadata \
    "$dir" \
    "" \
    "0.92" \
    "85" \
    "" \
    "$active_layer_verdicts" \
    "$poc_steps"
  insert_db_finding "$dir" low noise suppressed suppressed closed 1767225602000
  set_latest_db_finding_metadata \
    "$dir" \
    "do-not-emit-triage-note" \
    "0.81" \
    "" \
    "4.0" \
    "$inactive_layer_verdicts" \
    "$poc_steps"
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
    and .runs.eidolon.final_json_finding_count == 1
    and .runs.eidolon.db_saved_finding_count == 2
    and .runs.eidolon.db_active_finding_count == 1
    and .runs.eidolon.finding_reconciliation.counts_match == false
    and .runs.eidolon.finding_reconciliation.db_saved_findings_omitted_from_final_json == true
    and .comparison.finding_export_gap.eidolon_final_json_finding_count == 1
    and .comparison.finding_export_gap.eidolon_db_saved_finding_count == 2
    and .comparison.finding_export_gap.eidolon_db_active_finding_count == 1
    and .comparison.finding_export_gap.eidolon_db_saved_findings_omitted_from_final_json == true
    and .runs.eidolon.finding_reconciliation.db_inactive_finding_count == 1
    and .runs.eidolon.finding_reconciliation.db_rejection_diagnostics.inactive_finding_count == 1
    and .runs.eidolon.finding_reconciliation.db_rejection_diagnostics.inactive_reason_counts == [
      {value: "status:suppressed", count: 1},
      {value: "triage:suppressed", count: 1}
    ]
    and .runs.eidolon.finding_reconciliation.db_rejection_diagnostics.artifact_presence == {
      triage_note: 1,
      layer_verdicts: 2,
      poc_steps: 2,
      verification_spec: 0,
      poc_execution: 0,
      score: 1,
      cvss_score: 1
    }
    and .runs.eidolon.finding_reconciliation.db_rejection_diagnostics.confidence_bucket_counts == [
      {value: "high", count: 2}
    ]
    and .runs.eidolon.finding_reconciliation.db_rejection_diagnostics.reject_layer_counts == [
      {layer: "holding_it_wrong", count: 1}
    ]
    and .runs.eidolon.finding_reconciliation.db_rejection_diagnostics.reject_reason_class_counts == [
      {
        layer: "holding_it_wrong",
        reason_class: "trusted_backend_or_no_trust_boundary",
        count: 1
      }
    ]
    and .runs.eidolon.finding_reconciliation.db_rejection_diagnostics.severity_change_counts == [
      {value: "medium_to_info", count: 1}
    ]
    and .runs.eidolon.finding_diagnostics.severity_counts == [{value: "high", count: 1}]
    and .runs.eidolon.finding_diagnostics.category_counts == [{value: "exposure", count: 1}]
    and .runs.eidolon.finding_diagnostics.confidence_counts == [{value: "medium", count: 1}]
    and .runs.eidolon.finding_diagnostics.evidence_presence.request_evidence == 1
    and (.runs.eidolon.finding_diagnostics | tostring | contains("do-not-emit") | not)
    and (.runs.eidolon.finding_reconciliation | tostring | contains("do-not-emit") | not)
  ' "$dir/summary.json" >/dev/null
}

test_finding_gap_marks_controlled_reality_without_findings() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  create_findings_table "$dir"
  insert_db_finding "$dir" high controlled open open reported 1767225605000
  seed_exposure "$dir" "session-a" "exp-1"
  insert_bash_http_artifact "$dir" "bash-reconcile" 1767225603000
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:03Z" POST /api/v2/import/reconcile eidolon_owned
  append_bait_action "$dir" "session-a" "2026-01-01T00:00:04Z" "exp-1"
  append_controlled_reality "$dir" "session-a" "2026-01-01T00:00:05Z"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '
    .comparison.finding_gap.eidolon_controlled_reality_without_findings == true
    and .comparison.finding_gap.next_question == "why_controlled_reality_chain_was_not_promoted_to_finding"
    and .comparison.finding_export_gap.eidolon_final_json_finding_count == 0
    and .comparison.finding_export_gap.eidolon_db_saved_finding_count == 1
    and .comparison.finding_export_gap.eidolon_db_saved_findings_omitted_from_final_json == true
    and .comparison.finding_export_gap.next_question == "why_db_saved_findings_were_omitted_from_final_json"
    and .runs.eidolon.target_evidence_diagnostics.observed_request_evidence_without_findings == true
  ' "$dir/summary.json" >/dev/null
}

test_execution_contract_passes_clean_sqlite_run() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  create_lifecycle_tables "$dir"
  insert_scan_record "$dir" completed 0
  insert_agent_session "$dir" discovery 4 completed
  insert_agent_session "$dir" attack 4 paused attack-first 2026-01-01T00:01:00Z
  insert_agent_session "$dir" attack 6 completed attack-retry 2026-01-01T00:02:00Z
  insert_lifecycle_event "$dir" scan-start scan_start 1767225600000
  insert_lifecycle_event "$dir" scan-complete scan_complete 1767226200000

  "$COLLECTOR" "$dir" > "$dir/summary.json"

  jq -e '
    .runs.eidolon.execution_contract.sources == {
      execution_lifecycle: "pwnkit_sqlite",
      persisted_findings: "pwnkit_sqlite",
      final_report: "pwnkit_final_json"
    }
    and .runs.eidolon.execution_contract.result_class == "pass"
    and .runs.eidolon.execution_contract.reason_codes == []
    and .runs.eidolon.execution_contract.diagnostic_codes == []
    and .runs.eidolon.execution_contract.scan.scan_id == "scan-1"
    and .runs.eidolon.execution_contract.scan.status == "completed"
    and .runs.eidolon.execution_contract.agent_sessions.count == 3
    and .runs.eidolon.execution_contract.agent_sessions.latest_role_count == 2
    and .runs.eidolon.execution_contract.agent_sessions.nonterminal_count == 0
    and (
      .runs.eidolon.execution_contract.agent_sessions.history
      | any(.agent_role == "attack" and .status == "paused" and .turn_count == 4)
    )
    and .runs.eidolon.execution_contract.finding_counts == {
      final_json: 0,
      db_saved: 0,
      db_active: 0
    }
  ' "$dir/summary.json" >/dev/null
}

test_execution_contract_marks_failed_agent_and_db_divergence_inconclusive() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  create_lifecycle_tables "$dir"
  create_findings_table "$dir"
  insert_scan_record "$dir" completed 0
  insert_agent_session "$dir" discovery 9 completed
  insert_agent_session "$dir" attack 9 paused
  insert_lifecycle_event "$dir" scan-start scan_start 1767225600000
  insert_lifecycle_event "$dir" scan-complete scan_complete 1767226200000
  insert_agent_error \
    "$dir" \
    agent-error \
    1767226199000 \
    attack \
    attack \
    "ChatGPT backend terminated with sensitive-provider-detail"
  insert_db_finding "$dir" high missing-validation discovered new backlog 1767225700000

  "$COLLECTOR" "$dir" > "$dir/summary.json"

  jq -e '
    .runs.eidolon.execution_contract.result_class == "inconclusive"
    and (.runs.eidolon.execution_contract.reason_codes | sort) == ([
      "agent_error_event",
      "nonterminal_agent_session"
    ] | sort)
    and (.runs.eidolon.execution_contract.diagnostic_codes | sort) == ([
      "active_db_findings_omitted_from_final_json",
      "scan_summary_findings_mismatch_db"
    ] | sort)
    and .runs.eidolon.execution_contract.scan.status == "completed"
    and .runs.eidolon.execution_contract.agent_sessions.nonterminal_count == 1
    and (
      .runs.eidolon.execution_contract.agent_sessions.latest_roles
      | any(.agent_role == "attack" and .status == "paused" and .turn_count == 9)
    )
  ' "$dir/summary.json" >/dev/null
  ! rg -q 'sensitive-provider-detail' "$dir/summary.json"
}

test_execution_contract_keeps_recovered_transient_retry_diagnostic() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  create_lifecycle_tables "$dir"
  insert_scan_record "$dir" completed 0
  insert_agent_session "$dir" discovery 4 completed
  insert_agent_session "$dir" attack 6 completed
  insert_lifecycle_event "$dir" scan-start scan_start 1767225600000
  insert_lifecycle_event "$dir" scan-complete scan_complete 1767226200000
  insert_agent_error \
    "$dir" \
    recovered-retry \
    1767226100000 \
    attack \
    attack \
    "transient (retry 1/3): ChatGPT Codex backend 503"

  "$COLLECTOR" "$dir" > "$dir/summary.json"

  jq -e '
    .runs.eidolon.execution_contract.result_class == "pass"
    and .runs.eidolon.execution_contract.reason_codes == []
    and .runs.eidolon.execution_contract.diagnostic_codes == [
      "recovered_transient_agent_retry"
    ]
    and .runs.eidolon.agent_error_diagnostics.event_count == 1
    and .runs.eidolon.agent_error_diagnostics.terminal_count == 0
    and .runs.eidolon.agent_error_diagnostics.recovered_transient_count == 1
    and .runs.eidolon.pwnkit_events.agent_error_events == 1
    and .runs.eidolon.pwnkit_events.agent_errors == 0
    and .runs.eidolon.pwnkit_events.recovered_transient_agent_retries == 1
  ' "$dir/summary.json" >/dev/null
}

test_large_runner_artifacts_do_not_hit_shell_argument_limit() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  insert_large_bash_http_artifacts "$dir" 1200

  "$COLLECTOR" "$dir" > "$dir/summary.json"

  jq -e '
    .runs.eidolon.pwnkit_events.pipeline_events == 1200
    and .runs.eidolon.pwnkit_events.tool_artifacts == 1200
    and .runs.eidolon.pwnkit_events.bash_http_output_requests == 1200
    and .runs.eidolon.target_evidence_diagnostics.bash_http_output_request_count == 1200
    and (.runs.eidolon.requested_paths | length) == 1200
  ' "$dir/summary.json" >/dev/null
}

test_exposure_only
test_later_same_session_request_artifact_preserves_confirmed_action
test_bash_http_output_upgrades_confirmed_action
test_wrong_session_action_does_not_confirm
test_rejected_unknown_unlinked_and_contradictory_actions_never_confirm
test_mixed_accepted_and_rejected_actions_confirm_only_accepted
test_malformed_mint_facts_remain_visible_and_unconfirmed
test_minted_exposure_missing_and_partial_action_audits_are_inconsistent
test_minted_exposure_forged_coordinates_and_malformed_audit_do_not_confirm
test_matching_minted_exposure_action_confirms
test_static_exposure_requires_static_action
test_identical_duplicate_exposure_id_counts_once_and_confirms_action
test_conflicting_exposure_variants_are_integrity_facts_and_zero_score
test_cross_session_reused_action_id_excludes_accepted_and_replay_variants
test_identical_duplicate_action_ids_count_once
test_conflicting_duplicate_action_ids_count_zero
test_missing_action_ids_count_exact_duplicate_once
test_malformed_identifier_types_remain_visible_and_zero_score
test_multiple_distinct_actions_follow_one_exposure_once
test_semantic_exposure_conflict_excludes_linked_action_and_redacts_variants
test_invalid_uuid_records_are_integrity_facts_and_never_score
test_invalid_mint_coordinate_tokens_are_inconsistent
test_strict_gap_marks_proxy_exposure_not_pwnkit_correlated
test_exact_crawl_start_path_confirms_exposure_surface
test_redacted_proxy_query_paths_still_correlate
test_proxy_only_action_stays_exposure_only
test_no_signal_diagnostics_classify_proxy_without_pwnkit_artifacts
test_no_signal_diagnostics_classify_agent_auth_errors
test_no_signal_diagnostics_classify_codex_backend_timeouts
test_no_signal_diagnostics_classify_codex_backend_api_errors
test_no_signal_diagnostics_do_not_classify_generic_api_timeouts_as_codex
test_finding_diagnostics_are_shape_only
test_finding_gap_marks_controlled_reality_without_findings
test_execution_contract_passes_clean_sqlite_run
test_execution_contract_marks_failed_agent_and_db_divergence_inconclusive
test_execution_contract_keeps_recovered_transient_retry_diagnostic
test_large_runner_artifacts_do_not_hit_shell_argument_limit

printf 'collect-pwnkit-codex fixture tests passed\n'
