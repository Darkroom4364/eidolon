#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
COLLECTOR="$SCRIPT_DIR/collect-pwnkit-codex.sh"

new_artifact() {
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-collector-test.XXXXXX")"
  printf '%s\n' "$dir"
}

sha256_file() {
  local path="$1"
  local output

  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum "$path")"
  else
    output="$(shasum -a 256 "$path")"
  fi

  printf '%s' "${output%% *}"
}

sha256_jsonl() {
  local path="$1"
  local output

  if command -v sha256sum >/dev/null 2>&1; then
    output="$(jq -cS '.' "$path" | sha256sum)"
  else
    output="$(jq -cS '.' "$path" | shasum -a 256)"
  fi

  printf '%s' "${output%% *}"
}

write_docs_profile_provenance() {
  local dir="$1"
  local execution_id="$2"
  local profile="$dir/private/bait-profile.json"
  local profile_sha256

  mkdir -p "$dir/private"
  jq -n '{
    schema_version: 1,
    profile_id: "docs_session_minted_probe",
    baits: [{
      id: "rel_2025_04_b7f2",
      bait_class: "docs",
      surface: "/docs/legacy-import",
      surface_kind: "docs",
      expected_action: {
        method: "POST",
        path: "/api/v2/import/reconcile",
        header_name: "X-Migration-Trace",
        header_value_mint: {
          kind: "session_hmac_sha256_v1",
          prefix: "mig",
          proof_window_seconds: 300
        }
      }
    }]
  }' > "$profile"
  profile_sha256="$(sha256_file "$profile")"

  jq --arg sha256 "$profile_sha256" '{
    schema_version: 1,
    profile_id: .profile_id,
    sha256: $sha256,
    baits: [
      .baits[]
      | {
          bait_id: .id,
          bait_class: .bait_class
        }
    ]
  }' "$profile" > "$dir/bait-profile-metadata.json"

  jq -n \
    --arg execution_id "$execution_id" \
    --arg profile_sha256 "$profile_sha256" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_sample_run",
      execution_id: $execution_id,
      profile_sha256: $profile_sha256
    }' > "$dir/sample-run-metadata.json"
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

insert_bash_http_path_artifact() {
  local dir="$1"
  local id="$2"
  local timestamp_ms="$3"
  local method="$4"
  local path="$5"
  local output
  local payload

  output="$(printf '==== %s %s ====\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' "$method" "$path")"
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
  local request_id="$5"

  jq -cn \
    --arg session_id "$session_id" \
    --arg observed_at "$observed_at" \
    --arg policy_state "$policy_state" \
    --arg request_id "$request_id" \
    --argjson kind "$kind" \
    '{
      schema_version: 2,
      id: ("evt-" + ($observed_at | gsub("[^0-9]"; ""))),
      session_id: $session_id,
      observed_at: $observed_at,
      source: "fixture",
      policy_state: $policy_state,
      kind: $kind
    }
    + (
      if $request_id == "" then {}
      else {request_id: $request_id}
      end
    )'
}

append_request_seen() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local method="$4"
  local path="$5"
  local routing_decision="$6"
  local request_id="${7:-}"
  if [[ -z "$request_id" ]]; then
    if [[ "$method" == "POST" ]]; then
      request_id="00000000-0000-4000-8000-000000000002"
    else
      request_id="00000000-0000-4000-8000-000000000001"
    fi
  fi

  event "$session_id" "$observed_at" "observe" \
    "$(jq -cn \
      --arg method "$method" \
      --arg path "$path" \
      --arg routing_decision "$routing_decision" \
      '{type:"request_seen", method:$method, path:$path, routing_decision:$routing_decision}')" \
    "$request_id" \
    >> "$dir/proxy-events.jsonl"
}

append_bait_exposed() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local exposure_id="$4"
  local surface="${5:-/openapi.json}"
  local request_id="${6:-00000000-0000-4000-8000-000000000001}"
  local bait_id="${7:-openapi_reconcile_trace}"
  local bait_class="${8:-open_api}"
  local mint_prefix="${9:-}"

  event "$session_id" "$observed_at" "observe" \
    "$(jq -cn \
      --arg exposure_id "$exposure_id" \
      --arg surface "$surface" \
      --arg bait_id "$bait_id" \
      --arg bait_class "$bait_class" \
      --arg mint_prefix "$mint_prefix" \
      '{
        type: "bait_exposed",
        bait_id: $bait_id,
        bait_class: $bait_class,
        exposure_id: $exposure_id,
        surface: $surface
      }
      + (
        if $mint_prefix == "" then {}
        else {
          header_value_mint: {
            header_name: "X-Migration-Trace",
            kind: "session_hmac_sha256_v1",
            prefix: $mint_prefix
          }
        }
        end
      )')" \
    "$request_id" \
    >> "$dir/proxy-events.jsonl"
}

append_bait_action() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local exposure_id="$4"
  local path="${5:-/api/v2/import/reconcile}"
  local request_id="${6:-00000000-0000-4000-8000-000000000002}"
  local bait_id="${7:-openapi_reconcile_trace}"
  local bait_class="${8:-open_api}"

  event "$session_id" "$observed_at" "observe" \
    "$(jq -cn \
      --arg exposure_id "$exposure_id" \
      --arg path "$path" \
      --arg bait_id "$bait_id" \
      --arg bait_class "$bait_class" \
      '{
        type: "bait_action_observed",
        bait_id: $bait_id,
        bait_class: $bait_class,
        exposure_id: $exposure_id,
        method: "POST",
        path: $path
      }')" \
    "$request_id" \
    >> "$dir/proxy-events.jsonl"
}

append_minted_bait_action() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local exposure_id="$4"
  local request_id="$5"
  local mint_status="${6:-}"
  local bait_id="${7:-openapi_reconcile_trace}"
  local prefix="${8:-minted}"
  local bait_class="${9:-open_api}"
  local kind

  kind="$(jq -cn \
    --arg exposure_id "$exposure_id" \
    --arg mint_status "$mint_status" \
    --arg bait_id "$bait_id" \
    --arg bait_class "$bait_class" \
    --arg prefix "$prefix" \
    '{
      type: "bait_action_observed",
      bait_id: $bait_id,
      bait_class: $bait_class,
      exposure_id: $exposure_id,
      method: "POST",
      path: "/api/v2/import/reconcile",
      header_value_mint: {
        header_name: "X-Migration-Trace",
        kind: "session_hmac_sha256_v1",
        prefix: $prefix
      }
    }
    + (
      if $mint_status == "" then {}
      else {header_value_mint_status: $mint_status}
      end
    )')"

  event "$session_id" "$observed_at" "observe" "$kind" "$request_id" \
    >> "$dir/proxy-events.jsonl"
}

append_controlled_reality() {
  local dir="$1"
  local session_id="$2"
  local observed_at="$3"
  local request_id="${4:-00000000-0000-4000-8000-000000000002}"

  event "$session_id" "$observed_at" "controlled_reality" \
    "$(jq -cn '{type:"controlled_reality_entered", reason:"confirmed bait-derived action moved session into controlled reality"}')" \
    "$request_id" \
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

assert_collector_fails_with() {
  local dir="$1"
  local pattern="$2"
  local output
  local status=0

  output="$("$COLLECTOR" "$dir" 2>&1)" || status="$?"
  [[ "$status" -eq 2 ]]
  rg -q "$pattern" <<<"$output"
}

test_exposure_only() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"

  assert_claim "$dir" "bait_exposed_without_action"
  jq -e '
    .execution_id == null
    and (
      .comparison.correlated_bait_events.matrix[0]
      | .bait_class == "open_api"
      and .profile_id == null
      and .profile_sha256 == null
    )
  ' "$dir/summary.json" >/dev/null
}

test_public_metadata_without_private_profile_does_not_bind_profile() {
  local dir

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-public-only
  mv "$dir/private/bait-profile.json" "$dir/private/bait-profile.unavailable"
  insert_http_artifact \
    "$dir" "http-docs" 1767225600000 GET /docs/legacy-import 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:00Z" \
    GET /docs/legacy-import protected_upstream
  append_bait_exposed \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    exp-docs /docs/legacy-import \
    00000000-0000-4000-8000-000000000001 rel_2025_04_b7f2 docs

  assert_claim "$dir" "bait_exposed_without_action"
  jq -e '
    .execution_id == "execution-public-only"
    and (
      .comparison.correlated_bait_events.matrix[0]
      | .bait_class == "docs"
      and .profile_id == null
      and .profile_sha256 == null
    )
  ' "$dir/summary.json" >/dev/null
}

test_observed_class_must_match_private_profile_pair() {
  local dir

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-wrong-class
  insert_http_artifact \
    "$dir" "http-docs" 1767225600000 GET /docs/legacy-import 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:00Z" \
    GET /docs/legacy-import protected_upstream
  append_bait_exposed \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    exp-docs /docs/legacy-import \
    00000000-0000-4000-8000-000000000001 rel_2025_04_b7f2 open_api

  assert_claim "$dir" "bait_exposed_without_action"
  jq -e '
    .comparison.correlated_bait_events.matrix[0]
    | .bait_id == "rel_2025_04_b7f2"
      and .bait_class == "open_api"
      and .profile_id == null
      and .profile_sha256 == null
  ' "$dir/summary.json" >/dev/null
}

test_profile_provenance_mismatches_fail() {
  local dir
  local tmp

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-public-mismatch
  tmp="$dir/bait-profile-metadata.json.tmp"
  jq '
    .sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  ' "$dir/bait-profile-metadata.json" > "$tmp"
  mv "$tmp" "$dir/bait-profile-metadata.json"
  assert_collector_fails_with "$dir" 'public bait profile metadata does not match'

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-run-mismatch
  tmp="$dir/sample-run-metadata.json.tmp"
  jq '
    .profile_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  ' "$dir/sample-run-metadata.json" > "$tmp"
  mv "$tmp" "$dir/sample-run-metadata.json"
  assert_collector_fails_with "$dir" 'sample run metadata bait profile digest does not match'

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-malformed-profile
  printf '{malformed\n' > "$dir/private/bait-profile.json"
  assert_collector_fails_with "$dir" 'malformed private bait profile'
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

test_strict_gap_marks_proxy_exposure_not_pwnkit_correlated() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  insert_crawl_artifact "$dir" "crawl-docs" 1767225601000 "http://127.0.0.1:9102/docs" 2 5
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:01Z" GET /docs/legacy-import protected_upstream
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
        artifact_seq: 1,
        timestamp_ms: 1767225601000,
        start_path: "/docs",
        query_present: false,
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
  insert_crawl_artifact "$dir" "crawl-legacy-import" 1767225601000 "http://127.0.0.1:9102/docs/legacy-import" 2 5
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen "$dir" "session-a" "2026-01-01T00:00:01Z" GET /docs/legacy-import protected_upstream
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

test_later_same_session_request_does_not_reconstruct_action_causality() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:03Z" \
    POST /api/v2/import/reconcile eidolon_owned \
    "00000000-0000-4000-8000-000000000003"
  append_bait_action \
    "$dir" "session-a" "2026-01-01T00:00:03Z" "exp-1" \
    /api/v2/import/reconcile "00000000-0000-4000-8000-000000000003"
  append_controlled_reality \
    "$dir" "session-a" "2026-01-01T00:00:04Z" \
    "00000000-0000-4000-8000-000000000003"
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:05Z" \
    POST /api/v2/import/reconcile eidolon_owned \
    "00000000-0000-4000-8000-000000000004"
  insert_http_artifact "$dir" "http-action-late" 1767225605000 POST /api/v2/import/reconcile 202

  assert_claim "$dir" "bait_exposed_without_action"
  jq -e '
    .comparison.same_session_confirmed_bait_action == false
    and .comparison.controlled_reality_entered == false
    and .comparison.strict_correlation_gap.strict_confirmed_action_count == 0
    and .comparison.strict_correlation_gap.correlation_basis_counts == []
    and .comparison.strict_correlation_gap.request_id_count == 0
    and .comparison.strict_correlation_gap.request_after_action_same_session_count == 0
    and .comparison.strict_correlation_gap.proxy_confirmed_action_not_strict_count == 1
    and (.comparison.correlated_bait_events.actions | length) == 0
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
    and (.comparison.correlated_bait_events.controlled_reality_entries | length) == 0
  ' "$dir/summary.json" >/dev/null
}

test_redacted_query_paths_do_not_create_false_correlation() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  insert_http_artifact "$dir" "http-openapi-secret" 1767225600000 GET "/openapi.json?eidolon_surface=legacy-import&token=secret-token" 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:00Z" \
    GET "/openapi.json?<redacted>" protected_upstream \
    "00000000-0000-4000-8000-000000000010"
  append_bait_exposed \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    "exp-1" "/openapi.json" "00000000-0000-4000-8000-000000000010"
  insert_http_artifact "$dir" "http-flag-secret" 1767225602000 GET "/docs?sk_live_secret=x" 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:02Z" \
    GET "/docs?<redacted>" protected_upstream \
    "00000000-0000-4000-8000-000000000011"
  insert_bash_http_path_artifact "$dir" "bash-flag-secret" 1767225602500 GET "/docs?bash_secret_key=x"
  insert_http_artifact "$dir" "http-action-secret" 1767225603000 POST "/api/v2/import/reconcile?api_key=action-secret" 202
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:03Z" \
    POST "/api/v2/import/reconcile?<redacted>" eidolon_owned \
    "00000000-0000-4000-8000-000000000012"
  append_bait_action \
    "$dir" "session-a" "2026-01-01T00:00:04Z" \
    "exp-1" "/api/v2/import/reconcile" \
    "00000000-0000-4000-8000-000000000012"

  assert_claim "$dir" "no_target_interaction"
  jq -e '
    (.runs.eidolon.requested_paths | length) == 4
    and all(
      .runs.eidolon.requested_paths[];
      .query_present == true and (.path | endswith("?<redacted>"))
    )
    and (.runs.eidolon.requested_paths | any(.evidence_label == "GET /docs?<redacted>"))
    and (.eidolon_proxy.request_paths | length) == 3
    and all(
      .eidolon_proxy.request_paths[];
      .query_present == true and (.path | endswith("?<redacted>"))
    )
    and .eidolon_proxy.bait_events.exposures[0].query_present == true
    and .eidolon_proxy.bait_events.actions[0].query_present == true
    and .eidolon_proxy.bait_events.actions[0].request_id == "00000000-0000-4000-8000-000000000012"
    and (.comparison.correlated_target_requests | length) == 0
    and (.comparison.correlated_bait_events.actions | length) == 0
    and .comparison.same_session_confirmed_bait_action == false
    and (tostring | contains("secret-token") | not)
    and (tostring | contains("action-secret") | not)
    and (tostring | contains("sk_live_secret") | not)
    and (tostring | contains("bash_secret_key") | not)
  ' "$dir/summary.json" >/dev/null
}

test_ambiguous_concurrent_proxy_requests_do_not_cross_pair() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  insert_http_artifact "$dir" "http-docs" 1767225601000 GET /docs 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    GET /docs protected_upstream \
    "00000000-0000-4000-8000-000000000030"
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:02Z" \
    GET /docs protected_upstream \
    "00000000-0000-4000-8000-000000000031"

  assert_claim "$dir" "no_target_interaction"
  jq -e '
    (.comparison.correlated_target_requests | length) == 0
    and .comparison.target_interaction_observed == false
    and .comparison.target_correlation_diagnostics.eidolon_proxy_request_count == 2
    and .comparison.target_correlation_diagnostics.correlated_target_request_count == 0
  ' "$dir/summary.json" >/dev/null
}

test_ambiguous_crawl_artifact_does_not_confirm_concurrent_exposures() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  insert_crawl_artifact \
    "$dir" "crawl-shared" 1767225601000 \
    "http://127.0.0.1:9102/docs/legacy-import" 2 5
  insert_http_artifact "$dir" "http-action" 1767225603000 POST /api/v2/import/reconcile 202
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    GET /docs/legacy-import protected_upstream \
    "00000000-0000-4000-8000-000000000040"
  append_bait_exposed \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    "exp-a" /docs/legacy-import \
    "00000000-0000-4000-8000-000000000040"
  append_request_seen \
    "$dir" "session-b" "2026-01-01T00:00:02Z" \
    GET /docs/legacy-import protected_upstream \
    "00000000-0000-4000-8000-000000000041"
  append_bait_exposed \
    "$dir" "session-b" "2026-01-01T00:00:02Z" \
    "exp-b" /docs/legacy-import \
    "00000000-0000-4000-8000-000000000041"
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:03Z" \
    POST /api/v2/import/reconcile eidolon_owned \
    "00000000-0000-4000-8000-000000000042"
  append_bait_action \
    "$dir" "session-a" "2026-01-01T00:00:04Z" \
    "exp-a" /api/v2/import/reconcile \
    "00000000-0000-4000-8000-000000000042"
  append_controlled_reality \
    "$dir" "session-a" "2026-01-01T00:00:05Z" \
    "00000000-0000-4000-8000-000000000042"

  assert_claim "$dir" "bait_action_observed_without_same_session"
  jq -e '
    (.comparison.correlated_bait_events.exposures | length) == 0
    and (.comparison.correlated_bait_events.actions | length) == 1
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
    and (.comparison.correlated_bait_events.controlled_reality_entries | length) == 0
    and .comparison.same_session_confirmed_bait_action == false
    and .comparison.controlled_reality_entered == false
  ' "$dir/summary.json" >/dev/null
}

test_missing_request_ids_remain_visible_but_unlinked() {
  local dir
  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  seed_exposure "$dir" "session-a" "exp-1"
  insert_http_artifact "$dir" "http-legacy-action" 1767225603000 POST /api/v2/import/reconcile 202
  event \
    "session-a" "2026-01-01T00:00:03Z" observe \
    "$(jq -cn '{
      type: "request_seen",
      method: "POST",
      path: "/api/v2/import/reconcile",
      routing_decision: "eidolon_owned"
    }')" \
    "" >> "$dir/proxy-events.jsonl"
  event \
    "session-a" "2026-01-01T00:00:04Z" observe \
    "$(jq -cn '{
      type: "bait_action_observed",
      bait_id: "openapi_reconcile_trace",
      exposure_id: "exp-1",
      method: "POST",
      path: "/api/v2/import/reconcile"
    }')" \
    "" >> "$dir/proxy-events.jsonl"

  assert_claim "$dir" "bait_exposed_without_action"
  jq -e '
    .eidolon_proxy.bait_events.actions[0].request_id == null
    and .eidolon_proxy.bait_events.actions[0].query_present == null
    and .eidolon_proxy.bait_events.actions[0].same_session_confirmed == false
    and (.comparison.correlated_bait_events.actions | length) == 0
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
  ' "$dir/summary.json" >/dev/null
}

test_rejected_minted_proof_remains_visible_but_unconfirmed() {
  local dir
  local request_id="00000000-0000-4000-8000-000000000020"
  local mint_status

  for mint_status in \
    expired_session_value \
    replay_seen \
    replay_state_capacity_exceeded \
    replay_state_unavailable \
    missing_session_value \
    malformed_session_value \
    session_value_mismatch; do
    dir="$(new_artifact)"
    init_artifact "$dir" "session-a"
    seed_exposure "$dir" "session-a" "exp-1"
    insert_http_artifact "$dir" "http-rejected-action" 1767225603000 POST /api/v2/import/reconcile 403
    append_request_seen \
      "$dir" "session-a" "2026-01-01T00:00:03Z" \
      POST /api/v2/import/reconcile eidolon_owned "$request_id"
    append_minted_bait_action \
      "$dir" "session-a" "2026-01-01T00:00:04Z" \
      "exp-1" "$request_id" "$mint_status"
    append_controlled_reality \
      "$dir" "session-a" "2026-01-01T00:00:05Z" "$request_id"

    assert_claim "$dir" "bait_action_observed_without_same_session"
    jq -e --arg mint_status "$mint_status" '
      .eidolon_proxy.counts.rejected_bait_actions == 1
      and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
      and .eidolon_proxy.bait_events.actions[0].header_value_mint_status == $mint_status
      and .eidolon_proxy.bait_events.actions[0].proof_outcome == "rejected"
      and .eidolon_proxy.bait_events.actions[0].same_session_confirmed == false
      and (.comparison.correlated_bait_events.actions | length) == 1
      and .comparison.correlated_bait_events.actions[0].proof_outcome == "rejected"
      and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
      and (.comparison.correlated_bait_events.controlled_reality_entries | length) == 0
      and .comparison.same_session_confirmed_bait_action == false
      and .comparison.controlled_reality_entered == false
      and .comparison.strict_correlation_gap.unconfirmed_actions[0].reason == "proof_rejected"
      and .comparison.strict_correlation_gap.likely_cause == "proof_rejected"
    ' "$dir/summary.json" >/dev/null
  done
}

test_accepted_docs_minted_action_preserves_typed_bait_evidence() {
  local dir
  local exposure_request_id="00000000-0000-4000-8000-000000000030"
  local action_request_id="00000000-0000-4000-8000-000000000031"
  local profile_sha256
  local proxy_events_sha256

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-docs-1
  profile_sha256="$(sha256_file "$dir/private/bait-profile.json")"
  insert_http_artifact \
    "$dir" "http-docs" 1767225600000 GET /docs/legacy-import 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:00Z" \
    GET /docs/legacy-import protected_upstream "$exposure_request_id"
  append_bait_exposed \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    "exp-docs" /docs/legacy-import "$exposure_request_id" \
    rel_2025_04_b7f2 docs mig
  insert_http_artifact \
    "$dir" "http-docs-action" 1767225603000 \
    POST /api/v2/import/reconcile 202
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:03Z" \
    POST /api/v2/import/reconcile eidolon_owned "$action_request_id"
  append_minted_bait_action \
    "$dir" "session-a" "2026-01-01T00:00:04Z" \
    "exp-docs" "$action_request_id" matched_session_value \
    rel_2025_04_b7f2 mig docs
  append_controlled_reality \
    "$dir" "session-a" "2026-01-01T00:00:05Z" "$action_request_id"
  proxy_events_sha256="$(sha256_jsonl "$dir/proxy-events.jsonl")"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e \
    --arg profile_sha256 "$profile_sha256" \
    --arg proxy_events_sha256 "$proxy_events_sha256" '
    .execution_id == "execution-docs-1"
    and .proxy_events_canonical_sha256 == $proxy_events_sha256
    and .eidolon_proxy.counts.accepted_bait_actions == 1
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .eidolon_proxy.bait_events.exposures[0].mint_contract_status
      == "mint_contract_satisfied"
    and .eidolon_proxy.bait_events.exposures[0].header_value_mint
      == .eidolon_proxy.bait_events.actions[0].header_value_mint
    and .eidolon_proxy.bait_events.actions[0].bait_id == "rel_2025_04_b7f2"
    and .eidolon_proxy.bait_events.actions[0].bait_class == "docs"
    and .eidolon_proxy.bait_events.actions[0].header_value_mint_status
      == "matched_session_value"
    and .eidolon_proxy.bait_events.actions[0].mint_contract_status
      == "mint_contract_satisfied"
    and .eidolon_proxy.bait_events.actions[0].proof_outcome == "accepted"
    and .eidolon_proxy.bait_events.actions[0].same_session_confirmed == true
    and .eidolon_proxy.bait_events.actions[0].request_routing == {
      request_seen_count: 1,
      exact_request_seen_count: 1,
      prior_exact_request_seen_count: 1,
      routing_decisions: ["eidolon_owned"],
      protected_upstream_request_seen_count: 0,
      eidolon_owned_or_controlled_request_seen_count: 1,
      boundary_satisfied: true
    }
    and .eidolon_proxy.bait_action_routing_boundary == {
      accepted_action_count: 1,
      accepted_action_boundary_satisfied_count: 1,
      protected_upstream_request_seen_count: 0,
      all_accepted_actions_boundary_satisfied: true
    }
    and .eidolon_proxy.bait_events.matrix[0].bait_class == "docs"
    and .eidolon_proxy.bait_events.matrix[0].profile_id == "docs_session_minted_probe"
    and .eidolon_proxy.bait_events.matrix[0].profile_sha256 == $profile_sha256
    and .comparison.correlated_bait_events.matrix == [{
      bait_id: "rel_2025_04_b7f2",
      bait_class: "docs",
      profile_id: "docs_session_minted_probe",
      profile_sha256: $profile_sha256,
      exposure_count: 1,
      action_count: 1,
      same_session_confirmed_action_count: 1,
      surfaces: ["/docs/legacy-import"],
      action_paths: ["/api/v2/import/reconcile"]
    }]
    and .comparison.same_session_confirmed_bait_action == true
    and .comparison.controlled_reality_entered == true
    and .comparison.target_runtime_bait == {
      profile_snapshot_present: true,
      profile_id: "docs_session_minted_probe",
      profile_sha256: $profile_sha256,
      target_identification: "single_bait_private_profile",
      target_bait: {
        bait_id: "rel_2025_04_b7f2",
        bait_class: "docs",
        expected_action: {
          header_name: "X-Migration-Trace",
          header_value_mint: {
            kind: "session_hmac_sha256_v1",
            prefix: "mig"
          }
        }
      },
      exposure_count: 1,
      accepted_action_count: 1,
      confirmed_action_count: 1,
      controlled_reality_entry_count: 1,
      routing_boundary_satisfied: true,
      target_exposed: true,
      accepted_same_session_action: true,
      controlled_reality_entered: true,
      run_satisfied: true
    }
  ' "$dir/summary.json" >/dev/null
}

test_forwarded_accepted_action_fails_routing_boundary() {
  local dir
  local exposure_request_id="00000000-0000-4000-8000-000000000040"
  local action_request_id="00000000-0000-4000-8000-000000000041"

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-forwarded-1
  insert_http_artifact \
    "$dir" "http-docs-forwarded" 1767225600000 \
    GET /docs/legacy-import 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:00Z" \
    GET /docs/legacy-import protected_upstream "$exposure_request_id"
  append_bait_exposed \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    exp-forwarded /docs/legacy-import "$exposure_request_id" \
    rel_2025_04_b7f2 docs mig
  insert_http_artifact \
    "$dir" "http-action-forwarded" 1767225603000 \
    POST /api/v2/import/reconcile 202
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:03Z" \
    POST /api/v2/import/reconcile protected_upstream "$action_request_id"
  append_minted_bait_action \
    "$dir" "session-a" "2026-01-01T00:00:04Z" \
    exp-forwarded "$action_request_id" matched_session_value \
    rel_2025_04_b7f2 mig docs
  append_controlled_reality \
    "$dir" "session-a" "2026-01-01T00:00:05Z" "$action_request_id"

  assert_claim "$dir" "bait_action_observed_without_same_session"
  jq -e '
    .eidolon_proxy.counts.accepted_bait_actions == 1
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
    and .eidolon_proxy.bait_events.actions[0].same_session_confirmed == false
    and .eidolon_proxy.bait_events.actions[0].request_routing.boundary_satisfied == false
    and .eidolon_proxy.bait_events.actions[0].request_routing.routing_decisions == [
      "protected_upstream"
    ]
    and .eidolon_proxy.bait_events.actions[0].request_routing.protected_upstream_request_seen_count == 1
    and .eidolon_proxy.bait_action_routing_boundary.all_accepted_actions_boundary_satisfied == false
    and (.comparison.correlated_bait_events.actions | length) == 1
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
    and (.comparison.correlated_bait_events.controlled_reality_entries | length) == 0
    and .comparison.strict_correlation_gap.unconfirmed_actions[0].reason == "routing_boundary_failed"
    and .comparison.target_runtime_bait.target_exposed == true
    and .comparison.target_runtime_bait.accepted_action_count == 1
    and .comparison.target_runtime_bait.confirmed_action_count == 0
    and .comparison.target_runtime_bait.routing_boundary_satisfied == false
    and .comparison.target_runtime_bait.run_satisfied == false
  ' "$dir/summary.json" >/dev/null
}

test_mixed_safe_and_forwarded_actions_fail_runtime_stability() {
  local dir
  local exposure_request_id="00000000-0000-4000-8000-000000000050"
  local safe_request_id="00000000-0000-4000-8000-000000000051"
  local forwarded_request_id="00000000-0000-4000-8000-000000000052"

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-mixed-1
  insert_http_artifact \
    "$dir" "http-docs-mixed" 1767225600000 GET /docs/legacy-import 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:00Z" \
    GET /docs/legacy-import protected_upstream "$exposure_request_id"
  append_bait_exposed \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    exp-mixed /docs/legacy-import "$exposure_request_id" \
    rel_2025_04_b7f2 docs mig

  insert_http_artifact \
    "$dir" "http-action-safe" 1767225603000 \
    POST /api/v2/import/reconcile 202
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:03Z" \
    POST /api/v2/import/reconcile eidolon_owned "$safe_request_id"
  append_minted_bait_action \
    "$dir" "session-a" "2026-01-01T00:00:04Z" \
    exp-mixed "$safe_request_id" matched_session_value \
    rel_2025_04_b7f2 mig docs

  insert_http_artifact \
    "$dir" "http-action-forwarded-mixed" 1767225645000 \
    POST /api/v2/import/reconcile 202
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:45Z" \
    POST /api/v2/import/reconcile protected_upstream "$forwarded_request_id"
  append_minted_bait_action \
    "$dir" "session-a" "2026-01-01T00:00:46Z" \
    exp-mixed "$forwarded_request_id" matched_session_value \
    rel_2025_04_b7f2 mig docs
  append_controlled_reality \
    "$dir" "session-a" "2026-01-01T00:00:47Z" "$safe_request_id"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '
    .eidolon_proxy.counts.accepted_bait_actions == 2
    and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 1
    and .eidolon_proxy.bait_action_routing_boundary == {
      accepted_action_count: 2,
      accepted_action_boundary_satisfied_count: 1,
      protected_upstream_request_seen_count: 1,
      all_accepted_actions_boundary_satisfied: false
    }
    and (.comparison.correlated_bait_events.actions | length) == 2
    and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 1
    and (.comparison.correlated_bait_events.controlled_reality_entries | length) == 1
    and .comparison.target_runtime_bait.accepted_action_count == 2
    and .comparison.target_runtime_bait.confirmed_action_count == 1
    and .comparison.target_runtime_bait.controlled_reality_entry_count == 1
    and .comparison.target_runtime_bait.routing_boundary_satisfied == false
    and .comparison.target_runtime_bait.run_satisfied == false
  ' "$dir/summary.json" >/dev/null
}

test_unrelated_upstream_traffic_does_not_poison_action_boundary() {
  local dir
  local exposure_request_id="00000000-0000-4000-8000-000000000060"
  local unrelated_request_id="00000000-0000-4000-8000-000000000061"
  local action_request_id="00000000-0000-4000-8000-000000000062"

  dir="$(new_artifact)"
  init_artifact "$dir" "session-a"
  write_docs_profile_provenance "$dir" execution-unrelated-1
  insert_http_artifact \
    "$dir" "http-docs-unrelated" 1767225600000 \
    GET /docs/legacy-import 200
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:00Z" \
    GET /docs/legacy-import protected_upstream "$exposure_request_id"
  append_bait_exposed \
    "$dir" "session-a" "2026-01-01T00:00:01Z" \
    exp-unrelated /docs/legacy-import "$exposure_request_id" \
    rel_2025_04_b7f2 docs mig
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:02Z" \
    GET /health protected_upstream "$unrelated_request_id"
  insert_http_artifact \
    "$dir" "http-action-unrelated" 1767225603000 \
    POST /api/v2/import/reconcile 202
  append_request_seen \
    "$dir" "session-a" "2026-01-01T00:00:03Z" \
    POST /api/v2/import/reconcile eidolon_owned "$action_request_id"
  append_minted_bait_action \
    "$dir" "session-a" "2026-01-01T00:00:04Z" \
    exp-unrelated "$action_request_id" matched_session_value \
    rel_2025_04_b7f2 mig docs
  append_controlled_reality \
    "$dir" "session-a" "2026-01-01T00:00:05Z" "$action_request_id"

  assert_claim "$dir" "controlled_reality_entered"
  jq -e '
    .eidolon_proxy.counts.protected_upstream_requests == 2
    and .eidolon_proxy.bait_events.actions[0].request_routing.boundary_satisfied == true
    and .eidolon_proxy.bait_events.actions[0].request_routing.protected_upstream_request_seen_count == 0
    and .eidolon_proxy.bait_action_routing_boundary.all_accepted_actions_boundary_satisfied == true
    and .comparison.target_runtime_bait.routing_boundary_satisfied == true
    and .comparison.target_runtime_bait.run_satisfied == true
  ' "$dir/summary.json" >/dev/null
}

test_minted_proof_without_known_status_is_unknown() {
  local dir
  local request_id="00000000-0000-4000-8000-000000000021"
  local mint_status

  for mint_status in "" future_status; do
    dir="$(new_artifact)"
    init_artifact "$dir" "session-a"
    seed_exposure "$dir" "session-a" "exp-1"
    insert_http_artifact "$dir" "http-unknown-action" 1767225603000 POST /api/v2/import/reconcile 202
    append_request_seen \
      "$dir" "session-a" "2026-01-01T00:00:03Z" \
      POST /api/v2/import/reconcile eidolon_owned "$request_id"
    append_minted_bait_action \
      "$dir" "session-a" "2026-01-01T00:00:04Z" \
      "exp-1" "$request_id" "$mint_status"

    assert_claim "$dir" "bait_action_observed_without_same_session"
    jq -e '
      .eidolon_proxy.counts.unknown_proof_bait_actions == 1
      and .eidolon_proxy.counts.same_session_confirmed_bait_actions == 0
      and .eidolon_proxy.bait_events.actions[0].proof_outcome == "unknown"
      and (.comparison.correlated_bait_events.actions | length) == 1
      and (.comparison.correlated_bait_events.same_session_confirmed_actions | length) == 0
      and .comparison.strict_correlation_gap.unconfirmed_actions[0].reason == "proof_outcome_unknown"
      and .comparison.strict_correlation_gap.likely_cause == "proof_outcome_unknown"
    ' "$dir/summary.json" >/dev/null
  done
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
test_public_metadata_without_private_profile_does_not_bind_profile
test_observed_class_must_match_private_profile_pair
test_profile_provenance_mismatches_fail
test_later_same_session_request_does_not_reconstruct_action_causality
test_bash_http_output_upgrades_confirmed_action
test_wrong_session_action_does_not_confirm
test_strict_gap_marks_proxy_exposure_not_pwnkit_correlated
test_exact_crawl_start_path_confirms_exposure_surface
test_redacted_query_paths_do_not_create_false_correlation
test_ambiguous_concurrent_proxy_requests_do_not_cross_pair
test_ambiguous_crawl_artifact_does_not_confirm_concurrent_exposures
test_missing_request_ids_remain_visible_but_unlinked
test_rejected_minted_proof_remains_visible_but_unconfirmed
test_accepted_docs_minted_action_preserves_typed_bait_evidence
test_forwarded_accepted_action_fails_routing_boundary
test_mixed_safe_and_forwarded_actions_fail_runtime_stability
test_unrelated_upstream_traffic_does_not_poison_action_boundary
test_minted_proof_without_known_status_is_unknown
test_proxy_only_action_stays_exposure_only
test_no_signal_diagnostics_classify_proxy_without_pwnkit_artifacts
test_no_signal_diagnostics_classify_agent_auth_errors
test_no_signal_diagnostics_classify_codex_backend_timeouts
test_no_signal_diagnostics_classify_codex_backend_api_errors
test_no_signal_diagnostics_do_not_classify_generic_api_timeouts_as_codex
test_finding_diagnostics_are_shape_only
test_finding_gap_marks_controlled_reality_without_findings
test_large_runner_artifacts_do_not_hit_shell_argument_limit

printf 'collect-pwnkit-codex fixture tests passed\n'
