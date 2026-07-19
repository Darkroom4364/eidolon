#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR="${1:-${EIDOLON_M3_ARTIFACT_DIR:-}}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/collect-pwnkit-codex.sh <artifact-dir>

Summarizes artifacts from examples/m3/pwnkit-codex.sh plus the Eidolon proxy
event log in the same directory. The summary reports target-tool activity,
proxy routing, and whether the M3 bait catalog influenced the pwnkit run.

Requires jq and sqlite3.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$ARTIFACT_DIR" || ! -d "$ARTIFACT_DIR" ]]; then
  echo "error: artifact directory not found; pass it as the first argument" >&2
  exit 2
fi

for tool in jq sqlite3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: missing required tool: $tool" >&2
    exit 2
  fi
done

TMP_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-collect.XXXXXX")"
cleanup() {
  rm -rf "$TMP_WORK_DIR"
}
trap cleanup EXIT

tmp_json_file() {
  local name="$1"
  printf '%s/%s.json' "$TMP_WORK_DIR" "$name"
}

write_json_file() {
  local path="$1"
  local json="$2"

  printf '%s\n' "$json" > "$path"
}

sqlite_json() {
  local db="$1"
  local query="$2"
  if [[ ! -f "$db" ]]; then
    printf '[]'
    return
  fi
  local output
  output="$(sqlite3 -json "$db" "$query")"
  if [[ -z "$output" ]]; then
    printf '[]'
  else
    printf '%s' "$output"
  fi
}

sqlite_scalar() {
  local db="$1"
  local query="$2"
  if [[ ! -f "$db" ]]; then
    printf '0'
    return
  fi
  local output
  output="$(sqlite3 "$db" "$query")"
  if [[ -z "$output" ]]; then
    printf '0'
  else
    printf '%s' "$output"
  fi
}

sqlite_table_exists() {
  local db="$1"
  local table="$2"

  [[ -f "$db" ]] || return 1
  [[ "$(sqlite3 "$db" \
    "select count(*) from sqlite_master where type = 'table' and name = '$table';" \
    2>/dev/null || printf '0')" == "1" ]]
}

sqlite_has_column() {
  local db="$1"
  local table="$2"
  local column="$3"

  [[ -f "$db" ]] || return 1
  [[ "$(sqlite3 "$db" \
    "select count(*) from pragma_table_info('$table') where name = '$column';" \
    2>/dev/null || printf '0')" == "1" ]]
}

sqlite_column_expr() {
  local db="$1"
  local table="$2"
  local column="$3"
  local alias="$4"

  if sqlite_has_column "$db" "$table" "$column"; then
    printf 'cast("%s" as text) as "%s"' "$column" "$alias"
  else
    printf 'null as "%s"' "$alias"
  fi
}

sqlite_presence_expr() {
  local db="$1"
  local table="$2"
  local column="$3"
  local alias="$4"

  if sqlite_has_column "$db" "$table" "$column"; then
    printf 'case when "%s" is null or "%s" = "" then 0 else 1 end as "%s"' \
      "$column" \
      "$column" \
      "$alias"
  else
    printf '0 as "%s"' "$alias"
  fi
}

run_summary() {
  local label="$1"
  local report_file="$ARTIFACT_DIR/pwnkit-$label.json"
  local db_file="$ARTIFACT_DIR/pwnkit-$label.db"
  local report_json_file
  local status="missing"

  report_json_file="$(tmp_json_file "$label-report")"
  if [[ -s "$report_file" ]]; then
    report_json_file="$report_file"
    status="present"
  else
    write_json_file "$report_json_file" '{}'
    if [[ -f "$report_file" ]]; then
      status="present"
    fi
  fi

  local tool_counts
  tool_counts="$(sqlite_json "$db_file" \
    "select json_extract(payload, '$.tool') as tool, count(*) as count
     from pipeline_events
     where eventType = 'tool_artifact'
     group by tool
     order by tool;")"

  local http_requests
  http_requests="$(sqlite_json "$db_file" \
    "select
       timestamp as timestamp_ms,
       json_extract(payload, '$.request.method') as method,
       json_extract(payload, '$.request.url') as url,
       json_extract(payload, '$.response.status') as status
     from pipeline_events
     where eventType = 'tool_artifact'
       and json_extract(payload, '$.tool') = 'http_request'
       and json_extract(payload, '$.request.url') is not null
     order by timestamp;")"

  local bash_http_outputs
  bash_http_outputs="$(sqlite_json "$db_file" \
    "select
       timestamp as timestamp_ms,
       json_extract(payload, '$.output') as output
     from pipeline_events
     where eventType = 'tool_artifact'
       and json_extract(payload, '$.tool') = 'bash'
       and json_extract(payload, '$.output') is not null
       and json_extract(payload, '$.output') like '%HTTP/1.1%'
     order by timestamp;")"

  local crawl_artifacts
  crawl_artifacts="$(sqlite_json "$db_file" \
    "select
       timestamp as timestamp_ms,
       json_extract(payload, '$.startUrl') as start_url,
       json_extract(payload, '$.depth') as depth,
       json_extract(payload, '$.pagesVisited') as pages_visited
     from pipeline_events
     where eventType = 'tool_artifact'
       and json_extract(payload, '$.tool') = 'crawl'
     order by timestamp;")"

  local agent_errors
  agent_errors="$(sqlite_json "$db_file" \
    "with classified as (
       select
         coalesce(stage, 'unknown') as stage,
         coalesce(agentRole, 'unknown') as agent_role,
         case
           when lower(coalesce(json_extract(payload, '$.error'), '')) like 'transient (retry %'
             then 'recovered_transient_retry'
           when lower(coalesce(json_extract(payload, '$.error'), '')) like '%refresh token%'
             or lower(coalesce(json_extract(payload, '$.error'), '')) like '%token refresh failed%'
             then 'codex_token_refresh_failed'
           when lower(coalesce(json_extract(payload, '$.error'), '')) like '%401%'
             or lower(coalesce(json_extract(payload, '$.error'), '')) like '%invalid_request_error%'
             or lower(coalesce(json_extract(payload, '$.error'), '')) like '%authentication%'
             then 'codex_authentication_failed'
           when lower(coalesce(json_extract(payload, '$.error'), '')) like '%codex backend%'
             and (
               lower(coalesce(json_extract(payload, '$.error'), '')) like '%timed out%'
               or lower(coalesce(json_extract(payload, '$.error'), '')) like '%timeout%'
             )
             then 'codex_backend_timeout'
           when lower(coalesce(json_extract(payload, '$.error'), '')) like '%chatgpt (codex backend) api error%'
             then 'codex_backend_api_error'
           when lower(coalesce(json_extract(payload, '$.error'), '')) like '%api request timed out%'
             or lower(coalesce(json_extract(payload, '$.error'), '')) like '%api timeout%'
             then 'agent_api_timeout'
           when lower(coalesce(json_extract(payload, '$.error'), '')) like '%api error%'
             then 'agent_api_error'
           else 'pwnkit_agent_error'
         end as error_class
       from pipeline_events
       where eventType = 'agent_error'
     )
     select
       stage,
       agent_role as agentRole,
       error_class,
       count(*) as count
     from classified
     group by stage, agent_role, error_class
     order by stage, agent_role, error_class;")"

  local scan_records="[]"
  if sqlite_table_exists "$db_file" "scans"; then
    scan_records="$(sqlite_json "$db_file" \
      "select
         id as scan_id,
         target,
         depth,
         runtime,
         mode,
         status,
         startedAt as started_at,
         completedAt as completed_at,
         durationMs as duration_ms,
         case when json_valid(summary) then json_extract(summary, '$.totalAttacks') end
           as total_attacks,
         case when json_valid(summary) then json_extract(summary, '$.totalFindings') end
           as total_findings
       from scans
       order by startedAt, id;")"
  fi

  local agent_sessions="[]"
  if sqlite_table_exists "$db_file" "agent_sessions"; then
    agent_sessions="$(sqlite_json "$db_file" \
      "select
         agentRole as agent_role,
         turnCount as turn_count,
         status,
         createdAt as created_at,
         updatedAt as updated_at
       from agent_sessions
       order by createdAt, id;")"
  fi

  local terminal_events="[]"
  if sqlite_table_exists "$db_file" "pipeline_events"; then
    terminal_events="$(sqlite_json "$db_file" \
      "select eventType as event_type, count(*) as count
       from pipeline_events
       where eventType in (
         'scan_start',
         'scan_complete',
         'scan_error',
         'scan_aborted',
         'agent_error'
       )
       group by eventType
       order by eventType;")"
  fi

  local event_count
  local tool_artifacts
  event_count="$(sqlite_scalar "$db_file" "select count(*) from pipeline_events;")"
  tool_artifacts="$(sqlite_scalar "$db_file" "select count(*) from pipeline_events where eventType = 'tool_artifact';")"

  local db_findings="[]"
  if sqlite_table_exists "$db_file" "findings"; then
    local finding_select
    finding_select="select
       $(sqlite_column_expr "$db_file" "findings" "severity" "severity"),
       $(sqlite_column_expr "$db_file" "findings" "category" "category"),
       $(sqlite_column_expr "$db_file" "findings" "status" "status"),
       $(sqlite_column_expr "$db_file" "findings" "triageStatus" "triage_status"),
       $(sqlite_column_expr "$db_file" "findings" "workflowStatus" "workflow_status"),
       $(sqlite_column_expr "$db_file" "findings" "confidence" "confidence"),
       $(sqlite_column_expr "$db_file" "findings" "score" "score"),
       $(sqlite_column_expr "$db_file" "findings" "cvssScore" "cvss_score"),
       $(sqlite_column_expr "$db_file" "findings" "layerVerdicts" "layer_verdicts"),
       $(sqlite_presence_expr "$db_file" "findings" "triageNote" "triage_note_present"),
       $(sqlite_presence_expr "$db_file" "findings" "layerVerdicts" "layer_verdicts_present"),
       $(sqlite_presence_expr "$db_file" "findings" "pocSteps" "poc_steps_present"),
       $(sqlite_presence_expr "$db_file" "findings" "verificationSpec" "verification_spec_present"),
       $(sqlite_presence_expr "$db_file" "findings" "pocExecution" "poc_execution_present"),
       $(sqlite_column_expr "$db_file" "findings" "timestamp" "timestamp")
     from findings
     order by rowid;"
    db_findings="$(sqlite_json "$db_file" "$finding_select")"
  fi

  local tool_counts_file
  local http_requests_file
  local bash_http_outputs_file
  local crawl_artifacts_file
  local agent_errors_file
  local db_findings_file
  local scan_records_file
  local agent_sessions_file
  local terminal_events_file
  tool_counts_file="$(tmp_json_file "$label-tool-counts")"
  http_requests_file="$(tmp_json_file "$label-http-requests")"
  bash_http_outputs_file="$(tmp_json_file "$label-bash-http-outputs")"
  crawl_artifacts_file="$(tmp_json_file "$label-crawl-artifacts")"
  agent_errors_file="$(tmp_json_file "$label-agent-errors")"
  db_findings_file="$(tmp_json_file "$label-db-findings")"
  scan_records_file="$(tmp_json_file "$label-scan-records")"
  agent_sessions_file="$(tmp_json_file "$label-agent-sessions")"
  terminal_events_file="$(tmp_json_file "$label-terminal-events")"
  write_json_file "$tool_counts_file" "$tool_counts"
  write_json_file "$http_requests_file" "$http_requests"
  write_json_file "$bash_http_outputs_file" "$bash_http_outputs"
  write_json_file "$crawl_artifacts_file" "$crawl_artifacts"
  write_json_file "$agent_errors_file" "$agent_errors"
  write_json_file "$db_findings_file" "$db_findings"
  write_json_file "$scan_records_file" "$scan_records"
  write_json_file "$agent_sessions_file" "$agent_sessions"
  write_json_file "$terminal_events_file" "$terminal_events"

  jq -n \
    --arg label "$label" \
    --arg artifact_status "$status" \
    --argjson event_count "$event_count" \
    --argjson tool_artifacts "$tool_artifacts" \
    --slurpfile report_json "$report_json_file" \
    --slurpfile tool_counts_json "$tool_counts_file" \
    --slurpfile http_requests_json "$http_requests_file" \
    --slurpfile bash_http_outputs_json "$bash_http_outputs_file" \
    --slurpfile crawl_artifacts_json "$crawl_artifacts_file" \
    --slurpfile agent_errors_json "$agent_errors_file" \
    --slurpfile db_findings_json "$db_findings_file" \
    --slurpfile scan_records_json "$scan_records_file" \
    --slurpfile agent_sessions_json "$agent_sessions_file" \
    --slurpfile terminal_events_json "$terminal_events_file" \
    '($report_json[0] // {}) as $report
     | ($tool_counts_json[0] // []) as $tool_counts
     | ($http_requests_json[0] // []) as $http_requests
     | ($bash_http_outputs_json[0] // []) as $bash_http_outputs
     | ($crawl_artifacts_json[0] // []) as $crawl_artifacts
     | ($agent_errors_json[0] // []) as $agent_errors
     | ($db_findings_json[0] // []) as $db_findings
     | ($scan_records_json[0] // []) as $scan_records
     | ($agent_sessions_json[0] // []) as $agent_sessions
     | ($terminal_events_json[0] // []) as $terminal_events
     | def path_without_origin($url):
       ($url // "")
       | sub("^https?://[^/]+"; "")
       | if . == "" then "/" else . end;
     def safe_path_from_url($url):
       path_without_origin($url)
       | split("#")[0]
       | split("?")[0]
       | if . == "" then "/" else . end;
     def maybe_capture($value; $pattern):
       ([ $value | capture($pattern) ] | first // null);
     def bash_output_requests:
       [
         $bash_http_outputs[] as $artifact
         | (($artifact.output // "") | split("==== ")[] | select(length > 0))
         | (split("\n")) as $lines
         | {
             label: ($lines[0] | sub("[ =]+$"; "")),
             body: ($lines[1:] | join("\n"))
           } as $block
         | select($block.label != "")
         | maybe_capture(
             $block.label;
             "^(?<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD) (?<path>/[^ ]+)"
           ) as $explicit
         | maybe_capture($block.label; "^(?<path>/[^ ]+)") as $implicit_get
         | maybe_capture(
             $block.body;
             "\"path\"[[:space:]]*:[[:space:]]*\"(?<path>[^\"]+)\""
           ) as $body_path
         | maybe_capture($block.body; "HTTP/1\\.1 (?<status>[0-9]{3})") as $http_status
         | ($explicit.path // $implicit_get.path // $body_path.path) as $path
         | select($path != null)
         | {
             timestamp_ms: $artifact.timestamp_ms,
             method: (
               $explicit.method // (
                 if ($implicit_get.path // null) != null then
                   "GET"
                 elif (
                   (($body_path.path // "") == "/api/v2/import/reconcile")
                   and ($block.body | contains("\"write_committed\":false"))
                 ) then
                   "POST"
                 else
                   null
                 end
               )
             ),
             url: null,
             path: safe_path_from_url($path),
             status: (($http_status.status // null) | if . == null then null else tonumber end),
             source: "bash_http_output",
             evidence_label: (($explicit.method // "GET") + " " + safe_path_from_url($path))
           }
       ];
     def structured_http_requests:
       $http_requests
       | map({
           timestamp_ms,
           method,
           url: null,
           path: safe_path_from_url(.url),
           status,
           source: "http_request",
           evidence_label: null
         });
     def all_requested_paths:
       (structured_http_requests + bash_output_requests)
       | unique_by(.timestamp_ms, .method, .path, .source, (.evidence_label // ""));
     def crawl_artifact_summaries:
       $crawl_artifacts
       | map({
           timestamp_ms,
           start_path: safe_path_from_url(.start_url),
           depth: (.depth // null),
           pages_visited: (.pages_visited // null)
         })
       | unique_by(.timestamp_ms, .start_path, (.depth // null), (.pages_visited // null));
     def findings: ($report.findings // []);
     def finding_count: (findings | length);
     def db_findings: ($db_findings // []);
     def normalized_value:
       if . == null then null
       elif type == "string" then (if length == 0 then null else . end)
       elif type == "number" or type == "boolean" then tostring
       else null
       end;
     def first_present($finding; $fields):
       reduce $fields[] as $field (null; . // ($finding[$field] // null));
     def count_by($values):
       $values
       | map(select(. != null and . != ""))
       | sort
       | group_by(.)
       | map({value: .[0], count: length});
     def rejected_finding_status($value):
       (($value // "") | tostring | ascii_downcase) as $status
       | (
           $status == "false-positive"
           or $status == "false_positive"
           or $status == "suppressed"
           or $status == "rejected"
           or $status == "closed"
         );
     def present_flag:
       . == true or . == 1 or . == "1";
     def parse_json_array:
       if . == null then
         []
       elif type == "array" then
         .
       elif type == "string" and length > 0 then
         try (fromjson | if type == "array" then . else [] end) catch []
       else
         []
       end;
     def numeric_value:
       if . == null or . == "" then null else (try tonumber catch null) end;
     def confidence_bucket:
       (numeric_value) as $confidence
       | if $confidence == null then
           null
         elif $confidence >= 0.8 then
           "high"
         elif $confidence >= 0.5 then
           "medium"
         else
           "low"
         end;
     def reason_class:
       ((. // "") | tostring | ascii_downcase) as $reason
       | if $reason == "" then
           null
         elif (
           ($reason | contains("trust boundary"))
           or ($reason | contains("trusted backend"))
           or ($reason | contains("trusted provider"))
           or ($reason | contains("host application"))
           or ($reason | contains("holding-it-wrong"))
         ) then
           "trusted_backend_or_no_trust_boundary"
         elif (
           ($reason | contains("evidence_completeness"))
           or ($reason | contains("evidence completeness"))
           or ($reason | contains("insufficient evidence"))
         ) then
           "evidence_gate"
         elif (
           ($reason | contains("reachability"))
           or ($reason | contains("not reachable"))
         ) then
           "reachability_gate"
         elif ($reason | contains("no oracle")) then
           "oracle_unavailable"
         elif (
           ($reason | contains("pwnkit_feature_"))
           or ($reason | contains("feature disabled"))
         ) then
           "feature_disabled"
         elif (
           ($reason | contains("could not independently reproduce"))
           or ($reason | contains("verifier error"))
           or ($reason | contains("verification failed"))
         ) then
           "verification_rejected"
         elif (
           ($reason | contains("timeout"))
           or ($reason | contains("timed out"))
         ) then
           "timeout"
         else
           "other"
         end;
     def severity_change_class:
       if (. // null) == null then
         null
       else
         (((.from // "unknown") | tostring) + "_to_" + ((.to // "unknown") | tostring))
       end;
     def db_findings_with_lifecycle:
       db_findings
       | map(
           . + {
             active: (
               (rejected_finding_status(.status) | not)
               and (rejected_finding_status(.triage_status) | not)
             )
           }
         );
     def db_active_findings:
       db_findings_with_lifecycle | map(select(.active));
     def db_inactive_findings:
       db_findings_with_lifecycle | map(select(.active | not));
     def db_saved_finding_count: (db_findings | length);
     def db_active_finding_count: (db_active_findings | length);
     def db_inactive_finding_count: (db_inactive_findings | length);
     def positive_delta($left; $right):
       if $left > $right then $left - $right else 0 end;
     def lifecycle_rejection_reasons($finding):
       [
         if rejected_finding_status($finding.status) then
           "status:" + (($finding.status | normalized_value) // "unknown")
         else
           empty
         end,
         if rejected_finding_status($finding.triage_status) then
           "triage:" + (($finding.triage_status | normalized_value) // "unknown")
         else
           empty
         end,
         if (($finding.workflow_status // "") | tostring | ascii_downcase) == "cancelled" then
           "workflow:cancelled"
         else
           empty
         end
       ];
     def db_lifecycle_counts($findings):
       $findings
       | map({
           status: ((.status | normalized_value) // "unknown"),
           triage_status: ((.triage_status | normalized_value) // "unknown"),
           workflow_status: ((.workflow_status | normalized_value) // "unknown"),
           active: (.active // false)
         })
       | sort_by(.status, .triage_status, .workflow_status, .active)
       | group_by([.status, .triage_status, .workflow_status, .active])
       | map({
           status: .[0].status,
           triage_status: .[0].triage_status,
           workflow_status: .[0].workflow_status,
           active: .[0].active,
           count: length
         });
     def db_artifact_presence($findings):
       {
         triage_note: ($findings | map(select(.triage_note_present | present_flag)) | length),
         layer_verdicts: ($findings | map(select(.layer_verdicts_present | present_flag)) | length),
         poc_steps: ($findings | map(select(.poc_steps_present | present_flag)) | length),
         verification_spec: (
           $findings | map(select(.verification_spec_present | present_flag)) | length
         ),
         poc_execution: (
           $findings | map(select(.poc_execution_present | present_flag)) | length
         ),
         score: ($findings | map(select((.score | numeric_value) != null)) | length),
         cvss_score: ($findings | map(select((.cvss_score | numeric_value) != null)) | length)
       };
     def parsed_layer_verdicts($findings):
       $findings
       | map(
           . as $finding
           | (
               $finding.layer_verdicts
               | parse_json_array
               | map({
                   layer: ((.layer | normalized_value) // "unknown"),
                   verdict: ((.verdict | normalized_value) // "unknown"),
                   reason_class: (.reason | reason_class),
                   severity_change: (.changedSeverity | severity_change_class),
                   finding_active: ($finding.active // false)
                 })
             )
         )
       | add // [];
     def count_by_layer_verdict($layer_verdicts):
       $layer_verdicts
       | sort_by(.layer, .verdict)
       | group_by([.layer, .verdict])
       | map({
           layer: .[0].layer,
           verdict: .[0].verdict,
           count: length
         });
     def count_by_layer($layer_verdicts):
       $layer_verdicts
       | sort_by(.layer)
       | group_by(.layer)
       | map({layer: .[0].layer, count: length});
     def count_by_layer_reason($layer_verdicts):
       $layer_verdicts
       | map(select(.reason_class != null))
       | sort_by(.layer, .reason_class)
       | group_by([.layer, .reason_class])
       | map({
           layer: .[0].layer,
           reason_class: .[0].reason_class,
           count: length
         });
     def count_by_severity_change($layer_verdicts):
       $layer_verdicts
       | map(.severity_change)
       | count_by(.);
     def db_rejection_diagnostics:
       (db_findings_with_lifecycle) as $all_findings
       | (db_inactive_findings) as $inactive_findings
       | (parsed_layer_verdicts($all_findings)) as $all_layer_verdicts
       | (parsed_layer_verdicts($inactive_findings)) as $inactive_layer_verdicts
       | {
           inactive_finding_count: ($inactive_findings | length),
           inactive_reason_counts: count_by(
             $inactive_findings
             | map(lifecycle_rejection_reasons(.))
             | add // []
           ),
           lifecycle_counts: db_lifecycle_counts($all_findings),
           inactive_lifecycle_counts: db_lifecycle_counts($inactive_findings),
           artifact_presence: db_artifact_presence($all_findings),
           inactive_artifact_presence: db_artifact_presence($inactive_findings),
           confidence_bucket_counts: count_by(
             $all_findings | map(.confidence | confidence_bucket)
           ),
           layer_verdict_counts: count_by_layer_verdict($all_layer_verdicts),
           inactive_layer_verdict_counts: count_by_layer_verdict($inactive_layer_verdicts),
           reject_layer_counts: count_by_layer(
             $all_layer_verdicts | map(select(.verdict == "reject"))
           ),
           inactive_reject_layer_counts: count_by_layer(
             $inactive_layer_verdicts | map(select(.verdict == "reject"))
           ),
           reject_reason_class_counts: count_by_layer_reason(
             $all_layer_verdicts | map(select(.verdict == "reject"))
           ),
           inactive_reject_reason_class_counts: count_by_layer_reason(
             $inactive_layer_verdicts | map(select(.verdict == "reject"))
           ),
           severity_change_counts: count_by_severity_change($all_layer_verdicts),
           inactive_severity_change_counts: count_by_severity_change(
             $inactive_layer_verdicts
           )
         };
     def finding_reconciliation:
       {
         final_json_finding_count: finding_count,
         db_saved_finding_count: db_saved_finding_count,
         db_active_finding_count: db_active_finding_count,
         db_inactive_finding_count: db_inactive_finding_count,
         counts_match: (finding_count == db_saved_finding_count),
         db_saved_findings_omitted_from_final_json: (
           db_saved_finding_count > finding_count
         ),
         final_json_omitted_db_saved_finding_count: (
           positive_delta(db_saved_finding_count; finding_count)
         ),
         final_json_exceeds_db_saved_finding_count: (
           positive_delta(finding_count; db_saved_finding_count)
         ),
         db_status_counts: count_by(db_findings | map(.status | normalized_value)),
         db_triage_status_counts: count_by(
           db_findings | map(.triage_status | normalized_value)
         ),
         db_workflow_status_counts: count_by(
           db_findings | map(.workflow_status | normalized_value)
         ),
         db_severity_counts: count_by(db_findings | map(.severity | normalized_value)),
         db_category_counts: count_by(db_findings | map(.category | normalized_value)),
         db_rejection_diagnostics: db_rejection_diagnostics
       };
     def field_presence($fields):
       $fields
       | map(. as $field | {
           field: $field,
           count: (findings | map(select(has($field))) | length)
         })
       | map(select(.count > 0));
     def finding_diagnostics:
       {
         count: finding_count,
         severity_counts: count_by(
           findings
           | map(first_present(.; ["severity", "risk", "impact", "level"]) | normalized_value)
         ),
         category_counts: count_by(
           findings
           | map(first_present(.; ["category", "type", "kind", "class", "issueType"]) | normalized_value)
         ),
         confidence_counts: count_by(
           findings
           | map(first_present(.; ["confidence", "confidenceLevel"]) | normalized_value)
         ),
         field_presence: field_presence([
           "id",
           "title",
           "severity",
           "risk",
           "impact",
           "level",
           "category",
           "type",
           "kind",
           "class",
           "issueType",
           "confidence",
           "confidenceLevel",
           "evidence",
           "request",
           "url",
           "endpoint"
         ]),
         evidence_presence: {
           evidence_object: (findings | map(select((.evidence // null) != null)) | length),
           request_evidence: (
             findings
             | map(select(
                 (.evidence.request // null) != null
                 or (.request // null) != null
                 or (.url // null) != null
                 or (.endpoint // null) != null
               ))
             | length
           ),
           analysis_text: (
             findings
             | map(select((.evidence.analysis // null) != null or (.analysis // null) != null))
             | length
           )
         }
       };
     def target_evidence_diagnostics:
       {
         request_artifact_count: (all_requested_paths | length),
         http_request_artifact_count: (structured_http_requests | length),
         bash_http_output_request_count: (bash_output_requests | length),
         crawl_artifact_count: (crawl_artifact_summaries | length),
         crawl_start_paths: (crawl_artifact_summaries | map(.start_path) | unique),
         observed_request_evidence_without_findings: (
           finding_count == 0 and ((all_requested_paths | length) > 0)
         )
       };
     def agent_error_diagnostics:
       ($agent_errors // []) as $errors
       | ($errors | map(select(.error_class != "recovered_transient_retry")))
         as $terminal_errors
       | ($errors | map(select(.error_class == "recovered_transient_retry")))
         as $recovered_transient_errors
       | {
           event_count: ($errors | map(.count) | add // 0),
           count: ($terminal_errors | map(.count) | add // 0),
           terminal_count: ($terminal_errors | map(.count) | add // 0),
           recovered_transient_count: (
             $recovered_transient_errors | map(.count) | add // 0
           ),
           stage_counts: (
             $errors
             | sort_by(.stage, .agentRole)
             | group_by([.stage, .agentRole])
             | map({
                 stage: .[0].stage,
                 agentRole: .[0].agentRole,
                 count: (map(.count) | add)
               })
           ),
           class_counts: (
             $errors
             | sort_by(.error_class)
             | group_by(.error_class)
             | map({
                 error_class: .[0].error_class,
               count: (map(.count) | add)
             })
           ),
           terminal_class_counts: (
             $terminal_errors
             | sort_by(.error_class)
             | group_by(.error_class)
             | map({
                 error_class: .[0].error_class,
                 count: (map(.count) | add)
               })
           ),
           has_agent_error: (($terminal_errors | map(.count) | add // 0) > 0),
           has_codex_token_refresh_failure: any(
             $errors[];
             .error_class == "codex_token_refresh_failed"
           ),
           has_codex_authentication_failure: any(
             $errors[];
             .error_class == "codex_token_refresh_failed"
             or .error_class == "codex_authentication_failed"
           ),
           has_codex_backend_api_error: any(
             $errors[];
             .error_class == "codex_backend_api_error"
             or .error_class == "codex_backend_timeout"
             or .error_class == "codex_token_refresh_failed"
             or .error_class == "codex_authentication_failed"
           ),
           has_codex_backend_timeout: any(
             $errors[];
             .error_class == "codex_backend_timeout"
           )
         };
     def terminal_event_count($event_type):
       [
         $terminal_events[]
         | select(.event_type == $event_type)
         | (.count // 0)
       ]
       | add // 0;
     def session_status_counts:
       $agent_sessions
       | sort_by(.status)
       | group_by(.status)
       | map({status: .[0].status, count: length});
     def latest_agent_sessions:
       $agent_sessions
       | sort_by(.agent_role, .created_at, .updated_at)
       | group_by(.agent_role)
       | map(last);
     def latest_session_status_counts:
       latest_agent_sessions
       | sort_by(.status)
       | group_by(.status)
       | map({status: .[0].status, count: length});
     def nonterminal_sessions:
       [
         latest_agent_sessions[]
         | select((.status // "unknown") != "completed")
         | {
             agent_role: (.agent_role // "unknown"),
             turn_count: (.turn_count // 0),
             status: (.status // "unknown")
           }
       ];
     def execution_contract:
       ($scan_records | last // null) as $scan
       | (agent_error_diagnostics) as $agent_errors_summary
       | (nonterminal_sessions) as $nonterminal_sessions
       | ([
           if $artifact_status != "present" then
             "missing_final_report"
           else empty end,
           if ($scan_records | length) == 0 then
             "missing_scan_record"
           else empty end,
           if ($scan_records | length) > 1 then
             "multiple_scan_records"
           else empty end,
           if ($scan.status // null) == "failed" then
             "scan_status_failed"
           elif $scan != null and ($scan.status // "unknown") != "completed" then
             "scan_status_nonterminal"
           else empty end,
           if terminal_event_count("scan_error") > 0 then
             "scan_error_event"
           else empty end,
           if terminal_event_count("scan_complete") == 0 then
             "missing_scan_complete_event"
           else empty end,
           if terminal_event_count("scan_aborted") > 0 then
             "scan_aborted_event"
           else empty end,
           if ($agent_errors_summary.count // 0) > 0 then
             "agent_error_event"
           else empty end,
           if $scan != null
             and ($scan.mode // null) == "web"
             and ($agent_sessions | length) == 0 then
             "missing_agent_sessions"
           else empty end,
           if ($nonterminal_sessions | length) > 0 then
             "nonterminal_agent_session"
           else empty end,
           if ($report.costCeilingExceeded // false) == true then
             "cost_ceiling_exceeded"
           else empty end
         ] | unique) as $reason_codes
       | ([
           if ($agent_errors_summary.recovered_transient_count // 0) > 0 then
             "recovered_transient_agent_retry"
           else empty end,
           if db_active_finding_count > finding_count then
             "active_db_findings_omitted_from_final_json"
           else empty end,
           if finding_count > db_active_finding_count then
             "final_json_findings_missing_from_active_db"
           else empty end,
           if $scan != null
             and ($scan.total_findings // null) != null
             and ($scan.total_findings != db_saved_finding_count) then
             "scan_summary_findings_mismatch_db"
           else empty end
         ] | unique) as $diagnostic_codes
       | {
           sources: {
             execution_lifecycle: "pwnkit_sqlite",
             persisted_findings: "pwnkit_sqlite",
             final_report: "pwnkit_final_json"
           },
           result_class: (
             if ($scan.status // null) == "failed"
               or terminal_event_count("scan_error") > 0 then
               "fail"
             elif ($reason_codes | length) > 0 then
               "inconclusive"
             else
               "pass"
             end
           ),
           reason_codes: $reason_codes,
           diagnostic_codes: $diagnostic_codes,
           scan_record_count: ($scan_records | length),
           scan: (
             if $scan == null then null else {
               scan_id: $scan.scan_id,
               target: $scan.target,
               depth: $scan.depth,
               runtime: $scan.runtime,
               mode: $scan.mode,
               status: $scan.status,
               started_at: $scan.started_at,
               completed_at: $scan.completed_at,
               duration_ms: $scan.duration_ms,
               summary: {
                 total_attacks: $scan.total_attacks,
                 total_findings: $scan.total_findings
               }
             } end
           ),
           terminal_event_counts: $terminal_events,
           agent_sessions: {
             count: ($agent_sessions | length),
             status_counts: session_status_counts,
             latest_role_count: (latest_agent_sessions | length),
             latest_status_counts: latest_session_status_counts,
             nonterminal_count: ($nonterminal_sessions | length),
             latest_roles: latest_agent_sessions,
             history: $agent_sessions
           },
           finding_counts: {
             final_json: finding_count,
             db_saved: db_saved_finding_count,
             db_active: db_active_finding_count
           },
           report_exit_reason: ($report.exitReason // null),
           cost_ceiling_exceeded: ($report.costCeilingExceeded // false)
         };
     {
      label: $label,
      artifact_status: $artifact_status,
      target: ($report.target // null),
      scan_depth: ($report.scanDepth // null),
      duration_ms: ($report.durationMs // null),
      finding_count: finding_count,
      final_json_finding_count: finding_count,
      db_saved_finding_count: db_saved_finding_count,
      db_active_finding_count: db_active_finding_count,
      execution_contract: execution_contract,
      finding_diagnostics: finding_diagnostics,
      finding_reconciliation: finding_reconciliation,
      warnings: ($report.warnings // []),
      pwnkit_events: {
        pipeline_events: $event_count,
        tool_artifacts: $tool_artifacts,
        tool_counts: $tool_counts,
        bash_http_output_requests: (bash_output_requests | length),
        crawl_artifacts: crawl_artifact_summaries,
        agent_error_events: (agent_error_diagnostics.event_count),
        agent_errors: (agent_error_diagnostics.terminal_count),
        recovered_transient_agent_retries: (
          agent_error_diagnostics.recovered_transient_count
        )
      },
      agent_error_diagnostics: agent_error_diagnostics,
      target_evidence_diagnostics: target_evidence_diagnostics,
      requested_paths: all_requested_paths
    }'
}

proxy_summary() {
  local proxy_log="$ARTIFACT_DIR/proxy-events.jsonl"
  if [[ ! -s "$proxy_log" ]]; then
    jq -n '{
      present: false,
      event_count: 0,
      request_count: 0,
      kind_counts: [],
      routing_counts: [],
      event_integrity: {
        raw_event_count: 0,
        canonical_event_count: 0,
        identical_duplicate_record_count: 0,
        conflicting_event_id_count: 0,
        conflicting_record_count: 0,
        invalid_identifier_record_count: 0,
        identical_duplicates: [],
        conflicts: [],
        warnings: [],
        invalid_identifier_facts: []
      },
      counts: {
        bait_exposures: 0,
        bait_actions: 0,
        same_session_confirmed_bait_actions: 0,
        unconfirmed_bait_actions: 0,
        controlled_reality_entries: 0,
        protected_upstream_requests: 0
      },
      bait_events: {
        exposures: [],
        actions: [],
        controlled_reality_entries: [],
        matrix: []
      },
      request_paths: []
    }'
    return
  fi

  jq -s 'def event_observed_at_ms($event):
    (($event.observed_at // "")
     | sub("\\.[0-9]+Z$"; "Z")
     | fromdateiso8601?) as $seconds
    | if $seconds == null then null else ($seconds * 1000) end;
  def raw_indexed_events:
    to_entries | map({event_index: .key, event: .value});
  def safe_path($path):
    if ($path | type) == "string" then
      ($path | split("#")[0] | split("?")[0])
      | if . == "" then "/" else . end
    else
      $path
    end;
  def nonempty_string:
    type == "string" and length > 0;
  def valid_uuid:
    type == "string"
    and test("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$");
  def valid_evidence_token:
    type == "string"
    and (utf8bytelength >= 1 and utf8bytelength <= 128)
    and test("^[A-Za-z0-9][A-Za-z0-9._:-]*$");
  def valid_header_name:
    type == "string"
    and (utf8bytelength >= 1 and utf8bytelength <= 128)
    and test("^[!#$%&\\u0027*+\\-.^_`|~0-9A-Za-z]+$");
  def valid_bait_identifier:
    valid_evidence_token;
  def valid_bait_event($entry):
    ($entry.event | .session_id | valid_uuid)
    and ($entry.event.id | valid_uuid)
    and ($entry.event.kind.bait_id | valid_bait_identifier)
    and ($entry.event.kind.exposure_id | valid_bait_identifier);
  def valid_event_identifiers($entry):
    ($entry.event.id | valid_uuid)
    and ($entry.event.session_id | valid_uuid)
    and (
      ($entry.event.kind.type != "bait_exposed" and $entry.event.kind.type != "bait_action_observed")
      or valid_bait_event($entry)
    );
  def valid_event_identity($entry):
    ($entry.event.id | valid_uuid)
    and ($entry.event.session_id | valid_uuid);
  def trustworthy_indexed_event:
    (.event | has("id"))
    and (.event.id | valid_uuid)
    and (.event.session_id | valid_uuid);
  def event_canonicalization_status($events; $entry):
    if ((valid_event_identity($entry)) | not) then
      "invalid_identifier_types"
    elif ((valid_event_identifiers($entry)) | not) then
      "invalid_bait_identifier"
    else
      (
        $events
        | map(select(
            (. | trustworthy_indexed_event)
            and .event.id == $entry.event.id
          ))
      ) as $same_event_id
      | if ($same_event_id | map(.event) | unique | length) > 1 then
          "conflicting_duplicate_id"
        elif $entry.event_index == ($same_event_id | map(.event_index) | min) then
          "canonical"
        else
          "identical_duplicate_id"
        end
    end;
  def classified_events:
    raw_indexed_events as $events
    | [
        $events[] as $entry
        | $entry + {
            canonicalization_status: event_canonicalization_status($events; $entry)
          }
      ];
  def indexed_events:
    classified_events
    | map(select(
        .canonicalization_status == "canonical"
        or .canonicalization_status == "invalid_bait_identifier"
      ));
  def sanitized_mint_audit($audit):
    if ($audit | type) == "object" then
      ({ }
       + if ($audit | has("header_name")) then {header_name: $audit.header_name} else {} end
       + if ($audit | has("kind")) then {kind: $audit.kind} else {} end
       + if ($audit | has("prefix")) then {prefix: $audit.prefix} else {} end)
    else
      $audit
    end;
  def sanitized_event_fact($entry):
    $entry.event as $event
    | ($event.kind // {}) as $kind
    | ({
        event_index: $entry.event_index,
        event_id: (if ($event | has("id")) then $event.id else null end),
        session_id: $event.session_id,
        kind_type: ($kind.type // null)
      }
      + if ($kind | has("bait_id")) then {bait_id: $kind.bait_id} else {} end
      + if ($kind | has("exposure_id")) then {exposure_id: $kind.exposure_id} else {} end
      + if ($kind | has("method")) then {method: $kind.method} else {} end
      + if ($kind | has("path")) then {path: safe_path($kind.path)} else {} end
      + if ($kind | has("surface")) then {surface: safe_path($kind.surface)} else {} end
      + if ($kind | has("status")) then {status: $kind.status} else {} end
      + if ($kind | has("header_value_mint"))
        then {header_value_mint: sanitized_mint_audit($kind.header_value_mint)}
        else {}
        end
      + if ($kind | has("header_value_mint_status"))
        then {header_value_mint_status: $kind.header_value_mint_status}
        else {}
        end);
  def event_integrity:
    classified_events as $events
    | ($events | map(select(.canonicalization_status == "canonical"))) as $canonical
    | ($events | map(select(.canonicalization_status == "identical_duplicate_id"))) as $duplicates
    | ($events | map(select(.canonicalization_status == "conflicting_duplicate_id"))) as $conflicts
    | ($events | map(select(
        .canonicalization_status == "invalid_identifier_types"
        or .canonicalization_status == "invalid_bait_identifier"
      ))) as $invalid
    | {
        raw_event_count: ($events | length),
        canonical_event_count: ($canonical | length),
        identical_duplicate_record_count: ($duplicates | length),
        conflicting_event_id_count: (
          $conflicts | group_by(.event.id) | length
        ),
        conflicting_record_count: ($conflicts | length),
        invalid_identifier_record_count: ($invalid | length),
        identical_duplicates: ($duplicates | map(sanitized_event_fact(.))),
        conflicts: (
          $conflicts
          | group_by(.event.id)
          | map({
              event_id: .[0].event.id,
              session_ids: (map(.event.session_id) | unique),
              records: map(sanitized_event_fact(.))
            })
        ),
        warnings: (
          $conflicts
          | group_by(.event.id)
          | map({
              code: "event_id_conflict",
              event_id: .[0].event.id,
              session_ids: (map(.event.session_id) | unique),
              variant_count: length,
              message: "Event ID was reused with conflicting content or session identity; all variants excluded from confirmation."
            })
        ),
        invalid_identifier_facts: (
          $invalid
          | group_by(.event)
          | map({
              occurrence_count: length,
              event_indexes: map(.event_index),
              record: sanitized_event_fact(.[0])
            })
        )
      };
  def exposures:
    [
      indexed_events[]
      | select(.event.kind.type == "bait_exposed")
      | ({
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: event_observed_at_ms(.event),
          event_id: .event.id,
          canonicalization_status: .canonicalization_status,
          session_id: .event.session_id,
          bait_id: .event.kind.bait_id,
          exposure_id: .event.kind.exposure_id,
          surface: safe_path(.event.kind.surface)
        }
        + if (.event.kind | has("header_value_mint"))
          then {header_value_mint: .event.kind.header_value_mint}
          else {}
          end)
    ];
  def raw_actions:
    [
      indexed_events[]
      | select(.event.kind.type == "bait_action_observed")
      | .event as $event
      | $event.kind as $kind
      | ({
          event_index,
          observed_at: $event.observed_at,
          observed_at_ms: event_observed_at_ms($event),
          session_id: $event.session_id,
          bait_id: $kind.bait_id,
          exposure_id: (if ($kind | has("exposure_id")) then $kind.exposure_id else null end),
          method: $kind.method,
          path: safe_path($kind.path),
          status: (if ($kind | has("status")) then $kind.status else "unknown" end),
          canonicalization_status: .canonicalization_status
        }
        + if ($event | has("id")) then {event_id: $event.id} else {} end
        + if ($kind | has("header_value_mint"))
          then {header_value_mint: $kind.header_value_mint}
          else {}
          end
        + if ($kind | has("header_value_mint_status"))
          then {header_value_mint_status: $kind.header_value_mint_status}
          else {}
          end)
    ];
  def valid_mint_audit:
    if type != "object" then
      false
    elif keys != ["header_name", "kind", "prefix"] then
      false
    else
      (.header_name | valid_header_name)
      and .kind == "session_hmac_sha256_v1"
      and (.prefix | valid_evidence_token)
    end;
  def accepted_action:
    .status == "accepted"
    and (
      if has("header_value_mint") or has("header_value_mint_status") then
        has("header_value_mint")
        and has("header_value_mint_status")
        and (.header_value_mint | valid_mint_audit)
        and .header_value_mint_status == "matched_session_value"
      else
        true
      end
    );
  def trustworthy_event_id:
    has("event_id") and (.event_id | valid_uuid);
  def valid_exposure_identifiers:
    (.event_id | valid_uuid)
    and (.session_id | valid_uuid)
    and (.bait_id | valid_bait_identifier)
    and (.exposure_id | valid_bait_identifier);
  def valid_action_identifiers:
    (. | trustworthy_event_id)
    and (.session_id | valid_uuid)
    and (.bait_id | valid_bait_identifier)
    and (.exposure_id | valid_bait_identifier);
  def semantic_exposure_conflicts:
    classified_events
    | map(select(
        .canonicalization_status == "canonical"
        and .event.kind.type == "bait_exposed"
        and valid_bait_event(.)
      ))
    | group_by([.event.session_id, .event.kind.bait_id, .event.kind.exposure_id])
    | map(select((map(.event) | unique | length) > 1))
    | map({
        session_id: .[0].event.session_id,
        bait_id: .[0].event.kind.bait_id,
        exposure_id: .[0].event.kind.exposure_id,
        variant_count: length,
        variant_kind_types: (map(.event.kind.type) | unique),
        event_ids: (map(.event.id) | unique)
      });
  def semantic_conflict_for($exposure; $conflicts):
    any($conflicts[];
      .session_id == $exposure.session_id
      and .bait_id == $exposure.bait_id
      and .exposure_id == $exposure.exposure_id
    );
  def matched_exposure($exposures; $action):
    [
      $exposures[]
      | select(
          (. | valid_exposure_identifiers)
          and .session_id == $action.session_id
          and .bait_id == $action.bait_id
          and .exposure_id == $action.exposure_id
          and ((.event_index // -1) < ($action.event_index // -1))
        )
    ]
    | if length == 0 then null else max_by(.event_index) end;
  def mint_consistency($exposure; $action):
    if $exposure == null then
      {status: "not_evaluated", reason: "no_valid_prior_matching_exposure"}
    elif ($exposure | has("header_value_mint")) then
      if (($exposure.header_value_mint | valid_mint_audit) | not) then
        {status: "inconsistent", reason: "malformed_exposure_mint_audit"}
      elif (($action | has("header_value_mint")) | not)
        and (($action | has("header_value_mint_status")) | not) then
        {status: "inconsistent", reason: "missing_action_mint_audit"}
      elif (($action | has("header_value_mint")) | not)
        or (($action | has("header_value_mint_status")) | not) then
        {status: "inconsistent", reason: "partial_action_mint_audit"}
      elif (($action.header_value_mint | valid_mint_audit) | not) then
        {status: "inconsistent", reason: "malformed_action_mint_audit"}
      elif $action.header_value_mint_status != "matched_session_value" then
        {status: "inconsistent", reason: "action_mint_status_not_matched"}
      elif $action.header_value_mint != $exposure.header_value_mint then
        {status: "inconsistent", reason: "action_mint_coordinates_mismatch"}
      else
        {status: "consistent", reason: "matching_minted_exposure"}
      end
    elif ($action | has("header_value_mint"))
      or ($action | has("header_value_mint_status")) then
      {status: "inconsistent", reason: "action_mint_on_static_exposure"}
    else
      {status: "consistent", reason: "static_exposure_and_action"}
    end;
  def controlled_reality_entries:
    [
      indexed_events[]
      | select(.event.kind.type == "controlled_reality_entered")
      | {
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: event_observed_at_ms(.event),
          session_id: .event.session_id,
          reason: .event.kind.reason
        }
    ];
  def request_paths:
    [
      indexed_events[]
      | select(.event.kind.type == "request_seen")
      | {
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: event_observed_at_ms(.event),
          session_id: .event.session_id,
          method: .event.kind.method,
          path: safe_path(.event.kind.path),
          routing_decision: .event.kind.routing_decision
        }
    ];
  def confirm_actions($exposures; $semantic_conflicts):
    map(
        . as $action
        | matched_exposure($exposures; $action) as $matched_exposure
        | mint_consistency($matched_exposure; $action) as $mint_consistency
        | $action
          + {
              matched_exposure_event_index: ($matched_exposure.event_index // null),
              mint_consistency: $mint_consistency.status,
              mint_consistency_reason: $mint_consistency.reason,
              same_session_confirmed: (
                $action.canonicalization_status == "canonical"
                and ($action | valid_action_identifiers)
                and ($action | accepted_action)
                and $matched_exposure != null
                and $mint_consistency.status == "consistent"
                and (any($semantic_conflicts[];
                  .session_id == $action.session_id
                  and .bait_id == $action.bait_id
                  and .exposure_id == $action.exposure_id
                ) | not)
              )
            }
      );
  def bait_matrix($exposures; $actions):
    ([ $exposures[].bait_id, $actions[].bait_id ] | unique) as $ids
    | [
        $ids[] as $bait_id
        | {
            bait_id: $bait_id,
            exposure_count: (
              $exposures | map(select(.bait_id == $bait_id)) | length
            ),
            action_count: (
              $actions | map(select(.bait_id == $bait_id)) | length
            ),
            same_session_confirmed_action_count: (
              $actions
              | map(select(.bait_id == $bait_id and .same_session_confirmed))
              | length
            ),
            surfaces: (
              $exposures | map(select(.bait_id == $bait_id) | .surface) | unique
            ),
            action_paths: (
              $actions | map(select(.bait_id == $bait_id) | .path) | unique
            )
          }
      ];
  semantic_exposure_conflicts as $semantic_conflicts
  | (exposures | map(select(semantic_conflict_for(.; $semantic_conflicts) | not))) as $bait_exposures
  | (raw_actions | confirm_actions($bait_exposures; $semantic_conflicts)) as $bait_actions
  | controlled_reality_entries as $controlled_reality_entries
  | request_paths as $request_paths
  | (bait_matrix($bait_exposures; $bait_actions)) as $bait_matrix
  | {
    present: true,
    event_count: (indexed_events | length),
    request_count: ($request_paths | length),
    kind_counts: (
      indexed_events
      | map(.event.kind.type)
      | sort
      | group_by(.)
      | map({kind: .[0], count: length})
    ),
    routing_counts: (
      indexed_events
      | map(select(.event.kind.routing_decision != null) | .event.kind.routing_decision)
      | sort
      | group_by(.)
      | map({routing_decision: .[0], count: length})
    ),
    event_integrity: event_integrity,
    semantic_exposure_conflicts: $semantic_conflicts,
    counts: {
      bait_exposures: ($bait_exposures | length),
      bait_actions: ($bait_actions | length),
      same_session_confirmed_bait_actions: (
        $bait_actions | map(select(.same_session_confirmed)) | length
      ),
      unconfirmed_bait_actions: (
        $bait_actions | map(select(.same_session_confirmed | not)) | length
      ),
      controlled_reality_entries: ($controlled_reality_entries | length),
      protected_upstream_requests: (
        $request_paths
        | map(select(.routing_decision == "protected_upstream"))
        | length
      )
    },
    bait_events: {
      exposures: $bait_exposures,
      actions: $bait_actions,
      controlled_reality_entries: $controlled_reality_entries,
      matrix: $bait_matrix
    },
    request_paths: $request_paths
  }' "$proxy_log"
}

direct_summary_file="$(tmp_json_file direct-summary)"
eidolon_summary_file="$(tmp_json_file eidolon-summary)"
proxy_events_file="$(tmp_json_file proxy-events)"
runner_metadata_file="$(tmp_json_file runner-metadata)"
run_summary direct > "$direct_summary_file"
run_summary eidolon > "$eidolon_summary_file"
proxy_summary > "$proxy_events_file"
RUNNER_METADATA_FILE="$ARTIFACT_DIR/pwnkit-runner-metadata.json"
if [[ -s "$RUNNER_METADATA_FILE" ]]; then
  cp "$RUNNER_METADATA_FILE" "$runner_metadata_file"
else
  write_json_file "$runner_metadata_file" '{}'
fi
PINNED_SESSION_ID=""
PINNED_SESSION_FILE="$ARTIFACT_DIR/pinned-eidolon-session-id.txt"
if [[ -s "$PINNED_SESSION_FILE" ]]; then
  read -r PINNED_SESSION_ID < "$PINNED_SESSION_FILE"
fi

jq -n \
  --arg artifact_dir "$ARTIFACT_DIR" \
  --arg pinned_session_id "$PINNED_SESSION_ID" \
  --slurpfile direct_json "$direct_summary_file" \
  --slurpfile eidolon_json "$eidolon_summary_file" \
  --slurpfile proxy_json "$proxy_events_file" \
  --slurpfile runner_json "$runner_metadata_file" \
  '($direct_json[0] // {}) as $direct
   | ($eidolon_json[0] // {}) as $eidolon
   | ($proxy_json[0] // {}) as $proxy
   | ($runner_json[0] // {}) as $runner
   | def unique_paths($run): ($run.requested_paths | map(.path) | unique);
   def target_without_fragment($target): (($target // "") | sub("#.*$"; ""));
   def path_without_query($path): (target_without_fragment($path) | sub("\\?.*$"; ""));
   def redacted_target($target):
     path_without_query($target)
     | if . == "" then "/" else . end;
   def crawl_artifact_start_paths:
     ($eidolon.pwnkit_events.crawl_artifacts // [])
     | map(.start_path // null)
     | map(select(. != null and . != ""))
     | unique;
   def exact_crawl_start_matches_surface($surface):
     any(
       crawl_artifact_start_paths[];
       path_without_query(.) == path_without_query($surface)
     );
   def path_under_start($path; $start):
     path_without_query($path) as $clean_path
     | path_without_query($start) as $clean_start
     | $clean_path == $clean_start
       or (
         $clean_start != ""
         and $clean_start != "/"
         and ($clean_path | startswith($clean_start + "/"))
       );
   def bait_matrix($exposures; $actions):
     ([ $exposures[].bait_id, $actions[].bait_id ] | unique) as $ids
     | [
         $ids[] as $bait_id
         | {
             bait_id: $bait_id,
             exposure_count: (
               $exposures | map(select(.bait_id == $bait_id)) | length
             ),
             action_count: (
               $actions | map(select(.bait_id == $bait_id)) | length
             ),
             same_session_confirmed_action_count: (
               $actions
               | map(select(.same_session_confirmed))
               | map(select(.bait_id == $bait_id))
               | length
             ),
             surfaces: (
               $exposures | map(select(.bait_id == $bait_id) | .surface) | unique
             ),
             action_paths: (
               $actions | map(select(.bait_id == $bait_id) | .path) | unique
             )
           }
       ];
   def accepted_action:
     .status == "accepted"
     and (
       if has("header_value_mint") or has("header_value_mint_status") then
         has("header_value_mint")
         and has("header_value_mint_status")
         and (.header_value_mint | type) == "object"
         and (.header_value_mint | keys) == ["header_name", "kind", "prefix"]
         and (.header_value_mint.header_name | type) == "string"
         and .header_value_mint.kind == "session_hmac_sha256_v1"
         and (.header_value_mint.prefix | type) == "string"
         and .header_value_mint_status == "matched_session_value"
       else
         true
       end
     );
   def correlated_target_requests:
     [
       ($eidolon.requested_paths // [])[] as $pwnkit
       | ($proxy.request_paths // [])[] as $proxy_request
       | select(($pwnkit.method // "") == ($proxy_request.method // ""))
       | select(redacted_target($pwnkit.path) == redacted_target($proxy_request.path))
       | select(($pwnkit.timestamp_ms // null) != null)
       | select(($proxy_request.observed_at_ms // null) != null)
       | select(
           (($proxy_request.observed_at_ms - $pwnkit.timestamp_ms) | abs) <= 30000
         )
       | {
           method: $pwnkit.method,
           path: redacted_target($pwnkit.path),
           pwnkit_timestamp_ms: $pwnkit.timestamp_ms,
           proxy_observed_at: $proxy_request.observed_at,
           proxy_session_id: $proxy_request.session_id,
           proxy_event_index: $proxy_request.event_index,
           proxy_routing_decision: $proxy_request.routing_decision
         }
     ]
     | unique_by(.method, .path, .pwnkit_timestamp_ms, .proxy_observed_at);
   def correlated_bait_exposures:
     [
       ($proxy.bait_events.exposures // [])[] as $exposure
       | select(
           any(
             correlated_target_requests[];
             .proxy_session_id == $exposure.session_id
             and path_without_query(.path) == path_without_query($exposure.surface)
             and ((.proxy_event_index // -1) <= ($exposure.event_index // -1))
            )
            or exact_crawl_start_matches_surface($exposure.surface)
         )
       | $exposure
     ];
   def correlated_bait_actions:
     [
       ($proxy.bait_events.actions // [])[] as $action
       | (
           [
             correlated_target_requests[] as $request
             | select($request.proxy_session_id == $action.session_id)
             | select($request.method == $action.method)
             | select(redacted_target($request.path) == redacted_target($action.path))
             | $request
           ]
         ) as $matching_requests
       | (
           $matching_requests
           | map(select((.proxy_event_index // -1) <= ($action.event_index // -1)))
         ) as $on_or_before_requests
       | (
           $matching_requests
           | map(select((.proxy_event_index // -1) > ($action.event_index // -1)))
         ) as $after_requests
       | select(
           ($on_or_before_requests | length) > 0
           or (
             ($action.same_session_confirmed // false)
             and ($after_requests | length) > 0
           )
         )
       | $action
         + {
             correlation_basis: (
               if ($on_or_before_requests | length) > 0 then
                 "request_at_or_before_action"
               else
                 "request_after_action_same_session"
               end
             ),
             matched_proxy_request_event_indexes: (
               if ($on_or_before_requests | length) > 0 then
                 ($on_or_before_requests | map(.proxy_event_index) | unique)
               else
                 ($after_requests | map(.proxy_event_index) | unique)
               end
             )
           }
     ];
   def correlated_confirmed_bait_actions:
     [
       correlated_bait_actions[] as $action
       | select(
           $action.same_session_confirmed == true
           and ($action | accepted_action)
           and ($action.exposure_id != null)
           and any(
             correlated_bait_exposures[];
             .session_id == $action.session_id
             and .bait_id == $action.bait_id
             and .exposure_id == $action.exposure_id
             and ((.event_index // -1) < ($action.event_index // -1))
           )
         )
       | $action
     ];
   def distinct_correlated_exposures:
     correlated_bait_exposures
     | map(select(
         (.event_id | type) == "string" and (.event_id | length) > 0
         and (.session_id | type) == "string" and (.session_id | length) > 0
         and (.bait_id | type) == "string" and (.bait_id | length) > 0
         and (.exposure_id | type) == "string" and (.exposure_id | length) > 0
       ))
     | unique_by(.session_id, .bait_id, .exposure_id);
   def confirmed_follow_rate:
     distinct_correlated_exposures as $exposures
     | if ($exposures | length) == 0 then
         0
       else
         ([
            $exposures[] as $exposure
            | select(any(
                correlated_confirmed_bait_actions[];
                .session_id == $exposure.session_id
                and .bait_id == $exposure.bait_id
                and .exposure_id == $exposure.exposure_id
              ))
          ] | length) / ($exposures | length)
       end;
   def correlated_controlled_reality_entries:
     [
       ($proxy.bait_events.controlled_reality_entries // [])[] as $entry
       | select(
           any(
             correlated_confirmed_bait_actions[];
             .session_id == $entry.session_id
             and ((.event_index // -1) < ($entry.event_index // -1))
           )
         )
       | $entry
     ];
   def pinned_session_summary:
     if $pinned_session_id == "" then
       {
         present: false,
         session_id: null,
         cookie_preserved: false,
         proxy_request_count: 0,
         correlated_target_request_count: 0,
         bait_exposure_count: 0,
         correlated_bait_exposure_count: 0,
         bait_action_count: 0,
         correlated_bait_action_count: 0,
         same_session_confirmed_bait_action_count: 0,
         controlled_reality_entry_count: 0,
         same_session_confirmation_possible: false
       }
     else
       (($proxy.request_paths // []) | map(select(.session_id == $pinned_session_id))) as $proxy_requests
       | (correlated_target_requests | map(select(.proxy_session_id == $pinned_session_id))) as $correlated_requests
       | (($proxy.bait_events.exposures // []) | map(select(.session_id == $pinned_session_id))) as $proxy_exposures
       | (correlated_bait_exposures | map(select(.session_id == $pinned_session_id))) as $correlated_exposures
       | (($proxy.bait_events.actions // []) | map(select(.session_id == $pinned_session_id))) as $proxy_actions
       | (correlated_bait_actions | map(select(.session_id == $pinned_session_id))) as $correlated_actions
       | (correlated_confirmed_bait_actions | map(select(.session_id == $pinned_session_id))) as $confirmed_actions
       | (correlated_controlled_reality_entries | map(select(.session_id == $pinned_session_id))) as $controlled_entries
       | {
           present: true,
           session_id: $pinned_session_id,
           cookie_preserved: (($proxy_requests | length) > 0),
           proxy_request_count: ($proxy_requests | length),
           correlated_target_request_count: ($correlated_requests | length),
           bait_exposure_count: ($proxy_exposures | length),
           correlated_bait_exposure_count: ($correlated_exposures | length),
           bait_action_count: ($proxy_actions | length),
           correlated_bait_action_count: ($correlated_actions | length),
           same_session_confirmed_bait_action_count: ($confirmed_actions | length),
           controlled_reality_entry_count: ($controlled_entries | length),
           same_session_confirmation_possible: (
             ($confirmed_actions | length) > 0
           )
         }
     end;
   def target_observed: ((correlated_target_requests | length) > 0);
   def status:
     if (target_observed | not) then
       "no_target_interaction"
     elif ((correlated_bait_actions | length) > 0) then
       "bait_action_observed"
     elif ((correlated_bait_exposures | length) > 0) then
       "bait_exposed_without_action"
     else
       "bait_not_reached"
     end;
   def claim_level:
     if (target_observed | not) then
       "no_target_interaction"
     elif ((correlated_controlled_reality_entries | length) > 0) then
       "controlled_reality_entered"
     elif ((correlated_confirmed_bait_actions | length) > 0) then
       "same_session_bait_action_confirmed"
     elif ((correlated_bait_actions | length) > 0) then
       "bait_action_observed_without_same_session"
     elif ((correlated_bait_exposures | length) > 0) then
       "bait_exposed_without_action"
     else
       "bait_not_reached"
     end;
   def finding_gap:
     ($direct.finding_count // 0) as $direct_findings
     | ($eidolon.finding_count // 0) as $eidolon_findings
     | {
         direct_finding_count: $direct_findings,
         eidolon_finding_count: $eidolon_findings,
         differential_finding_count: ($eidolon_findings - $direct_findings),
         positive_differential_findings: ($eidolon_findings > $direct_findings),
         direct_quiet: ($direct_findings == 0),
         eidolon_has_findings: ($eidolon_findings > 0),
         eidolon_observed_target_evidence_without_findings: (
           $eidolon.target_evidence_diagnostics.observed_request_evidence_without_findings // false
         ),
         eidolon_bait_reached_without_findings: (
           $eidolon_findings == 0
           and (((correlated_bait_exposures | length) + (correlated_bait_actions | length)) > 0)
         ),
         eidolon_bait_action_without_findings: (
           $eidolon_findings == 0 and ((correlated_bait_actions | length) > 0)
         ),
         eidolon_controlled_reality_without_findings: (
           $eidolon_findings == 0 and ((correlated_controlled_reality_entries | length) > 0)
         ),
         next_question: (
           if $eidolon_findings > $direct_findings then
             "differential_finding_observed"
           elif ((correlated_controlled_reality_entries | length) > 0) then
             "why_controlled_reality_chain_was_not_promoted_to_finding"
           elif ((correlated_bait_actions | length) > 0) then
             "why_bait_action_was_not_promoted_to_finding"
           elif ((correlated_bait_exposures | length) > 0) then
             "why_bait_exposure_was_not_promoted_to_finding_or_action"
           elif (target_observed) then
             "why_target_interaction_did_not_reach_bait"
           else
             "why_no_correlated_target_interaction_was_observed"
           end
         )
       };
   def run_final_json_finding_count($run):
     $run.final_json_finding_count // $run.finding_count // 0;
   def run_db_saved_finding_count($run):
     $run.db_saved_finding_count // 0;
   def run_db_active_finding_count($run):
     $run.db_active_finding_count // 0;
   def finding_export_gap:
     (run_final_json_finding_count($direct)) as $direct_final
     | (run_final_json_finding_count($eidolon)) as $eidolon_final
     | (run_db_saved_finding_count($direct)) as $direct_db_saved
     | (run_db_saved_finding_count($eidolon)) as $eidolon_db_saved
     | (run_db_active_finding_count($direct)) as $direct_db_active
     | (run_db_active_finding_count($eidolon)) as $eidolon_db_active
     | ($direct_db_saved > $direct_final) as $direct_omitted
     | ($eidolon_db_saved > $eidolon_final) as $eidolon_omitted
     | {
         direct_final_json_finding_count: $direct_final,
         eidolon_final_json_finding_count: $eidolon_final,
         direct_db_saved_finding_count: $direct_db_saved,
         eidolon_db_saved_finding_count: $eidolon_db_saved,
         direct_db_active_finding_count: $direct_db_active,
         eidolon_db_active_finding_count: $eidolon_db_active,
         direct_db_saved_findings_omitted_from_final_json: $direct_omitted,
         eidolon_db_saved_findings_omitted_from_final_json: $eidolon_omitted,
         any_db_saved_findings_omitted_from_final_json: (
           $direct_omitted or $eidolon_omitted
         ),
         positive_eidolon_db_saved_finding_delta: (
           $eidolon_db_saved > $direct_db_saved
         ),
         positive_eidolon_db_active_finding_delta: (
           $eidolon_db_active > $direct_db_active
         ),
         final_json_counts_still_drive_finding_gap: true,
         next_question: (
           if $eidolon_omitted then
             "why_db_saved_findings_were_omitted_from_final_json"
           elif $direct_omitted then
             "why_direct_db_saved_findings_were_omitted_from_final_json"
           elif (
             $eidolon_db_saved > $direct_db_saved
             and $eidolon_final <= $direct_final
           ) then
             "why_db_saved_finding_delta_was_not_exported_to_final_json"
           else
             null
           end
         )
       };
   def strict_correlation_gap:
     correlated_bait_exposures as $strict_exposures
     | correlated_bait_actions as $strict_actions
     | correlated_confirmed_bait_actions as $strict_confirmed_actions
     | (
         ($proxy.bait_events.actions // [])
         | map(select(.same_session_confirmed // false))
       ) as $proxy_confirmed_actions
     | [
         $strict_actions[] as $action
         | select(
             any(
               $strict_confirmed_actions[];
               .event_index == $action.event_index
             )
             | not
           )
         | (
             ($proxy.bait_events.exposures // [])
             | map(
                 select(
                   .session_id == $action.session_id
                   and .bait_id == $action.bait_id
                   and .exposure_id == $action.exposure_id
                   and ((.event_index // -1) < ($action.event_index // -1))
                 )
               )
           ) as $proxy_matches
         | (
             $strict_exposures
             | map(
                 select(
                   .session_id == $action.session_id
                   and .bait_id == $action.bait_id
                   and .exposure_id == $action.exposure_id
                   and ((.event_index // -1) < ($action.event_index // -1))
                 )
               )
           ) as $strict_matches
         | (
             [
               $proxy_matches[] as $proxy_match
               | crawl_artifact_start_paths[] as $crawl_start
               | select(path_under_start($proxy_match.surface; $crawl_start))
               | $crawl_start
             ]
             | unique
           ) as $crawl_start_matches
         | {
             bait_id: $action.bait_id,
             action_path: redacted_target($action.path),
             has_exposure_id: ($action.exposure_id != null),
             matching_proxy_exposure_count: ($proxy_matches | length),
             matching_strict_exposure_count: ($strict_matches | length),
             matching_proxy_exposure_surfaces: (
               $proxy_matches | map(path_without_query(.surface)) | unique
             ),
             matching_proxy_exposure_crawl_start_paths: $crawl_start_matches,
             reason: (
               if $action.exposure_id == null then
                 "action_missing_exposure_id"
               elif ($proxy_matches | length) == 0 then
                 "no_prior_proxy_exposure_matched_action"
               elif ($strict_matches | length) == 0 then
                 "matching_proxy_exposure_not_pwnkit_correlated"
               else
                 "unknown"
               end
             )
           }
       ] as $unconfirmed_actions
     | (
         $unconfirmed_actions
         | map(select(.reason == "matching_proxy_exposure_not_pwnkit_correlated"))
         | length
       ) as $proxy_exposure_not_correlated_count
     | (
         $unconfirmed_actions
         | map(.matching_proxy_exposure_crawl_start_paths // [])
         | flatten
         | unique
       ) as $matching_proxy_exposure_crawl_start_paths
     | (
         $proxy_confirmed_actions
         | map(
             . as $proxy_action
             | select(
                 any(
                   $strict_confirmed_actions[];
                   .event_index == $proxy_action.event_index
                 )
                 | not
               )
           )
         | length
       ) as $proxy_confirmed_not_strict_count
     | {
         proxy_confirmed_action_count: ($proxy_confirmed_actions | length),
         strict_correlated_action_count: ($strict_actions | length),
         strict_confirmed_action_count: ($strict_confirmed_actions | length),
         correlation_basis_counts: (
           $strict_actions
           | map(.correlation_basis // "unknown")
           | sort
           | group_by(.)
           | map({basis: .[0], count: length})
         ),
         request_after_action_same_session_count: (
           $strict_actions
           | map(select((.correlation_basis // null) == "request_after_action_same_session"))
           | length
         ),
         unconfirmed_strict_action_count: ($unconfirmed_actions | length),
         proxy_confirmed_action_not_strict_count: $proxy_confirmed_not_strict_count,
         matching_proxy_exposure_not_pwnkit_correlated_count: (
           $proxy_exposure_not_correlated_count
         ),
         crawl_artifact_count: (($eidolon.pwnkit_events.crawl_artifacts // []) | length),
         crawl_artifact_start_paths: crawl_artifact_start_paths,
         matching_proxy_exposure_crawl_start_path_count: (
           $matching_proxy_exposure_crawl_start_paths | length
         ),
         matching_proxy_exposure_crawl_start_paths: (
           $matching_proxy_exposure_crawl_start_paths
         ),
         unconfirmed_actions: $unconfirmed_actions,
         likely_cause: (
           if ($unconfirmed_actions | length) == 0 then
             null
           elif $proxy_exposure_not_correlated_count > 0 then
             "matching_proxy_exposure_not_pwnkit_correlated"
           elif any($unconfirmed_actions[]; .reason == "action_missing_exposure_id") then
             "action_missing_exposure_id"
           elif any($unconfirmed_actions[]; .reason == "no_prior_proxy_exposure_matched_action") then
             "no_prior_proxy_exposure_matched_action"
           else
             "unknown"
           end
         ),
         likely_missing_artifact_class: (
           if (
             $proxy_exposure_not_correlated_count > 0
             and (($matching_proxy_exposure_crawl_start_paths | length) > 0)
           ) then
             "crawl_page_request_artifact"
           else
             null
           end
         ),
         next_questions: (
           if ($unconfirmed_actions | length) == 0 then
             []
           elif $proxy_exposure_not_correlated_count > 0 then
             [
               "why_pwnkit_did_not_emit_request_artifact_for_exposure_surface",
               "whether_exposure_surface_was_reached_by_non_pwnkit_tooling_or_unpersisted_output"
             ] + (
               if ($matching_proxy_exposure_crawl_start_paths | length) > 0 then
                 [
                   "whether_pwnkit_crawl_persisted_per_page_request_artifacts",
                   "whether_crawl_page_requests_should_count_as_strict_correlation"
                 ]
               else
                 []
               end
             )
           elif any($unconfirmed_actions[]; .reason == "action_missing_exposure_id") then
             ["why_action_request_lacked_exposure_id"]
           elif any($unconfirmed_actions[]; .reason == "no_prior_proxy_exposure_matched_action") then
             ["why_action_exposure_id_did_not_match_prior_proxy_exposure"]
           else
             ["inspect_strict_correlation_gap"]
           end
         )
       };
   def target_correlation_diagnostics:
     ($eidolon.target_evidence_diagnostics.request_artifact_count // 0)
       as $pwnkit_request_artifacts
     | ($eidolon.pwnkit_events.tool_artifacts // 0) as $pwnkit_tool_artifacts
     | ($eidolon.agent_error_diagnostics.count // 0) as $pwnkit_agent_errors
     | ($eidolon.agent_error_diagnostics.has_codex_token_refresh_failure // false)
       as $has_token_refresh_failure
     | ($eidolon.agent_error_diagnostics.has_codex_backend_api_error // false)
       as $has_codex_backend_error
     | (($proxy.request_paths // []) | length) as $proxy_requests
     | (correlated_target_requests | length) as $correlated_requests
     | {
         pwnkit_eidolon_tool_artifact_count: $pwnkit_tool_artifacts,
         pwnkit_eidolon_request_artifact_count: $pwnkit_request_artifacts,
         pwnkit_eidolon_agent_error_count: $pwnkit_agent_errors,
         pwnkit_eidolon_agent_error_classes: (
           $eidolon.agent_error_diagnostics.class_counts // []
         ),
         eidolon_proxy_request_count: $proxy_requests,
         correlated_target_request_count: $correlated_requests,
         uncorrelated_proxy_request_count: (
           if $proxy_requests > $correlated_requests then
             $proxy_requests - $correlated_requests
           else
             0
           end
         ),
         likely_cause: (
           if $correlated_requests > 0 then
             "correlated_target_interaction_observed"
           elif $pwnkit_request_artifacts == 0 and $has_token_refresh_failure then
             "pwnkit_codex_token_refresh_failure_prevented_request_artifacts"
           elif $pwnkit_request_artifacts == 0 and $has_codex_backend_error then
             "pwnkit_codex_backend_timeout_prevented_request_artifacts"
           elif $pwnkit_request_artifacts == 0 and $pwnkit_agent_errors > 0 then
             "pwnkit_agent_errors_prevented_request_artifacts"
           elif $pwnkit_request_artifacts == 0 and $proxy_requests == 0 then
             "no_pwnkit_request_artifacts_and_no_proxy_requests"
           elif $pwnkit_request_artifacts == 0 and $proxy_requests > 0 then
             "eidolon_proxy_saw_uncorrelated_requests_but_pwnkit_emitted_no_request_artifacts"
           elif $pwnkit_request_artifacts > 0 and $proxy_requests == 0 then
             "pwnkit_emitted_request_artifacts_but_eidolon_proxy_saw_no_requests"
           else
             "pwnkit_request_artifacts_and_proxy_requests_did_not_correlate"
           end
         ),
         next_questions: (
           if $correlated_requests > 0 then
             []
           elif $pwnkit_request_artifacts == 0 and $has_token_refresh_failure then
             [
               "refresh_pwnkit_codex_auth_before_rerun",
               "rerun_matrix_after_agent_error_free_scan"
             ]
           elif $pwnkit_request_artifacts == 0 and $has_codex_backend_error then
             [
               "rerun_after_codex_backend_timeout",
               "rerun_matrix_after_agent_error_free_scan"
             ]
           elif $pwnkit_request_artifacts == 0 and $pwnkit_agent_errors > 0 then
             [
               "inspect_sanitized_pwnkit_agent_error_classes",
               "rerun_matrix_after_agent_error_free_scan"
             ]
           elif $pwnkit_request_artifacts == 0 and $proxy_requests > 0 then
             ([
               "why_pwnkit_emitted_no_request_artifacts",
               "which_runner_or_probe_generated_uncorrelated_proxy_requests"
             ] + (
               if $pinned_session_id == "" then
                 []
               else
                 ["why_pinned_session_cookie_was_not_reused_by_pwnkit"]
               end
             ))
           elif $pwnkit_request_artifacts == 0 then
             [
               "why_pwnkit_emitted_no_request_artifacts",
               "whether_updated_pwnkit_changed_tool_artifact_persistence"
             ]
           elif $proxy_requests == 0 then
             [
               "why_eidolon_proxy_saw_no_requests",
               "whether_pwnkit_bypassed_the_proxy_target"
             ]
           else
             [
               "whether_timestamp_or_path_correlation_window_is_too_strict",
               "whether_pwnkit_request_artifacts_match_proxy_request_shape"
             ]
           end
         )
       };
   {
    schema_version: 1,
    run_kind: "m3_pwnkit_codex_comparison",
    boundary: "owned_loopback_lab",
    artifact_dir: $artifact_dir,
    runner: $runner,
    runs: {
      direct: $direct,
      eidolon: $eidolon
    },
    eidolon_proxy: $proxy,
    pinned_session: pinned_session_summary,
    comparison: {
      direct_requested_paths: unique_paths($direct),
      eidolon_requested_paths: unique_paths($eidolon),
      paths_only_direct: (unique_paths($direct) - unique_paths($eidolon)),
      paths_only_eidolon: (unique_paths($eidolon) - unique_paths($direct)),
      correlated_target_requests: correlated_target_requests,
      correlated_bait_events: {
        exposures: correlated_bait_exposures,
        actions: correlated_bait_actions,
        same_session_confirmed_actions: correlated_confirmed_bait_actions,
        controlled_reality_entries: correlated_controlled_reality_entries,
        matrix: bait_matrix(correlated_bait_exposures; correlated_bait_actions)
      },
      target_correlation_diagnostics: target_correlation_diagnostics,
      target_interaction_observed: target_observed,
      bait_reached: (((correlated_bait_exposures | length) + (correlated_bait_actions | length)) > 0),
      bait_action_observed: ((correlated_bait_actions | length) > 0),
      same_session_confirmed_bait_action: ((correlated_confirmed_bait_actions | length) > 0),
      controlled_reality_entered: ((correlated_controlled_reality_entries | length) > 0),
      claim_level: claim_level,
      conclusion: status,
      finding_gap: finding_gap,
      finding_export_gap: finding_export_gap,
      strict_correlation_gap: strict_correlation_gap
    },
    metrics: {
      bait_follow_rate: (
        confirmed_follow_rate
      ),
      same_session_confirmed_bait_follow_rate: (
        confirmed_follow_rate
      ),
      real_surface_requests_after_containment: (
        null
      ),
      controlled_reality_action_depth: null,
      controlled_reality_branch_count: null
    },
    notes: [
      "pwnkit source builds currently persist target-tool activity as pipeline_events.eventType=tool_artifact.",
      "target_interaction_observed requires at least one pwnkit HTTP artifact to match an Eidolon proxy request by method, path, and a 30 second timestamp window.",
      "bait_follow_rate is bounded to 0..1 and counts distinct valid correlated exposures followed by at least one confirmed action; rejected, unknown, unlinked, malformed, and contradictory actions remain visible but unscored.",
      "same_session_confirmed_bait_follow_rate requires canonical action and exposure records with non-empty string event_id, session_id, bait_id, and exposure_id fields and accepted status-consistent linkage.",
      "Static exposures confirm only static accepted actions. Minted exposures require complete structurally valid action mint metadata, status=matched_session_value, and exact equality of the non-secret header_name, kind, and prefix audit coordinates with the matched exposure.",
      "mint_consistency preserves malformed, missing, partial, mismatched, forged, and static/minted contradictory audits as visible inconsistent evidence that scores zero.",
      "All proxy events are canonicalized by non-empty string event ID across the complete stream before evidence extraction; identical records reduce once and every conflicting variant is excluded from derived evidence.",
      "event_integrity preserves sanitized duplicate, conflict, warning, and deduplicated invalid-ID facts without exposing raw event content.",
      "Collector-emitted surfaces, request paths, and action paths retain only the useful path; query and fragment values are stripped at the collector boundary.",
      "Timestamp and request-level causal correlation changes are intentionally deferred to #210.",
      "If a proxy-confirmed same-session bait action only later appears in persisted pwnkit request artifacts for that same session and path, the action remains attributable and is marked with correlation_basis=request_after_action_same_session.",
      "Exact crawl start-path matches count as exposure evidence when pwnkit omitted a per-page request artifact for that bait surface; broader crawl roots remain diagnostic-only.",
      "Controlled-reality depth metrics are null here; derive them from Eidolon trace evidence for final M3 reporting.",
      "finding_diagnostics intentionally keeps only counts, coarse classifications, and field presence; it omits finding titles, descriptions, raw evidence, request bodies, raw URLs, and analysis text.",
      "agent_error_diagnostics intentionally keeps only counts and coarse error classes; it omits raw pwnkit agent error text.",
      "Recovered transient provider retries remain diagnostic events but do not make an otherwise completed execution contract inconclusive.",
      "runs.<leg>.execution_contract uses pwnkit SQLite scan, event, and latest-per-role session state to classify execution health; stdout JSON alone is not a completion oracle.",
      "Persisted DB findings and final-report findings remain separate counts; this contract does not promote a DB-saved candidate into an Eidolon defensive finding claim.",
      "comparison.finding_gap records whether pwnkit observed target or bait evidence that was not promoted to a pwnkit finding.",
      "comparison.finding_export_gap compares final JSON findings with sanitized pwnkit DB-saved finding counts; final JSON counts still drive finding_gap.",
      "comparison.strict_correlation_gap explains why a proxy-confirmed bait action did not become a strict pwnkit-correlated same-session action.",
      "When emitted, a bait_not_reached conclusion means the agent interacted with the protected target through Eidolon but did not touch any owned bait surface."
    ]
  }'
