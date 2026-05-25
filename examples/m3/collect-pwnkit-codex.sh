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

run_summary() {
  local label="$1"
  local report_file="$ARTIFACT_DIR/pwnkit-$label.json"
  local db_file="$ARTIFACT_DIR/pwnkit-$label.db"
  local report_json='{}'
  local status="missing"

  if [[ -f "$report_file" ]]; then
    report_json="$(cat "$report_file")"
    status="present"
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

  local agent_errors
  agent_errors="$(sqlite_json "$db_file" \
    "with classified as (
       select
         coalesce(stage, 'unknown') as stage,
         coalesce(agentRole, 'unknown') as agent_role,
         case
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

  local event_count
  local tool_artifacts
  event_count="$(sqlite_scalar "$db_file" "select count(*) from pipeline_events;")"
  tool_artifacts="$(sqlite_scalar "$db_file" "select count(*) from pipeline_events where eventType = 'tool_artifact';")"

  jq -n \
    --arg label "$label" \
    --arg artifact_status "$status" \
    --argjson report "$report_json" \
    --argjson tool_counts "$tool_counts" \
    --argjson http_requests "$http_requests" \
    --argjson bash_http_outputs "$bash_http_outputs" \
    --argjson agent_errors "$agent_errors" \
    --argjson event_count "$event_count" \
    --argjson tool_artifacts "$tool_artifacts" \
    'def path_from_url:
       (.url // "")
       | sub("^https?://[^/]+"; "")
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
             path: $path,
             status: (($http_status.status // null) | if . == null then null else tonumber end),
             source: "bash_http_output",
             evidence_label: $block.label
           }
       ];
     def structured_http_requests:
       $http_requests
       | map(. + {
           path: path_from_url,
           source: "http_request",
           evidence_label: null
         });
     def all_requested_paths:
       (structured_http_requests + bash_output_requests)
       | unique_by(.timestamp_ms, .method, .path, .source, (.evidence_label // ""));
     def findings: ($report.findings // []);
     def finding_count: (findings | length);
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
         observed_request_evidence_without_findings: (
           finding_count == 0 and ((all_requested_paths | length) > 0)
         )
       };
     def agent_error_diagnostics:
       ($agent_errors // []) as $errors
       | {
           count: ($errors | map(.count) | add // 0),
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
           has_agent_error: (($errors | map(.count) | add // 0) > 0),
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
     {
      label: $label,
      artifact_status: $artifact_status,
      target: ($report.target // null),
      scan_depth: ($report.scanDepth // null),
      duration_ms: ($report.durationMs // null),
      finding_count: finding_count,
      finding_diagnostics: finding_diagnostics,
      warnings: ($report.warnings // []),
      pwnkit_events: {
        pipeline_events: $event_count,
        tool_artifacts: $tool_artifacts,
        tool_counts: $tool_counts,
        bash_http_output_requests: (bash_output_requests | length),
        agent_errors: (agent_error_diagnostics.count)
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
  def indexed_events:
    to_entries | map({event_index: .key, event: .value});
  def exposures:
    [
      indexed_events[]
      | select(.event.kind.type == "bait_exposed")
      | {
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: event_observed_at_ms(.event),
          session_id: .event.session_id,
          bait_id: .event.kind.bait_id,
          exposure_id: .event.kind.exposure_id,
          surface: .event.kind.surface
        }
    ];
  def actions:
    [
      indexed_events[]
      | select(.event.kind.type == "bait_action_observed")
      | {
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: event_observed_at_ms(.event),
          session_id: .event.session_id,
          bait_id: .event.kind.bait_id,
          exposure_id: (.event.kind.exposure_id // null),
          method: .event.kind.method,
          path: .event.kind.path
        }
    ];
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
          path: .event.kind.path,
          routing_decision: .event.kind.routing_decision
        }
    ];
  def confirm_actions($exposures):
    map(
      . as $action
      | . + {
          same_session_confirmed: (
            ($action.exposure_id != null)
            and any(
              $exposures[];
              .session_id == $action.session_id
              and .bait_id == $action.bait_id
              and .exposure_id == $action.exposure_id
              and ((.event_index // -1) < ($action.event_index // -1))
            )
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
  exposures as $bait_exposures
  | (actions | confirm_actions($bait_exposures)) as $bait_actions
  | controlled_reality_entries as $controlled_reality_entries
  | request_paths as $request_paths
  | (bait_matrix($bait_exposures; $bait_actions)) as $bait_matrix
  | {
    present: true,
    event_count: length,
    request_count: ($request_paths | length),
    kind_counts: (
      map(.kind.type)
      | sort
      | group_by(.)
      | map({kind: .[0], count: length})
    ),
    routing_counts: (
      map(select(.kind.routing_decision != null) | .kind.routing_decision)
      | sort
      | group_by(.)
      | map({routing_decision: .[0], count: length})
    ),
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

direct_summary="$(run_summary direct)"
eidolon_summary="$(run_summary eidolon)"
proxy_events="$(proxy_summary)"
runner_metadata='{}'
RUNNER_METADATA_FILE="$ARTIFACT_DIR/pwnkit-runner-metadata.json"
if [[ -s "$RUNNER_METADATA_FILE" ]]; then
  runner_metadata="$(cat "$RUNNER_METADATA_FILE")"
fi
PINNED_SESSION_ID=""
PINNED_SESSION_FILE="$ARTIFACT_DIR/pinned-eidolon-session-id.txt"
if [[ -s "$PINNED_SESSION_FILE" ]]; then
  read -r PINNED_SESSION_ID < "$PINNED_SESSION_FILE"
fi

jq -n \
  --arg artifact_dir "$ARTIFACT_DIR" \
  --arg pinned_session_id "$PINNED_SESSION_ID" \
  --argjson direct "$direct_summary" \
  --argjson eidolon "$eidolon_summary" \
  --argjson proxy "$proxy_events" \
  --argjson runner "$runner_metadata" \
  'def unique_paths($run): ($run.requested_paths | map(.path) | unique);
   def target_without_fragment($target): (($target // "") | sub("#.*$"; ""));
   def path_without_query($path): (target_without_fragment($path) | sub("\\?.*$"; ""));
   def redacted_query($query):
     ($query
      | split("&")
      | map(
          select(length > 0)
          | (split("=")[0]) as $key
          | if $key == "" then "<redacted>" else "\($key)=<redacted>" end
        )) as $pairs
     | if ($pairs | length) == 0 then "<redacted>" else ($pairs | join("&")) end;
   def redacted_target($target):
     target_without_fragment($target) as $without_fragment
     | ($without_fragment | sub("\\?.*$"; "")) as $path
     | ($without_fragment
        | if contains("?") then sub("^[^?]*\\?"; "") else null end) as $query
     | $path
       + (if $query == null then "" else "?" + redacted_query($query) end)
       + (if (($target // "") | contains("#")) then "#<redacted>" else "" end);
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
         )
       | $exposure
     ];
   def correlated_bait_actions:
     [
       ($proxy.bait_events.actions // [])[] as $action
       | select(
           any(
             correlated_target_requests[];
             .proxy_session_id == $action.session_id
             and .method == $action.method
             and redacted_target(.path) == redacted_target($action.path)
             and ((.proxy_event_index // -1) <= ($action.event_index // -1))
           )
         )
       | $action
     ];
   def correlated_confirmed_bait_actions:
     [
       correlated_bait_actions[] as $action
       | select(
           ($action.exposure_id != null)
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
             ($correlated_exposures | length) > 0 and ($correlated_actions | length) > 0
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
      finding_gap: finding_gap
    },
    metrics: {
      bait_follow_rate: (
        if ((correlated_bait_exposures | length) > 0)
        then ((correlated_bait_actions | length) / (correlated_bait_exposures | length))
        else 0
        end
      ),
      same_session_confirmed_bait_follow_rate: (
        if ((correlated_bait_exposures | length) > 0)
        then ((correlated_confirmed_bait_actions | length) / (correlated_bait_exposures | length))
        else 0
        end
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
      "bait_follow_rate counts bait-shaped actions whether or not the action preserved the original exposure session.",
      "same_session_confirmed_bait_follow_rate counts only bait actions whose exposure_id matches a prior bait exposure in the same session.",
      "Controlled-reality depth metrics are null here; derive them from Eidolon trace evidence for final M3 reporting.",
      "finding_diagnostics intentionally keeps only counts, coarse classifications, and field presence; it omits finding titles, descriptions, raw evidence, request bodies, raw URLs, and analysis text.",
      "agent_error_diagnostics intentionally keeps only counts and coarse error classes; it omits raw pwnkit agent error text.",
      "comparison.finding_gap records whether pwnkit observed target or bait evidence that was not promoted to a pwnkit finding.",
      "When emitted, a bait_not_reached conclusion means the agent interacted with the protected target through Eidolon but did not touch any owned bait surface."
    ]
  }'
