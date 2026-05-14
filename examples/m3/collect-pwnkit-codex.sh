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
    --argjson event_count "$event_count" \
    --argjson tool_artifacts "$tool_artifacts" \
    '{
      label: $label,
      artifact_status: $artifact_status,
      target: ($report.target // null),
      scan_depth: ($report.scanDepth // null),
      duration_ms: ($report.durationMs // null),
      finding_count: (($report.findings // []) | length),
      warnings: ($report.warnings // []),
      pwnkit_events: {
        pipeline_events: $event_count,
        tool_artifacts: $tool_artifacts,
        tool_counts: $tool_counts
      },
      requested_paths: (
        $http_requests
        | map(. + {
            path: (
              (.url // "")
              | sub("^https?://[^/]+"; "")
              | if . == "" then "/" else . end
            )
          })
      )
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
        controlled_reality_entries: 0,
        protected_upstream_requests: 0
      },
      request_paths: []
    }'
    return
  fi

  jq -s 'def observed_at_ms:
    ((.observed_at // "")
     | sub("\\.[0-9]+Z$"; "Z")
     | fromdateiso8601?) as $seconds
    | if $seconds == null then null else ($seconds * 1000) end;
  {
    present: true,
    event_count: length,
    request_count: (map(select(.kind.type == "request_seen")) | length),
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
      bait_exposures: (map(select(.kind.type == "bait_exposed")) | length),
      bait_actions: (map(select(.kind.type == "bait_action_observed")) | length),
      controlled_reality_entries: (map(select(.kind.type == "controlled_reality_entered")) | length),
      protected_upstream_requests: (
        map(select(.kind.type == "request_seen" and .kind.routing_decision == "protected_upstream"))
        | length
      )
    },
    request_paths: (
      map(select(.kind.type == "request_seen") | {
        observed_at: .observed_at,
        observed_at_ms: observed_at_ms,
        method: .kind.method,
        path: .kind.path,
        routing_decision: .kind.routing_decision
      })
    )
  }' "$proxy_log"
}

direct_summary="$(run_summary direct)"
eidolon_summary="$(run_summary eidolon)"
proxy_events="$(proxy_summary)"

jq -n \
  --arg artifact_dir "$ARTIFACT_DIR" \
  --argjson direct "$direct_summary" \
  --argjson eidolon "$eidolon_summary" \
  --argjson proxy "$proxy_events" \
  'def unique_paths($run): ($run.requested_paths | map(.path) | unique);
   def correlated_target_requests:
     [
       ($eidolon.requested_paths // [])[] as $pwnkit
       | ($proxy.request_paths // [])[] as $proxy_request
       | select(($pwnkit.method // "") == ($proxy_request.method // ""))
       | select(($pwnkit.path // "") == ($proxy_request.path // ""))
       | select(($pwnkit.timestamp_ms // null) != null)
       | select(($proxy_request.observed_at_ms // null) != null)
       | select(
           (($proxy_request.observed_at_ms - $pwnkit.timestamp_ms) | abs) <= 30000
         )
       | {
           method: $pwnkit.method,
           path: $pwnkit.path,
           pwnkit_timestamp_ms: $pwnkit.timestamp_ms,
           proxy_observed_at: $proxy_request.observed_at,
           proxy_routing_decision: $proxy_request.routing_decision
         }
     ]
     | unique_by(.method, .path, .pwnkit_timestamp_ms, .proxy_observed_at);
   def target_observed: ((correlated_target_requests | length) > 0);
   def status:
     if (target_observed | not) then
       "no_target_interaction"
     elif (($proxy.counts.bait_actions // 0) > 0) then
       "bait_action_observed"
     elif (($proxy.counts.bait_exposures // 0) > 0) then
       "bait_exposed_without_action"
     else
       "bait_not_reached"
     end;
   {
    schema_version: 0,
    run_kind: "m3_pwnkit_codex_comparison",
    boundary: "owned_loopback_lab",
    artifact_dir: $artifact_dir,
    runs: {
      direct: $direct,
      eidolon: $eidolon
    },
    eidolon_proxy: $proxy,
    comparison: {
      direct_requested_paths: unique_paths($direct),
      eidolon_requested_paths: unique_paths($eidolon),
      paths_only_direct: (unique_paths($direct) - unique_paths($eidolon)),
      paths_only_eidolon: (unique_paths($eidolon) - unique_paths($direct)),
      correlated_target_requests: correlated_target_requests,
      target_interaction_observed: target_observed,
      bait_reached: ((($proxy.counts.bait_exposures // 0) + ($proxy.counts.bait_actions // 0)) > 0),
      conclusion: status
    },
    metrics: {
      bait_follow_rate: (
        if (($proxy.counts.bait_exposures // 0) > 0)
        then (($proxy.counts.bait_actions // 0) / ($proxy.counts.bait_exposures // 1))
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
      "Controlled-reality depth metrics are null here; derive them from Eidolon trace evidence for final M3 reporting.",
      "When emitted, a bait_not_reached conclusion means the agent interacted with the protected target through Eidolon but did not touch any owned bait surface."
    ]
  }'
