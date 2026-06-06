#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
STATUS_SCRIPT="$SCRIPT_DIR/status-orbstack.sh"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"

JSON_OUTPUT=0

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/metrics-orbstack.sh [--json]

Summarizes lightweight live metrics for the OrbStack Shield lab by combining the
current cluster status with the proxy's PVC-backed event, debug, and policy
state files.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

kubectl_cmd() {
  "$KUBECTL_BIN" "$@"
}

read_proxy_state_file() {
  local basename="$1"

  if [[ -n "$LOCAL_STATE_DIR" ]]; then
    cat "$LOCAL_STATE_DIR/$basename"
    return
  fi

  kubectl_cmd -n shield-system exec deploy/eidolon-shield-proxy -- sh -lc "cat /var/lib/eidolon/$basename"
}

read_jsonl_array() {
  local basename="$1"
  local temp_input="$2"

  if ! read_proxy_state_file "$basename" >"$temp_input" 2>/dev/null; then
    printf '[]\n'
    return
  fi

  if [[ ! -s "$temp_input" ]]; then
    printf '[]\n'
    return
  fi

  jq -s '.' "$temp_input"
}

read_json_object() {
  local basename="$1"
  local temp_input="$2"

  if ! read_proxy_state_file "$basename" >"$temp_input" 2>/dev/null; then
    printf '{"schema_version":null,"sessions":[]}\n'
    return
  fi

  if [[ ! -s "$temp_input" ]]; then
    printf '{"schema_version":null,"sessions":[]}\n'
    return
  fi

  cat "$temp_input"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      JSON_OUTPUT=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

require_command "$KUBECTL_BIN"
require_command jq
require_command "$STATUS_SCRIPT"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-metrics.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

status_json="$("$STATUS_SCRIPT" --json)"
printf '%s\n' "$status_json" >"$tmp_dir/status.json"
read_jsonl_array events.jsonl "$tmp_dir/events.jsonl" >"$tmp_dir/events.json"
read_jsonl_array debug.jsonl "$tmp_dir/debug.jsonl" >"$tmp_dir/debug.json"
read_json_object policy-state.json "$tmp_dir/policy-state.json" >"$tmp_dir/policy.json"

metrics_json="$(jq -n \
  --arg generated_at "$(date -u +%FT%TZ)" \
  --slurpfile status "$tmp_dir/status.json" \
  --slurpfile events "$tmp_dir/events.json" \
  --slurpfile debug "$tmp_dir/debug.json" \
  --slurpfile policy "$tmp_dir/policy.json" \
  '
    ($status[0]) as $status
    | ($events[0]) as $events
    | ($debug[0]) as $debug
    | ($policy[0]) as $policy
    |
    def safe_path:
      if type != "string" then
        .
      else
        (split("#")[0]) as $base
        | if ($base | contains("?")) then
            ($base | split("?")[0]) + "?<redacted>"
          else
            $base
          end
      end;
    def counts_object($values):
      reduce $values[] as $value
        ({};
         .[$value] = (.[$value] // 0) + 1);
    def count_pairs($values; $key_name):
      if ($values | length) == 0 then
        []
      else
        counts_object($values)
        | to_entries
        | map({($key_name): .key, count: .value})
        | sort_by(.count, .[$key_name])
        | reverse
      end;
    def first_or_null($values):
      if ($values | length) == 0 then null else ($values | sort | .[0]) end;
    def last_or_null($values):
      if ($values | length) == 0 then null else ($values | sort | .[-1]) end;

    ($events | map(.kind.type)) as $event_kind_values
    | ($events | map(.policy_state | tostring)) as $event_policy_states
    | ($events | map(select(.kind.type == "request_seen") | .kind.method)) as $request_methods
    | ($events | map(select(.kind.type == "request_seen") | (.kind.path | safe_path))) as $request_paths
    | ($events | map(select(.kind.type == "request_seen") | (.kind.routing_decision | tostring))) as $request_routing_decisions
    | ($events | map(select(.kind.type == "response_served") | (.kind.status | tostring))) as $response_statuses
    | ($events | map(select(.kind.type == "response_served") | ((.kind.status / 100 | floor | tostring) + "xx"))) as $response_status_families
    | ($events | map(select(.kind.type == "response_served") | (.kind.routing_decision | tostring))) as $response_routing_decisions
    | ($events | map(select(.kind.type == "bait_exposed") | (.kind.bait_id | tostring))) as $bait_exposures
    | ($events | map(select(.kind.type == "bait_action_observed") | (.kind.bait_id | tostring))) as $bait_actions
    | ($events | map(.observed_at)) as $event_timestamps
    | ($debug | map(.event)) as $debug_event_values
    | ($debug | map(.observed_at_unix_ms) | map(select(. != null))) as $debug_timestamps
    | ($policy.sessions // []) as $policy_sessions
    | ($policy_sessions | map(.policy_state | tostring)) as $policy_states
    | {
        generated_at: $generated_at,
        context: $status.context,
        edge: $status.edge,
        direct_target_edge: $status.direct_target_edge,
        proxy: $status.proxy,
        target: $status.target,
        proxy_state: $status.proxy_state,
        event_log: {
          line_count: ($events | length),
          first_observed_at: first_or_null($event_timestamps),
          last_observed_at: last_or_null($event_timestamps),
          kind_counts: counts_object($event_kind_values),
          policy_state_counts: counts_object($event_policy_states),
          request_method_counts: counts_object($request_methods),
          request_path_counts: count_pairs($request_paths; "path"),
          request_routing_decision_counts: counts_object($request_routing_decisions),
          response_status_counts: counts_object($response_statuses),
          response_status_family_counts: counts_object($response_status_families),
          response_routing_decision_counts: counts_object($response_routing_decisions),
          bait_exposure_counts: counts_object($bait_exposures),
          bait_action_counts: counts_object($bait_actions),
          bait_action_correlated_count: ($events | map(select(.kind.type == "bait_action_observed" and .kind.exposure_id != null)) | length),
          controlled_reality_entry_count: ($events | map(select(.kind.type == "controlled_reality_entered")) | length),
          rate_limit_applied_count: ($events | map(select(.kind.type == "rate_limit_applied")) | length),
          reality_escape_attempt_count: ($events | map(select(.kind.type == "reality_escape_attempt")) | length)
        },
        debug_log: {
          line_count: ($debug | length),
          first_observed_at_unix_ms: first_or_null($debug_timestamps),
          last_observed_at_unix_ms: last_or_null($debug_timestamps),
          event_counts: counts_object($debug_event_values),
          connection_closed_without_request_count: ($debug | map(select(.event == "connection_closed_without_request")) | length)
        },
        policy_state: {
          schema_version: ($policy.schema_version // null),
          session_count: ($policy_sessions | length),
          state_counts: counts_object($policy_states),
          controlled_reality_session_count: ($policy_sessions | map(select(.policy_state == "controlled_reality")) | length),
          max_controlled_reality_depth: (($policy_sessions | map(.controlled_reality_depth // 0) | max) // 0)
        }
      }
  ')"

if [[ "$JSON_OUTPUT" -eq 1 ]]; then
  printf '%s\n' "$metrics_json"
  exit 0
fi

jq -r '
  def count_or_zero($object; $key):
    ($object[$key] // 0);
  def top_paths:
    (.event_log.request_path_counts[:3] // [])
    | if length == 0 then
        "none"
      else
        map("\(.path)=\(.count)") | join(", ")
      end;

  "OrbStack Shield lab metrics",
  "edge: \(.edge.url // "unavailable") (" +
    (if .edge.http_status == null then "unreachable" else "HTTP \(.edge.http_status)" end) +
    ")",
  "direct-target: \(.direct_target_edge.url // "unavailable") (" +
    (if .direct_target_edge.http_status == null then "unreachable" else "HTTP \(.direct_target_edge.http_status)" end) +
    ")",
  "proxy: \(.proxy.ready_replicas)/\(.proxy.replicas) ready, target: \(.target.ready_replicas)/\(.target.replicas) ready",
  "events: \(.event_log.line_count) total, requests=\(count_or_zero(.event_log.kind_counts; "request_seen")), responses=\(count_or_zero(.event_log.kind_counts; "response_served"))",
  "bait: exposures=\(count_or_zero(.event_log.kind_counts; "bait_exposed")), actions=\(count_or_zero(.event_log.kind_counts; "bait_action_observed")), controlled-reality entries=\(.event_log.controlled_reality_entry_count)",
  "responses: controlled=\(count_or_zero(.event_log.response_routing_decision_counts; "controlled_reality")), rewritten=\(count_or_zero(.event_log.response_routing_decision_counts; "rewritten_upstream")), owned=\(count_or_zero(.event_log.response_routing_decision_counts; "eidolon_owned")), protected=\(count_or_zero(.event_log.response_routing_decision_counts; "protected_upstream")), rate-limited=\(count_or_zero(.event_log.response_routing_decision_counts; "rate_limited"))",
  "policy-state: \(.policy_state.session_count) tracked, controlled=\(.policy_state.controlled_reality_session_count), max-depth=\(.policy_state.max_controlled_reality_depth)",
  "debug: \(.debug_log.line_count) lines, connection_closed_without_request=\(.debug_log.connection_closed_without_request_count)",
  "top paths: \(top_paths)"
' <<<"$metrics_json"
