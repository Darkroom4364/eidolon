#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
METRICS_SCRIPT="$SCRIPT_DIR/metrics-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-metrics-test.XXXXXX"
}

make_stub_bins() {
  local dir="$1"

  cat > "$dir/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  "config current-context")
    printf 'orbstack\n'
    ;;
  "-n shield-system get deploy eidolon-shield-proxy -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-proxy"},"spec":{"replicas":1},"status":{"readyReplicas":1,"availableReplicas":1}}
JSON
    ;;
  "-n shield-system get pods -l app.kubernetes.io/name=eidolon-shield-proxy -o json")
    cat <<'JSON'
{"items":[{"metadata":{"name":"eidolon-shield-proxy-abc"},"status":{"containerStatuses":[{"imageID":"docker://sha256:proxy"}]}}]}
JSON
    ;;
  "-n shield-targets get deploy eidolon-owned-demo-target -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-owned-demo-target"},"spec":{"replicas":2},"status":{"readyReplicas":2,"availableReplicas":2}}
JSON
    ;;
  "-n shield-targets get pods -l app.kubernetes.io/name=eidolon-owned-demo-target -o json")
    cat <<'JSON'
{"items":[
  {"metadata":{"name":"eidolon-owned-demo-target-a"},"status":{"containerStatuses":[{"imageID":"docker://sha256:target-a"}]}},
  {"metadata":{"name":"eidolon-owned-demo-target-b"},"status":{"containerStatuses":[{"imageID":"docker://sha256:target-b"}]}}
]}
JSON
    ;;
  "-n shield-system get svc eidolon-shield-edge -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-edge"},"spec":{"type":"NodePort","ports":[{"name":"http","port":80,"nodePort":31080}]}}
JSON
    ;;
  "-n shield-targets get svc eidolon-owned-demo-target-edge -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-owned-demo-target-edge"},"spec":{"type":"NodePort","ports":[{"name":"http","port":80,"nodePort":31081}]}}
JSON
    ;;
  "-n shield-system get pvc eidolon-shield-proxy-state -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-proxy-state"},"spec":{"storageClassName":"local-path","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}},"status":{"phase":"Bound","capacity":{"storage":"1Gi"},"accessModes":["ReadWriteOnce"]}}
JSON
    ;;
  *)
    echo "unexpected kubectl invocation: $*" >&2
    exit 1
    ;;
esac
SH

  cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"%{http_code}"* ]]; then
  printf '200'
  exit 0
fi
echo "unexpected curl invocation: $*" >&2
exit 1
SH

  chmod +x "$dir/kubectl" "$dir/curl"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-04T00:00:00Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/openapi.json?token=secret","safe_headers":[],"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-04T00:00:01Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"openapi_reconcile_trace","exposure_id":"exp-1234","surface":"/openapi.json?eidolon_surface=secret"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-04T00:00:02Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"openapi_reconcile_trace","exposure_id":"exp-1234","method":"POST","path":"/api/v2/import/reconcile?token=secret"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-04T00:00:03Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-04T00:00:04Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"controlled_reality_entered","reason":"confirmed bait-derived action moved session into controlled reality"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-04T00:00:05Z","source":"proxy","policy_state":"controlled_reality","kind":{"type":"response_served","status":202,"routing_decision":"controlled_reality"}}
{"schema_version":2,"id":"77777777-7777-7777-7777-777777777777","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","observed_at":"2026-06-04T00:00:06Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/health","safe_headers":[],"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"88888888-8888-8888-8888-888888888888","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","observed_at":"2026-06-04T00:00:07Z","source":"proxy","policy_state":"observe","kind":{"type":"response_served","status":200,"routing_decision":"protected_upstream"}}
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"proxy_started","fields":{"listen_addr":"0.0.0.0:9102"},"observed_at_unix_ms":1780521426739,"run_kind":"eidolon_proxy_debug","session_id":null}
{"event":"request_received","fields":{"client_peer":"192.168.194.1:48090","path":"/api/v2/import/reconcile?token=secret"},"observed_at_unix_ms":1780521426740,"run_kind":"eidolon_proxy_debug","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
{"event":"connection_closed_without_request","fields":{"client_peer":"192.168.194.1:48091"},"observed_at_unix_ms":1780521426741,"run_kind":"eidolon_proxy_debug","session_id":null}
JSONL

  cat > "$dir/policy-state.json" <<'JSON'
{
  "schema_version": 1,
  "sessions": [
    {
      "session_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "policy_state": "controlled_reality",
      "controlled_reality_depth": 1
    },
    {
      "session_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "policy_state": "observe",
      "controlled_reality_depth": 0
    }
  ]
}
JSON
}

test_metrics_json_summarizes_event_and_policy_counts() {
  local temp_dir
  local state_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    "$METRICS_SCRIPT" --json \
    | jq -e '
      .edge.url == "http://127.0.0.1:31080"
      and .direct_target_edge.url == "http://127.0.0.1:31081"
      and .event_log.line_count == 8
      and .event_log.kind_counts.request_seen == 2
      and .event_log.kind_counts.bait_exposed == 1
      and .event_log.kind_counts.bait_action_observed == 1
      and .event_log.controlled_reality_entry_count == 1
      and .event_log.response_routing_decision_counts.controlled_reality == 1
      and .event_log.response_routing_decision_counts.protected_upstream == 1
      and (.event_log.request_path_counts | any(.path == "/openapi.json?<redacted>" and .count == 1))
      and (.event_log.request_path_counts | any(.path == "/health" and .count == 1))
      and .debug_log.line_count == 3
      and .debug_log.connection_closed_without_request_count == 1
      and .policy_state.session_count == 2
      and .policy_state.controlled_reality_session_count == 1
      and .policy_state.max_controlled_reality_depth == 1
    ' >/dev/null
}

test_human_metrics_reports_topline_counts() {
  local temp_dir
  local state_dir
  local output
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      "$METRICS_SCRIPT"
  )"

  rg -q '^OrbStack Shield lab metrics$' <<<"$output"
  rg -q 'edge: http://127.0.0.1:31080 \(HTTP 200\)' <<<"$output"
  rg -q 'direct-target: http://127.0.0.1:31081 \(HTTP 200\)' <<<"$output"
  rg -q 'events: 8 total, requests=2, responses=2' <<<"$output"
  rg -q 'bait: exposures=1, actions=1, controlled-reality entries=1' <<<"$output"
  rg -q 'policy-state: 2 tracked, controlled=1, max-depth=1' <<<"$output"
  rg -q 'top paths: /openapi.json\?<redacted>=1, /health=1' <<<"$output"
}

test_metrics_json_handles_missing_state_files() {
  local temp_dir
  local state_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    "$METRICS_SCRIPT" --json \
    | jq -e '
      .event_log.line_count == 0
      and .debug_log.line_count == 0
      and .policy_state.session_count == 0
      and .policy_state.max_controlled_reality_depth == 0
    ' >/dev/null
}

test_metrics_json_summarizes_event_and_policy_counts
test_human_metrics_reports_topline_counts
test_metrics_json_handles_missing_state_files

printf 'shield-lab metrics checks passed\n'
