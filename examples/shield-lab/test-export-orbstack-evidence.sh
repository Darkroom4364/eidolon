#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPORT_SCRIPT="$SCRIPT_DIR/export-orbstack-evidence.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-export-test.XXXXXX"
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
{"items":[{"metadata":{"name":"eidolon-owned-demo-target-a"},"status":{"containerStatuses":[{"imageID":"docker://sha256:target"}]}}]}
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
JSONL

  cat > "$dir/debug.jsonl" <<'JSONL'
{"event":"proxy_started","fields":{"listen_addr":"0.0.0.0:9102","upstream":"http://eidolon-owned-demo-target.shield-targets.svc.cluster.local:9101"},"observed_at_unix_ms":1780521426739,"run_kind":"eidolon_proxy_debug","session_id":null}
{"event":"request_received","fields":{"client_peer":"192.168.194.1:48090","path":"/api/v2/import/reconcile?token=secret"},"observed_at_unix_ms":1780521426740,"run_kind":"eidolon_proxy_debug","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
JSONL

  cat > "$dir/policy-state.json" <<'JSON'
{
  "schema_version": 1,
  "sessions": [
    {
      "session_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "policy_state": "controlled_reality",
      "controlled_reality_depth": 1
    }
  ]
}
JSON
}

test_export_bundle_redacts_sensitive_values() {
  local temp_dir
  local state_dir
  local bundle_dir
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  KUBECTL_BIN="$temp_dir/kubectl" \
    CURL_BIN="$temp_dir/curl" \
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    "$EXPORT_SCRIPT" "$bundle_dir" >/dev/null

  [[ -f "$bundle_dir/README.md" ]]
  [[ -f "$bundle_dir/cluster-status.json" ]]
  [[ -f "$bundle_dir/events.redacted.jsonl" ]]
  [[ -f "$bundle_dir/debug.redacted.jsonl" ]]
  [[ -f "$bundle_dir/policy-state.redacted.json" ]]
  [[ -f "$bundle_dir/SHA256SUMS" ]]

  ! rg -q 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa|11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|secret|192.168.194.1:48090|http://eidolon-owned-demo-target' "$bundle_dir"

  jq -e '
    .edge.url == "http://127.0.0.1:31080"
    and .proxy_state.status == "Bound"
  ' "$bundle_dir/cluster-status.json" >/dev/null

  jq -e '
    .sessions == [
      {
        session_id: "<redacted>",
        policy_state: "controlled_reality",
        controlled_reality_depth: 1
      }
    ]
  ' "$bundle_dir/policy-state.redacted.json" >/dev/null

  rg -q 'events.redacted.jsonl' "$bundle_dir/SHA256SUMS"
  rg -q 'debug.redacted.jsonl' "$bundle_dir/SHA256SUMS"
  rg -q 'policy-state.redacted.json' "$bundle_dir/SHA256SUMS"
  rg -q 'Redacted event log lines: `2`' "$bundle_dir/README.md"
  rg -q 'Direct target URL: `http://127.0.0.1:31081` \(HTTP `200`\)' "$bundle_dir/README.md"
}

test_export_refuses_non_empty_bundle_dir() {
  local temp_dir
  local state_dir
  local bundle_dir
  local output
  local status=0
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  bundle_dir="$temp_dir/bundle"
  mkdir -p "$state_dir" "$bundle_dir"
  printf 'existing\n' > "$bundle_dir/existing.txt"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      "$EXPORT_SCRIPT" "$bundle_dir" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'bundle directory must be empty' <<<"$output"
}

test_export_bundle_redacts_sensitive_values
test_export_refuses_non_empty_bundle_dir

printf 'shield-lab export checks passed\n'
