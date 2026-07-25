#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-controlled-reality-isolation-kind.sh"

new_fixture() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-isolation-fixture.XXXXXX"
}

write_valid_fixture() {
  local dir="$1"

  cat >"$dir/metadata.json" <<'JSON'
{"flow_started_at":"2026-07-24T17:00:00Z","isolated_pod":"eidolon-isolated-170001","ingress_probe_pod":"eidolon-ingress-170001"}
JSON
  cat >"$dir/baseline.log" <<'LOG'
target=connected
api=connected
metadata=connected
internet=connected
LOG
  cat >"$dir/isolated.log" <<'LOG'
target=blocked
api=blocked
metadata=blocked
internet=blocked
LOG
  printf '%s\n' 'renderer=blocked' >"$dir/ingress.log"
  printf '%s\n' '202' >"$dir/action.status"
  printf '%s\n' '{"job_id":"job_test","write_committed":false}' >"$dir/action.body"
  cat >"$dir/proxy-events.jsonl" <<'JSONL'
{"schema_version":2,"session_id":"session-a","request_id":"request-exposure","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","exposure_id":"exposure-a"}}
{"schema_version":2,"session_id":"session-a","request_id":"request-action","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile"}}
{"schema_version":2,"session_id":"session-a","request_id":"request-action","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","exposure_id":"exposure-a","header_value_mint_status":"matched_session_value"}}
{"schema_version":2,"session_id":"session-a","request_id":"request-action","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality"}}
{"schema_version":2,"session_id":"session-a","request_id":"request-action","kind":{"type":"response_served","status":202,"routing_decision":"controlled_reality","controlled_reality":{"origin_request_id":"request-action"}}}
JSONL
  printf '%s\n' \
    '{"event":"served","request_id":"request-action","status":202}' \
    >"$dir/renderer.jsonl"
  cat >"$dir/flows.jsonl" <<'JSONL'
{"end_time":"2026-07-24T17:00:15Z","action":"Deny","source_name":"eidolon-isolated-170001","source_namespace":"shield-controlled-reality","dest_name":"target-*","dest_namespace":"shield-targets","dest_port":9101,"policies":{"enforced":[{"name":"","trigger":{"name":"controlled-reality-default-deny"}}]}}
{"end_time":"2026-07-24T17:00:15Z","action":"Deny","source_name":"eidolon-isolated-170001","source_namespace":"shield-controlled-reality","dest_name":"PRIVATE NETWORK","dest_namespace":"-","dest_port":6443,"policies":{"enforced":[{"name":"","trigger":{"name":"controlled-reality-default-deny"}}]}}
{"end_time":"2026-07-24T17:00:15Z","action":"Deny","source_name":"eidolon-isolated-170001","source_namespace":"shield-controlled-reality","dest_name":"PUBLIC NETWORK","dest_namespace":"-","dest_port":80,"policies":{"enforced":[{"name":"","trigger":{"name":"controlled-reality-default-deny"}}]}}
{"end_time":"2026-07-24T17:00:15Z","action":"Deny","source_name":"eidolon-isolated-170001","source_namespace":"shield-controlled-reality","dest_name":"PUBLIC NETWORK","dest_namespace":"-","dest_port":443,"policies":{"enforced":[{"name":"","trigger":{"name":"controlled-reality-default-deny"}}]}}
{"end_time":"2026-07-24T17:00:15Z","action":"Deny","source_name":"eidolon-ingress-170001","source_namespace":"shield-system","dest_name":"renderer-*","dest_namespace":"shield-controlled-reality","dest_port":9103,"policies":{"enforced":[{"name":"","trigger":{"name":"controlled-reality-default-deny"}}]}}
JSONL
}

expect_failure() {
  local dir="$1"
  if "$SMOKE_SCRIPT" --validate-fixture "$dir" >/dev/null 2>&1; then
    echo "fixture unexpectedly passed: $dir" >&2
    exit 1
  fi
}

valid="$(new_fixture)"
trap 'rm -rf "$valid" "${bad_dirs[@]:-}"' EXIT
bad_dirs=()
write_valid_fixture "$valid"

"$SMOKE_SCRIPT" --help | grep -Fq 'Runs the live kind boundary proof'
"$SMOKE_SCRIPT" --validate-fixture "$valid" \
  | jq -e '.result == "passed" and .proxy_renderer.renderer_audit_correlated' >/dev/null

bad_baseline="$(new_fixture)"
bad_dirs+=("$bad_baseline")
cp -R "$valid/." "$bad_baseline/"
sed -i.bak 's/target=connected/target=blocked/' "$bad_baseline/baseline.log"
rm "$bad_baseline/baseline.log.bak"
expect_failure "$bad_baseline"

bad_isolation="$(new_fixture)"
bad_dirs+=("$bad_isolation")
cp -R "$valid/." "$bad_isolation/"
sed -i.bak 's/internet=blocked/internet=connected/' "$bad_isolation/isolated.log"
rm "$bad_isolation/isolated.log.bak"
expect_failure "$bad_isolation"

bad_request="$(new_fixture)"
bad_dirs+=("$bad_request")
cp -R "$valid/." "$bad_request/"
sed -i.bak 's/request-action/request-stale/' "$bad_request/renderer.jsonl"
rm "$bad_request/renderer.jsonl.bak"
expect_failure "$bad_request"

missing_flow="$(new_fixture)"
bad_dirs+=("$missing_flow")
cp -R "$valid/." "$missing_flow/"
jq -c 'select(.dest_port != 80)' "$missing_flow/flows.jsonl" \
  >"$missing_flow/flows.filtered"
mv "$missing_flow/flows.filtered" "$missing_flow/flows.jsonl"
expect_failure "$missing_flow"

wrong_source="$(new_fixture)"
bad_dirs+=("$wrong_source")
cp -R "$valid/." "$wrong_source/"
sed -i.bak 's/eidolon-isolated-170001/eidolon-isolated-old/' \
  "$wrong_source/flows.jsonl"
rm "$wrong_source/flows.jsonl.bak"
expect_failure "$wrong_source"

echo "kind controlled-reality isolation fixture tests ok"
