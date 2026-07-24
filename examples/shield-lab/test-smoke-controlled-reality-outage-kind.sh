#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-controlled-reality-outage-kind.sh"

new_fixture() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-outage-fixture.XXXXXX"
}

write_valid_fixture() {
  local dir="$1"

  cat >"$dir/action.meta" <<'META'
action_status=503
cache_control=private, no-store
cache_private=true
cache_no_store=true
eidolon_synthetic=true
META
  printf '%s\n' \
    '{"status":"unavailable","synthetic":true,"write_committed":false,"message":"controlled reality renderer unavailable"}' \
    >"$dir/action.body"
  cat >"$dir/proxy-events.jsonl" <<'JSONL'
{"session_id":"session-a","request_id":"request-exposure","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","exposure_id":"exposure-a"}}
{"session_id":"session-a","request_id":"request-action","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","routing_decision":"eidolon_owned"}}
{"session_id":"session-a","request_id":"request-action","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","exposure_id":"exposure-a","header_value_mint_status":"matched_session_value"}}
{"session_id":"session-a","request_id":"request-action","policy_state":"controlled_reality","kind":{"type":"policy_changed","from":"observe","to":"controlled_reality"}}
{"session_id":"session-a","request_id":"request-action","policy_state":"controlled_reality","kind":{"type":"response_served","status":503,"routing_decision":"eidolon_owned"}}
JSONL
  printf '%s\n' \
    '{"event":"controlled_reality_backend_failed","fields":{"request_id":"request-action","reason":"connect_failed","response_status":503,"local_fallback":false}}' \
    >"$dir/proxy-debug.jsonl"
  cat >"$dir/target-probes.meta" <<'META'
baseline_probe_id=shield-probe-baseline-fixture
outage_probe_id=shield-probe-outage-fixture
META
  cat >"$dir/target-audit.log" <<'LOG'
eidolon-demo-target listening on http://0.0.0.0:9101
{"event":"protected_upstream_probe_observed","method":"POST","probe_id":"shield-probe-baseline-fixture","route":"api_v2_import_reconcile"}
LOG
}

expect_failure() {
  local dir="$1"
  if "$SMOKE_SCRIPT" --validate-fixture "$dir" >/dev/null 2>&1; then
    echo "fixture unexpectedly passed: $dir" >&2
    exit 1
  fi
}

valid="$(new_fixture)"
bad_dirs=()
trap 'rm -rf "$valid" "${bad_dirs[@]:-}"' EXIT
write_valid_fixture "$valid"

"$SMOKE_SCRIPT" --help | grep -Fq 'fails closed'
"$SMOKE_SCRIPT" --validate-fixture "$valid" \
  | jq -e '.result == "passed" and .protected_upstream.outage_requests_observed == 0' \
    >/dev/null

bad_status="$(new_fixture)"
bad_dirs+=("$bad_status")
cp -R "$valid/." "$bad_status/"
sed -i.bak 's/action_status=503/action_status=202/' "$bad_status/action.meta"
rm "$bad_status/action.meta.bak"
expect_failure "$bad_status"

bad_cache="$(new_fixture)"
bad_dirs+=("$bad_cache")
cp -R "$valid/." "$bad_cache/"
sed -i.bak 's/cache_control=private, no-store/cache_control=public, no-store/' \
  "$bad_cache/action.meta"
rm "$bad_cache/action.meta.bak"
expect_failure "$bad_cache"

bad_body="$(new_fixture)"
bad_dirs+=("$bad_body")
cp -R "$valid/." "$bad_body/"
sed -i.bak 's/controlled reality renderer unavailable/temporary outage/' \
  "$bad_body/action.body"
rm "$bad_body/action.body.bak"
expect_failure "$bad_body"

target_reached="$(new_fixture)"
bad_dirs+=("$target_reached")
cp -R "$valid/." "$target_reached/"
printf '%s\n' \
  '{"event":"protected_upstream_probe_observed","method":"POST","probe_id":"shield-probe-outage-fixture","route":"api_v2_import_reconcile"}' \
  >>"$target_reached/target-audit.log"
expect_failure "$target_reached"

target_reached_without_marker="$(new_fixture)"
bad_dirs+=("$target_reached_without_marker")
cp -R "$valid/." "$target_reached_without_marker/"
printf '%s\n' \
  '{"event":"protected_upstream_probe_observed","method":"POST","route":"api_v2_import_reconcile"}' \
  >>"$target_reached_without_marker/target-audit.log"
expect_failure "$target_reached_without_marker"

baseline_missing="$(new_fixture)"
bad_dirs+=("$baseline_missing")
cp -R "$valid/." "$baseline_missing/"
sed -i.bak '/shield-probe-baseline-fixture/d' "$baseline_missing/target-audit.log"
rm "$baseline_missing/target-audit.log.bak"
expect_failure "$baseline_missing"

duplicate_probe_id="$(new_fixture)"
bad_dirs+=("$duplicate_probe_id")
cp -R "$valid/." "$duplicate_probe_id/"
sed -i.bak \
  's/outage_probe_id=shield-probe-outage-fixture/outage_probe_id=shield-probe-baseline-fixture/' \
  "$duplicate_probe_id/target-probes.meta"
rm "$duplicate_probe_id/target-probes.meta.bak"
expect_failure "$duplicate_probe_id"

bad_request_link="$(new_fixture)"
bad_dirs+=("$bad_request_link")
cp -R "$valid/." "$bad_request_link/"
sed -i.bak 's/request-action/request-stale/' "$bad_request_link/proxy-debug.jsonl"
rm "$bad_request_link/proxy-debug.jsonl.bak"
expect_failure "$bad_request_link"

bad_routing="$(new_fixture)"
bad_dirs+=("$bad_routing")
cp -R "$valid/." "$bad_routing/"
sed -i.bak 's/"routing_decision":"eidolon_owned"/"routing_decision":"protected_upstream"/g' \
  "$bad_routing/proxy-events.jsonl"
rm "$bad_routing/proxy-events.jsonl.bak"
expect_failure "$bad_routing"

echo "kind controlled-reality outage fixture tests ok"
