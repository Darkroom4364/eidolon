#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-controlled-reality-escape-kind.sh"

new_fixture() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-kind-escape-fixture.XXXXXX"
}

write_valid_fixture() {
  local dir="$1"

  cat >"$dir/probe-ids.meta" <<'META'
baseline_probe_id=shield-probe-baseline-fixture
escape_probe_id=shield-probe-escape-fixture
META
  cat >"$dir/target-identity.meta" <<'META'
pod_uid_stable=true
restart_count_stable=true
META
  printf '%s\n' 'target_status=202' >"$dir/baseline.log"
  cat >"$dir/escape.log" <<'LOG'
entry_status=202
entry_write_committed=false
first_escape_status=404
first_escape_synthetic=true
second_escape_status=403
LOG
  cat >"$dir/target-audit.log" <<'LOG'
eidolon-demo-target listening on http://0.0.0.0:9101
{"event":"protected_upstream_probe_observed","method":"POST","probe_id":"shield-probe-baseline-fixture","route":"api_v1_imports"}
LOG
  cat >"$dir/proxy-events.jsonl" <<'JSONL'
{"session_id":"session-a","request_id":"request-exposure","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","exposure_id":"exposure-a"}}
{"session_id":"session-a","request_id":"request-entry","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","path":"/api/v2/import/reconcile","exposure_id":"exposure-a","header_value_mint_status":"matched_session_value"}}
{"session_id":"session-a","request_id":"request-first","policy_state":"controlled_reality","kind":{"type":"reality_escape_attempt","method":"POST","path":"/api/v1/imports","routing_decision":"controlled_reality"}}
{"session_id":"session-a","request_id":"request-first","policy_state":"controlled_reality","kind":{"type":"response_served","status":404,"routing_decision":"controlled_reality"}}
{"session_id":"session-a","request_id":"request-second","policy_state":"controlled_reality","kind":{"type":"reality_escape_attempt","method":"POST","path":"/api/v1/imports","routing_decision":"controlled_reality"}}
{"session_id":"session-a","request_id":"request-second","policy_state":"blocked","persistence":{"post_containment_persistence_kind":"controlled_reality_branch_escape"},"kind":{"type":"policy_changed","from":"controlled_reality","to":"blocked"}}
{"session_id":"session-a","request_id":"request-second","policy_state":"blocked","kind":{"type":"response_served","status":403,"routing_decision":"eidolon_owned"}}
JSONL
  printf '%s\n' \
    '{"event":"served","request_id":"request-first","status":404}' \
    >"$dir/renderer.jsonl"
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

"$SMOKE_SCRIPT" --help | grep -Fq 'zero protected-upstream write requests'
"$SMOKE_SCRIPT" --validate-fixture "$valid" \
  | jq -e '
      .result == "passed"
      and .escape.attempts == 2
      and .protected_upstream.escape_requests_observed == 0
    ' >/dev/null

for mutation in target_leak stripped_marker missing_baseline wrong_routing \
  missing_escape duplicate_request restarted_target
do
  dir="$(new_fixture)"
  bad_dirs+=("$dir")
  cp -R "$valid/." "$dir/"
  case "$mutation" in
    target_leak)
      printf '%s\n' \
        '{"event":"protected_upstream_probe_observed","method":"POST","probe_id":"shield-probe-escape-fixture","route":"api_v1_imports"}' \
        >>"$dir/target-audit.log"
      ;;
    stripped_marker)
      printf '%s\n' \
        '{"event":"protected_upstream_probe_observed","method":"POST","route":"api_v1_imports"}' \
        >>"$dir/target-audit.log"
      ;;
    missing_baseline)
      sed -i.bak '/shield-probe-baseline-fixture/d' "$dir/target-audit.log"
      rm "$dir/target-audit.log.bak"
      ;;
    wrong_routing)
      sed -i.bak \
        '3s/"routing_decision":"controlled_reality"/"routing_decision":"protected_upstream"/' \
        "$dir/proxy-events.jsonl"
      rm "$dir/proxy-events.jsonl.bak"
      ;;
    missing_escape)
      sed -i.bak '/request-first/d' "$dir/proxy-events.jsonl"
      rm "$dir/proxy-events.jsonl.bak"
      ;;
    duplicate_request)
      sed -i.bak 's/request-second/request-first/g' "$dir/proxy-events.jsonl"
      rm "$dir/proxy-events.jsonl.bak"
      ;;
    restarted_target)
      sed -i.bak 's/restart_count_stable=true/restart_count_stable=false/' \
        "$dir/target-identity.meta"
      rm "$dir/target-identity.meta.bak"
      ;;
  esac
  expect_failure "$dir"
done

echo "kind controlled-reality escape fixture tests ok"
