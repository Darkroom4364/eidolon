#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-session-minted-expired-legacy-import-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-session-minted-expired-legacy-import-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"15151515-1515-1515-1515-151515151515","observed_at":"2026-07-06T10:10:00Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"rel_2025_04_b7f2","exposure_id":"exp-expired-legacy-import","surface":"/docs/legacy-import","header_value_mint":{"header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"}}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"15151515-1515-1515-1515-151515151515","observed_at":"2026-07-06T10:10:00Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"15151515-1515-1515-1515-151515151515","observed_at":"2026-07-06T10:10:00Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"rel_2025_04_b7f2","exposure_id":"exp-expired-legacy-import","method":"POST","path":"/api/v2/import/reconcile","header_value_mint":{"header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},"header_value_mint_status":"expired_session_value"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"15151515-1515-1515-1515-151515151515","observed_at":"2026-07-06T10:10:01Z","source":"proxy","policy_state":"observe","kind":{"type":"response_served","status":404,"routing_decision":"protected_upstream"}}
JSONL
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
  *)
    echo "unexpected kubectl invocation: $*" >&2
    exit 1
    ;;
esac
SH

  cat > "$dir/edge-export" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

events=""
session=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --events)
      events="$2"
      shift 2
      ;;
    --session)
      session="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

[[ -f "$events" ]]
case "$session" in
  "15151515-1515-1515-1515-151515151515")
    cat <<'JSON'
{"contract_version":"2026-07-06.v1","observed_at":"2026-07-06T10:10:00Z","session_id":"15151515-1515-1515-1515-151515151515","request":{"method":"POST","path":"/api/v2/import/reconcile"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"observe","routing_decision":"protected_upstream","reason":"session-minted bait proof expired before use; request left on normal routing path"},"evidence":{"event_schema_version":2,"event_ids":["22222222-2222-2222-2222-222222222222","33333333-3333-3333-3333-333333333333"],"bundle_ref":"session:15151515-1515-1515-1515-151515151515","bait_header_value_mints":[{"bait_id":"rel_2025_04_b7f2","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"}],"latest_bait_header_value_mint":{"bait_id":"rel_2025_04_b7f2","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig","status":"expired_session_value"}},"edge_recommendation":{"action":"observe","reason_codes":["protected_upstream"]}}
JSON
    ;;
  *)
    echo "unexpected session for edge-export stub: $session" >&2
    exit 1
    ;;
esac
SH

  chmod +x "$dir/kubectl" "$dir/edge-export"
}

test_smoke_script_verifies_expired_session_minted_legacy_import() {
  local temp_dir
  local state_dir
  local output

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_LEGACY_IMPORT_SESSION_ID=15151515-1515-1515-1515-151515151515 \
      KUBECTL_BIN="$temp_dir/kubectl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$SMOKE_SCRIPT"
  )"

  rg -q 'session-minted expired legacy-import smoke ok:' <<<"$output"
  rg -q '15151515-1515-1515-1515-151515151515' <<<"$output"
  rg -q 'protected-upstream' <<<"$output"
  rg -q 'expired_session_value' <<<"$output"
}

test_smoke_script_verifies_expired_session_minted_legacy_import

printf 'shield-lab expired session-minted legacy-import smoke checks passed\n'
