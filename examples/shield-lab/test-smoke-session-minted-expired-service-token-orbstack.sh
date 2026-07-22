#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-session-minted-expired-service-token-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-session-minted-expired-service-token-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"13131313-1313-1313-1313-131313131313","observed_at":"2026-07-06T10:00:00Z","source":"surface_controller","policy_state":"observe","kind":{"type":"bait_exposed","bait_id":"fake_service_token","exposure_id":"exp-expired","surface":"/docs/service-token","header_value_mint":{"header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"13131313-1313-1313-1313-131313131313","observed_at":"2026-07-06T10:00:00Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"eidolon_owned"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"13131313-1313-1313-1313-131313131313","observed_at":"2026-07-06T10:00:00Z","source":"bait_engine","policy_state":"observe","kind":{"type":"bait_action_observed","bait_id":"fake_service_token","exposure_id":"exp-expired","method":"POST","path":"/api/v2/import/reconcile","header_value_mint":{"header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"},"header_value_mint_status":"expired_session_value"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"13131313-1313-1313-1313-131313131313","observed_at":"2026-07-06T10:00:01Z","source":"proxy","policy_state":"observe","kind":{"type":"response_served","status":202,"routing_decision":"eidolon_owned"}}
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
  "13131313-1313-1313-1313-131313131313")
    cat <<'JSON'
{"contract_version":"2026-07-06.v1","observed_at":"2026-07-06T10:00:00Z","session_id":"13131313-1313-1313-1313-131313131313","request":{"method":"POST","path":"/api/v2/import/reconcile"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"observe","routing_decision":"eidolon_owned","reason":"session-minted bait proof expired before use; unsafe bait action held Eidolon-owned"},"evidence":{"event_schema_version":2,"event_ids":["22222222-2222-2222-2222-222222222222","33333333-3333-3333-3333-333333333333"],"bundle_ref":"session:13131313-1313-1313-1313-131313131313","bait_header_value_mints":[{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"latest_bait_header_value_mint":{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc","status":"expired_session_value"}},"edge_recommendation":{"action":"observe","reason_codes":["eidolon_owned"]}}
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

test_smoke_script_verifies_expired_session_minted_service_token() {
  local temp_dir
  local state_dir
  local output

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_SESSION_MINTED_EXPIRED_SERVICE_TOKEN_SESSION_ID=13131313-1313-1313-1313-131313131313 \
      KUBECTL_BIN="$temp_dir/kubectl" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$SMOKE_SCRIPT"
  )"

  rg -q 'session-minted expired service-token smoke ok:' <<<"$output"
  rg -q '13131313-1313-1313-1313-131313131313' <<<"$output"
  rg -q 'held Eidolon-owned' <<<"$output"
  rg -q 'expired_session_value' <<<"$output"
}

test_smoke_script_verifies_expired_session_minted_service_token

printf 'shield-lab expired session-minted service-token smoke checks passed\n'
