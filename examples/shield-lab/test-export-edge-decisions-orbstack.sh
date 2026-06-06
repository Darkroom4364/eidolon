#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPORT_SCRIPT="$SCRIPT_DIR/export-edge-decisions-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-edge-decisions-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-05T00:00:00Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/docs","safe_headers":[],"ingress_identity":{"source":"verified_bot","trust_tier":"edge_verified","label":"googlebot"},"routing_decision":"protected_upstream"}}
{"schema_version":2,"id":"22222222-2222-2222-2222-222222222222","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-05T00:00:01Z","source":"policy_router","policy_state":"observe","kind":{"type":"policy_decision","routing_decision":"protected_upstream","reason":"trusted ingress identity suppressed bait surface intervention before runtime suspicion was established"}}
{"schema_version":2,"id":"33333333-3333-3333-3333-333333333333","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","observed_at":"2026-06-05T00:01:00Z","source":"proxy","policy_state":"controlled_reality","kind":{"type":"request_seen","method":"POST","path":"/api/v2/import/reconcile","safe_headers":[],"ingress_identity":{"source":"none","trust_tier":"none"},"routing_decision":"controlled_reality"}}
{"schema_version":2,"id":"44444444-4444-4444-4444-444444444444","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","observed_at":"2026-06-05T00:01:01Z","source":"policy_router","policy_state":"controlled_reality","kind":{"type":"controlled_reality_entered","reason":"confirmed bait-derived action moved session into controlled reality"}}
JSONL
}

make_stub_bins() {
  local dir="$1"

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

if [[ ! -f "$events" ]]; then
  echo "missing events file" >&2
  exit 1
fi

if [[ "$session" == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" ]]; then
  printf '%s\n' '{"contract_version":"2026-06-05.v1","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","edge_recommendation":{"action":"allow","ttl_seconds":300,"reason_codes":["trusted_identity","bait_softened"]}}'
elif [[ "$session" == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" ]]; then
  printf '%s\n' '{"contract_version":"2026-06-05.v1","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","controlled_reality"]}}'
else
  echo "unexpected session $session" >&2
  exit 1
fi
SH

  cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${EDGE_WEBHOOK_LOG:?}"
exit 0
SH

  chmod +x "$dir/edge-export" "$dir/curl"
}

test_exports_all_sessions_as_json_array() {
  local temp_dir state_dir output
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT"
  )"

  jq -e '
    length == 2
    and any(.[]; .session_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" and .edge_recommendation.action == "allow")
    and any(.[]; .session_id == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" and .edge_recommendation.action == "preserve_eidolon_routing")
  ' <<<"$output" >/dev/null
}

test_exports_one_session_as_ndjson() {
  local temp_dir state_dir output
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --format ndjson \
      --session bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
  )"

  jq -e '
    .session_id == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    and .edge_recommendation.action == "preserve_eidolon_routing"
  ' <<<"$output" >/dev/null
}

test_posts_each_export_to_webhook_and_writes_output_file() {
  local temp_dir state_dir output_file webhook_log
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  output_file="$temp_dir/edge-exports.json"
  webhook_log="$temp_dir/webhook.log"
  mkdir -p "$state_dir"
  : > "$webhook_log"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
    EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
    CURL_BIN="$temp_dir/curl" \
    EDGE_WEBHOOK_LOG="$webhook_log" \
    "$EXPORT_SCRIPT" \
    --output "$output_file" \
    --webhook-url https://collector.example.test/eidolon >/dev/null

  [[ -f "$output_file" ]]
  jq -e 'length == 2' "$output_file" >/dev/null
  [[ "$(wc -l < "$webhook_log" | tr -d ' ')" -eq 2 ]]
  rg -q 'https://collector.example.test/eidolon' "$webhook_log"
}

test_fails_when_no_request_seen_sessions_exist() {
  local temp_dir state_dir output status=0
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  cat > "$state_dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","observed_at":"2026-06-05T00:00:01Z","source":"policy_router","policy_state":"observe","kind":{"type":"policy_decision","routing_decision":"protected_upstream","reason":"no request seen"}}
JSONL
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'contains no request_seen sessions to export' <<<"$output"
}

test_exports_all_sessions_as_json_array
test_exports_one_session_as_ndjson
test_posts_each_export_to_webhook_and_writes_output_file
test_fails_when_no_request_seen_sessions_exist

printf 'shield-lab edge export checks passed\n'
