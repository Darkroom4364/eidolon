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
{"schema_version":2,"id":"55555555-5555-5555-5555-555555555555","session_id":"cccccccc-cccc-cccc-cccc-cccccccccccc","observed_at":"2026-06-05T00:00:30Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"GET","path":"/openapi.json","safe_headers":[],"ingress_identity":{"source":"local_allowlist","trust_tier":"allowlisted","label":"docs-crawler"},"routing_decision":"rewritten_upstream"}}
{"schema_version":2,"id":"66666666-6666-6666-6666-666666666666","session_id":"cccccccc-cccc-cccc-cccc-cccccccccccc","observed_at":"2026-06-05T00:00:31Z","source":"policy_router","policy_state":"observe","kind":{"type":"policy_decision","routing_decision":"rewritten_upstream","reason":"surface controller rewrote upstream response"}}
JSONL

  cat > "$dir/cluster-status.json" <<'JSON'
{"bait_profile":{"profile_id":"orbstack_default_m3_catalog","polymorphic_baits":[{"bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","surface_kind":"docs","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"},{"bait_id":"openapi_reconcile_trace","surface":"/openapi.json","surface_kind":"open_api","header_name":"X-OpenAPI-Trace","kind":"session_hmac_sha256_v1","prefix":"oapi"},{"bait_id":"fake_service_token","surface":"/docs/service-token","surface_kind":"token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}]},"ingress_trust":{"trusted_soften_scopes":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"]}]}}
JSON
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
  printf '%s\n' '{"contract_version":"2026-06-05.v1","observed_at":"2026-06-05T00:00:00Z","session_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","request":{"method":"GET","path":"/docs/service-token"},"ingress_identity":{"source":"local_allowlist","trust_tier":"allowlisted","label":"docs-crawler"},"trusted_ingress_soften_match":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"request_path_softened":true},"policy":{"state":"observe","routing_decision":"protected_upstream","reason":"trusted ingress identity suppressed bait surface intervention before runtime suspicion was established"},"evidence":{"event_schema_version":2,"event_ids":["11111111-1111-1111-1111-111111111111"],"bundle_ref":"session:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","trusted_ingress_soften_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"saw_request_path_softened":true,"saw_request_path_unsoftened":false}],"bait_header_value_mints":[{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc"}],"latest_bait_header_value_mint":{"bait_id":"fake_service_token","header_name":"X-Api-Key","kind":"session_hmac_sha256_v1","prefix":"svc","status":"matched_session_value"}},"edge_recommendation":{"action":"allow","ttl_seconds":300,"reason_codes":["trusted_identity","bait_softened"]}}'
elif [[ "$session" == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" ]]; then
  printf '%s\n' '{"contract_version":"2026-06-05.v1","observed_at":"2026-06-05T00:01:00Z","session_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","request":{"method":"POST","path":"/api/v2/import/reconcile"},"ingress_identity":{"source":"none","trust_tier":"none"},"policy":{"state":"controlled_reality","routing_decision":"controlled_reality","reason":"confirmed bait-derived action moved session into controlled reality","post_containment_persistence_kind":"controlled_reality_branch_escape"},"evidence":{"event_schema_version":2,"event_ids":["33333333-3333-3333-3333-333333333333"],"bundle_ref":"session:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","trusted_ingress_soften_histories":[{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"saw_request_path_softened":true,"saw_request_path_unsoftened":true}]},"edge_recommendation":{"action":"preserve_eidolon_routing","ttl_seconds":300,"reason_codes":["eidolon_runtime_enforcement","controlled_reality"]}}'
elif [[ "$session" == "cccccccc-cccc-cccc-cccc-cccccccccccc" ]]; then
  printf '%s\n' '{"contract_version":"2026-06-05.v1","observed_at":"2026-06-05T00:00:30Z","session_id":"cccccccc-cccc-cccc-cccc-cccccccccccc","request":{"method":"GET","path":"/openapi.json"},"ingress_identity":{"source":"local_allowlist","trust_tier":"allowlisted","label":"docs-crawler"},"trusted_ingress_soften_match":{"label":"docs-crawler","source":"local_allowlist","trust_tier":"allowlisted","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"request_path_softened":false},"policy":{"state":"observe","routing_decision":"rewritten_upstream","reason":"surface controller rewrote upstream response"},"evidence":{"event_schema_version":2,"event_ids":["55555555-5555-5555-5555-555555555555"],"bundle_ref":"session:cccccccc-cccc-cccc-cccc-cccccccccccc"},"edge_recommendation":{"action":"observe","reason_codes":["rewritten_upstream"]}}'
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
    length == 3
    and any(.[]; .session_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      and .edge_recommendation.action == "allow"
      and .deployment_context.bait_profile_id == "orbstack_default_m3_catalog"
      and .evidence.latest_bait_header_value_mint.status == "matched_session_value"
      and .deployment_context.polymorphic_bait_coverage.active_bait_count == 3
      and .deployment_context.polymorphic_bait_coverage.observed_bait_count == 1
      and .deployment_context.polymorphic_bait_coverage.observed_bait_ids == ["fake_service_token"]
      and .trusted_ingress_soften_match.label == "docs-crawler"
      and .trusted_ingress_soften_match.request_path_softened == true
      and .deployment_context.trusted_ingress_soften_scopes[0].label == "docs-crawler"
      and .deployment_context.trusted_ingress_soften_scopes[0].bait_soften_path_prefixes == ["/docs"])
    and any(.[]; .session_id == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
      and .edge_recommendation.action == "preserve_eidolon_routing"
      and (.deployment_context.polymorphic_baits | length) == 3
      and .deployment_context.polymorphic_bait_coverage.active_bait_count == 3
      and .deployment_context.polymorphic_bait_coverage.observed_bait_count == 0
      and .deployment_context.trusted_ingress_soften_scopes[0].source == "local_allowlist")
    and any(.[]; .session_id == "cccccccc-cccc-cccc-cccc-cccccccccccc"
      and .edge_recommendation.action == "observe"
      and .trusted_ingress_soften_match.label == "docs-crawler"
      and .trusted_ingress_soften_match.request_path_softened == false)
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
    and .deployment_context.polymorphic_baits[0].prefix == "mig"
    and .deployment_context.polymorphic_bait_coverage.active_bait_count == 3
    and .deployment_context.polymorphic_bait_coverage.observed_bait_count == 0
    and .deployment_context.trusted_ingress_soften_scopes[0].path_prefixes == ["/docs", "/openapi.json"]
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
  jq -e '
    length == 3
    and .[0].deployment_context.bait_profile_id == "orbstack_default_m3_catalog"
    and .[0].deployment_context.polymorphic_bait_coverage.active_bait_count == 3
    and .[0].deployment_context.trusted_ingress_soften_scopes[0].trust_tier == "allowlisted"
  ' "$output_file" >/dev/null
  [[ "$(wc -l < "$webhook_log" | tr -d ' ')" -eq 3 ]]
  rg -q 'https://collector.example.test/eidolon' "$webhook_log"
  rg -q 'deployment_context' "$webhook_log"
}

test_limits_to_top_ranked_sessions() {
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
      --top 1
  )"

  jq -e '
    length == 1
    and .[0].session_id == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    and .[0].policy.state == "controlled_reality"
  ' <<<"$output" >/dev/null
}

test_filters_sessions_by_min_polymorphic_coverage() {
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
      --min-polymorphic-coverage 1
  )"

  jq -e '
    length == 1
    and .[0].session_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    and .[0].deployment_context.polymorphic_bait_coverage.observed_bait_count == 1
  ' <<<"$output" >/dev/null
}

test_filters_sessions_by_latest_mint_outcome() {
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
      --latest-mint-outcome matched_session_value
  )"

  jq -e '
    length == 1
    and .[0].session_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    and .[0].evidence.latest_bait_header_value_mint.status == "matched_session_value"
  ' <<<"$output" >/dev/null
}

test_filters_sessions_by_trusted_soften_label() {
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
      --trusted-soften-label docs-crawler
  )"

  jq -e '
    length == 2
    and any(.[]; .session_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      and .trusted_ingress_soften_match.request_path_softened == true)
    and any(.[]; .session_id == "cccccccc-cccc-cccc-cccc-cccccccccccc"
      and .trusted_ingress_soften_match.request_path_softened == false)
  ' <<<"$output" >/dev/null
}

test_filters_sessions_by_trusted_soften_path_softened() {
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
      --trusted-soften-path-softened false
  )"

  jq -e '
    length == 1
    and .[0].session_id == "cccccccc-cccc-cccc-cccc-cccccccccccc"
    and .[0].trusted_ingress_soften_match.request_path_softened == false
  ' <<<"$output" >/dev/null
}

test_filters_sessions_by_trusted_soften_history_label() {
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
      --trusted-soften-history-label docs-crawler
  )"

  jq -e '
    length == 2
    and any(.[]; .session_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      and .evidence.trusted_ingress_soften_histories[0].saw_request_path_softened == true)
    and any(.[]; .session_id == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
      and .evidence.trusted_ingress_soften_histories[0].saw_request_path_unsoftened == true)
  ' <<<"$output" >/dev/null
}

test_filters_sessions_by_trusted_soften_history_path_softened() {
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
      --trusted-soften-history-path-softened false
  )"

  jq -e '
    length == 1
    and .[0].session_id == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    and .[0].evidence.trusted_ingress_soften_histories[0].saw_request_path_unsoftened == true
  ' <<<"$output" >/dev/null
}

test_renders_single_session_markdown_summary() {
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
      --format markdown \
      --session aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
  )"

  rg -q '^# Eidolon Edge Session Summary$' <<<"$output"
  rg -q '## Observed Minted Bait Evidence' <<<"$output"
  rg -q 'fake_service_token' <<<"$output"
  rg -q 'X-Api-Key' <<<"$output"
  rg -q 'Latest minted outcome: `matched_session_value` via `X-Api-Key` \[prefix `svc`, bait `fake_service_token`\]' <<<"$output"
  rg -q '## Active Deployment Polymorphism' <<<"$output"
  rg -q 'orbstack_default_m3_catalog' <<<"$output"
  rg -q 'Coverage: `1/3` active session-minted baits observed' <<<"$output"
  rg -q 'Observed active minted baits: `fake_service_token`' <<<"$output"
  rg -q 'Remaining active minted baits: `rel_2025_04_b7f2`, `openapi_reconcile_trace`' <<<"$output"
  rg -q '/docs/legacy-import' <<<"$output"
  rg -q '/openapi.json' <<<"$output"
  rg -q '/docs/service-token' <<<"$output"
  rg -q 'Trusted soften match: `docs-crawler` \(`local_allowlist` / `allowlisted`\)' <<<"$output"
  rg -q 'Trusted soften scope: soften `/docs`; match `/docs`, `/openapi.json`; request path softened `true`' <<<"$output"
  rg -q 'Trusted soften history: `docs-crawler` \[softened `true`, unsoftened `false`\]' <<<"$output"
  rg -q '## Active Trusted Ingress Softening' <<<"$output"
  rg -q 'Scope `docs-crawler`: soften `/docs`; match `/docs`, `/openapi.json`; identity `local_allowlist` / `allowlisted`' <<<"$output"
}

test_renders_trusted_soften_history_when_current_match_is_absent() {
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
      --format markdown \
      --session bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
  )"

  ! rg -q 'Trusted soften match:' <<<"$output"
  rg -q 'Trusted soften history: `docs-crawler` \[softened `true`, unsoftened `true`\]' <<<"$output"
  rg -q 'Policy state: `controlled_reality`' <<<"$output"
}

test_markdown_requires_single_session_and_no_webhook() {
  local temp_dir state_dir output status=0
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --format markdown 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'markdown export requires --session' <<<"$output"

  status=0
  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --format markdown \
      --session aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
      --webhook-url https://collector.example.test/eidolon 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'markdown export does not support --webhook-url' <<<"$output"
}

test_top_rejects_invalid_combinations() {
  local temp_dir state_dir output status=0
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --top 0 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q -- '--top must be a positive integer' <<<"$output"

  status=0
  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --min-polymorphic-coverage 0 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q -- '--min-polymorphic-coverage must be a positive integer' <<<"$output"

  status=0
  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --latest-mint-outcome wrong-value 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q -- '--latest-mint-outcome must be matched_session_value or session_value_mismatch' <<<"$output"

  status=0
  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --trusted-soften-path-softened maybe 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q -- '--trusted-soften-path-softened must be true or false' <<<"$output"

  status=0
  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --trusted-soften-history-path-softened maybe 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q -- '--trusted-soften-history-path-softened must be true or false' <<<"$output"

  status=0
  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --top 1 \
      --session aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q -- '--top cannot be combined with --session' <<<"$output"
}

test_fails_when_no_sessions_match_min_polymorphic_coverage() {
  local temp_dir state_dir output status=0
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --min-polymorphic-coverage 2 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'no edge decision exports matched --min-polymorphic-coverage 2' <<<"$output"
}

test_fails_when_no_sessions_match_trusted_soften_filters() {
  local temp_dir state_dir output status=0
  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --trusted-soften-label missing-crawler 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'no edge decision exports matched --trusted-soften-label missing-crawler' <<<"$output"

  status=0
  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --trusted-soften-path-softened false \
      --trusted-soften-label googlebot 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'no edge decision exports matched --trusted-soften-label googlebot' <<<"$output"

  status=0
  output="$(
    EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      "$EXPORT_SCRIPT" \
      --trusted-soften-history-label missing-crawler 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'no edge decision exports matched --trusted-soften-history-label missing-crawler' <<<"$output"
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
test_limits_to_top_ranked_sessions
test_filters_sessions_by_min_polymorphic_coverage
test_filters_sessions_by_latest_mint_outcome
test_filters_sessions_by_trusted_soften_label
test_filters_sessions_by_trusted_soften_path_softened
test_filters_sessions_by_trusted_soften_history_label
test_filters_sessions_by_trusted_soften_history_path_softened
test_renders_single_session_markdown_summary
test_renders_trusted_soften_history_when_current_match_is_absent
test_markdown_requires_single_session_and_no_webhook
test_top_rejects_invalid_combinations
test_fails_when_no_sessions_match_min_polymorphic_coverage
test_fails_when_no_sessions_match_trusted_soften_filters
test_fails_when_no_request_seen_sessions_exist

printf 'shield-lab edge export checks passed\n'
