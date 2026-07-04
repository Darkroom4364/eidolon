#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-trusted-ingress-explicit-method-export-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-explicit-method-export-test.XXXXXX"
}

write_fixture_state() {
  local dir="$1"

  cat > "$dir/events.jsonl" <<'JSONL'
{"schema_version":2,"id":"11111111-1111-1111-1111-111111111111","session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","observed_at":"2026-06-20T10:00:01Z","source":"proxy","policy_state":"observe","kind":{"type":"request_seen","method":"POST","path":"/docs?topic=<redacted>","safe_headers":[],"ingress_identity":{"source":"signed_agent","trust_tier":"weakly_asserted","label":"docs-signed-agent"},"authenticated_ingress_rule_rejection":{"label":"docs-signed-agent","source":"signed_agent","trust_tier":"signed_attested","methods":["GET"],"path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"verified_categories":["AI Assistant"],"reason":"method_mismatch"},"routing_decision":"rewritten_upstream"}}
JSONL

  cat > "$dir/cluster-status.json" <<'JSON'
{"bait_profile":{"profile_id":"orbstack_default_m3_catalog","polymorphic_baits":[{"bait_id":"rel_2025_04_b7f2","surface":"/docs/legacy-import","surface_kind":"docs","header_name":"X-Migration-Trace","kind":"session_hmac_sha256_v1","prefix":"mig"}]},"ingress_trust":{"authenticated_trusted_ingress_rules":[{"label":"docs-signed-agent","source":"signed_agent","trust_tier":"signed_attested","path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"verified_categories":["AI Assistant"],"methods":["GET"]}],"trusted_soften_scopes":[]}}
JSON
}

make_stub_bins() {
  local dir="$1"

  cat > "$dir/smoke-explicit-method-gate" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'trusted-ingress explicit method gate smoke ok: session aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa downgraded to weakly_asserted and stayed baited because the authenticated rule method scope did not match'
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
[[ "$session" == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" ]]

printf '%s\n' '{"contract_version":"2026-06-05.v1","observed_at":"2026-06-20T10:00:01Z","session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","request":{"method":"POST","path":"/docs?topic=<redacted>"},"ingress_identity":{"source":"signed_agent","trust_tier":"weakly_asserted","label":"docs-signed-agent"},"authenticated_ingress_rule_rejection":{"label":"docs-signed-agent","source":"signed_agent","trust_tier":"signed_attested","methods":["GET"],"path_prefixes":["/docs","/openapi.json"],"bait_soften_path_prefixes":["/docs"],"verified_categories":["AI Assistant"],"reason":"method_mismatch"},"policy":{"state":"observe","routing_decision":"protected_upstream","reason":"signed agent claim stayed baited after authenticated explicit rule method mismatch"},"evidence":{"event_schema_version":2,"event_ids":["11111111-1111-1111-1111-111111111111"],"bundle_ref":"session:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},"edge_recommendation":{"action":"observe","reason_codes":["protected_upstream"]}}'
SH

  chmod +x "$dir/smoke-explicit-method-gate" "$dir/edge-export"
}

test_smoke_script_proves_method_mismatch_survives_edge_export() {
  local temp_dir
  local state_dir
  local output

  temp_dir="$(new_temp_dir)"
  state_dir="$temp_dir/state"
  mkdir -p "$state_dir"
  write_fixture_state "$state_dir"
  make_stub_bins "$temp_dir"

  output="$(
    EIDOLON_SHIELD_METHOD_GATE_SMOKE_SCRIPT="$temp_dir/smoke-explicit-method-gate" \
      EIDOLON_SHIELD_LOCAL_STATE_DIR="$state_dir" \
      EIDOLON_EDGE_EXPORT_BIN="$temp_dir/edge-export" \
      bash "$SMOKE_SCRIPT"
  )"

  rg -q 'trusted-ingress explicit method export smoke ok:' <<<"$output"
  rg -q 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' <<<"$output"
}

test_smoke_script_proves_method_mismatch_survives_edge_export

printf 'shield-lab trusted ingress explicit method export smoke checks passed\n'
