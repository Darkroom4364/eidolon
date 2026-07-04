#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PATH_GATE_SMOKE_SCRIPT="${EIDOLON_SHIELD_PATH_GATE_SMOKE_SCRIPT:-$SCRIPT_DIR/smoke-trusted-ingress-explicit-path-gate-orbstack.sh}"
EXPORT_SCRIPT="${EIDOLON_SHIELD_EXPORT_SCRIPT:-$SCRIPT_DIR/export-edge-decisions-orbstack.sh}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
LOCAL_STATUS_JSON="${EIDOLON_SHIELD_LOCAL_STATUS_JSON:-}"
EDGE_EXPORT_BIN="${EIDOLON_EDGE_EXPORT_BIN:-}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-explicit-path-export-orbstack.sh

Performs a live OrbStack operator-surface smoke check for an authenticated
explicit trusted-ingress path mismatch. It first runs the live explicit
path-gate smoke to produce a real session, then exports that session through
the edge export contract and verifies that the authenticated rule rejection and
deployment-context rule metadata remain visible to operators.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command bash
require_command jq
require_command awk

smoke_output="$(
  EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
    EIDOLON_SHIELD_LOCAL_STATUS_JSON="$LOCAL_STATUS_JSON" \
    EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
    bash "$PATH_GATE_SMOKE_SCRIPT"
)"

session_id="$(
  awk '
    match($0, /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/) {
      print substr($0, RSTART, RLENGTH)
      exit
    }
  ' <<<"$smoke_output"
)"
[[ -n "$session_id" ]] || fail "could not extract session id from path-gate smoke output"

export_output="$(
  EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
    EIDOLON_SHIELD_LOCAL_STATUS_JSON="$LOCAL_STATUS_JSON" \
    EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
    bash "$EXPORT_SCRIPT" --session "$session_id"
)"

jq -e --arg session_id "$session_id" '
  length == 1
  and .[0].session_id == $session_id
  and .[0].ingress_identity.source == "signed_agent"
  and .[0].ingress_identity.trust_tier == "weakly_asserted"
  and .[0].authenticated_ingress_rule_rejection.label == "docs-signed-agent"
  and .[0].authenticated_ingress_rule_rejection.reason == "path_mismatch"
  and .[0].authenticated_ingress_rule_rejection.methods == ["GET"]
  and .[0].authenticated_ingress_rule_rejection.path_prefixes == ["/docs", "/openapi.json"]
  and .[0].authenticated_ingress_rule_rejection.verified_categories == ["AI Assistant"]
  and .[0].deployment_context.authenticated_trusted_ingress_rules[0].label == "docs-signed-agent"
  and .[0].deployment_context.authenticated_trusted_ingress_rules[0].path_prefixes == ["/docs", "/openapi.json"]
  and .[0].deployment_context.authenticated_trusted_ingress_rules[0].verified_categories == ["AI Assistant"]
' <<<"$export_output" >/dev/null \
  || fail "explicit trusted path-gate export did not preserve the authenticated rejection contract"

echo "trusted-ingress explicit path export smoke ok: session ${session_id} preserved path_mismatch in the edge export contract"
