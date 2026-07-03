#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
TRUSTED_INGRESS_SECRET_NAME="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
TRUSTED_INGRESS_SECRET_KEY="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
IDENTITY_SOURCE="${EIDOLON_SHIELD_EXPLICIT_PATH_GATE_IDENTITY_SOURCE:-signed_agent}"
TRUST_TIER="${EIDOLON_SHIELD_EXPLICIT_PATH_GATE_TRUST_TIER:-signed_attested}"
IDENTITY_LABEL="${EIDOLON_SHIELD_EXPLICIT_PATH_GATE_LABEL:-docs-signed-agent}"
VERIFIED_CATEGORY="${EIDOLON_SHIELD_EXPLICIT_PATH_GATE_VERIFIED_CATEGORY:-AI Assistant}"
PATH_GATE_PATH="${EIDOLON_SHIELD_EXPLICIT_PATH_GATE_PATH:-/customer/import-recovery-checklist?topic=imports}"
PATH_GATE_PATH_PREFIX="${EIDOLON_SHIELD_EXPLICIT_PATH_GATE_PATH_PREFIX:-/customer/import-recovery-checklist}"
PATH_GATE_BAIT_MARKER="${EIDOLON_SHIELD_EXPLICIT_PATH_GATE_BAIT_MARKER:-X-Migration-Trace}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-explicit-path-gate-orbstack.sh

Performs a live OrbStack smoke check for an authenticated explicit trusted-
ingress rule path mismatch. It sends a transport-authenticated signed-agent
claim with the right label and verified category, but targets a baited surface
outside the configured explicit rule path prefixes. The request must be
downgraded, stay baited, and emit an explicit `path_mismatch` authenticated
rule rejection.
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

kubectl_cmd() {
  "$KUBECTL_BIN" "$@"
}

curl_cmd() {
  "$CURL_BIN" "$@"
}

read_proxy_state_file() {
  local basename="$1"

  if [[ -n "$LOCAL_STATE_DIR" ]]; then
    cat "$LOCAL_STATE_DIR/$basename"
    return
  fi

  kubectl_cmd -n shield-system exec deploy/eidolon-shield-proxy -- sh -lc "cat /var/lib/eidolon/$basename"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command "$KUBECTL_BIN"
require_command "$CURL_BIN"
require_command jq
require_command base64
require_command mktemp
require_command awk
require_command grep

context="$(kubectl_cmd config current-context)"
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  fail "expected kubectl current-context to be ${EXPECTED_CONTEXT}, got: ${context}"
fi

edge_svc_json="$(kubectl_cmd -n shield-system get svc eidolon-shield-edge -o json)"
edge_node_port="$(jq -r '.spec.ports[] | select(.name == "http") | (.nodePort // empty)' <<<"$edge_svc_json")"
[[ -n "$edge_node_port" ]] || fail "shield edge service has no http NodePort"
edge_url="http://${EDGE_HOST}:${edge_node_port}"

secret_json="$(kubectl_cmd -n shield-system get secret "$TRUSTED_INGRESS_SECRET_NAME" -o json)"
transport_auth_secret="$(jq -r --arg key "$TRUSTED_INGRESS_SECRET_KEY" '.data[$key] // empty' <<<"$secret_json" | base64 --decode)"
[[ -n "$transport_auth_secret" ]] || fail "trusted ingress secret key ${TRUSTED_INGRESS_SECRET_KEY} is empty"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-explicit-path-gate.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

headers_file="$tmp_dir/response.headers"
body_file="$tmp_dir/response.body"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"

curl_cmd -fsS \
  -D "$headers_file" \
  -o "$body_file" \
  -H "X-Eidolon-Ingress-Identity-Source: ${IDENTITY_SOURCE}" \
  -H "X-Eidolon-Ingress-Trust-Tier: ${TRUST_TIER}" \
  -H "X-Eidolon-Ingress-Identity-Label: ${IDENTITY_LABEL}" \
  -H "X-Eidolon-Ingress-Verified-Category: ${VERIFIED_CATEGORY}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${PATH_GATE_PATH}"

http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$headers_file")"
[[ "$http_code" == "200" ]] || fail "expected HTTP 200 for explicit trusted path-gate request, got: ${http_code:-none}"
grep -Fq "$PATH_GATE_BAIT_MARKER" "$body_file" \
  || fail "explicit trusted path-gate request did not receive the baited surface"

read_proxy_state_file events.jsonl > "$events_file"
read_proxy_state_file debug.jsonl > "$debug_file"

request_json="$(
  jq -c -e -s \
    --arg path_prefix "$PATH_GATE_PATH_PREFIX" \
    --arg label "$IDENTITY_LABEL" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
          and (.kind.ingress_identity.label // "") == $label
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the explicit trusted path-gate request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$request_json")"
[[ -n "$session_id" ]] || fail "explicit trusted path-gate request had no session id"

jq -e '
  (.kind.ingress_identity.source // "") == "signed_agent"
  and (.kind.ingress_identity.trust_tier // "") == "weakly_asserted"
  and (.kind.authenticated_ingress_rule_rejection.label // "") == "docs-signed-agent"
  and (.kind.authenticated_ingress_rule_rejection.reason // "") == "path_mismatch"
  and (.kind.authenticated_ingress_rule_rejection.methods // []) == ["GET"]
  and (.kind.authenticated_ingress_rule_rejection.path_prefixes // []) == ["/docs", "/openapi.json"]
  and (.kind.authenticated_ingress_rule_rejection.verified_categories // []) == ["AI Assistant"]
  and (.kind.trusted_ingress_soften_match // null) == null
' <<<"$request_json" >/dev/null \
  || fail "explicit trusted path-gate request did not downgrade and record path_mismatch"

surface_debug="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "explicit trusted path-gate session ${session_id} had no surface_action_selected debug record"

jq -e '
  .fields.candidate_surface_action.type == "eidolon_owned"
  and .fields.surface_action.type == "eidolon_owned"
  and .fields.trusted_ingress_softened_surface == false
' <<<"$surface_debug" >/dev/null \
  || fail "explicit trusted path-gate session ${session_id} did not preserve the baited surface"

request_debug="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "request_received"))
      | last
    ' "$debug_file"
)" || fail "explicit trusted path-gate session ${session_id} had no request_received debug record"

jq -e '
  (.fields.authenticated_ingress_rule_rejection.reason // "") == "path_mismatch"
' <<<"$request_debug" >/dev/null \
  || fail "explicit trusted path-gate session ${session_id} did not record path_mismatch in request debug output"

echo "trusted-ingress explicit path gate smoke ok: session ${session_id} downgraded to weakly_asserted and stayed baited because the authenticated rule path scope did not match"
