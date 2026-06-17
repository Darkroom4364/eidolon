#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
TRUSTED_ACTOR_HEADER_NAME="${EIDOLON_SHIELD_TRUSTED_ACTOR_HEADER_NAME:-X-Eidolon-Trusted-Actor}"
TRUSTED_ACTOR_HEADER_VALUE="${EIDOLON_SHIELD_TRUSTED_ACTOR_HEADER_VALUE:-docs-crawler}"
TRUSTED_USER_AGENT="${EIDOLON_SHIELD_TRUSTED_USER_AGENT:-eidolon-docs-crawler/1.0}"
PATH_GATE_PATH="${EIDOLON_SHIELD_TRUSTED_PATH_GATE_PATH:-/customer/import-recovery-checklist?topic=imports}"
PATH_GATE_PATH_PREFIX="${EIDOLON_SHIELD_TRUSTED_PATH_GATE_PATH_PREFIX:-/customer/import-recovery-checklist}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-path-gate-orbstack.sh

Performs a live OrbStack smoke check for the local allowlist request-path gate.
It uses the default docs-crawler trust config, sends the correct trusted actor
and crawler user-agent, but targets a baited surface outside the allowlisted
match prefixes. The request must stay baited and emit an explicit
`path_mismatch` local trust rejection.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-path-gate-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

headers_file="$tmp_dir/response.headers"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"

curl_cmd -fsS \
  -D "$headers_file" \
  -o "$tmp_dir/response.body" \
  -H "${TRUSTED_ACTOR_HEADER_NAME}: ${TRUSTED_ACTOR_HEADER_VALUE}" \
  -H "User-Agent: ${TRUSTED_USER_AGENT}" \
  "${edge_url}${PATH_GATE_PATH}"

http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$headers_file")"
[[ "$http_code" == "200" ]] || fail "expected HTTP 200 for trusted path-gate request, got: ${http_code:-none}"

read_proxy_state_file events.jsonl > "$events_file"
read_proxy_state_file debug.jsonl > "$debug_file"

request_json="$(
  jq -c -e -s \
    --arg path_prefix "$PATH_GATE_PATH_PREFIX" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the trusted path-gate request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$request_json")"
[[ -n "$session_id" ]] || fail "trusted path-gate request had no session id"

jq -e '
  (.kind.ingress_identity.source // "") == "none"
  and (.kind.ingress_identity.trust_tier // "") == "none"
  and (.kind.local_ingress_trust_scope_rejection.label // "") == "docs-crawler"
  and (.kind.local_ingress_trust_scope_rejection.reason // "") == "path_mismatch"
  and (.kind.local_ingress_trust_scope_rejection.methods // []) == ["GET"]
  and (.kind.local_ingress_trust_scope_rejection.path_prefixes // []) == ["/docs", "/openapi.json"]
  and (.kind.trusted_ingress_soften_match // null) == null
' <<<"$request_json" >/dev/null \
  || fail "trusted path-gate request unexpectedly matched the local allowlist despite the path mismatch"

surface_debug="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "trusted path-gate session ${session_id} had no surface_action_selected debug record"

jq -e '
  .fields.candidate_surface_action.type == "eidolon_owned"
  and .fields.surface_action.type == "eidolon_owned"
  and .fields.trusted_ingress_softened_surface == false
' <<<"$surface_debug" >/dev/null \
  || fail "trusted path-gate session ${session_id} did not preserve the baited surface after the path gate rejected the local allowlist"

request_debug="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "request_received"))
      | last
    ' "$debug_file"
)" || fail "trusted path-gate session ${session_id} had no request_received debug record"

jq -e '
  (.fields.local_ingress_trust_scope_rejection.reason // "") == "path_mismatch"
' <<<"$request_debug" >/dev/null \
  || fail "trusted path-gate session ${session_id} did not record path_mismatch in request debug output"

echo "trusted-ingress path gate smoke ok: session ${session_id} stayed baited because the local allowlist path scope did not match"
