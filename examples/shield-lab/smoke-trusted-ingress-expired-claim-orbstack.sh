#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
TRUSTED_INGRESS_SECRET_NAME="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
TRUSTED_INGRESS_SECRET_KEY="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
IDENTITY_SOURCE="${EIDOLON_SHIELD_EXPIRED_TRUSTED_IDENTITY_SOURCE:-signed_agent}"
TRUST_TIER="${EIDOLON_SHIELD_EXPIRED_TRUSTED_TRUST_TIER:-signed_attested}"
IDENTITY_LABEL="${EIDOLON_SHIELD_EXPIRED_TRUSTED_IDENTITY_LABEL:-expired-orbstack-smoke}"
IDENTITY_EXPIRES_AT="${EIDOLON_SHIELD_EXPIRED_TRUSTED_IDENTITY_EXPIRES_AT:-2000-01-01T00:00:00Z}"
OPENAPI_PATH="${EIDOLON_SHIELD_EXPIRED_TRUSTED_OPENAPI_PATH:-/openapi.json}"
OPENAPI_BAIT_PATH="${EIDOLON_SHIELD_EXPIRED_TRUSTED_OPENAPI_BAIT_PATH:-/api/v2/import/reconcile}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-expired-claim-orbstack.sh

Performs a live OrbStack smoke check for explicit trusted-ingress freshness.
It proves that a transport-authenticated but expired ingress identity claim is
degraded and still receives the baited OpenAPI surface instead of being softened.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-ingress-expired-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

openapi_headers="$tmp_dir/openapi.headers"
openapi_body="$tmp_dir/openapi.json"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"

curl_cmd -fsS \
  -D "$openapi_headers" \
  -o "$openapi_body" \
  -H "X-Eidolon-Ingress-Identity-Source: ${IDENTITY_SOURCE}" \
  -H "X-Eidolon-Ingress-Trust-Tier: ${TRUST_TIER}" \
  -H "X-Eidolon-Ingress-Identity-Label: ${IDENTITY_LABEL}" \
  -H "X-Eidolon-Ingress-Identity-Expires-At: ${IDENTITY_EXPIRES_AT}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${OPENAPI_PATH}"

openapi_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$openapi_headers")"
[[ "$openapi_http_code" == "200" ]] || fail "expected HTTP 200 for expired trusted openapi request, got: ${openapi_http_code:-none}"
jq -e --arg bait_path "$OPENAPI_BAIT_PATH" '.paths[$bait_path]' "$openapi_body" >/dev/null \
  || fail "expired trusted ingress request did not receive the baited OpenAPI surface"

read_proxy_state_file events.jsonl > "$events_file"
read_proxy_state_file debug.jsonl > "$debug_file"

request_event_json="$(
  jq -c -e -s \
    --arg path "$OPENAPI_PATH" \
    --arg label "$IDENTITY_LABEL" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "") == $path
          and (.kind.ingress_identity.label // "") == $label
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the expired trusted openapi request in the proxy event log"

session_id="$(jq -r '.session_id // empty' <<<"$request_event_json")"
[[ -n "$session_id" ]] || fail "expired trusted openapi request had no session id"

jq -e \
  --arg expires_at "$IDENTITY_EXPIRES_AT" '
    (.kind.ingress_identity.source // "") == "signed_agent"
    and (.kind.ingress_identity.trust_tier // "") == "weakly_asserted"
    and (.kind.ingress_identity.expires_at // "") == $expires_at
    and (.kind.trusted_ingress_soften_match // null) == null
  ' <<<"$request_event_json" >/dev/null \
  || fail "expired trusted openapi request did not degrade to weakly_asserted without softening"

surface_debug="$(
  jq -c -e -s \
    --arg session_id "$session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "expired trusted openapi session ${session_id} had no surface_action_selected debug record"

jq -e '
  .fields.surface_action.type == "rewritten_upstream"
  and .fields.trusted_ingress_softened_surface == false
' <<<"$surface_debug" >/dev/null \
  || fail "expired trusted openapi session ${session_id} unexpectedly softened the baited surface"

echo "trusted-ingress expired-claim smoke ok: session ${session_id} degraded to weakly_asserted and stayed baited"
