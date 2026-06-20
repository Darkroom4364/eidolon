#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
TRUSTED_INGRESS_SECRET_NAME="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
TRUSTED_INGRESS_SECRET_KEY="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
IDENTITY_SOURCE="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_IDENTITY_SOURCE:-signed_agent}"
TRUST_TIER="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_TRUST_TIER:-signed_attested}"
IDENTITY_LABEL="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_LABEL:-docs-signed-agent}"
VERIFIED_CATEGORY="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_VERIFIED_CATEGORY:-AI Assistant}"
DOCS_PATH="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_DOCS_PATH:-/docs?topic=imports}"
DOCS_PATH_PREFIX="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_DOCS_PATH_PREFIX:-/docs}"
DOCS_BAIT_MARKER="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_DOCS_BAIT_MARKER:-/docs/legacy-import}"
OPENAPI_PATH="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_OPENAPI_PATH:-/openapi.json}"
OPENAPI_BAIT_PATH="${EIDOLON_SHIELD_EXPLICIT_RULE_SPECIFICITY_OPENAPI_BAIT_PATH:-/api/v2/import/reconcile}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-explicit-rule-specificity-orbstack.sh

Performs a live OrbStack smoke check for overlapping authenticated explicit
trusted-ingress rules. It proves the more specific docs/category-scoped rule
drives the explicit soften-match metadata on `/docs`, while the broader
overlapping rule still leaves `/openapi.json` on the generic strong-identity
softening path with no explicit soften-match record.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-explicit-specificity-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

docs_headers="$tmp_dir/docs.headers"
docs_body="$tmp_dir/docs.body"
openapi_headers="$tmp_dir/openapi.headers"
openapi_body="$tmp_dir/openapi.json"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"

curl_cmd -fsS \
  -D "$docs_headers" \
  -o "$docs_body" \
  -H "X-Eidolon-Ingress-Identity-Source: ${IDENTITY_SOURCE}" \
  -H "X-Eidolon-Ingress-Trust-Tier: ${TRUST_TIER}" \
  -H "X-Eidolon-Ingress-Identity-Label: ${IDENTITY_LABEL}" \
  -H "X-Eidolon-Ingress-Verified-Category: ${VERIFIED_CATEGORY}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${DOCS_PATH}"

curl_cmd -fsS \
  -D "$openapi_headers" \
  -o "$openapi_body" \
  -H "X-Eidolon-Ingress-Identity-Source: ${IDENTITY_SOURCE}" \
  -H "X-Eidolon-Ingress-Trust-Tier: ${TRUST_TIER}" \
  -H "X-Eidolon-Ingress-Identity-Label: ${IDENTITY_LABEL}" \
  -H "X-Eidolon-Ingress-Verified-Category: ${VERIFIED_CATEGORY}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${OPENAPI_PATH}"

docs_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$docs_headers")"
[[ "$docs_http_code" == "200" ]] || fail "expected HTTP 200 for specific explicit docs request, got: ${docs_http_code:-none}"
if grep -Fq "$DOCS_BAIT_MARKER" "$docs_body"; then
  fail "specific explicit docs request still received the baited docs surface"
fi

openapi_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$openapi_headers")"
[[ "$openapi_http_code" == "200" ]] || fail "expected HTTP 200 for broad explicit openapi request, got: ${openapi_http_code:-none}"
if jq -e --arg bait_path "$OPENAPI_BAIT_PATH" '.paths[$bait_path]' "$openapi_body" >/dev/null 2>&1; then
  fail "broad explicit openapi request unexpectedly received the baited OpenAPI surface"
fi

read_proxy_state_file events.jsonl > "$events_file"
read_proxy_state_file debug.jsonl > "$debug_file"

docs_request_json="$(
  jq -c -e -s \
    --arg path_prefix "$DOCS_PATH_PREFIX" \
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
)" || fail "could not find the specific explicit docs request in the proxy event log"

docs_session_id="$(jq -r '.session_id // empty' <<<"$docs_request_json")"
[[ -n "$docs_session_id" ]] || fail "specific explicit docs request had no session id"

docs_surface_debug="$(
  jq -c -e -s \
    --arg session_id "$docs_session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "specific explicit docs session ${docs_session_id} had no surface_action_selected debug record"

jq -e \
  --arg category "$VERIFIED_CATEGORY" '
    (.kind.ingress_identity.source // "") == "signed_agent"
    and (.kind.ingress_identity.trust_tier // "") == "signed_attested"
    and (.kind.trusted_ingress_soften_match.label // "") == "docs-signed-agent"
    and (.kind.trusted_ingress_soften_match.path_prefixes // []) == ["/docs"]
    and (.kind.trusted_ingress_soften_match.verified_categories // []) == [$category]
    and (.kind.trusted_ingress_soften_match.request_path_softened // false) == true
    and .fields.surface_action.type == "protected_upstream"
    and .fields.trusted_ingress_softened_surface == true
  ' <<<"$(jq -n \
    --argjson event "$docs_request_json" \
    --argjson debug "$docs_surface_debug" \
    '{kind: $event.kind, fields: $debug.fields}')" >/dev/null \
  || fail "specific explicit docs session ${docs_session_id} did not record the expected most-specific softening"

openapi_request_json="$(
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
)" || fail "could not find the broad explicit openapi request in the proxy event log"

openapi_session_id="$(jq -r '.session_id // empty' <<<"$openapi_request_json")"
[[ -n "$openapi_session_id" ]] || fail "broad explicit openapi request had no session id"

openapi_surface_debug="$(
  jq -c -e -s \
    --arg session_id "$openapi_session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "broad explicit openapi session ${openapi_session_id} had no surface_action_selected debug record"

jq -e '
  (.kind.ingress_identity.source // "") == "signed_agent"
  and (.kind.ingress_identity.trust_tier // "") == "signed_attested"
  and (.kind.trusted_ingress_soften_match // null) == null
  and .fields.candidate_surface_action.type == "rewritten_upstream"
  and .fields.surface_action.type == "protected_upstream"
  and .fields.trusted_ingress_softened_surface == true
' <<<"$(jq -n \
  --argjson event "$openapi_request_json" \
  --argjson debug "$openapi_surface_debug" \
  '{kind: $event.kind, fields: $debug.fields}')" >/dev/null \
  || fail "broad explicit openapi session ${openapi_session_id} did not stay on the expected generic strong-identity softening path"

echo "trusted-ingress explicit-rule specificity smoke ok: docs session ${docs_session_id} used the narrower explicit rule and openapi session ${openapi_session_id} fell back to the broader strong-identity softening path"
