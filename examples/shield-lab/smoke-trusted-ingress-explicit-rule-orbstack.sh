#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
TRUSTED_INGRESS_SECRET_NAME="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
TRUSTED_INGRESS_SECRET_KEY="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
IDENTITY_SOURCE="${EIDOLON_SHIELD_EXPLICIT_RULE_IDENTITY_SOURCE:-signed_agent}"
TRUST_TIER="${EIDOLON_SHIELD_EXPLICIT_RULE_TRUST_TIER:-signed_attested}"
MATCHED_IDENTITY_LABEL="${EIDOLON_SHIELD_EXPLICIT_RULE_MATCHED_LABEL:-docs-signed-agent}"
MISMATCHED_IDENTITY_LABEL="${EIDOLON_SHIELD_EXPLICIT_RULE_MISMATCHED_LABEL:-wrong-signed-agent}"
VERIFIED_CATEGORY="${EIDOLON_SHIELD_EXPLICIT_RULE_VERIFIED_CATEGORY:-AI Assistant}"
DOCS_PATH="${EIDOLON_SHIELD_EXPLICIT_RULE_DOCS_PATH:-/docs?topic=imports}"
DOCS_PATH_PREFIX="${EIDOLON_SHIELD_EXPLICIT_RULE_DOCS_PATH_PREFIX:-/docs}"
DOCS_BAIT_MARKER="${EIDOLON_SHIELD_EXPLICIT_RULE_DOCS_BAIT_MARKER:-/docs/legacy-import}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-explicit-rule-orbstack.sh

Performs a live OrbStack smoke check for authenticated explicit trusted-ingress
rules. It proves that a configured signed-agent claim softens `/docs`, while an
unconfigured signed-agent label is downgraded to `weakly_asserted` and stays
baited on the same docs surface.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-explicit-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

matched_headers="$tmp_dir/matched.headers"
matched_body="$tmp_dir/matched.body"
mismatched_headers="$tmp_dir/mismatched.headers"
mismatched_body="$tmp_dir/mismatched.body"
events_file="$tmp_dir/events.jsonl"
debug_file="$tmp_dir/debug.jsonl"

curl_cmd -fsS \
  -D "$matched_headers" \
  -o "$matched_body" \
  -H "X-Eidolon-Ingress-Identity-Source: ${IDENTITY_SOURCE}" \
  -H "X-Eidolon-Ingress-Trust-Tier: ${TRUST_TIER}" \
  -H "X-Eidolon-Ingress-Identity-Label: ${MATCHED_IDENTITY_LABEL}" \
  -H "X-Eidolon-Ingress-Verified-Category: ${VERIFIED_CATEGORY}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${DOCS_PATH}"

curl_cmd -fsS \
  -D "$mismatched_headers" \
  -o "$mismatched_body" \
  -H "X-Eidolon-Ingress-Identity-Source: ${IDENTITY_SOURCE}" \
  -H "X-Eidolon-Ingress-Trust-Tier: ${TRUST_TIER}" \
  -H "X-Eidolon-Ingress-Identity-Label: ${MISMATCHED_IDENTITY_LABEL}" \
  -H "X-Eidolon-Ingress-Verified-Category: ${VERIFIED_CATEGORY}" \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}${DOCS_PATH}"

matched_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$matched_headers")"
[[ "$matched_http_code" == "200" ]] || fail "expected HTTP 200 for configured explicit docs request, got: ${matched_http_code:-none}"
if grep -Fq "$DOCS_BAIT_MARKER" "$matched_body"; then
  fail "configured explicit docs request still received the baited docs surface"
fi

mismatched_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$mismatched_headers")"
[[ "$mismatched_http_code" == "200" ]] || fail "expected HTTP 200 for mismatched explicit docs request, got: ${mismatched_http_code:-none}"
grep -Fq "$DOCS_BAIT_MARKER" "$mismatched_body" \
  || fail "mismatched explicit docs request did not receive the baited docs surface"

read_proxy_state_file events.jsonl > "$events_file"
read_proxy_state_file debug.jsonl > "$debug_file"

matched_request_json="$(
  jq -c -e -s \
    --arg path_prefix "$DOCS_PATH_PREFIX" \
    --arg label "$MATCHED_IDENTITY_LABEL" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
          and (.kind.ingress_identity.label // "") == $label
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the configured explicit docs request in the proxy event log"

matched_session_id="$(jq -r '.session_id // empty' <<<"$matched_request_json")"
[[ -n "$matched_session_id" ]] || fail "configured explicit docs request had no session id"

matched_surface_debug="$(
  jq -c -e -s \
    --arg session_id "$matched_session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "configured explicit docs session ${matched_session_id} had no surface_action_selected debug record"

jq -e \
  --arg category "$VERIFIED_CATEGORY" '
    (.kind.ingress_identity.source // "") == "signed_agent"
    and (.kind.ingress_identity.trust_tier // "") == "signed_attested"
    and (.kind.trusted_ingress_soften_match.label // "") == "docs-signed-agent"
    and (.kind.trusted_ingress_soften_match.verified_categories // []) == [$category]
    and (.kind.trusted_ingress_soften_match.request_path_softened // false) == true
    and .fields.surface_action.type == "protected_upstream"
    and .fields.trusted_ingress_softened_surface == true
  ' <<<"$(jq -n \
    --argjson event "$matched_request_json" \
    --argjson debug "$matched_surface_debug" \
    '{kind: $event.kind, fields: $debug.fields}')" >/dev/null \
  || fail "configured explicit docs session ${matched_session_id} did not record the expected authenticated softening"

mismatched_request_json="$(
  jq -c -e -s \
    --arg path_prefix "$DOCS_PATH_PREFIX" \
    --arg label "$MISMATCHED_IDENTITY_LABEL" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
          and (.kind.ingress_identity.label // "") == $label
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the mismatched explicit docs request in the proxy event log"

mismatched_session_id="$(jq -r '.session_id // empty' <<<"$mismatched_request_json")"
[[ -n "$mismatched_session_id" ]] || fail "mismatched explicit docs request had no session id"

mismatched_surface_debug="$(
  jq -c -e -s \
    --arg session_id "$mismatched_session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "mismatched explicit docs session ${mismatched_session_id} had no surface_action_selected debug record"

jq -e '
  (.kind.ingress_identity.source // "") == "signed_agent"
  and (.kind.ingress_identity.trust_tier // "") == "weakly_asserted"
  and (.kind.authenticated_ingress_rule_rejection.label // "") == "docs-signed-agent"
  and (.kind.authenticated_ingress_rule_rejection.reason // "") == "label_mismatch"
  and (.kind.authenticated_ingress_rule_rejection.verified_categories // []) == ["AI Assistant"]
  and (.kind.trusted_ingress_soften_match // null) == null
  and .fields.candidate_surface_action.type == "rewritten_upstream"
  and .fields.surface_action.type == "rewritten_upstream"
  and .fields.trusted_ingress_softened_surface == false
' <<<"$(jq -n \
  --argjson event "$mismatched_request_json" \
  --argjson debug "$mismatched_surface_debug" \
  '{kind: $event.kind, fields: $debug.fields}')" >/dev/null \
  || fail "mismatched explicit docs session ${mismatched_session_id} did not downgrade and stay baited"

mismatched_request_debug="$(
  jq -c -e -s \
    --arg session_id "$mismatched_session_id" '
      map(select(.session_id == $session_id and .event == "request_received"))
      | last
    ' "$debug_file"
)" || fail "mismatched explicit docs session ${mismatched_session_id} had no request_received debug record"

jq -e '
  (.fields.authenticated_ingress_rule_rejection.reason // "") == "label_mismatch"
' <<<"$mismatched_request_debug" >/dev/null \
  || fail "mismatched explicit docs session ${mismatched_session_id} did not record label_mismatch in request debug output"

echo "trusted-ingress explicit-rule smoke ok: configured session ${matched_session_id} softened /docs, mismatched session ${mismatched_session_id} downgraded to weakly_asserted and stayed baited"
