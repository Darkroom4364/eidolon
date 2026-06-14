#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
TRUSTED_ACTOR_HEADER_NAME="${EIDOLON_SHIELD_TRUSTED_ACTOR_HEADER_NAME:-X-Eidolon-Trusted-Actor}"
TRUSTED_ACTOR_HEADER_VALUE="${EIDOLON_SHIELD_TRUSTED_ACTOR_HEADER_VALUE:-docs-crawler}"
DOCS_PATH="${EIDOLON_SHIELD_TRUSTED_SCOPE_DOCS_PATH:-/docs?topic=imports}"
DOCS_PATH_PREFIX="${EIDOLON_SHIELD_TRUSTED_SCOPE_DOCS_PATH_PREFIX:-/docs}"
OPENAPI_PATH="${EIDOLON_SHIELD_TRUSTED_SCOPE_OPENAPI_PATH:-/openapi.json}"
DOCS_BAIT_MARKER="${EIDOLON_SHIELD_TRUSTED_SCOPE_DOCS_BAIT_MARKER:-X-Migration-Trace: }"
OPENAPI_BAIT_PATH="${EIDOLON_SHIELD_TRUSTED_SCOPE_OPENAPI_BAIT_PATH:-/api/v2/import/reconcile}"
EXPECTED_LOCAL_SOFTEN_PREFIX="${EIDOLON_SHIELD_TRUSTED_SCOPE_LOCAL_PREFIX:-/docs}"
EXPECTED_HOST="${EIDOLON_SHIELD_TRUSTED_SCOPE_HOST:-127.0.0.1}"
EXPECTED_SOURCE_CIDR="${EIDOLON_SHIELD_TRUSTED_SCOPE_SOURCE_CIDR:-192.168.194.1/32}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-scoped-softening-orbstack.sh

Performs a live OrbStack smoke check for the local allowlist soften-scope path.
It proves the default docs-crawler allowlist entry softens `/docs` while the
same trusted actor still receives the baited `/openapi.json` surface.
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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-scope-smoke.XXXXXX")"
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
  -H "${TRUSTED_ACTOR_HEADER_NAME}: ${TRUSTED_ACTOR_HEADER_VALUE}" \
  "${edge_url}${DOCS_PATH}"

curl_cmd -fsS \
  -D "$openapi_headers" \
  -o "$openapi_body" \
  -H "${TRUSTED_ACTOR_HEADER_NAME}: ${TRUSTED_ACTOR_HEADER_VALUE}" \
  "${edge_url}${OPENAPI_PATH}"

docs_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$docs_headers")"
[[ "$docs_http_code" == "200" ]] || fail "expected HTTP 200 for trusted docs request, got: ${docs_http_code:-none}"
if grep -Fq "$DOCS_BAIT_MARKER" "$docs_body"; then
  fail "trusted docs request still received the baited docs surface"
fi

openapi_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$openapi_headers")"
[[ "$openapi_http_code" == "200" ]] || fail "expected HTTP 200 for trusted openapi request, got: ${openapi_http_code:-none}"
jq -e --arg bait_path "$OPENAPI_BAIT_PATH" '.paths[$bait_path]' "$openapi_body" >/dev/null \
  || fail "trusted openapi request did not receive the baited OpenAPI surface"

read_proxy_state_file events.jsonl > "$events_file"
read_proxy_state_file debug.jsonl > "$debug_file"

docs_request_json="$(
  jq -c -e -s \
    --arg path_prefix "$DOCS_PATH_PREFIX" \
    --arg label "$TRUSTED_ACTOR_HEADER_VALUE" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
          and (.kind.ingress_identity.source // "") == "local_allowlist"
          and (.kind.ingress_identity.trust_tier // "") == "allowlisted"
          and (.kind.ingress_identity.label // "") == $label
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the trusted docs request in the proxy event log"

docs_session_id="$(jq -r '.session_id // empty' <<<"$docs_request_json")"
[[ -n "$docs_session_id" ]] || fail "trusted docs request had no session id"

docs_surface_debug="$(
  jq -c -e -s \
    --arg session_id "$docs_session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "trusted docs session ${docs_session_id} had no surface_action_selected debug record"

jq -e \
  --arg expected_host "$EXPECTED_HOST" \
  --arg expected_source_cidr "$EXPECTED_SOURCE_CIDR" \
  --arg local_prefix "$EXPECTED_LOCAL_SOFTEN_PREFIX" '
    ((.kind.trusted_ingress_soften_match.hosts // []) | index($expected_host)) != null
    and
    (.kind.trusted_ingress_soften_match.source_cidrs // []) == [$expected_source_cidr]
    and
    .fields.surface_action.type == "protected_upstream"
    and .fields.trusted_ingress_softened_surface == true
    and (.fields.trusted_ingress_local_soften_path_prefixes // []) == [$local_prefix]
  ' <<<"$(jq -n \
    --argjson event "$docs_request_json" \
    --argjson debug "$docs_surface_debug" \
    '{kind: $event.kind, fields: $debug.fields}')" >/dev/null \
  || fail "trusted docs session ${docs_session_id} did not record scoped docs softening with the expected source CIDR"

openapi_request_json="$(
  jq -c -e -s \
    --arg path "$OPENAPI_PATH" \
    --arg label "$TRUSTED_ACTOR_HEADER_VALUE" '
      map(
        select(
          .kind.type == "request_seen"
          and (.kind.path // "") == $path
          and (.kind.ingress_identity.source // "") == "local_allowlist"
          and (.kind.ingress_identity.trust_tier // "") == "allowlisted"
          and (.kind.ingress_identity.label // "") == $label
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the trusted openapi request in the proxy event log"

openapi_session_id="$(jq -r '.session_id // empty' <<<"$openapi_request_json")"
[[ -n "$openapi_session_id" ]] || fail "trusted openapi request had no session id"

openapi_surface_debug="$(
  jq -c -e -s \
    --arg session_id "$openapi_session_id" '
      map(select(.session_id == $session_id and .event == "surface_action_selected"))
      | last
    ' "$debug_file"
)" || fail "trusted openapi session ${openapi_session_id} had no surface_action_selected debug record"

jq -e \
  --arg expected_host "$EXPECTED_HOST" \
  --arg expected_source_cidr "$EXPECTED_SOURCE_CIDR" \
  --arg local_prefix "$EXPECTED_LOCAL_SOFTEN_PREFIX" '
    ((.kind.trusted_ingress_soften_match.hosts // []) | index($expected_host)) != null
    and
    (.kind.trusted_ingress_soften_match.source_cidrs // []) == [$expected_source_cidr]
    and
    .fields.candidate_surface_action.type == "rewritten_upstream"
    and .fields.surface_action.type == "rewritten_upstream"
    and .fields.trusted_ingress_softened_surface == false
    and (.fields.trusted_ingress_local_soften_path_prefixes // []) == [$local_prefix]
  ' <<<"$(jq -n \
    --argjson event "$openapi_request_json" \
    --argjson debug "$openapi_surface_debug" \
    '{kind: $event.kind, fields: $debug.fields}')" >/dev/null \
  || fail "trusted openapi session ${openapi_session_id} did not preserve the scoped baited surface with the expected source CIDR"

echo "trusted-ingress scoped softening smoke ok: docs session ${docs_session_id} softened only on /docs from ${EXPECTED_SOURCE_CIDR}, openapi session ${openapi_session_id} stayed baited"
