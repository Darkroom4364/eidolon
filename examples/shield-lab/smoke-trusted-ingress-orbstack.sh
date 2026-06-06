#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
TRUSTED_INGRESS_SECRET_NAME="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
TRUSTED_INGRESS_SECRET_KEY="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-orbstack.sh

Performs a live OrbStack smoke check for the trusted-ingress transport-auth
path. It proves that a forged raw NodePort request stays baited while the same
request with the configured transport-auth secret is accepted as trusted ingress.
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

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command "$KUBECTL_BIN"
require_command "$CURL_BIN"
require_command jq
require_command base64

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

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-ingress-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

untrusted_file="$tmp_dir/untrusted-openapi.json"
trusted_file="$tmp_dir/trusted-openapi.json"

curl_cmd -fsS \
  -H 'X-Eidolon-Ingress-Identity-Source: signed_agent' \
  -H 'X-Eidolon-Ingress-Trust-Tier: signed_attested' \
  -H 'X-Eidolon-Ingress-Identity-Label: orbstack-smoke' \
  "${edge_url}/openapi.json" > "$untrusted_file"

curl_cmd -fsS \
  -H 'X-Eidolon-Ingress-Identity-Source: signed_agent' \
  -H 'X-Eidolon-Ingress-Trust-Tier: signed_attested' \
  -H 'X-Eidolon-Ingress-Identity-Label: orbstack-smoke' \
  -H "X-Eidolon-Ingress-Transport-Auth: ${transport_auth_secret}" \
  "${edge_url}/openapi.json" > "$trusted_file"

jq -e '.paths["/api/v2/import/reconcile"]' "$untrusted_file" >/dev/null \
  || fail "raw forged request did not receive the baited OpenAPI surface"
jq -e '.paths["/api/v2/import/reconcile"] | not' "$trusted_file" >/dev/null \
  || fail "transport-authenticated request still received the baited OpenAPI surface"
jq -e '.paths["/api/v1/imports"]' "$trusted_file" >/dev/null \
  || fail "transport-authenticated request did not fall back to the protected upstream OpenAPI surface"

echo "trusted-ingress smoke ok: raw forged request stayed baited, authenticated request was softened"
