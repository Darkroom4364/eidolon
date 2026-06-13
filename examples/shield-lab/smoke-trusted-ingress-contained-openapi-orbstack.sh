#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EXPORT_SCRIPT="${EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT:-$SCRIPT_DIR/export-edge-decisions-orbstack.sh}"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
EDGE_HOST="${EIDOLON_SHIELD_EDGE_HOST:-127.0.0.1}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
EDGE_EXPORT_BIN="${EIDOLON_EDGE_EXPORT_BIN:-}"
TRUSTED_ACTOR_HEADER_NAME="${EIDOLON_SHIELD_TRUSTED_ACTOR_HEADER_NAME:-X-Eidolon-Trusted-Actor}"
TRUSTED_ACTOR_HEADER_VALUE="${EIDOLON_SHIELD_TRUSTED_ACTOR_HEADER_VALUE:-docs-crawler}"
SESSION_ID="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_SESSION_ID:-}"
DOCS_PATH="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_DOCS_PATH:-/docs?topic=imports}"
DOCS_PATH_PREFIX="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_DOCS_PATH_PREFIX:-/docs}"
OPENAPI_PATH="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_OPENAPI_PATH:-/openapi.json}"
ACTION_PATH="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_ACTION_PATH:-/api/v2/import/reconcile}"
DOCS_BAIT_MARKER="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_DOCS_BAIT_MARKER:-X-Migration-Trace: }"
OPENAPI_BAIT_PATH="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_OPENAPI_BAIT_PATH:-/api/v2/import/reconcile}"
OPENAPI_HEADER_NAME="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_OPENAPI_HEADER_NAME:-X-OpenAPI-Trace}"
OPENAPI_HEADER_PREFIX="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_OPENAPI_HEADER_PREFIX:-oapi}"
OPENAPI_MINTED_VALUE_PATTERN="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_OPENAPI_VALUE_PATTERN:-oapi_[0-9a-f]+}"
EXPECTED_SOFTEN_PREFIX="${EIDOLON_SHIELD_TRUSTED_CONTAINMENT_SOFTEN_PREFIX:-/docs}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/smoke-trusted-ingress-contained-openapi-orbstack.sh

Performs a live OrbStack smoke check proving that scoped trusted-ingress
softening does not bypass later containment. One fixed session first receives a
softened trusted `/docs` response, then still gets the baited `/openapi.json`
surface, and finally enters controlled reality on the same-session exact
OpenAPI bait action.
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

resolve_session_id() {
  local current_value="$1"

  if [[ -n "$current_value" ]]; then
    printf '%s' "$current_value"
    return
  fi

  uuidgen | tr '[:upper:]' '[:lower:]'
}

extract_minted_value() {
  local file="$1"
  local value

  value="$(
    jq -r \
      --arg path "$ACTION_PATH" \
      --arg header_name "$OPENAPI_HEADER_NAME" '
        .paths[$path].post.parameters[]?
        | select(.name == $header_name)
        | .schema.example // empty
      ' "$file" | head -n 1
  )"
  [[ -n "$value" ]] || fail "could not extract a minted OpenAPI header example from $file"
  [[ "$value" =~ ^${OPENAPI_MINTED_VALUE_PATTERN}$ ]] \
    || fail "extracted OpenAPI header example from $file did not match the expected minted pattern"
  printf '%s' "$value"
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
if [[ -z "$SESSION_ID" ]]; then
  require_command uuidgen
fi

context="$(kubectl_cmd config current-context)"
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  fail "expected kubectl current-context to be ${EXPECTED_CONTEXT}, got: ${context}"
fi

edge_svc_json="$(kubectl_cmd -n shield-system get svc eidolon-shield-edge -o json)"
edge_node_port="$(jq -r '.spec.ports[] | select(.name == "http") | (.nodePort // empty)' <<<"$edge_svc_json")"
[[ -n "$edge_node_port" ]] || fail "shield edge service has no http NodePort"
edge_url="http://${EDGE_HOST}:${edge_node_port}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-contained-openapi.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
SESSION_ID="$(resolve_session_id "$SESSION_ID")"

docs_headers="$tmp_dir/docs.headers"
docs_body="$tmp_dir/docs.body"
openapi_headers="$tmp_dir/openapi.headers"
openapi_body="$tmp_dir/openapi.json"
action_headers="$tmp_dir/action.headers"
action_body="$tmp_dir/action.body"
events_file="$tmp_dir/events.jsonl"
edge_export_file="$tmp_dir/edge-export.json"

curl_cmd -fsS \
  -D "$docs_headers" \
  -o "$docs_body" \
  -H "Cookie: eidolon_session=${SESSION_ID}" \
  -H "${TRUSTED_ACTOR_HEADER_NAME}: ${TRUSTED_ACTOR_HEADER_VALUE}" \
  "${edge_url}${DOCS_PATH}"

docs_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$docs_headers")"
[[ "$docs_http_code" == "200" ]] || fail "expected HTTP 200 for trusted docs request, got: ${docs_http_code:-none}"
if grep -Fq "$DOCS_BAIT_MARKER" "$docs_body"; then
  fail "trusted docs request still received the baited docs surface"
fi

curl_cmd -fsS \
  -D "$openapi_headers" \
  -o "$openapi_body" \
  -H "Cookie: eidolon_session=${SESSION_ID}" \
  -H "${TRUSTED_ACTOR_HEADER_NAME}: ${TRUSTED_ACTOR_HEADER_VALUE}" \
  "${edge_url}${OPENAPI_PATH}"

openapi_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$openapi_headers")"
[[ "$openapi_http_code" == "200" ]] || fail "expected HTTP 200 for trusted openapi request, got: ${openapi_http_code:-none}"
jq -e --arg bait_path "$OPENAPI_BAIT_PATH" '.paths[$bait_path]' "$openapi_body" >/dev/null \
  || fail "trusted openapi request did not receive the baited OpenAPI surface"

minted_openapi_trace="$(extract_minted_value "$openapi_body")"

curl_cmd -sS \
  -X POST \
  -D "$action_headers" \
  -o "$action_body" \
  -H "Cookie: eidolon_session=${SESSION_ID}" \
  -H "${TRUSTED_ACTOR_HEADER_NAME}: ${TRUSTED_ACTOR_HEADER_VALUE}" \
  -H "${OPENAPI_HEADER_NAME}: ${minted_openapi_trace}" \
  "${edge_url}${ACTION_PATH}"

action_http_code="$(awk 'BEGIN{IGNORECASE=1} /^HTTP\// {code=$2} END{print code}' "$action_headers")"
[[ "$action_http_code" == "202" ]] \
  || fail "expected HTTP 202 from the same-session exact trusted OpenAPI bait action, got: ${action_http_code:-none}"
grep -Fq '"write_committed":false' "$action_body" \
  || fail "same-session exact trusted OpenAPI bait action did not receive the expected controlled-reality body"

read_proxy_state_file events.jsonl > "$events_file"

docs_request_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" \
    --arg path_prefix "$DOCS_PATH_PREFIX" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "request_seen"
          and (.kind.path // "" | startswith($path_prefix))
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the trusted docs request for session ${SESSION_ID} in the proxy event log"

jq -e \
  --arg label "$TRUSTED_ACTOR_HEADER_VALUE" '
    (.kind.ingress_identity.source // "") == "local_allowlist"
    and (.kind.ingress_identity.trust_tier // "") == "allowlisted"
    and (.kind.ingress_identity.label // "") == $label
    and (.kind.trusted_ingress_soften_match.label // "") == $label
    and (.kind.trusted_ingress_soften_match.request_path_softened // false) == true
  ' <<<"$docs_request_json" >/dev/null \
  || fail "trusted docs request for session ${SESSION_ID} did not record a matched scoped soften path"

openapi_request_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" \
    --arg path "$OPENAPI_PATH" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "request_seen"
          and (.kind.path // "") == $path
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the trusted openapi request for session ${SESSION_ID} in the proxy event log"

jq -e \
  --arg label "$TRUSTED_ACTOR_HEADER_VALUE" '
    (.kind.ingress_identity.source // "") == "local_allowlist"
    and (.kind.ingress_identity.trust_tier // "") == "allowlisted"
    and (.kind.ingress_identity.label // "") == $label
    and (.kind.trusted_ingress_soften_match.label // "") == $label
    and (.kind.trusted_ingress_soften_match.request_path_softened == false)
  ' <<<"$openapi_request_json" >/dev/null \
  || fail "trusted openapi request for session ${SESSION_ID} did not preserve the unsoftened scoped bait path"

action_request_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" \
    --arg path "$ACTION_PATH" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "request_seen"
          and (.kind.path // "") == $path
        )
      )
      | last
    ' "$events_file"
)" || fail "could not find the exact trusted OpenAPI bait action request for session ${SESSION_ID} in the proxy event log"

jq -e '
    .kind.method == "POST"
    and .kind.path == "/api/v2/import/reconcile"
  ' <<<"$action_request_json" >/dev/null \
  || fail "same-session trusted OpenAPI bait action request for session ${SESSION_ID} was not recorded as expected"

policy_changed_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "policy_changed"
          and .kind.to == "controlled_reality"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_ID} had no transition into controlled reality after the trusted OpenAPI bait action"

jq -e \
  --arg reason_substring "confirmed bait-derived action moved session into controlled reality" '
    (.kind.reason // "") | contains($reason_substring)
  ' <<<"$policy_changed_json" >/dev/null \
  || fail "session ${SESSION_ID} controlled-reality transition reason did not match the exact bait-derived action path"

action_response_json="$(
  jq -c -e -s \
    --arg session_id "$SESSION_ID" '
      map(
        select(
          .session_id == $session_id
          and .kind.type == "response_served"
        )
      )
      | last
    ' "$events_file"
)" || fail "session ${SESSION_ID} had no response_served event after the trusted OpenAPI bait action"

jq -e '
    .policy_state == "controlled_reality"
    and .kind.status == 202
    and .kind.routing_decision == "controlled_reality"
  ' <<<"$action_response_json" >/dev/null \
  || fail "session ${SESSION_ID} did not serve the exact trusted OpenAPI bait action from controlled reality"

EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
EIDOLON_EDGE_EXPORT_BIN="$EDGE_EXPORT_BIN" \
KUBECTL_BIN="$KUBECTL_BIN" \
"$EXPORT_SCRIPT" \
  --session "$SESSION_ID" \
  --format json > "$edge_export_file"

jq -e \
  --arg session_id "$SESSION_ID" \
  --arg path "$ACTION_PATH" '
    length == 1
    and .[0].session_id == $session_id
    and .[0].request.method == "POST"
    and .[0].request.path == $path
    and .[0].policy.state == "controlled_reality"
    and .[0].policy.routing_decision == "controlled_reality"
    and .[0].edge_recommendation.action == "preserve_eidolon_routing"
    and (.[0].edge_recommendation.reason_codes // []) == ["eidolon_runtime_enforcement", "controlled_reality"]
  ' "$edge_export_file" >/dev/null \
  || fail "session ${SESSION_ID} edge export did not preserve the expected controlled-reality outcome"

echo "trusted-ingress containment smoke ok: session ${SESSION_ID} softened /docs, kept bait on /openapi.json, and still entered controlled reality on the same-session exact bait action"
