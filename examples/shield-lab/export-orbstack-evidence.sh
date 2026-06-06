#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
STATUS_SCRIPT="$SCRIPT_DIR/status-orbstack.sh"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
BUNDLE_DIR="${1:-}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/export-orbstack-evidence.sh <bundle-dir>

Exports a redacted Shield lab evidence bundle from the PVC-backed proxy state.

Outputs:
  <bundle-dir>/README.md
  <bundle-dir>/cluster-status.json
  <bundle-dir>/events.redacted.jsonl
  <bundle-dir>/debug.redacted.jsonl
  <bundle-dir>/policy-state.redacted.json
  <bundle-dir>/SHA256SUMS
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

sha256_file() {
  local path="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path"
    return
  fi

  shasum -a 256 "$path"
}

ensure_empty_bundle_dir() {
  if [[ -z "$BUNDLE_DIR" ]]; then
    usage >&2
    exit 2
  fi

  if [[ -e "$BUNDLE_DIR" && ! -d "$BUNDLE_DIR" ]]; then
    fail "bundle path exists and is not a directory: $BUNDLE_DIR"
  fi

  if [[ -d "$BUNDLE_DIR" ]] && [[ -n "$(find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    fail "bundle directory must be empty: $BUNDLE_DIR"
  fi

  mkdir -p "$BUNDLE_DIR"
}

read_proxy_state_file() {
  local basename="$1"

  if [[ -n "$LOCAL_STATE_DIR" ]]; then
    cat "$LOCAL_STATE_DIR/$basename"
    return
  fi

  kubectl_cmd -n shield-system exec deploy/eidolon-shield-proxy -- sh -lc "cat /var/lib/eidolon/$basename"
}

copy_optional_redacted_json_file() {
  local basename="$1"
  local jq_filter="$2"
  local output="$3"
  local temp_input="$4"

  if ! read_proxy_state_file "$basename" >"$temp_input" 2>/dev/null; then
    return 0
  fi

  jq "$jq_filter" "$temp_input" > "$output"
}

copy_optional_redacted_jsonl_file() {
  local basename="$1"
  local jq_filter="$2"
  local output="$3"
  local temp_input="$4"

  if ! read_proxy_state_file "$basename" >"$temp_input" 2>/dev/null; then
    return 0
  fi

  jq -c "$jq_filter" "$temp_input" > "$output"
}

write_readme() {
  local event_count="$1"
  local debug_count="$2"
  local policy_session_count="$3"

  local edge_url
  local edge_status
  local direct_url
  local direct_status
  local proxy_ready
  local target_ready
  local pvc_status
  edge_url="$(jq -r '.edge.url // "unavailable"' "$BUNDLE_DIR/cluster-status.json")"
  edge_status="$(jq -r 'if .edge.http_status == null then "unreachable" else (.edge.http_status | tostring) end' "$BUNDLE_DIR/cluster-status.json")"
  direct_url="$(jq -r '.direct_target_edge.url // "unavailable"' "$BUNDLE_DIR/cluster-status.json")"
  direct_status="$(jq -r 'if .direct_target_edge.http_status == null then "unreachable" else (.direct_target_edge.http_status | tostring) end' "$BUNDLE_DIR/cluster-status.json")"
  proxy_ready="$(jq -r '"\(.proxy.ready_replicas)/\(.proxy.replicas)"' "$BUNDLE_DIR/cluster-status.json")"
  target_ready="$(jq -r '"\(.target.ready_replicas)/\(.target.replicas)"' "$BUNDLE_DIR/cluster-status.json")"
  pvc_status="$(jq -r '.proxy_state.status // "unknown"' "$BUNDLE_DIR/cluster-status.json")"

  {
    printf '# OrbStack Shield Evidence Bundle\n\n'
    printf 'Collected on `%s` from context `%s`.\n\n' \
      "$(jq -r '.generated_at' "$BUNDLE_DIR/cluster-status.json")" \
      "$(jq -r '.context' "$BUNDLE_DIR/cluster-status.json")"
    printf '## Summary\n\n'
    printf -- '- Edge URL: `%s` (HTTP `%s`)\n' "$edge_url" "$edge_status"
    printf -- '- Direct target URL: `%s` (HTTP `%s`)\n' "$direct_url" "$direct_status"
    printf -- '- Proxy readiness: `%s`\n' "$proxy_ready"
    printf -- '- Target readiness: `%s`\n' "$target_ready"
    printf -- '- Proxy state PVC: `%s`\n' "$pvc_status"
    printf -- '- Redacted event log lines: `%s`\n' "$event_count"
    printf -- '- Redacted debug log lines: `%s`\n' "$debug_count"
    printf -- '- Redacted persisted policy sessions: `%s`\n\n' "$policy_session_count"
    printf '## Included files\n\n'
    printf -- '- `cluster-status.json`: current cluster-facing operator status.\n'
    printf -- '- `events.redacted.jsonl`: proxy event log with session ids, event ids, exposure ids, and query values redacted.\n'
    printf -- '- `debug.redacted.jsonl`: proxy debug log with session ids, peer addresses, URLs, and query values redacted.\n'
    printf -- '- `policy-state.redacted.json`: persisted policy states with session ids redacted.\n'
    printf -- '- `SHA256SUMS`: checksums for every exported artifact.\n\n'
    printf 'This bundle intentionally omits raw cookies, unredacted session identifiers, raw PVC paths, and intervention-control overrides.\n'
  } > "$BUNDLE_DIR/README.md"
}

if [[ -z "$BUNDLE_DIR" || "$BUNDLE_DIR" == "-h" || "$BUNDLE_DIR" == "--help" ]]; then
  usage
  [[ -z "$BUNDLE_DIR" ]] && exit 2 || exit 0
fi

require_command "$KUBECTL_BIN"
require_command jq
require_command "$STATUS_SCRIPT"

ensure_empty_bundle_dir

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-export.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

status_json="$("$STATUS_SCRIPT" --json)"
printf '%s\n' "$status_json" > "$BUNDLE_DIR/cluster-status.json"

copy_optional_redacted_jsonl_file \
  events.jsonl \
  '
    def redact_path:
      if type != "string" then
        .
      else
        (split("#")[0]) as $base
        | if ($base | contains("?")) then
            ($base | split("?")[0]) + "?<redacted>"
          else
            $base
          end
      end;
    .id = "<redacted>"
    | .session_id = "<redacted>"
    | if .kind.exposure_id? then .kind.exposure_id = "<redacted>" else . end
    | if .kind.path? then .kind.path |= redact_path else . end
    | if .kind.surface? then .kind.surface |= redact_path else . end
  ' \
  "$BUNDLE_DIR/events.redacted.jsonl" \
  "$tmp_dir/events.jsonl"

copy_optional_redacted_jsonl_file \
  debug.jsonl \
  '
    def walk(f):
      . as $value
      | if type == "object" then
          reduce keys_unsorted[] as $key
            ({};
             . + { ($key): ($value[$key] | walk(f)) })
          | f
        elif type == "array" then
          map(walk(f)) | f
        else
          f
        end;
    def redact_path:
      if type != "string" then
        .
      else
        (split("#")[0]) as $base
        | if ($base | contains("?")) then
            ($base | split("?")[0]) + "?<redacted>"
          else
            $base
          end
      end;
    def redact_string:
      if test("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") then
        "<redacted>"
      elif test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}:[0-9]+$") then
        "<redacted-peer>"
      elif test("^https?://") then
        "<redacted-url>"
      elif startswith("/") then
        redact_path
      else
        .
      end;
    walk(if type == "string" then redact_string else . end)
  ' \
  "$BUNDLE_DIR/debug.redacted.jsonl" \
  "$tmp_dir/debug.jsonl"

copy_optional_redacted_json_file \
  policy-state.json \
  '
    {
      schema_version,
      sessions: [
        (.sessions // [])[] |
        {
          session_id: "<redacted>",
          policy_state,
          controlled_reality_depth
        }
      ],
      redaction: {
        session_ids_omitted: true
      }
    }
  ' \
  "$BUNDLE_DIR/policy-state.redacted.json" \
  "$tmp_dir/policy-state.json"

event_count=0
debug_count=0
policy_session_count=0

if [[ -f "$BUNDLE_DIR/events.redacted.jsonl" ]]; then
  event_count="$(wc -l < "$BUNDLE_DIR/events.redacted.jsonl" | tr -d ' ')"
fi
if [[ -f "$BUNDLE_DIR/debug.redacted.jsonl" ]]; then
  debug_count="$(wc -l < "$BUNDLE_DIR/debug.redacted.jsonl" | tr -d ' ')"
fi
if [[ -f "$BUNDLE_DIR/policy-state.redacted.json" ]]; then
  policy_session_count="$(jq -r '(.sessions // []) | length' "$BUNDLE_DIR/policy-state.redacted.json")"
fi

write_readme "$event_count" "$debug_count" "$policy_session_count"

(
  cd "$BUNDLE_DIR"
  find . -type f ! -name 'SHA256SUMS' -print0 \
    | sort -z \
    | while IFS= read -r -d '' path; do
        sha256_file "${path#./}"
      done \
    | sed 's#  \./#  #'
) > "$BUNDLE_DIR/SHA256SUMS"

printf 'exported shield evidence bundle: %s\n' "$BUNDLE_DIR"
