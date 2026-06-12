#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
STATUS_SCRIPT="$SCRIPT_DIR/status-orbstack.sh"
EDGE_EXPORT_SCRIPT="${EIDOLON_SHIELD_EDGE_EXPORT_SCRIPT:-$SCRIPT_DIR/export-edge-decisions-orbstack.sh}"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
SESSION_INDEX_LIMIT="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_LIMIT:-25}"
SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE:-}"
SESSION_INDEX_LATEST_MINT_OUTCOME="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_LATEST_MINT_OUTCOME:-}"
SELECTED_SESSION_ID=""
BUNDLE_DIR=""

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/export-orbstack-evidence.sh [--session <UUID>] <bundle-dir>

Exports a redacted Shield lab evidence bundle from the PVC-backed proxy state.

Outputs:
  <bundle-dir>/README.md
  <bundle-dir>/cluster-status.json
  <bundle-dir>/edge-session-index.md
  <bundle-dir>/events.redacted.jsonl
  <bundle-dir>/debug.redacted.jsonl
  <bundle-dir>/policy-state.redacted.json
  <bundle-dir>/SHA256SUMS

Options:
  --session <UUID>  Include one redacted per-session edge summary in the bundle.

Environment:
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_LIMIT
                         Maximum session rows in `edge-session-index.md`.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE
                         Keep only sessions that observed at least N active
                         session-minted bait surfaces in `edge-session-index.md`.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_LATEST_MINT_OUTCOME
                         Keep only sessions whose latest exported minted bait
                         outcome matches `matched_session_value` or
                         `session_value_mismatch`.
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

run_bundle_edge_export() {
  EIDOLON_SHIELD_LOCAL_STATE_DIR="$LOCAL_STATE_DIR" \
    EIDOLON_SHIELD_LOCAL_STATUS_JSON="$BUNDLE_DIR/cluster-status.json" \
    KUBECTL_BIN="$KUBECTL_BIN" \
    CURL_BIN="$CURL_BIN" \
    "$EDGE_EXPORT_SCRIPT" "$@"
}

render_edge_session_index() {
  local export_json="$1"
  local output_path="$2"
  local session_limit="$3"

  jq -r --arg limit "$session_limit" '
    def code($value):
      "`" + ($value | tostring) + "`";
    def redact_path($value):
      if ($value | type) != "string" then
        $value
      else
        ($value | split("#")[0]) as $base
        | if ($base | contains("?")) then
            ($base | split("?")[0]) + "?<redacted>"
          else
            $base
          end
      end;
    def stable_unique($items):
      reduce $items[] as $item ([]; if index($item) == null then . + [$item] else . end);
    def coverage_or_fallback($deployment; $mint_audits):
      if ($deployment.polymorphic_bait_coverage // null) != null then
        $deployment.polymorphic_bait_coverage
      else
        ($deployment.polymorphic_baits // []) as $active_baits
        | (stable_unique($active_baits | map(.bait_id))) as $active_ids
        | (stable_unique($mint_audits | map(.bait_id))) as $observed_ids
        | ($active_ids | map(. as $bait_id | select($observed_ids | index($bait_id) != null))) as $observed_active_ids
        | {
            active_bait_count: ($active_ids | length),
            observed_bait_count: ($observed_active_ids | length),
            observed_bait_ids: $observed_active_ids,
            unobserved_bait_ids: ($active_ids | map(. as $bait_id | select($observed_active_ids | index($bait_id) == null)))
          }
      end;
    def severity_rank($state):
      if $state == "blocked" then 5
      elif $state == "controlled_reality" then 4
      elif $state == "rate_limited" then 3
      elif $state == "suspicious" then 2
      elif $state == "observe" then 1
      else 0
      end;
    ($limit | tonumber) as $limit
    | (if type == "array" then . else [.] end) as $exports
    | ($exports | sort_by([severity_rank(.policy.state), .observed_at]) | reverse) as $sorted
    | ($sorted | length) as $total
    | ($sorted[:$limit]) as $shown
    | ($shown[0].deployment_context // {}) as $deployment
    | ($deployment.polymorphic_baits // []) as $active_polymorphic_baits
    | [
        "# Eidolon Edge Session Index",
        "",
        "This bundle-local index is rendered from the enriched edge export with session identifiers and query values redacted.",
        "",
        "- Exported sessions: " + code($total),
        "- Indexed sessions: " + code($shown | length),
        (
          if $total > ($shown | length) then
            "- Scope: top " + code($shown | length) + " sessions by enforcement severity and recency."
          else
            empty
          end
        ),
        (
          if ($deployment.bait_profile_id // null) != null then
            "- Bait profile: " + code($deployment.bait_profile_id)
          else
            empty
          end
        ),
        (
          if ($active_polymorphic_baits | length) > 0 then
            "- Active deployment polymorphism: "
            + ($active_polymorphic_baits
               | map(code(.surface) + " -> " + code(.header_name) + " [" + code(.prefix) + "]")
               | join(", "))
          else
            empty
          end
        ),
        "",
        "| Session | Observed | Request | Policy | Action | Minted Evidence | Latest Mint Outcome | Minted Coverage | Reason Codes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        (
          $shown
          | to_entries[]
          | .value as $value
          | ($value.deployment_context // {}) as $deployment
          | ($value.evidence.bait_header_value_mints // []) as $mint_audits
          | ($value.evidence.latest_bait_header_value_mint // null) as $latest_mint
          | (coverage_or_fallback($deployment; $mint_audits)) as $coverage
          | "| "
            + code("<redacted-" + ((.key + 1) | tostring) + ">")
            + " | "
            + code($value.observed_at)
            + " | "
            + code($value.request.method + " " + redact_path($value.request.path))
            + " | "
            + code($value.policy.state)
            + " | "
            + code($value.edge_recommendation.action)
            + " | "
            + (
                if ($mint_audits | length) == 0 then
                  code("none")
                else
                  ($mint_audits
                   | map(code(.header_name) + " [" + code(.prefix) + "]")
                   | join(", "))
                end
              )
            + " | "
            + (
                if $latest_mint == null then
                  code("none")
                else
                  code($latest_mint.status)
                  + " via "
                  + code($latest_mint.header_name)
                end
              )
            + " | "
            + (
                if (($deployment.polymorphic_baits // []) | length) == 0 then
                  code("n/a")
                else
                  code((($coverage.observed_bait_count // 0) | tostring) + "/" + (($coverage.active_bait_count // 0) | tostring))
                end
              )
            + " | "
            + (
                if (($value.edge_recommendation.reason_codes // []) | length) == 0 then
                  code("none")
                else
                  (($value.edge_recommendation.reason_codes // []) | map(code(.)) | join(", "))
                end
              )
            + " |"
        )
      ]
    | map(select(. != ""))
    | join("\n")
  ' "$export_json" > "$output_path"
}

write_edge_session_index() {
  local output_path="$1"
  local export_json="$tmp_dir/edge-session-index.json"
  local export_error="$tmp_dir/edge-session-index.err"
  local edge_export_args=(--format json --output "$export_json")

  if [[ -n "$SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE" ]]; then
    edge_export_args+=(
      --min-polymorphic-coverage
      "$SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE"
    )
  fi
  if [[ -n "$SESSION_INDEX_LATEST_MINT_OUTCOME" ]]; then
    edge_export_args+=(
      --latest-mint-outcome
      "$SESSION_INDEX_LATEST_MINT_OUTCOME"
    )
  fi

  if ! run_bundle_edge_export "${edge_export_args[@]}" > /dev/null 2>"$export_error"; then
    if grep -q 'contains no request_seen sessions to export' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --min-polymorphic-coverage' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --latest-mint-outcome' "$export_error"; then
      return 0
    fi
    cat "$export_error" >&2
    return 2
  fi

  if ! jq -e 'length > 0' "$export_json" >/dev/null 2>&1; then
    return 0
  fi

  render_edge_session_index "$export_json" "$output_path" "$SESSION_INDEX_LIMIT"
}

render_selected_session_summary() {
  local export_json="$1"
  local output_path="$2"

  jq -r '
    def present:
      . != null and . != "" and . != [] and . != {};
    def code($value):
      "`" + ($value | tostring) + "`";
    def optional_line($label; $value):
      if ($value | present) then
        "- " + $label + ": " + $value
      else
        empty
      end;
    def stable_unique($items):
      reduce $items[] as $item ([]; if index($item) == null then . + [$item] else . end);
    def coverage_or_fallback($deployment; $mint_audits):
      if ($deployment.polymorphic_bait_coverage // null) != null then
        $deployment.polymorphic_bait_coverage
      else
        ($deployment.polymorphic_baits // []) as $active_baits
        | (stable_unique($active_baits | map(.bait_id))) as $active_ids
        | (stable_unique($mint_audits | map(.bait_id))) as $observed_ids
        | ($active_ids | map(. as $bait_id | select($observed_ids | index($bait_id) != null))) as $observed_active_ids
        | {
            active_bait_count: ($active_ids | length),
            observed_bait_count: ($observed_active_ids | length),
            observed_bait_ids: $observed_active_ids,
            unobserved_bait_ids: ($active_ids | map(. as $bait_id | select($observed_active_ids | index($bait_id) == null)))
          }
      end;
    def redact_path($value):
      if ($value | type) != "string" then
        $value
      else
        ($value | split("#")[0]) as $base
        | if ($base | contains("?")) then
            ($base | split("?")[0]) + "?<redacted>"
          else
            $base
          end
      end;
    def ingress_identity_summary:
      if (.source // "none") == "none"
         and (.trust_tier // "none") == "none"
         and (.label // null) == null then
        code("none")
      else
        code(.source // "none")
        + " / "
        + code(.trust_tier // "none")
        + (if (.label // null) != null then " (" + code(.label) + ")" else "" end)
      end;
    def recon_component_lines($score):
      [
        optional_line("repeated_discovery_score"; ($score.repeated_discovery_score // 0 | if . > 0 then code(.) else empty end)),
        optional_line("query_score"; ($score.query_score // 0 | if . > 0 then code(.) else empty end)),
        optional_line("legacy_openapi_query_score"; ($score.legacy_openapi_query_score // 0 | if . > 0 then code(.) else empty end)),
        optional_line("linked_bait_surface_score"; ($score.linked_bait_surface_score // 0 | if . > 0 then code(.) else empty end)),
        optional_line("linked_bait_class_fanout_bonus"; ($score.linked_bait_class_fanout_bonus // 0 | if . > 0 then code(.) else empty end)),
        optional_line("decoy_write_probe_score"; ($score.decoy_write_probe_score // 0 | if . > 0 then code(.) else empty end)),
        optional_line("decoy_write_probe_path_fanout_bonus"; ($score.decoy_write_probe_path_fanout_bonus // 0 | if . > 0 then code(.) else empty end)),
        optional_line("detection_score"; ($score.detection_score // 0 | if . > 0 then code(.) else empty end))
      ]
      | map(select(. != ""));
    (if type == "array" then .[0] else . end) as $export
    | ($export.ingress_signals // {}) as $signals
    | ($export.discovery_recon_score // {}) as $score
    | ($export.deployment_context // {}) as $deployment
    | ($export.evidence.bait_header_value_mints // []) as $mint_audits
    | ($export.evidence.latest_bait_header_value_mint // null) as $latest_mint
    | ($deployment.polymorphic_baits // []) as $active_polymorphic_baits
    | (coverage_or_fallback($deployment; $mint_audits)) as $coverage
    | (recon_component_lines($score)) as $recon_components
    | [
        optional_line("Pre-containment class"; (($export.policy.pre_containment_persistence_class // null) | if . != null then code(.) else empty end)),
        optional_line("Pre-containment kind"; (($export.policy.pre_containment_persistence_kind // null) | if . != null then code(.) else empty end)),
        optional_line("Post-containment kind"; (($export.policy.post_containment_persistence_kind // null) | if . != null then code(.) else empty end))
      ] as $persistence_lines
    | [
        "# Eidolon Edge Session Summary",
        "",
        "This bundle-local summary is rendered from the enriched edge export with session identifiers and query values redacted.",
        "",
        "## Session",
        "- Session: `<redacted>`",
        "- Observed at: " + code($export.observed_at),
        "- Request: " + code($export.request.method + " " + redact_path($export.request.path)),
        "- Policy state: " + code($export.policy.state),
        "- Routing decision: " + code($export.policy.routing_decision),
        "- Edge action: " + code($export.edge_recommendation.action),
        (if ($export.edge_recommendation.ttl_seconds // null) != null then
          "- TTL seconds: " + code($export.edge_recommendation.ttl_seconds)
        else
          empty
        end),
        "- Policy reason: " + code($export.policy.reason),
        (if (($export.edge_recommendation.reason_codes // []) | length) > 0 then
          "- Reason codes: " + (($export.edge_recommendation.reason_codes // []) | map(code(.)) | join(", "))
        else
          empty
        end),
        "",
        "## Ingress Context",
        "- Identity: " + ($export.ingress_identity | ingress_identity_summary),
        optional_line("Verification strength"; (($signals.verification_strength // null) | if . != null and . != "none" then code(.) else empty end)),
        optional_line("Actor kind"; (($signals.actor_kind // null) | if . != null and . != "unknown" then code(.) else empty end)),
        optional_line("Verified category"; (($signals.verified_category // null) | if . != null then code(.) else empty end)),
        optional_line("Attestation ref"; (($signals.attestation_ref // null) | if . != null then code(.) else empty end)),
        optional_line("Vendor score"; (
          if ($signals.vendor_score // null) != null then
            code($signals.vendor_score)
            + (if ($signals.vendor_score_kind // null) != null then " (" + code($signals.vendor_score_kind) + ")" else "" end)
          else
            empty
          end
        )),
        optional_line("Detection ids"; (
          if (($signals.detection_ids // []) | length) > 0 then
            (($signals.detection_ids // []) | map(code(.)) | join(", "))
          else
            empty
          end
        )),
        optional_line("Ingress edge action hint"; (($signals.edge_action // null) | if . != null then code(.) else empty end)),
        "",
        "## Structured Recon Score",
        (if ($score.total // 0) > 0 then
          "- Total: " + code($score.total) + " / threshold " + code($score.threshold // 0)
        else
          "- No structured recon score recorded."
        end),
        ($recon_components[]?),
        (if ($persistence_lines | map(select(. != "")) | length) > 0 then "## Persistence Classification" else empty end),
        ($persistence_lines[]?),
        "",
        "## Observed Minted Bait Evidence",
        (if ($mint_audits | length) == 0 then
          "- No observed session-minted bait evidence."
        else
          empty
        end),
        (
          $mint_audits[]
          | "- Bait "
            + code(.bait_id)
            + ": "
            + code(.header_name)
            + " [prefix "
            + code(.prefix)
            + ", kind "
            + code(.kind)
            + "]"
        ),
        optional_line("Latest minted outcome"; (
          if $latest_mint != null then
            code($latest_mint.status)
            + " via "
            + code($latest_mint.header_name)
            + " [prefix "
            + code($latest_mint.prefix)
            + ", bait "
            + code($latest_mint.bait_id)
            + "]"
          else
            empty
          end
        )),
        "",
        "## Active Deployment Polymorphism",
        optional_line("Bait profile"; (($deployment.bait_profile_id // null) | if . != null then code(.) else empty end)),
        optional_line("Coverage"; (
          if ($active_polymorphic_baits | length) > 0 then
            code((($coverage.observed_bait_count // 0) | tostring) + "/" + (($coverage.active_bait_count // 0) | tostring))
            + " active session-minted baits observed"
          else
            empty
          end
        )),
        optional_line("Observed active minted baits"; (
          if (($coverage.observed_bait_ids // []) | length) > 0 then
            (($coverage.observed_bait_ids // []) | map(code(.)) | join(", "))
          else
            empty
          end
        )),
        optional_line("Remaining active minted baits"; (
          if (($coverage.unobserved_bait_ids // []) | length) > 0 then
            (($coverage.unobserved_bait_ids // []) | map(code(.)) | join(", "))
          else
            empty
          end
        )),
        (if ($active_polymorphic_baits | length) == 0 then
          "- No active deployment polymorphic bait context."
        else
          empty
        end),
        (
          $active_polymorphic_baits[]
          | "- Surface "
            + code(.surface)
            + ": "
            + code(.header_name)
            + " [prefix "
            + code(.prefix)
            + ", kind "
            + code(.kind)
            + ", bait "
            + code(.bait_id)
            + "]"
        )
      ]
    | map(select(. != ""))
    | join("\n")
  ' "$export_json" > "$output_path"
}

write_selected_session_summary() {
  local output_path="$1"
  local export_json="$tmp_dir/selected-session-edge-export.json"

  run_bundle_edge_export \
    --format json \
    --session "$SELECTED_SESSION_ID" \
    --output "$export_json" >/dev/null

  render_selected_session_summary "$export_json" "$output_path"
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
  local bait_profile_id
  local polymorphic_bait_count
  edge_url="$(jq -r '.edge.url // "unavailable"' "$BUNDLE_DIR/cluster-status.json")"
  edge_status="$(jq -r 'if .edge.http_status == null then "unreachable" else (.edge.http_status | tostring) end' "$BUNDLE_DIR/cluster-status.json")"
  direct_url="$(jq -r '.direct_target_edge.url // "unavailable"' "$BUNDLE_DIR/cluster-status.json")"
  direct_status="$(jq -r 'if .direct_target_edge.http_status == null then "unreachable" else (.direct_target_edge.http_status | tostring) end' "$BUNDLE_DIR/cluster-status.json")"
  proxy_ready="$(jq -r '"\(.proxy.ready_replicas)/\(.proxy.replicas)"' "$BUNDLE_DIR/cluster-status.json")"
  target_ready="$(jq -r '"\(.target.ready_replicas)/\(.target.replicas)"' "$BUNDLE_DIR/cluster-status.json")"
  pvc_status="$(jq -r '.proxy_state.status // "unknown"' "$BUNDLE_DIR/cluster-status.json")"
  bait_profile_id="$(jq -r '.bait_profile.profile_id // "unknown"' "$BUNDLE_DIR/cluster-status.json")"
  polymorphic_bait_count="$(jq -r '(.bait_profile.polymorphic_baits // []) | length' "$BUNDLE_DIR/cluster-status.json")"

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
    printf -- '- Bait profile: `%s`\n' "$bait_profile_id"
    printf -- '- Active polymorphic bait surfaces: `%s`\n' "$polymorphic_bait_count"
    printf -- '- Redacted event log lines: `%s`\n' "$event_count"
    printf -- '- Redacted debug log lines: `%s`\n' "$debug_count"
    printf -- '- Redacted persisted policy sessions: `%s`\n\n' "$policy_session_count"
    printf '## Active Polymorphic Baits\n\n'
    if [[ "$polymorphic_bait_count" -eq 0 ]]; then
      printf 'No active session-minted bait surfaces were exported in `cluster-status.json`.\n\n'
    else
      jq -r '
        (.bait_profile.polymorphic_baits // [])[]
        | "- `\(.surface)` -> `\(.header_name)` (`\(.prefix)`, `\(.kind)`, bait id `\(.bait_id)`)"
      ' "$BUNDLE_DIR/cluster-status.json"
      printf '\n'
    fi
    printf '## Included files\n\n'
    printf -- '- `cluster-status.json`: current cluster-facing operator status, including the active polymorphic bait matrix when available.\n'
    if [[ -f "$BUNDLE_DIR/edge-session-index.md" ]]; then
      printf -- '- `edge-session-index.md`: compact redacted summary of every exported session from the enriched edge export path.\n'
    fi
    printf -- '- `events.redacted.jsonl`: proxy event log with session ids, event ids, exposure ids, and query values redacted.\n'
    printf -- '- `debug.redacted.jsonl`: proxy debug log with session ids, peer addresses, URLs, and query values redacted.\n'
    printf -- '- `policy-state.redacted.json`: persisted policy states with session ids redacted.\n'
    if [[ -n "$SELECTED_SESSION_ID" ]]; then
      printf -- '- `selected-session-edge-summary.md`: one redacted per-session edge summary rendered from the enriched export path.\n'
    fi
    printf -- '- `SHA256SUMS`: checksums for every exported artifact.\n\n'
    printf 'This bundle intentionally omits raw cookies, unredacted session identifiers, raw PVC paths, and intervention-control overrides.\n'
  } > "$BUNDLE_DIR/README.md"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --session)
      [[ $# -ge 2 ]] || fail "missing value for --session"
      SELECTED_SESSION_ID="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      fail "unknown argument: $1"
      ;;
    *)
      if [[ -n "$BUNDLE_DIR" ]]; then
        fail "unexpected positional argument: $1"
      fi
      BUNDLE_DIR="$1"
      shift
      ;;
  esac
done

if [[ -z "$BUNDLE_DIR" ]]; then
  usage >&2
  exit 2
fi

if [[ -n "$SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE" \
  && ! "$SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE" =~ ^[1-9][0-9]*$ ]]; then
  fail "EIDOLON_SHIELD_EDGE_SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE must be a positive integer"
fi

if [[ -n "$SESSION_INDEX_LATEST_MINT_OUTCOME" ]]; then
  case "$SESSION_INDEX_LATEST_MINT_OUTCOME" in
    matched_session_value|session_value_mismatch)
      ;;
    *)
      fail "EIDOLON_SHIELD_EDGE_SESSION_INDEX_LATEST_MINT_OUTCOME must be matched_session_value or session_value_mismatch"
      ;;
  esac
fi

require_command "$KUBECTL_BIN"
require_command jq
require_command "$STATUS_SCRIPT"
if [[ ! -x "$EDGE_EXPORT_SCRIPT" ]]; then
  fail "missing required edge export script: $EDGE_EXPORT_SCRIPT"
fi

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

write_edge_session_index "$BUNDLE_DIR/edge-session-index.md"

if [[ -n "$SELECTED_SESSION_ID" ]]; then
  write_selected_session_summary "$BUNDLE_DIR/selected-session-edge-summary.md"
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
