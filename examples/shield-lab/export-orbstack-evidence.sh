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
SESSION_INDEX_LOCAL_TRUST_REJECTION_LABEL="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_LABEL:-}"
SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON:-}"
SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_LABEL="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_LABEL:-}"
SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON:-}"
SESSION_INDEX_TRUSTED_SOFTEN_LABEL="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_LABEL:-}"
SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED:-}"
SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_LABEL="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_LABEL:-}"
SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED="${EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED:-}"
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
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_LABEL
                         Keep only sessions whose latest local trust scope
                         rejection label matches the given value.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON
                         Keep only sessions whose latest local trust scope
                         rejection reason matches `not_yet_active`, `expired`,
                         `required_header_missing`,
                         `required_header_value_mismatch`,
                         `request_user_agent_missing`,
                         `user_agent_mismatch`, `request_host_missing`,
                         `host_mismatch`, `client_peer_missing`, or
                         `source_cidr_mismatch`.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_LABEL
                         Keep only sessions whose local trust scope rejection
                         history includes the given label.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON
                         Keep only sessions whose local trust scope rejection
                         history includes `not_yet_active`, `expired`,
                         `required_header_missing`,
                         `required_header_value_mismatch`,
                         `request_user_agent_missing`,
                         `user_agent_mismatch`, `request_host_missing`,
                         `host_mismatch`, `client_peer_missing`, or
                         `source_cidr_mismatch`.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_LABEL
                         Keep only sessions whose matched trusted-ingress
                         soften scope label matches the given value.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED
                         Keep only sessions whose matched trusted-ingress
                         soften scope recorded `true` or `false` for request
                         path softening.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_LABEL
                         Keep only sessions whose trusted-ingress soften
                         history includes the given label.
  EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED
                         Keep only sessions whose trusted-ingress soften
                         history includes at least one request with `true` or
                         `false` path softening.
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
    def trusted_soften_summary($match):
      if $match == null then
        code("none")
      else
        code($match.label // ($match.source + "/" + $match.trust_tier))
        + " (soften "
        + (
            if (($match.bait_soften_path_prefixes // []) | length) == 0 then
              code("none")
            else
              (($match.bait_soften_path_prefixes // []) | map(code(.)) | join(", "))
            end
          )
        + "; ua "
        + (
            if (($match.user_agent_substrings // []) | length) == 0 then
              code("any")
            else
              (($match.user_agent_substrings // []) | map(code(.)) | join(", "))
            end
          )
        + "; host "
        + (
            if (($match.hosts // []) | length) == 0 then
              code("any")
            else
              (($match.hosts // []) | map(code(.)) | join(", "))
            end
          )
        + (
            if (($match.methods // []) | length) == 0 then
              ""
            else
              "; methods " + (($match.methods // []) | map(code(.)) | join(", "))
            end
          )
        + "; headers "
        + (
            if (($match.required_header_names // []) | length) == 0 then
              code("any")
            else
              (($match.required_header_names // []) | map(code(.)) | join(", "))
            end
          )
        + "; path softened "
        + code($match.request_path_softened)
        + ")"
      end;
    def trusted_soften_history_summary($histories):
      if ($histories | length) == 0 then
        code("none")
      else
        ($histories
         | map(
             code(.label // (.source + "/" + .trust_tier))
             + " [softened "
             + code(.saw_request_path_softened)
             + ", unsoftened "
             + code(.saw_request_path_unsoftened)
             + (
                 if ((.methods // []) | length) == 0 then
                   ""
                 else
                   ", methods " + ((.methods // []) | map(code(.)) | join(", "))
                 end
               )
             + ", ua "
             + (
                 if ((.user_agent_substrings // []) | length) == 0 then
                   code("any")
                 else
                   ((.user_agent_substrings // []) | map(code(.)) | join(", "))
                 end
               )
             + ", host "
             + (
                 if ((.hosts // []) | length) == 0 then
                   code("any")
                 else
                   ((.hosts // []) | map(code(.)) | join(", "))
                 end
               )
             + ", source "
             + (
                 if ((.source_cidrs // []) | length) == 0 then
                   code("any")
                 else
                   ((.source_cidrs // []) | map(code(.)) | join(", "))
                 end
               )
             + ", headers "
             + (
                 if ((.required_header_names // []) | length) == 0 then
                   code("any")
                 else
                   ((.required_header_names // []) | map(code(.)) | join(", "))
                 end
               )
             + "]"
           )
         | join(", "))
      end;
    def local_trust_rejection_history_summary($histories):
      if ($histories | length) == 0 then
        code("none")
      else
        ($histories
         | map(
             code(.label // (.source + "/" + .trust_tier))
             + " ["
             + (
                 if ((.reasons // []) | length) == 0 then
                   code("none")
                 else
                   ((.reasons // []) | map(code(.)) | join(", "))
                 end
               )
             + (
                 if (.not_before // null) == null then
                   ""
                 else
                   "; not-before " + code(.not_before)
                 end
               )
             + (
                 if (.expires_at // null) == null then
                   ""
                 else
                   "; expires " + code(.expires_at)
                 end
               )
             + (
                 if ((.methods // []) | length) == 0 then
                   ""
                 else
                   "; methods " + ((.methods // []) | map(code(.)) | join(", "))
                 end
               )
             + "; ua "
             + (
                 if ((.user_agent_substrings // []) | length) == 0 then
                   code("any")
                 else
                   ((.user_agent_substrings // []) | map(code(.)) | join(", "))
                 end
               )
             + "; host "
             + (
                 if ((.hosts // []) | length) == 0 then
                   code("any")
                 else
                   ((.hosts // []) | map(code(.)) | join(", "))
                 end
               )
             + ", source "
             + (
                 if ((.source_cidrs // []) | length) == 0 then
                   code("any")
                 else
                   ((.source_cidrs // []) | map(code(.)) | join(", "))
                 end
               )
             + "; headers "
             + (
                 if ((.required_header_names // []) | length) == 0 then
                   code("any")
                 else
                   ((.required_header_names // []) | map(code(.)) | join(", "))
                 end
               )
             + "]"
           )
         | join(", "))
      end;
    def trusted_soften_context_summary($match; $histories):
      if $match != null then
        trusted_soften_summary($match)
      else
        trusted_soften_history_summary($histories)
      end;
    def local_trust_rejection_summary($rejection):
      if $rejection == null then
        code("none")
      else
        code($rejection.label // ($rejection.source + "/" + $rejection.trust_tier))
        + " ("
        + code($rejection.reason)
        + ")"
      end;
    def local_trust_rejection_context_summary($rejection; $histories):
      if $rejection != null then
        local_trust_rejection_summary($rejection)
      else
        local_trust_rejection_history_summary($histories)
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
        "| Session | Observed | Request | Policy | Action | Local Trust Rejection | Trusted Soften Context | Minted Evidence | Latest Mint Outcome | Minted Coverage | Reason Codes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        (
          $shown
          | to_entries[]
          | .value as $value
          | ($value.deployment_context // {}) as $deployment
          | ($value.evidence.bait_header_value_mints // []) as $mint_audits
          | ($value.evidence.latest_bait_header_value_mint // null) as $latest_mint
          | ($value.evidence.local_ingress_trust_scope_rejection_histories // [])
            as $local_trust_rejection_histories
          | ($value.evidence.trusted_ingress_soften_histories // []) as $trusted_soften_histories
          | ($value.local_ingress_trust_scope_rejection // null) as $local_trust_rejection
          | ($value.trusted_ingress_soften_match // null) as $trusted_soften_match
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
            + local_trust_rejection_context_summary(
                $local_trust_rejection;
                $local_trust_rejection_histories
              )
            + " | "
            + trusted_soften_context_summary($trusted_soften_match; $trusted_soften_histories)
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
  if [[ -n "$SESSION_INDEX_LOCAL_TRUST_REJECTION_LABEL" ]]; then
    edge_export_args+=(
      --local-trust-rejection-label
      "$SESSION_INDEX_LOCAL_TRUST_REJECTION_LABEL"
    )
  fi
  if [[ -n "$SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON" ]]; then
    edge_export_args+=(
      --local-trust-rejection-reason
      "$SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON"
    )
  fi
  if [[ -n "$SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_LABEL" ]]; then
    edge_export_args+=(
      --local-trust-rejection-history-label
      "$SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_LABEL"
    )
  fi
  if [[ -n "$SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON" ]]; then
    edge_export_args+=(
      --local-trust-rejection-history-reason
      "$SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON"
    )
  fi
  if [[ -n "$SESSION_INDEX_TRUSTED_SOFTEN_LABEL" ]]; then
    edge_export_args+=(
      --trusted-soften-label
      "$SESSION_INDEX_TRUSTED_SOFTEN_LABEL"
    )
  fi
  if [[ -n "$SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED" ]]; then
    edge_export_args+=(
      --trusted-soften-path-softened
      "$SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED"
    )
  fi
  if [[ -n "$SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_LABEL" ]]; then
    edge_export_args+=(
      --trusted-soften-history-label
      "$SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_LABEL"
    )
  fi
  if [[ -n "$SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED" ]]; then
    edge_export_args+=(
      --trusted-soften-history-path-softened
      "$SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED"
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
    if grep -q 'no edge decision exports matched --local-trust-rejection-label' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --local-trust-rejection-reason' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --local-trust-rejection-history-label' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --local-trust-rejection-history-reason' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --trusted-soften-label' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --trusted-soften-path-softened' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --trusted-soften-history-label' "$export_error"; then
      return 0
    fi
    if grep -q 'no edge decision exports matched --trusted-soften-history-path-softened' "$export_error"; then
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
    def trusted_soften_history_summary($histories):
      if ($histories | length) == 0 then
        empty
      else
        ($histories
         | map(
             code(.label // (.source + "/" + .trust_tier))
             + " [softened "
             + code(.saw_request_path_softened)
             + ", unsoftened "
             + code(.saw_request_path_unsoftened)
             + ", ua "
             + (
                 if ((.user_agent_substrings // []) | length) == 0 then
                   code("any")
                 else
                   ((.user_agent_substrings // []) | map(code(.)) | join(", "))
                 end
               )
             + ", host "
             + (
                 if ((.hosts // []) | length) == 0 then
                   code("any")
                 else
                   ((.hosts // []) | map(code(.)) | join(", "))
                 end
               )
             + ", source "
             + (
                 if ((.source_cidrs // []) | length) == 0 then
                   code("any")
                 else
                   ((.source_cidrs // []) | map(code(.)) | join(", "))
                 end
               )
             + ", headers "
             + (
                 if ((.required_header_names // []) | length) == 0 then
                   code("any")
                 else
                   ((.required_header_names // []) | map(code(.)) | join(", "))
                 end
               )
             + "]"
           )
         | join(", "))
      end;
    def local_trust_rejection_history_summary($histories):
      if ($histories | length) == 0 then
        empty
      else
        ($histories
         | map(
             code(.label // (.source + "/" + .trust_tier))
             + " ["
             + (
                 if ((.reasons // []) | length) == 0 then
                   code("none")
                 else
                   ((.reasons // []) | map(code(.)) | join(", "))
                 end
               )
             + (
                 if (.not_before // null) == null then
                   ""
                 else
                   "; not-before " + code(.not_before)
                 end
               )
             + (
                 if (.expires_at // null) == null then
                   ""
                 else
                   "; expires " + code(.expires_at)
                 end
               )
             + "; ua "
             + (
                 if ((.user_agent_substrings // []) | length) == 0 then
                   code("any")
                 else
                   ((.user_agent_substrings // []) | map(code(.)) | join(", "))
                 end
               )
             + "; host "
             + (
                 if ((.hosts // []) | length) == 0 then
                   code("any")
                 else
                   ((.hosts // []) | map(code(.)) | join(", "))
                 end
               )
             + ", source "
             + (
                 if ((.source_cidrs // []) | length) == 0 then
                   code("any")
                 else
                   ((.source_cidrs // []) | map(code(.)) | join(", "))
                 end
               )
             + "; headers "
             + (
                 if ((.required_header_names // []) | length) == 0 then
                   code("any")
                 else
                   ((.required_header_names // []) | map(code(.)) | join(", "))
                 end
               )
             + "]"
           )
         | join(", "))
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
    | ($export.authenticated_ingress_rule_rejection // null) as $authenticated_rule_rejection
    | ($export.local_ingress_trust_scope_rejection // null) as $local_trust_rejection
    | ($export.trusted_ingress_soften_match // null) as $trusted_soften_match
    | ($export.evidence.bait_header_value_mints // []) as $mint_audits
    | ($export.evidence.latest_bait_header_value_mint // null) as $latest_mint
    | ($export.evidence.authenticated_ingress_rule_rejection_histories // [])
      as $authenticated_rule_rejection_histories
    | ($export.evidence.local_ingress_trust_scope_rejection_histories // [])
      as $local_trust_rejection_histories
    | ($export.evidence.trusted_ingress_soften_histories // []) as $trusted_soften_histories
    | ($deployment.polymorphic_baits // []) as $active_polymorphic_baits
    | ($deployment.authenticated_trusted_ingress_rules // []) as $active_authenticated_rules
    | ($deployment.trusted_ingress_soften_scopes // []) as $active_trusted_soften_scopes
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
        optional_line("Authenticated rule rejection"; (
          if $authenticated_rule_rejection != null then
            code($authenticated_rule_rejection.label // ($authenticated_rule_rejection.source + "/" + $authenticated_rule_rejection.trust_tier))
            + " (" + code($authenticated_rule_rejection.reason) + ")"
          else
            empty
          end
        )),
        optional_line("Authenticated rule rejection history"; (
          if ($authenticated_rule_rejection_histories | length) == 0 then
            empty
          else
            ($authenticated_rule_rejection_histories
             | map(
                 code(.label // (.source + "/" + .trust_tier))
                 + " ["
                 + (
                     if ((.reasons // []) | length) == 0 then
                       code("none")
                     else
                       ((.reasons // []) | map(code(.)) | join(", "))
                     end
                   )
                 + (
                     if ((.verified_categories // []) | length) == 0 then
                       ""
                     else
                       "; categories " + ((.verified_categories // []) | map(code(.)) | join(", "))
                     end
                   )
                 + "]"
               )
             | join(", "))
          end
        )),
        optional_line("Local trust scope rejection"; (
          if $local_trust_rejection != null then
            code($local_trust_rejection.label // ($local_trust_rejection.source + "/" + $local_trust_rejection.trust_tier))
            + " (" + code($local_trust_rejection.reason) + ")"
          else
            empty
          end
        )),
        optional_line("Rejected local trust scope"; (
          if $local_trust_rejection != null then
            "soften "
            + (
                if (($local_trust_rejection.bait_soften_path_prefixes // []) | length) == 0 then
                  code("none")
                else
                  (($local_trust_rejection.bait_soften_path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + "; match "
            + (
                if (($local_trust_rejection.path_prefixes // []) | length) == 0 then
                  code("all")
                else
                  (($local_trust_rejection.path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if (($local_trust_rejection.methods // []) | length) == 0 then
                  ""
                else
                  "; methods "
                  + (($local_trust_rejection.methods // []) | map(code(.)) | join(", "))
                end
              )
            + "; ua "
            + (
                if (($local_trust_rejection.user_agent_substrings // []) | length) == 0 then
                  code("any")
                else
                  (($local_trust_rejection.user_agent_substrings // []) | map(code(.)) | join(", "))
                end
              )
            + "; host "
            + (
                if (($local_trust_rejection.hosts // []) | length) == 0 then
                  code("any")
                else
                  (($local_trust_rejection.hosts // []) | map(code(.)) | join(", "))
                end
              )
            + "; source "
            + (
                if (($local_trust_rejection.source_cidrs // []) | length) == 0 then
                  code("any")
                else
                  (($local_trust_rejection.source_cidrs // []) | map(code(.)) | join(", "))
                end
              )
            + "; headers "
            + (
                if (($local_trust_rejection.required_header_names // []) | length) == 0 then
                  code("any")
                else
                  (($local_trust_rejection.required_header_names // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if ($local_trust_rejection.not_before // null) == null then
                  ""
                else
                  "; not-before " + code($local_trust_rejection.not_before)
                end
              )
            + (
                if ($local_trust_rejection.expires_at // null) == null then
                  ""
                else
                  "; expires " + code($local_trust_rejection.expires_at)
                end
              )
          else
            empty
          end
        )),
        optional_line("Local trust rejection history"; local_trust_rejection_history_summary($local_trust_rejection_histories)),
        optional_line("Trusted soften match"; (
          if $trusted_soften_match != null then
            code($trusted_soften_match.label // ($trusted_soften_match.source + "/" + $trusted_soften_match.trust_tier))
            + " (" + code($trusted_soften_match.source) + " / " + code($trusted_soften_match.trust_tier) + ")"
          else
            empty
          end
        )),
        optional_line("Trusted soften scope"; (
          if $trusted_soften_match != null then
            "soften "
            + (
                if (($trusted_soften_match.bait_soften_path_prefixes // []) | length) == 0 then
                  code("none")
                else
                  (($trusted_soften_match.bait_soften_path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + "; match "
            + (
                if (($trusted_soften_match.path_prefixes // []) | length) == 0 then
                  code("all")
                else
                  (($trusted_soften_match.path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if (($trusted_soften_match.methods // []) | length) == 0 then
                  ""
                else
                  "; methods "
                  + (($trusted_soften_match.methods // []) | map(code(.)) | join(", "))
                end
              )
            + "; ua "
            + (
                if (($trusted_soften_match.user_agent_substrings // []) | length) == 0 then
                  code("any")
                else
                  (($trusted_soften_match.user_agent_substrings // []) | map(code(.)) | join(", "))
                end
              )
            + "; host "
            + (
                if (($trusted_soften_match.hosts // []) | length) == 0 then
                  code("any")
                else
                  (($trusted_soften_match.hosts // []) | map(code(.)) | join(", "))
                end
              )
            + "; source "
            + (
                if (($trusted_soften_match.source_cidrs // []) | length) == 0 then
                  code("any")
                else
                  (($trusted_soften_match.source_cidrs // []) | map(code(.)) | join(", "))
                end
              )
            + "; headers "
            + (
                if (($trusted_soften_match.required_header_names // []) | length) == 0 then
                  code("any")
                else
                  (($trusted_soften_match.required_header_names // []) | map(code(.)) | join(", "))
                end
              )
            + "; request path softened "
            + code($trusted_soften_match.request_path_softened)
          else
            empty
          end
        )),
        optional_line("Trusted soften history"; trusted_soften_history_summary($trusted_soften_histories)),
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
        ),
        "",
        "## Active Authenticated Trusted Ingress Rules",
        (if ($active_authenticated_rules | length) == 0 then
          "- No active authenticated trusted-ingress rules."
        else
          empty
        end),
        (
          $active_authenticated_rules[]
          | "- Rule "
            + code((.label // (.source + "/" + .trust_tier)))
            + ": match "
            + (
                if ((.path_prefixes // []) | length) == 0 then
                  code("all")
                else
                  ((.path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if ((.bait_soften_path_prefixes // []) | length) == 0 then
                  "; soften none"
                else
                  "; soften " + ((.bait_soften_path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if ((.verified_categories // []) | length) == 0 then
                  ""
                else
                  "; categories " + ((.verified_categories // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if ((.methods // []) | length) == 0 then
                  ""
                else
                  "; methods " + ((.methods // []) | map(code(.)) | join(", "))
                end
              )
        ),
        "",
        "## Active Trusted Ingress Softening",
        (if ($active_trusted_soften_scopes | length) == 0 then
          "- No active trusted-ingress soften scopes."
        else
          empty
        end),
        (
          $active_trusted_soften_scopes[]
          | "- Scope "
            + code((.label // (.source + "/" + .trust_tier)))
            + ": soften "
            + (
                if ((.bait_soften_path_prefixes // []) | length) == 0 then
                  code("none")
                else
                  ((.bait_soften_path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + "; match "
            + (
                if ((.path_prefixes // []) | length) == 0 then
                  code("all")
                else
                  ((.path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + "; ua "
            + (
                if ((.user_agent_substrings // []) | length) == 0 then
                  code("any")
                else
                  ((.user_agent_substrings // []) | map(code(.)) | join(", "))
                end
              )
            + "; host "
            + (
                if ((.hosts // []) | length) == 0 then
                  code("any")
                else
                  ((.hosts // []) | map(code(.)) | join(", "))
                end
              )
            + "; source "
            + (
                if ((.source_cidrs // []) | length) == 0 then
                  code("any")
                else
                  ((.source_cidrs // []) | map(code(.)) | join(", "))
                end
              )
            + "; headers "
            + (
                if ((.required_header_names // []) | length) == 0 then
                  code("any")
                else
                  ((.required_header_names // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if (.expires_at // null) == null then
                  ""
                else
                  "; expires " + code(.expires_at)
                end
              )
            + "; identity "
            + code(.source)
            + " / "
            + code(.trust_tier)
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
  local authenticated_rule_count
  local trusted_soften_scope_count
  edge_url="$(jq -r '.edge.url // "unavailable"' "$BUNDLE_DIR/cluster-status.json")"
  edge_status="$(jq -r 'if .edge.http_status == null then "unreachable" else (.edge.http_status | tostring) end' "$BUNDLE_DIR/cluster-status.json")"
  direct_url="$(jq -r '.direct_target_edge.url // "unavailable"' "$BUNDLE_DIR/cluster-status.json")"
  direct_status="$(jq -r 'if .direct_target_edge.http_status == null then "unreachable" else (.direct_target_edge.http_status | tostring) end' "$BUNDLE_DIR/cluster-status.json")"
  proxy_ready="$(jq -r '"\(.proxy.ready_replicas)/\(.proxy.replicas)"' "$BUNDLE_DIR/cluster-status.json")"
  target_ready="$(jq -r '"\(.target.ready_replicas)/\(.target.replicas)"' "$BUNDLE_DIR/cluster-status.json")"
  pvc_status="$(jq -r '.proxy_state.status // "unknown"' "$BUNDLE_DIR/cluster-status.json")"
  bait_profile_id="$(jq -r '.bait_profile.profile_id // "unknown"' "$BUNDLE_DIR/cluster-status.json")"
  polymorphic_bait_count="$(jq -r '(.bait_profile.polymorphic_baits // []) | length' "$BUNDLE_DIR/cluster-status.json")"
  authenticated_rule_count="$(jq -r '(.ingress_trust.authenticated_trusted_ingress_rules // []) | length' "$BUNDLE_DIR/cluster-status.json")"
  trusted_soften_scope_count="$(jq -r '(.ingress_trust.trusted_soften_scopes // []) | length' "$BUNDLE_DIR/cluster-status.json")"

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
    printf -- '- Active authenticated trusted-ingress rules: `%s`\n' "$authenticated_rule_count"
    printf -- '- Trusted ingress soften scopes: `%s`\n' "$trusted_soften_scope_count"
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
    printf '## Active Authenticated Trusted Ingress Rules\n\n'
    if [[ "$authenticated_rule_count" -eq 0 ]]; then
      printf 'No active authenticated trusted-ingress rules were exported in `cluster-status.json`.\n\n'
    else
      jq -r '
        (.ingress_trust.authenticated_trusted_ingress_rules // [])[]
        | "- `\(.label // (.source + "/" + .trust_tier))`: match "
          + (
              if ((.path_prefixes // []) | length) == 0 then
                "`all`"
              else
                ((.path_prefixes // []) | map("`" + . + "`") | join(", "))
              end
            )
          + (
              if ((.bait_soften_path_prefixes // []) | length) == 0 then
                "; soften `none`"
              else
                "; soften " + ((.bait_soften_path_prefixes // []) | map("`" + . + "`") | join(", "))
              end
            )
          + (
              if ((.verified_categories // []) | length) == 0 then
                ""
              else
                "; categories " + ((.verified_categories // []) | map("`" + . + "`") | join(", "))
              end
            )
          + (
              if ((.methods // []) | length) == 0 then
                ""
              else
                "; methods " + ((.methods // []) | map("`" + . + "`") | join(", "))
              end
            )
      ' "$BUNDLE_DIR/cluster-status.json"
      printf '\n'
    fi
    printf '## Active Trusted Ingress Softening\n\n'
    if [[ "$trusted_soften_scope_count" -eq 0 ]]; then
      printf 'No active trusted-ingress soften scopes were exported in `cluster-status.json`.\n\n'
    else
      jq -r '
        (.ingress_trust.trusted_soften_scopes // [])[]
        | "- `\(.label // (.source + "/" + .trust_tier))`: soften "
          + (
              if ((.bait_soften_path_prefixes // []) | length) == 0 then
                "`none`"
              else
                ((.bait_soften_path_prefixes // []) | map("`" + . + "`") | join(", "))
              end
            )
          + "; match "
          + (
              if ((.path_prefixes // []) | length) == 0 then
                "`all`"
              else
                ((.path_prefixes // []) | map("`" + . + "`") | join(", "))
              end
            )
          + (
              if ((.methods // []) | length) == 0 then
                ""
              else
                "; methods " + ((.methods // []) | map("`" + . + "`") | join(", "))
              end
            )
          + "; ua "
          + (
              if ((.user_agent_substrings // []) | length) == 0 then
                "`any`"
              else
                ((.user_agent_substrings // []) | map("`" + . + "`") | join(", "))
              end
            )
          + "; host "
          + (
              if ((.hosts // []) | length) == 0 then
                "`any`"
              else
                ((.hosts // []) | map("`" + . + "`") | join(", "))
              end
            )
          + "; source "
          + (
              if ((.source_cidrs // []) | length) == 0 then
                "`any`"
              else
                ((.source_cidrs // []) | map("`" + . + "`") | join(", "))
              end
            )
          + "; headers "
          + (
              if ((.required_header_names // []) | length) == 0 then
                "`any`"
              else
                ((.required_header_names // []) | map("`" + . + "`") | join(", "))
              end
            )
          + (
              if (.not_before // null) == null then
                ""
              else
                "; not-before `" + .not_before + "`"
              end
            )
          + (
              if (.expires_at // null) == null then
                ""
              else
                "; expires `" + .expires_at + "`"
              end
            )
          + "; identity `\(.source)` / `\(.trust_tier)`"
      ' "$BUNDLE_DIR/cluster-status.json"
      printf '\n'
    fi
    printf '## Included files\n\n'
    printf -- '- `cluster-status.json`: current cluster-facing operator status, including the active polymorphic bait matrix and trusted-ingress soften scopes when available.\n'
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

if [[ -n "$SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON" ]]; then
  case "$SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON" in
    not_yet_active|expired|method_mismatch|path_mismatch|required_header_missing|required_header_value_mismatch|request_user_agent_missing|user_agent_mismatch|request_host_missing|host_mismatch|client_peer_missing|source_cidr_mismatch)
      ;;
    *)
      fail "EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON must be one of: not_yet_active, expired, method_mismatch, path_mismatch, required_header_missing, required_header_value_mismatch, request_user_agent_missing, user_agent_mismatch, request_host_missing, host_mismatch, client_peer_missing, source_cidr_mismatch"
      ;;
  esac
fi

if [[ -n "$SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON" ]]; then
  case "$SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON" in
    not_yet_active|expired|method_mismatch|path_mismatch|required_header_missing|required_header_value_mismatch|request_user_agent_missing|user_agent_mismatch|request_host_missing|host_mismatch|client_peer_missing|source_cidr_mismatch)
      ;;
    *)
      fail "EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON must be one of: not_yet_active, expired, method_mismatch, path_mismatch, required_header_missing, required_header_value_mismatch, request_user_agent_missing, user_agent_mismatch, request_host_missing, host_mismatch, client_peer_missing, source_cidr_mismatch"
      ;;
  esac
fi

if [[ -n "$SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED" ]]; then
  case "$SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED" in
    true|false)
      ;;
    *)
      fail "EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED must be true or false"
      ;;
  esac
fi

if [[ -n "$SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED" ]]; then
  case "$SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED" in
    true|false)
      ;;
    *)
      fail "EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED must be true or false"
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
