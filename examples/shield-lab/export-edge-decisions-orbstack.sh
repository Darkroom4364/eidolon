#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
STATUS_SCRIPT="${EIDOLON_SHIELD_STATUS_SCRIPT:-$SCRIPT_DIR/status-orbstack.sh}"

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
LOCAL_STATE_DIR="${EIDOLON_SHIELD_LOCAL_STATE_DIR:-}"
LOCAL_STATUS_JSON="${EIDOLON_SHIELD_LOCAL_STATUS_JSON:-}"
EDGE_EXPORT_BIN="${EIDOLON_EDGE_EXPORT_BIN:-}"
FORMAT="json"
SESSION_ID=""
TOP_LIMIT=""
MIN_POLYMORPHIC_COVERAGE=""
LATEST_MINT_OUTCOME=""
AUTHENTICATED_RULE_REJECTION_LABEL=""
AUTHENTICATED_RULE_REJECTION_REASON=""
AUTHENTICATED_RULE_REJECTION_HISTORY_LABEL=""
AUTHENTICATED_RULE_REJECTION_HISTORY_REASON=""
LOCAL_TRUST_REJECTION_LABEL=""
LOCAL_TRUST_REJECTION_REASON=""
LOCAL_TRUST_REJECTION_HISTORY_LABEL=""
LOCAL_TRUST_REJECTION_HISTORY_REASON=""
TRUSTED_SOFTEN_LABEL=""
TRUSTED_SOFTEN_PATH_SOFTENED=""
TRUSTED_SOFTEN_HISTORY_LABEL=""
TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED=""
WEBHOOK_URL=""
OUTPUT_PATH=""

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/export-edge-decisions-orbstack.sh [OPTIONS]

Builds live Eidolon edge decision exports from the OrbStack Shield lab event log.

Options:
  --format json|ndjson|markdown
                         Output format. Defaults to json.
                         Markdown requires exactly one session.
  --session <UUID>       Export only one session. Defaults to all sessions with request_seen events.
  --top <N>              Keep only the top N sessions ranked by enforcement
                         severity and recency.
  --min-polymorphic-coverage <N>
                         Keep only sessions that observed at least N active
                         session-minted bait surfaces.
  --latest-mint-outcome <matched_session_value|session_value_mismatch>
                         Keep only sessions whose latest exported minted bait
                         outcome matches the given status.
  --authenticated-rule-rejection-label <label>
                         Keep only sessions whose latest authenticated
                         trusted-ingress rule rejection label matches the
                         given value.
  --authenticated-rule-rejection-reason <no_matching_rule|label_missing|label_mismatch|not_yet_active|expired|method_mismatch|path_mismatch|verified_category_missing|verified_category_mismatch>
                         Keep only sessions whose latest authenticated
                         trusted-ingress rule rejection reason matches the
                         given value.
  --authenticated-rule-rejection-history-label <label>
                         Keep only sessions whose authenticated trusted-ingress
                         rule rejection history includes the given label.
  --authenticated-rule-rejection-history-reason <no_matching_rule|label_missing|label_mismatch|not_yet_active|expired|method_mismatch|path_mismatch|verified_category_missing|verified_category_mismatch>
                         Keep only sessions whose authenticated trusted-ingress
                         rule rejection history includes the given reason.
  --local-trust-rejection-label <label>
                         Keep only sessions whose latest local trust scope
                         rejection label matches the given value.
  --local-trust-rejection-reason <not_yet_active|expired|method_mismatch|path_mismatch|required_header_missing|required_header_value_mismatch|request_user_agent_missing|user_agent_mismatch|request_host_missing|host_mismatch|client_peer_missing|source_cidr_mismatch>
                         Keep only sessions whose latest local trust scope
                         rejection reason matches the given value.
  --local-trust-rejection-history-label <label>
                         Keep only sessions whose local trust scope rejection
                         history includes the given label.
  --local-trust-rejection-history-reason <not_yet_active|expired|method_mismatch|path_mismatch|required_header_missing|required_header_value_mismatch|request_user_agent_missing|user_agent_mismatch|request_host_missing|host_mismatch|client_peer_missing|source_cidr_mismatch>
                         Keep only sessions whose local trust scope rejection
                         history includes the given reason.
  --trusted-soften-label <label>
                         Keep only sessions whose matched trusted-ingress
                         soften scope label matches the given value.
  --trusted-soften-path-softened <true|false>
                         Keep only sessions whose matched trusted-ingress
                         soften scope recorded the given request-path softened
                         status.
  --trusted-soften-history-label <label>
                         Keep only sessions whose trusted-ingress soften
                         history includes the given label.
  --trusted-soften-history-path-softened <true|false>
                         Keep only sessions whose trusted-ingress soften
                         history includes at least one request with the given
                         softened or unsoftened status.
  --webhook-url <URL>    POST each export to this webhook as application/json.
  --output <PATH>        Write exports to a file instead of stdout.
  -h, --help             Show this help text.

Environment:
  KUBECTL_BIN                   kubectl command override.
  CURL_BIN                      curl command override.
  EIDOLON_SHIELD_LOCAL_STATE_DIR
                                Read events.jsonl and retained numeric archives
                                from a local fixture directory instead of the
                                live cluster.
  EIDOLON_SHIELD_LOCAL_STATUS_JSON
                                Read status-orbstack JSON from this file when
                                enriching exports with deployment context.
  EIDOLON_EDGE_EXPORT_BIN       Explicit eidolon-edge-export executable path.
                                Defaults to target/debug/eidolon-edge-export if
                                present, otherwise cargo run -q -p eidolon-trace
                                --bin eidolon-edge-export --.

The script reads retained /var/lib/eidolon/events.jsonl.<numeric> archives
followed by /var/lib/eidolon/events.jsonl from the live proxy deployment,
generates one EidolonEdgeDecisionExport per session, and optionally POSTs each
JSON document to a webhook or SIEM receiver.
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

list_local_event_basenames() {
  local candidate
  local basename

  for candidate in "$LOCAL_STATE_DIR"/events.jsonl.*; do
    [[ -f "$candidate" ]] || continue
    basename="${candidate##*/}"
    if [[ "$basename" =~ ^events\.jsonl\.[0-9]+$ ]]; then
      printf '%s\n' "$basename"
    fi
  done | LC_ALL=C sort
  [[ -f "$LOCAL_STATE_DIR/events.jsonl" ]] && printf '%s\n' events.jsonl
}

local_event_log_signature() {
  local basename
  local size

  while IFS= read -r basename; do
    [[ -n "$basename" ]] || continue
    [[ -f "$LOCAL_STATE_DIR/$basename" ]] || return 1
    size="$(wc -c < "$LOCAL_STATE_DIR/$basename")" || return 1
    printf '%s:%s\n' "$basename" "$size"
  done < <(list_local_event_basenames)
}

read_local_event_log_snapshot() {
  local attempt
  local before
  local after
  local basename
  local snapshot
  local copy_ok

  for attempt in {1..8}; do
    before="$(local_event_log_signature 2>/dev/null)" || continue
    snapshot="$(mktemp "${TMPDIR:-/tmp}/eidolon-events-snapshot.XXXXXX")"
    copy_ok=true
    while IFS= read -r basename; do
      [[ -n "$basename" ]] || continue
      if ! cat "$LOCAL_STATE_DIR/$basename" >> "$snapshot"; then
        copy_ok=false
        break
      fi
    done < <(list_local_event_basenames)
    if [[ "$copy_ok" == true ]] \
      && after="$(local_event_log_signature 2>/dev/null)" \
      && [[ "$before" == "$after" ]]; then
      cat "$snapshot"
      rm -f "$snapshot"
      return
    fi
    rm -f "$snapshot"
  done

  fail "proxy event log changed during all snapshot attempts"
}

read_live_event_log_snapshot() {
  kubectl_cmd -n shield-system exec deploy/eidolon-shield-proxy -- sh -lc '
    set -eu

    event_files() {
      for file in /var/lib/eidolon/events.jsonl.*; do
        [ -f "$file" ] || continue
        basename="${file##*/}"
        suffix="${basename#events.jsonl.}"
        case "$suffix" in
          ""|*[!0-9]*) ;;
          *) printf "%s\n" "$basename" ;;
        esac
      done | LC_ALL=C sort
      [ -f /var/lib/eidolon/events.jsonl ] && printf "%s\n" events.jsonl
    }

    signature() {
      event_files | while IFS= read -r basename; do
        [ -n "$basename" ] || continue
        [ -f "/var/lib/eidolon/$basename" ] || exit 1
        size="$(wc -c < "/var/lib/eidolon/$basename")" || exit 1
        printf "%s:%s\n" "$basename" "$size"
      done
    }

    attempt=1
    while [ "$attempt" -le 8 ]; do
      before="$(signature)" || {
        attempt=$((attempt + 1))
        continue
      }
      snapshot="$(mktemp /tmp/eidolon-events-snapshot.XXXXXX)"
      copy_ok=true
      while IFS= read -r basename; do
        [ -n "$basename" ] || continue
        if ! cat "/var/lib/eidolon/$basename" >> "$snapshot"; then
          copy_ok=false
          break
        fi
      done <<EOF
$(event_files)
EOF
      if [ "$copy_ok" = true ]; then
        after="$(signature)" || after="__changed__"
        if [ "$before" = "$after" ]; then
          cat "$snapshot"
          rm -f "$snapshot"
          exit 0
        fi
      fi
      rm -f "$snapshot"
      attempt=$((attempt + 1))
    done

    echo "proxy event log changed during all snapshot attempts" >&2
    exit 1
  '
}

read_proxy_event_log_family() {
  if [[ -n "$LOCAL_STATE_DIR" ]]; then
    read_local_event_log_snapshot
  else
    read_live_event_log_snapshot
  fi
}

read_status_json() {
  if [[ -n "$LOCAL_STATUS_JSON" ]]; then
    cat "$LOCAL_STATUS_JSON"
    return
  fi

  if [[ -n "$LOCAL_STATE_DIR" ]]; then
    local fixture_status_json="$LOCAL_STATE_DIR/cluster-status.json"
    if [[ -f "$fixture_status_json" ]]; then
      cat "$fixture_status_json"
    fi
    return
  fi

  "$STATUS_SCRIPT" --json
}

run_edge_export() {
  if [[ -n "$EDGE_EXPORT_BIN" ]]; then
    "$EDGE_EXPORT_BIN" "$@"
    return
  fi

  if [[ -x "$REPO_ROOT/target/debug/eidolon-edge-export" ]]; then
    "$REPO_ROOT/target/debug/eidolon-edge-export" "$@"
    return
  fi

  cargo run -q -p eidolon-trace --bin eidolon-edge-export -- "$@"
}

collect_session_ids() {
  local events_file="$1"

  if [[ -n "$SESSION_ID" ]]; then
    printf '%s\n' "$SESSION_ID"
    return
  fi

  jq -r '
    select(.kind.type == "request_seen")
    | .session_id
  ' "$events_file" | sort -u
}

write_output() {
  local rendered="$1"

  if [[ -n "$OUTPUT_PATH" ]]; then
    printf '%s\n' "$rendered" > "$OUTPUT_PATH"
  else
    printf '%s\n' "$rendered"
  fi
}

post_webhook() {
  local ndjson_file="$1"

  [[ -n "$WEBHOOK_URL" ]] || return 0

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    curl_cmd -fsS \
      -H 'content-type: application/json' \
      --data "$line" \
      "$WEBHOOK_URL" >/dev/null
  done < "$ndjson_file"
}

rank_and_limit_exports() {
  local input_file="$1"
  local output_file="$2"
  local top_limit="$3"

  jq -s -c --argjson top_limit "$top_limit" '
    def severity_rank($state):
      if $state == "blocked" then 5
      elif $state == "controlled_reality" then 4
      elif $state == "rate_limited" then 3
      elif $state == "suspicious" then 2
      elif $state == "observe" then 1
      else 0
      end;
    sort_by([severity_rank(.policy.state), .observed_at])
    | reverse
    | .[:$top_limit]
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_min_polymorphic_coverage() {
  local input_file="$1"
  local output_file="$2"
  local min_coverage="$3"

  jq -s -c --argjson min_coverage "$min_coverage" '
    map(
      select(
        ((.deployment_context.polymorphic_bait_coverage.observed_bait_count // 0) >= $min_coverage)
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_latest_mint_outcome() {
  local input_file="$1"
  local output_file="$2"
  local outcome="$3"

  jq -s -c --arg outcome "$outcome" '
    map(
      select(
        (.evidence.latest_bait_header_value_mint.status // "") == $outcome
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_authenticated_rule_rejection_label() {
  local input_file="$1"
  local output_file="$2"
  local label="$3"

  jq -s -c --arg label "$label" '
    map(
      select(
        (.authenticated_ingress_rule_rejection.label // "") == $label
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_authenticated_rule_rejection_reason() {
  local input_file="$1"
  local output_file="$2"
  local reason="$3"

  jq -s -c --arg reason "$reason" '
    map(
      select(
        (.authenticated_ingress_rule_rejection.reason // "") == $reason
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_authenticated_rule_rejection_history_label() {
  local input_file="$1"
  local output_file="$2"
  local label="$3"

  jq -s -c --arg label "$label" '
    map(
      select(
        any(
          (.evidence.authenticated_ingress_rule_rejection_histories // [])[];
          (.label // "") == $label
        )
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_authenticated_rule_rejection_history_reason() {
  local input_file="$1"
  local output_file="$2"
  local reason="$3"

  jq -s -c --arg reason "$reason" '
    map(
      select(
        any(
          (.evidence.authenticated_ingress_rule_rejection_histories // [])[];
          any((.reasons // [])[]; . == $reason)
        )
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_local_trust_rejection_label() {
  local input_file="$1"
  local output_file="$2"
  local label="$3"

  jq -s -c --arg label "$label" '
    map(
      select(
        (.local_ingress_trust_scope_rejection.label // "") == $label
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_local_trust_rejection_reason() {
  local input_file="$1"
  local output_file="$2"
  local reason="$3"

  jq -s -c --arg reason "$reason" '
    map(
      select(
        (.local_ingress_trust_scope_rejection.reason // "") == $reason
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_local_trust_rejection_history_label() {
  local input_file="$1"
  local output_file="$2"
  local label="$3"

  jq -s -c --arg label "$label" '
    map(
      select(
        any(
          (.evidence.local_ingress_trust_scope_rejection_histories // [])[];
          (.label // "") == $label
        )
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_local_trust_rejection_history_reason() {
  local input_file="$1"
  local output_file="$2"
  local reason="$3"

  jq -s -c --arg reason "$reason" '
    map(
      select(
        any(
          (.evidence.local_ingress_trust_scope_rejection_histories // [])[];
          any((.reasons // [])[]; . == $reason)
        )
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_trusted_soften_label() {
  local input_file="$1"
  local output_file="$2"
  local label="$3"

  jq -s -c --arg label "$label" '
    map(
      select(
        (.trusted_ingress_soften_match.label // "") == $label
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_trusted_soften_path_softened() {
  local input_file="$1"
  local output_file="$2"
  local path_softened="$3"

  jq -s -c --argjson path_softened "$path_softened" '
    map(
      select(
        (.trusted_ingress_soften_match // null) != null
        and ((.trusted_ingress_soften_match.request_path_softened // false) == $path_softened)
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_trusted_soften_history_label() {
  local input_file="$1"
  local output_file="$2"
  local label="$3"

  jq -s -c --arg label "$label" '
    map(
      select(
        any(
          (.evidence.trusted_ingress_soften_histories // [])[];
          (.label // "") == $label
        )
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

filter_by_trusted_soften_history_path_softened() {
  local input_file="$1"
  local output_file="$2"
  local path_softened="$3"

  jq -s -c --argjson path_softened "$path_softened" '
    map(
      select(
        any(
          (.evidence.trusted_ingress_soften_histories // [])[];
          if $path_softened then
            (.saw_request_path_softened // false)
          else
            (.saw_request_path_unsoftened // false)
          end
        )
      )
    )
    | .[]
  ' "$input_file" > "$output_file"
}

render_markdown_export() {
  local export_file="$1"

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
             + (
                 if ((.verified_categories // []) | length) == 0 then
                   ""
                 else
                   ", categories " + ((.verified_categories // []) | map(code(.)) | join(", "))
                 end
               )
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
    . as $export
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
        "## Session",
        "- Session: " + code($export.session_id),
        "- Observed at: " + code($export.observed_at),
        "- Request: " + code($export.request.method + " " + $export.request.path),
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
        optional_line("Rejected authenticated rule"; (
          if $authenticated_rule_rejection != null then
            "soften "
            + (
                if (($authenticated_rule_rejection.bait_soften_path_prefixes // []) | length) == 0 then
                  code("none")
                else
                  (($authenticated_rule_rejection.bait_soften_path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + "; match "
            + (
                if (($authenticated_rule_rejection.path_prefixes // []) | length) == 0 then
                  code("all")
                else
                  (($authenticated_rule_rejection.path_prefixes // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if (($authenticated_rule_rejection.methods // []) | length) == 0 then
                  ""
                else
                  "; methods "
                  + (($authenticated_rule_rejection.methods // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if (($authenticated_rule_rejection.verified_categories // []) | length) == 0 then
                  ""
                else
                  "; categories "
                  + (($authenticated_rule_rejection.verified_categories // []) | map(code(.)) | join(", "))
                end
              )
            + (
                if ($authenticated_rule_rejection.not_before // null) == null then
                  ""
                else
                  "; not-before " + code($authenticated_rule_rejection.not_before)
                end
              )
            + (
                if ($authenticated_rule_rejection.expires_at // null) == null then
                  ""
                else
                  "; expires " + code($authenticated_rule_rejection.expires_at)
                end
              )
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
                if (($trusted_soften_match.verified_categories // []) | length) == 0 then
                  ""
                else
                  "; categories "
                  + (($trusted_soften_match.verified_categories // []) | map(code(.)) | join(", "))
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
            + "; identity "
            + code(.source)
            + " / "
            + code(.trust_tier)
        )
      ]
    | map(select(. != ""))
    | join("\n")
  ' "$export_file"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      [[ $# -ge 2 ]] || fail "missing value for --format"
      FORMAT="$2"
      shift 2
      ;;
    --session)
      [[ $# -ge 2 ]] || fail "missing value for --session"
      SESSION_ID="$2"
      shift 2
      ;;
    --top)
      [[ $# -ge 2 ]] || fail "missing value for --top"
      TOP_LIMIT="$2"
      shift 2
      ;;
    --min-polymorphic-coverage)
      [[ $# -ge 2 ]] || fail "missing value for --min-polymorphic-coverage"
      MIN_POLYMORPHIC_COVERAGE="$2"
      shift 2
      ;;
    --latest-mint-outcome)
      [[ $# -ge 2 ]] || fail "missing value for --latest-mint-outcome"
      LATEST_MINT_OUTCOME="$2"
      shift 2
      ;;
    --authenticated-rule-rejection-label)
      [[ $# -ge 2 ]] || fail "missing value for --authenticated-rule-rejection-label"
      AUTHENTICATED_RULE_REJECTION_LABEL="$2"
      shift 2
      ;;
    --authenticated-rule-rejection-reason)
      [[ $# -ge 2 ]] || fail "missing value for --authenticated-rule-rejection-reason"
      AUTHENTICATED_RULE_REJECTION_REASON="$2"
      shift 2
      ;;
    --authenticated-rule-rejection-history-label)
      [[ $# -ge 2 ]] || fail "missing value for --authenticated-rule-rejection-history-label"
      AUTHENTICATED_RULE_REJECTION_HISTORY_LABEL="$2"
      shift 2
      ;;
    --authenticated-rule-rejection-history-reason)
      [[ $# -ge 2 ]] || fail "missing value for --authenticated-rule-rejection-history-reason"
      AUTHENTICATED_RULE_REJECTION_HISTORY_REASON="$2"
      shift 2
      ;;
    --local-trust-rejection-label)
      [[ $# -ge 2 ]] || fail "missing value for --local-trust-rejection-label"
      LOCAL_TRUST_REJECTION_LABEL="$2"
      shift 2
      ;;
    --local-trust-rejection-reason)
      [[ $# -ge 2 ]] || fail "missing value for --local-trust-rejection-reason"
      LOCAL_TRUST_REJECTION_REASON="$2"
      shift 2
      ;;
    --local-trust-rejection-history-label)
      [[ $# -ge 2 ]] || fail "missing value for --local-trust-rejection-history-label"
      LOCAL_TRUST_REJECTION_HISTORY_LABEL="$2"
      shift 2
      ;;
    --local-trust-rejection-history-reason)
      [[ $# -ge 2 ]] || fail "missing value for --local-trust-rejection-history-reason"
      LOCAL_TRUST_REJECTION_HISTORY_REASON="$2"
      shift 2
      ;;
    --trusted-soften-label)
      [[ $# -ge 2 ]] || fail "missing value for --trusted-soften-label"
      TRUSTED_SOFTEN_LABEL="$2"
      shift 2
      ;;
    --trusted-soften-path-softened)
      [[ $# -ge 2 ]] || fail "missing value for --trusted-soften-path-softened"
      TRUSTED_SOFTEN_PATH_SOFTENED="$2"
      shift 2
      ;;
    --trusted-soften-history-label)
      [[ $# -ge 2 ]] || fail "missing value for --trusted-soften-history-label"
      TRUSTED_SOFTEN_HISTORY_LABEL="$2"
      shift 2
      ;;
    --trusted-soften-history-path-softened)
      [[ $# -ge 2 ]] || fail "missing value for --trusted-soften-history-path-softened"
      TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED="$2"
      shift 2
      ;;
    --webhook-url)
      [[ $# -ge 2 ]] || fail "missing value for --webhook-url"
      WEBHOOK_URL="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || fail "missing value for --output"
      OUTPUT_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

case "$FORMAT" in
  json|ndjson|markdown)
    ;;
  *)
    fail "format must be json, ndjson, or markdown"
    ;;
esac

if [[ "$FORMAT" == "markdown" && -z "$SESSION_ID" ]]; then
  fail "markdown export requires --session <UUID>"
fi

if [[ "$FORMAT" == "markdown" && -n "$WEBHOOK_URL" ]]; then
  fail "markdown export does not support --webhook-url"
fi

if [[ -n "$TOP_LIMIT" && ! "$TOP_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
  fail "--top must be a positive integer"
fi

if [[ -n "$MIN_POLYMORPHIC_COVERAGE" && ! "$MIN_POLYMORPHIC_COVERAGE" =~ ^[1-9][0-9]*$ ]]; then
  fail "--min-polymorphic-coverage must be a positive integer"
fi

if [[ -n "$LATEST_MINT_OUTCOME" ]]; then
  case "$LATEST_MINT_OUTCOME" in
    matched_session_value|session_value_mismatch)
      ;;
    *)
      fail "--latest-mint-outcome must be matched_session_value or session_value_mismatch"
      ;;
  esac
fi

if [[ -n "$AUTHENTICATED_RULE_REJECTION_REASON" ]]; then
  case "$AUTHENTICATED_RULE_REJECTION_REASON" in
    no_matching_rule|label_missing|label_mismatch|not_yet_active|expired|method_mismatch|path_mismatch|verified_category_missing|verified_category_mismatch)
      ;;
    *)
      fail "--authenticated-rule-rejection-reason must be one of: no_matching_rule, label_missing, label_mismatch, not_yet_active, expired, method_mismatch, path_mismatch, verified_category_missing, verified_category_mismatch"
      ;;
  esac
fi

if [[ -n "$AUTHENTICATED_RULE_REJECTION_HISTORY_REASON" ]]; then
  case "$AUTHENTICATED_RULE_REJECTION_HISTORY_REASON" in
    no_matching_rule|label_missing|label_mismatch|not_yet_active|expired|method_mismatch|path_mismatch|verified_category_missing|verified_category_mismatch)
      ;;
    *)
      fail "--authenticated-rule-rejection-history-reason must be one of: no_matching_rule, label_missing, label_mismatch, not_yet_active, expired, method_mismatch, path_mismatch, verified_category_missing, verified_category_mismatch"
      ;;
  esac
fi

if [[ -n "$LOCAL_TRUST_REJECTION_REASON" ]]; then
  case "$LOCAL_TRUST_REJECTION_REASON" in
    not_yet_active|expired|method_mismatch|path_mismatch|required_header_missing|required_header_value_mismatch|request_user_agent_missing|user_agent_mismatch|request_host_missing|host_mismatch|client_peer_missing|source_cidr_mismatch)
      ;;
    *)
      fail "--local-trust-rejection-reason must be one of: not_yet_active, expired, method_mismatch, path_mismatch, required_header_missing, required_header_value_mismatch, request_user_agent_missing, user_agent_mismatch, request_host_missing, host_mismatch, client_peer_missing, source_cidr_mismatch"
      ;;
  esac
fi

if [[ -n "$LOCAL_TRUST_REJECTION_HISTORY_REASON" ]]; then
  case "$LOCAL_TRUST_REJECTION_HISTORY_REASON" in
    not_yet_active|expired|method_mismatch|path_mismatch|required_header_missing|required_header_value_mismatch|request_user_agent_missing|user_agent_mismatch|request_host_missing|host_mismatch|client_peer_missing|source_cidr_mismatch)
      ;;
    *)
      fail "--local-trust-rejection-history-reason must be one of: not_yet_active, expired, method_mismatch, path_mismatch, required_header_missing, required_header_value_mismatch, request_user_agent_missing, user_agent_mismatch, request_host_missing, host_mismatch, client_peer_missing, source_cidr_mismatch"
      ;;
  esac
fi

if [[ -n "$TRUSTED_SOFTEN_PATH_SOFTENED" ]]; then
  case "$TRUSTED_SOFTEN_PATH_SOFTENED" in
    true|false)
      ;;
    *)
      fail "--trusted-soften-path-softened must be true or false"
      ;;
  esac
fi

if [[ -n "$TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED" ]]; then
  case "$TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED" in
    true|false)
      ;;
    *)
      fail "--trusted-soften-history-path-softened must be true or false"
      ;;
  esac
fi

if [[ -n "$TOP_LIMIT" && -n "$SESSION_ID" ]]; then
  fail "--top cannot be combined with --session"
fi

if [[ "$FORMAT" == "markdown" && -n "$TOP_LIMIT" ]]; then
  fail "--top is not supported for markdown export"
fi

require_command jq
if [[ -z "$LOCAL_STATE_DIR" ]]; then
  require_command "$KUBECTL_BIN"
fi
if [[ -n "$WEBHOOK_URL" ]]; then
  require_command "$CURL_BIN"
fi
if [[ -z "$LOCAL_STATE_DIR" && ! -x "$STATUS_SCRIPT" ]]; then
  fail "missing required status script: $STATUS_SCRIPT"
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-edge-decisions.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

events_file="$tmp_dir/events.jsonl"
read_proxy_event_log_family > "$events_file"
if [[ ! -s "$events_file" ]]; then
  fail "proxy event log is empty"
fi

session_file="$tmp_dir/sessions.txt"
collect_session_ids "$events_file" > "$session_file"
if [[ ! -s "$session_file" ]]; then
  fail "proxy event log contains no request_seen sessions to export"
fi

ndjson_file="$tmp_dir/edge-exports.ndjson"
while IFS= read -r session; do
  [[ -n "$session" ]] || continue
  run_edge_export --events "$events_file" --session "$session" >> "$ndjson_file"
done < "$session_file"

if [[ ! -s "$ndjson_file" ]]; then
  fail "no edge decision exports were produced"
fi

deployment_context_json='null'
if status_json="$(read_status_json 2>/dev/null)" && [[ -n "$status_json" ]]; then
  deployment_context_json="$(
    jq -c '
      if (.bait_profile.profile_id // null) == null
         and ((.bait_profile.polymorphic_baits // []) | length) == 0
         and ((.ingress_trust.authenticated_trusted_ingress_rules // []) | length) == 0
         and ((.ingress_trust.trusted_soften_scopes // []) | length) == 0 then
        null
      else
        {
          bait_profile_id: (.bait_profile.profile_id // null),
          polymorphic_baits: [
            (.bait_profile.polymorphic_baits // [])[]
            | {
                bait_id,
                surface,
                surface_kind,
                header_name,
                kind,
                prefix
              }
          ],
          authenticated_trusted_ingress_rules: [
            (.ingress_trust.authenticated_trusted_ingress_rules // [])[]
            | {
                label,
                source,
                trust_tier,
                not_before,
                expires_at,
                methods,
                path_prefixes,
                bait_soften_path_prefixes,
                verified_categories
              }
          ],
          trusted_ingress_soften_scopes: [
            (.ingress_trust.trusted_soften_scopes // [])[]
            | {
                label,
                source,
                trust_tier,
                not_before,
                expires_at,
                methods,
                path_prefixes,
                bait_soften_path_prefixes,
                user_agent_substrings,
                hosts,
                source_cidrs,
                required_header_names,
                verified_categories
              }
          ]
        }
      end
    ' <<<"$status_json"
  )"
fi

rendered_ndjson="$ndjson_file"
if [[ "$deployment_context_json" != "null" ]]; then
  rendered_ndjson="$tmp_dir/edge-exports.enriched.ndjson"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    jq -c --argjson deployment_context "$deployment_context_json" '
      ($deployment_context.polymorphic_baits // []) as $active_baits
      | (.evidence.bait_header_value_mints // []) as $mint_audits
      | (reduce ($active_baits | map(.bait_id))[] as $item ([]; if index($item) == null then . + [$item] else . end)) as $active_ids
      | (reduce ($mint_audits | map(.bait_id))[] as $item ([]; if index($item) == null then . + [$item] else . end)) as $observed_ids
      | ($active_ids | map(. as $bait_id | select($observed_ids | index($bait_id) != null))) as $observed_active_ids
      | . + {
          deployment_context: (
            $deployment_context
            + {
                polymorphic_bait_coverage: {
                  active_bait_count: ($active_ids | length),
                  observed_bait_count: ($observed_active_ids | length),
                  observed_bait_ids: $observed_active_ids,
                  unobserved_bait_ids: ($active_ids | map(. as $bait_id | select($observed_active_ids | index($bait_id) == null)))
                }
              }
          )
        }
    ' <<<"$line"
  done < "$ndjson_file" > "$rendered_ndjson"
fi

if [[ -n "$MIN_POLYMORPHIC_COVERAGE" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.coverage-filtered.ndjson"
  filter_by_min_polymorphic_coverage \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$MIN_POLYMORPHIC_COVERAGE"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --min-polymorphic-coverage ${MIN_POLYMORPHIC_COVERAGE}"
  fi
fi

if [[ -n "$LATEST_MINT_OUTCOME" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.mint-outcome-filtered.ndjson"
  filter_by_latest_mint_outcome \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$LATEST_MINT_OUTCOME"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --latest-mint-outcome ${LATEST_MINT_OUTCOME}"
  fi
fi

if [[ -n "$AUTHENTICATED_RULE_REJECTION_LABEL" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.authenticated-rule-label-filtered.ndjson"
  filter_by_authenticated_rule_rejection_label \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$AUTHENTICATED_RULE_REJECTION_LABEL"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --authenticated-rule-rejection-label ${AUTHENTICATED_RULE_REJECTION_LABEL}"
  fi
fi

if [[ -n "$AUTHENTICATED_RULE_REJECTION_REASON" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.authenticated-rule-reason-filtered.ndjson"
  filter_by_authenticated_rule_rejection_reason \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$AUTHENTICATED_RULE_REJECTION_REASON"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --authenticated-rule-rejection-reason ${AUTHENTICATED_RULE_REJECTION_REASON}"
  fi
fi

if [[ -n "$AUTHENTICATED_RULE_REJECTION_HISTORY_LABEL" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.authenticated-rule-history-label-filtered.ndjson"
  filter_by_authenticated_rule_rejection_history_label \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$AUTHENTICATED_RULE_REJECTION_HISTORY_LABEL"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --authenticated-rule-rejection-history-label ${AUTHENTICATED_RULE_REJECTION_HISTORY_LABEL}"
  fi
fi

if [[ -n "$AUTHENTICATED_RULE_REJECTION_HISTORY_REASON" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.authenticated-rule-history-reason-filtered.ndjson"
  filter_by_authenticated_rule_rejection_history_reason \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$AUTHENTICATED_RULE_REJECTION_HISTORY_REASON"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --authenticated-rule-rejection-history-reason ${AUTHENTICATED_RULE_REJECTION_HISTORY_REASON}"
  fi
fi

if [[ -n "$LOCAL_TRUST_REJECTION_LABEL" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.local-trust-label-filtered.ndjson"
  filter_by_local_trust_rejection_label \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$LOCAL_TRUST_REJECTION_LABEL"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --local-trust-rejection-label ${LOCAL_TRUST_REJECTION_LABEL}"
  fi
fi

if [[ -n "$LOCAL_TRUST_REJECTION_REASON" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.local-trust-reason-filtered.ndjson"
  filter_by_local_trust_rejection_reason \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$LOCAL_TRUST_REJECTION_REASON"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --local-trust-rejection-reason ${LOCAL_TRUST_REJECTION_REASON}"
  fi
fi

if [[ -n "$LOCAL_TRUST_REJECTION_HISTORY_LABEL" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.local-trust-history-label-filtered.ndjson"
  filter_by_local_trust_rejection_history_label \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$LOCAL_TRUST_REJECTION_HISTORY_LABEL"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --local-trust-rejection-history-label ${LOCAL_TRUST_REJECTION_HISTORY_LABEL}"
  fi
fi

if [[ -n "$LOCAL_TRUST_REJECTION_HISTORY_REASON" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.local-trust-history-reason-filtered.ndjson"
  filter_by_local_trust_rejection_history_reason \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$LOCAL_TRUST_REJECTION_HISTORY_REASON"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --local-trust-rejection-history-reason ${LOCAL_TRUST_REJECTION_HISTORY_REASON}"
  fi
fi

if [[ -n "$TRUSTED_SOFTEN_LABEL" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.trusted-soften-label-filtered.ndjson"
  filter_by_trusted_soften_label \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$TRUSTED_SOFTEN_LABEL"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --trusted-soften-label ${TRUSTED_SOFTEN_LABEL}"
  fi
fi

if [[ -n "$TRUSTED_SOFTEN_PATH_SOFTENED" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.trusted-soften-path-filtered.ndjson"
  filter_by_trusted_soften_path_softened \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$TRUSTED_SOFTEN_PATH_SOFTENED"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --trusted-soften-path-softened ${TRUSTED_SOFTEN_PATH_SOFTENED}"
  fi
fi

if [[ -n "$TRUSTED_SOFTEN_HISTORY_LABEL" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.trusted-soften-history-label-filtered.ndjson"
  filter_by_trusted_soften_history_label \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$TRUSTED_SOFTEN_HISTORY_LABEL"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --trusted-soften-history-label ${TRUSTED_SOFTEN_HISTORY_LABEL}"
  fi
fi

if [[ -n "$TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED" ]]; then
  filtered_ndjson="$tmp_dir/edge-exports.trusted-soften-history-path-filtered.ndjson"
  filter_by_trusted_soften_history_path_softened \
    "$rendered_ndjson" \
    "$filtered_ndjson" \
    "$TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED"
  rendered_ndjson="$filtered_ndjson"
  if [[ ! -s "$rendered_ndjson" ]]; then
    fail "no edge decision exports matched --trusted-soften-history-path-softened ${TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED}"
  fi
fi

if [[ -n "$TOP_LIMIT" ]]; then
  ranked_ndjson="$tmp_dir/edge-exports.top.ndjson"
  rank_and_limit_exports "$rendered_ndjson" "$ranked_ndjson" "$TOP_LIMIT"
  rendered_ndjson="$ranked_ndjson"
fi

post_webhook "$rendered_ndjson"

if [[ "$FORMAT" == "ndjson" ]]; then
  write_output "$(cat "$rendered_ndjson")"
  exit 0
fi

if [[ "$FORMAT" == "markdown" ]]; then
  session_count="$(wc -l < "$rendered_ndjson" | tr -d ' ')"
  if [[ "$session_count" -ne 1 ]]; then
    fail "markdown export requires exactly one rendered session export"
  fi
  write_output "$(render_markdown_export "$rendered_ndjson")"
  exit 0
fi

write_output "$(jq -s '.' "$rendered_ndjson")"
