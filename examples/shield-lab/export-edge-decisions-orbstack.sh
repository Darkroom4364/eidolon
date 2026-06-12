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
  --webhook-url <URL>    POST each export to this webhook as application/json.
  --output <PATH>        Write exports to a file instead of stdout.
  -h, --help             Show this help text.

Environment:
  KUBECTL_BIN                   kubectl command override.
  CURL_BIN                      curl command override.
  EIDOLON_SHIELD_LOCAL_STATE_DIR
                                Read events.jsonl from a local fixture directory
                                instead of the live cluster.
  EIDOLON_SHIELD_LOCAL_STATUS_JSON
                                Read status-orbstack JSON from this file when
                                enriching exports with deployment context.
  EIDOLON_EDGE_EXPORT_BIN       Explicit eidolon-edge-export executable path.
                                Defaults to target/debug/eidolon-edge-export if
                                present, otherwise cargo run -q -p eidolon-trace
                                --bin eidolon-edge-export --.

The script reads /var/lib/eidolon/events.jsonl from the live proxy deployment,
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

read_proxy_state_file() {
  local basename="$1"

  if [[ -n "$LOCAL_STATE_DIR" ]]; then
    cat "$LOCAL_STATE_DIR/$basename"
    return
  fi

  kubectl_cmd -n shield-system exec deploy/eidolon-shield-proxy -- sh -lc "cat /var/lib/eidolon/$basename"
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
    | ($export.evidence.bait_header_value_mints // []) as $mint_audits
    | ($export.evidence.latest_bait_header_value_mint // null) as $latest_mint
    | ($deployment.polymorphic_baits // []) as $active_polymorphic_baits
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
read_proxy_state_file events.jsonl > "$events_file"
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
          trusted_ingress_soften_scopes: [
            (.ingress_trust.trusted_soften_scopes // [])[]
            | {
                label,
                source,
                trust_tier,
                path_prefixes,
                bait_soften_path_prefixes
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
