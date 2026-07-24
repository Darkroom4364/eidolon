#!/usr/bin/env bash
set -euo pipefail

SAMPLE_FILE="${1:-}"
EIDOLON_M3_ALLOW_AGENT_ERRORS="${EIDOLON_M3_ALLOW_AGENT_ERRORS:-0}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/check-pwnkit-sample-health.sh <pwnkit-stability-sample.json>

Fails closed when an aggregated M3 pwnkit sample contains pwnkit agent_error
events. The check prints only sanitized counts and coarse error classes.

Environment:
  EIDOLON_M3_ALLOW_AGENT_ERRORS  If true, allow agent-error samples to pass.
                                 Defaults to 0.
USAGE
}

truthy() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
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

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$SAMPLE_FILE" || ! -f "$SAMPLE_FILE" ]]; then
  fail "pwnkit sample summary not found; pass pwnkit-stability-sample.json"
fi

require_command jq

track_summary="$(
  jq -r '
    def valid_track:
      . == "upstream_current"
      or . == "local_patched_pwnkit"
      or . == "historical_stale";
    def artifact_track:
      (.evidence_track // null) as $explicit
      | if ($explicit | valid_track) then
        $explicit
      elif (.stale_dist_guard_bypassed // false) == true then
        "historical_stale"
      elif .runner_git_dirty == true then
        "local_patched_pwnkit"
      elif ((.runner_origin_main.ahead // 0) > 0) then
        "local_patched_pwnkit"
      elif .runner_git_dirty == false
        and ((.runner_origin_main_in_sync // .runner_origin_main.in_sync // null) == true) then
        "upstream_current"
      elif ((.runner_origin_main.behind // 0) > 0) then
        "historical_stale"
      elif (.runner_pwnkit_fixture.pinned // false) == true
        and ((.runner_git_head // "") != "")
        and .runner_git_dirty == false then
        "local_patched_pwnkit"
      else
        "unknown"
      end;
    [(.artifacts // [])[] | select(.present != false) | artifact_track] as $tracks
    | ($tracks | unique) as $unique
    | {
        tracks: $unique,
        unknown_count: ($tracks | map(select(. == "unknown")) | length),
        mixed: (($unique | length) > 1),
        mixed_upstream_and_patched: (
          ($unique | index("upstream_current")) != null
          and ($unique | index("local_patched_pwnkit")) != null
        )
      }
  ' "$SAMPLE_FILE"
)"

track_count="$(printf '%s' "$track_summary" | jq '.tracks | length')"
unknown_track_count="$(printf '%s' "$track_summary" | jq '.unknown_count')"
mixed_tracks="$(printf '%s' "$track_summary" | jq -r '.mixed')"

if [[ "$track_count" -eq 0 || "$unknown_track_count" -gt 0 || "$mixed_tracks" == "true" ]]; then
  echo "error: pwnkit sample evidence tracks are not claim-safe: $SAMPLE_FILE" >&2
  printf '%s' "$track_summary" | jq -r '
    "       tracks=\((.tracks // []) | join(",")) unknown=\(.unknown_count) mixed=\(.mixed)",
    "       mixed_upstream_and_patched=\(.mixed_upstream_and_patched)"
  ' >&2
  exit 1
fi

finding_claim_violation="$(
  jq -r '
    (.finding_reconciliation // {}) as $fr
    | ($fr.direct_final_json_finding_total // 0) as $direct_final
    | ($fr.eidolon_final_json_finding_total // 0) as $eidolon_final
    | [
        if ($fr.final_json_counts_still_drive_finding_claims // false) != true then
          "final_json_counts_not_marked_authoritative"
        else
          empty
        end,
        if (.differential_findings.ready_for_differential_finding_claim // false)
          and ($eidolon_final <= $direct_final) then
          "differential_claim_without_final_json_delta"
        else
          empty
        end,
        if ((.counts.positive_differential_findings // 0) > 0)
          and ($eidolon_final <= $direct_final) then
          "positive_differential_count_without_final_json_delta"
        else
          empty
        end,
        if ((.rates.positive_differential_finding_rate // 0) > 0)
          and ($eidolon_final <= $direct_final) then
          "positive_differential_rate_without_final_json_delta"
        else
          empty
        end,
        if any(
          (.artifacts // [])[];
          (.finding_gap.positive_differential_findings // false)
          and (
            (.eidolon_final_json_finding_count // .eidolon_finding_count // 0)
            <= (.direct_final_json_finding_count // .direct_finding_count // 0)
          )
        ) then
          "artifact_positive_differential_without_final_json_delta"
        else
          empty
        end
      ]
      | join(",")
  ' "$SAMPLE_FILE"
)"

if [[ -n "$finding_claim_violation" ]]; then
  echo "error: pwnkit sample infers finding claims without final JSON support: $SAMPLE_FILE" >&2
  echo "       violations=$finding_claim_violation" >&2
  jq -r '
    .finding_reconciliation as $fr
    | "       final_json_totals: direct=\($fr.direct_final_json_finding_total // 0) eidolon=\($fr.eidolon_final_json_finding_total // 0)",
      "       db_saved_totals: direct=\($fr.direct_db_saved_finding_total // 0) eidolon=\($fr.eidolon_db_saved_finding_total // 0)"
  ' "$SAMPLE_FILE" >&2
  exit 1
fi

if truthy "$EIDOLON_M3_ALLOW_AGENT_ERRORS"; then
  exit 0
fi

agent_error_count="$(
  jq '
    def aggregate_total:
      (.no_signal_diagnostics.totals.direct_pwnkit_agent_errors // 0)
      + (.no_signal_diagnostics.totals.eidolon_pwnkit_agent_errors // 0);
    def artifact_total:
      [
        (.artifacts // [])[] |
        (.agent_error_diagnostics.direct.count // 0)
        + (.agent_error_diagnostics.eidolon.count // 0)
      ] | add // 0;
    [aggregate_total, artifact_total] | max
  ' "$SAMPLE_FILE"
)"

if [[ "$agent_error_count" -eq 0 ]]; then
  exit 0
fi

echo "error: pwnkit agent errors detected in sample $SAMPLE_FILE" >&2
echo "       clear pwnkit runtime/auth failures before collecting M3 evidence," >&2
echo "       or set EIDOLON_M3_ALLOW_AGENT_ERRORS=1 for diagnostic no-signal artifacts." >&2
jq -r '
  def public_error_class:
    if . == "codex_token_refresh_failed"
      or . == "codex_authentication_failed"
      or . == "codex_backend_timeout"
      or . == "codex_backend_api_error"
      or . == "agent_api_timeout"
      or . == "agent_api_error"
      or . == "pwnkit_agent_error"
    then
      .
    else
      "redacted_unknown"
    end;
  def class_counts:
    .no_signal_diagnostics.eidolon_agent_error_class_counts // []
    | map(
        ((.error_class // null) | public_error_class)
        + "="
        + ((.count // 0) | tostring)
      )
    | join(",");
  .no_signal_diagnostics.totals as $totals
  | "       totals: direct=\($totals.direct_pwnkit_agent_errors // 0) eidolon=\($totals.eidolon_pwnkit_agent_errors // 0)",
    "       eidolon classes=\(class_counts)"
' "$SAMPLE_FILE" >&2
exit 1
