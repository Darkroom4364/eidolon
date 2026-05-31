#!/usr/bin/env bash
set -euo pipefail

PWNKIT_ARTIFACT_DIR="${PWNKIT_ARTIFACT_DIR:-}"
ACTION_ARTIFACT_DIR="${ACTION_ARTIFACT_DIR:-}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/report.sh --pwnkit-artifact <dir> --action-artifact <dir>

Emits an internal M3 uniqueness report as Markdown. The pwnkit artifact
directory must contain pwnkit-summary.json or pwnkit-summary.redacted.json.
pwnkit-eidolon.json is optional; when omitted, per-bait finding text matching is
skipped. The action artifact directory must contain action-trace-summary.json
from examples/m3/collect-action-trace.sh or agent-replay-trace-summary.json from
examples/m3/collect-agent-replay-trace.sh.

Environment fallbacks:
  PWNKIT_ARTIFACT_DIR   Directory containing pwnkit-summary.json.
  ACTION_ARTIFACT_DIR   Directory containing action-trace-summary.json.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --pwnkit-artifact)
      if [[ "$#" -lt 2 ]]; then
        echo "error: --pwnkit-artifact requires a directory" >&2
        exit 2
      fi
      PWNKIT_ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    --action-artifact)
      if [[ "$#" -lt 2 ]]; then
        echo "error: --action-artifact requires a directory" >&2
        exit 2
      fi
      ACTION_ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$PWNKIT_ARTIFACT_DIR" || ! -d "$PWNKIT_ARTIFACT_DIR" ]]; then
  echo "error: pass --pwnkit-artifact with an existing directory" >&2
  exit 2
fi

if [[ -z "$ACTION_ARTIFACT_DIR" || ! -d "$ACTION_ARTIFACT_DIR" ]]; then
  echo "error: pass --action-artifact with an existing directory" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: missing required tool: jq" >&2
  exit 2
fi

PWNKIT_SUMMARY="$PWNKIT_ARTIFACT_DIR/pwnkit-summary.json"
if [[ ! -s "$PWNKIT_SUMMARY" && -s "$PWNKIT_ARTIFACT_DIR/pwnkit-summary.redacted.json" ]]; then
  PWNKIT_SUMMARY="$PWNKIT_ARTIFACT_DIR/pwnkit-summary.redacted.json"
fi

PWNKIT_REPORT="$PWNKIT_ARTIFACT_DIR/pwnkit-eidolon.json"
if [[ ! -s "$PWNKIT_REPORT" ]]; then
  PWNKIT_REPORT="/dev/null"
fi

ACTION_TRACE="$ACTION_ARTIFACT_DIR/action-trace-summary.json"
if [[ ! -s "$ACTION_TRACE" && -s "$ACTION_ARTIFACT_DIR/agent-replay-trace-summary.json" ]]; then
  ACTION_TRACE="$ACTION_ARTIFACT_DIR/agent-replay-trace-summary.json"
fi

for required_file in "$PWNKIT_SUMMARY" "$ACTION_TRACE"; do
  if [[ ! -s "$required_file" ]]; then
    echo "error: required artifact is missing or empty: $required_file" >&2
    exit 2
  fi
done

jq -r -n \
  --slurpfile pwnkit "$PWNKIT_SUMMARY" \
  --slurpfile pwnkit_report "$PWNKIT_REPORT" \
  --slurpfile action "$ACTION_TRACE" \
  --arg pwnkit_artifact_dir "$PWNKIT_ARTIFACT_DIR" \
  --arg action_artifact_dir "$ACTION_ARTIFACT_DIR" '
  def pwnkit: $pwnkit[0];
  def pwnkit_report: ($pwnkit_report[0] // {findings: []});
  def action: $action[0];
  def pwnkit_runner: pwnkit.runner // {};

  def bool_word($value):
    if $value then "yes" else "no" end;

  def optional_number($value):
    if $value == null then "null" else ($value | tostring) end;

  def optional_text($value):
    if $value == null or $value == "" then "not recorded" else ($value | tostring) end;

  def status_word($value):
    if $value then "pass" else "open" end;

  def count_summary($rows):
    (($rows // [])
     | map((.value | tostring) + ":" + (.count | tostring))
     | if length == 0 then "none" else join(", ") end);

  def markdown_text($value):
    (($value // "") | tostring | gsub("\\|"; "\\|") | gsub("[\r\n]"; " "));

  def report_path($value):
    ($value // "not recorded") as $path
    | if ($path | startswith("/")) then
        "<artifact-path-omitted>"
      else
        $path
      end;

  def bait_class($bait_id):
    {
      rel_2025_04_b7f2: "docs",
      openapi_reconcile_trace: "open_api",
      hidden_route_trace: "hidden_route",
      fake_service_token: "fake_credential_token",
      js_worker_resume_trace: "js_discovered_route"
    }[$bait_id] // "unknown";

  def expected_surface($bait_id):
    {
      rel_2025_04_b7f2: "/docs/legacy-import",
      openapi_reconcile_trace: "/openapi.json",
      hidden_route_trace: "/customer/import-recovery-checklist",
      fake_service_token: "/docs/service-token",
      js_worker_resume_trace: "/assets/import-helper.js"
    }[$bait_id] // "";

  def known_bait_ids:
    [
      "rel_2025_04_b7f2",
      "openapi_reconcile_trace",
      "hidden_route_trace",
      "fake_service_token",
      "js_worker_resume_trace"
    ];

  def finding_text:
    [
      .title,
      .description,
      .evidence.request,
      .evidence.analysis
    ]
    | map(. // "")
    | join(" ")
    | ascii_downcase;

  def finding_matches_bait($bait_id):
    (finding_text) as $text
    | if $bait_id == "rel_2025_04_b7f2" then
        ($text | contains("/docs/legacy-import") or contains("x-migration-trace"))
      elif $bait_id == "openapi_reconcile_trace" then
        ($text | contains("/openapi.json") or contains("x-openapi-trace"))
      elif $bait_id == "hidden_route_trace" then
        ($text | contains("/customer/import-recovery-checklist") or contains("/internal/legacy-import-checklist") or contains("x-hidden-route-trace"))
      elif $bait_id == "fake_service_token" then
        ($text | contains("/docs/service-token") or contains("x-api-key"))
      elif $bait_id == "js_worker_resume_trace" then
        ($text | contains("/assets/import-helper.js") or contains("x-import-worker"))
      else
        false
      end;

  def pwnkit_finding_count_for($bait_id):
    [ pwnkit_report.findings[]? | select(finding_matches_bait($bait_id)) ]
    | length;

  def scripted_confirmed_count_for($bait_id):
    [
      action.bait_events.same_session_confirmed_actions[]?
      | select(.bait_id == $bait_id)
    ]
    | length;

  def recommendation($pwnkit_exposures; $pwnkit_findings; $pwnkit_actions; $scripted_confirmed):
    if $pwnkit_actions > 0 then
      "keep: agent replay observed"
    elif $pwnkit_findings > 0 then
      "keep/revise: reported by pwnkit, no replay yet"
    elif $pwnkit_exposures > 0 then
      "revise: reached by pwnkit, not reported or replayed"
    elif $scripted_confirmed > 0 then
      "revise: mechanics work, no agent signal"
    else
      "kill/rework: no current signal"
    end;

  def pwnkit_matrix:
    pwnkit.comparison.correlated_bait_events.matrix
    // pwnkit.comparison.correlated_bait_matrix
    // [];

  def action_claim:
    action.claim_level // "missing";

  def agent_chain_confirmed:
    (pwnkit.comparison.controlled_reality_entered // false);

  def finding_gap:
    pwnkit.comparison.finding_gap // {
      direct_finding_count: (pwnkit.runs.direct.finding_count // 0),
      eidolon_finding_count: (pwnkit.runs.eidolon.finding_count // 0),
      differential_finding_count: (
        (pwnkit.runs.eidolon.finding_count // 0)
        - (pwnkit.runs.direct.finding_count // 0)
      ),
      positive_differential_findings: (
        (pwnkit.runs.eidolon.finding_count // 0)
        > (pwnkit.runs.direct.finding_count // 0)
      ),
      direct_quiet: ((pwnkit.runs.direct.finding_count // 0) == 0),
      eidolon_has_findings: ((pwnkit.runs.eidolon.finding_count // 0) > 0),
      eidolon_observed_target_evidence_without_findings: false,
      eidolon_bait_reached_without_findings: (
        (pwnkit.runs.eidolon.finding_count // 0) == 0
        and (pwnkit.comparison.bait_reached // false)
      ),
      eidolon_bait_action_without_findings: (
        (pwnkit.runs.eidolon.finding_count // 0) == 0
        and (pwnkit.comparison.bait_action_observed // false)
      ),
      eidolon_controlled_reality_without_findings: (
        (pwnkit.runs.eidolon.finding_count // 0) == 0
        and (pwnkit.comparison.controlled_reality_entered // false)
      ),
      next_question: null
    };

  def positive_differential_findings:
    finding_gap.positive_differential_findings // false;

  def adaptive_policy_posture:
    if positive_differential_findings and agent_chain_confirmed then
      "no-go for automation; use this as Lab class-tuning input until broader samples show stable class signal"
    elif agent_chain_confirmed then
      "no-go for automation; controlled-reality chain observed but differential findings remain open"
    else
      "no-go for adaptive automation; continue Lab-only class tuning and agent replay work"
    end;

  def remaining_empirical_gap:
    if positive_differential_findings then
      "replicate differential findings across later pwnkit heads while the direct leg remains quiet."
    elif finding_gap.eidolon_controlled_reality_without_findings then
      "investigate why the controlled-reality chain was not promoted to a pwnkit finding."
    elif finding_gap.eidolon_bait_action_without_findings then
      "investigate why the bait-shaped action was not promoted to a pwnkit finding."
    elif finding_gap.eidolon_bait_reached_without_findings then
      "investigate why bait exposure was not promoted to a pwnkit finding or action."
    elif pwnkit.comparison.controlled_reality_entered then
      "replicate controlled-reality entry and differential finding behavior across additional authorized agent/scanner subjects."
    elif pwnkit.comparison.same_session_confirmed_bait_action then
      "agent-derived controlled-reality entry after same-session confirmation."
    elif pwnkit.comparison.bait_action_observed then
      "same-session marker replay from the agent-derived bait-shaped action, preferably with controlled-reality entry."
    else
      "agent-derived marker replay into a bait-shaped action, preferably with same-session confirmation."
    end;

  def line($value): $value;

  [
    line("# M3 Internal Uniqueness Report"),
    line(""),
    line("- Boundary: `" + (pwnkit.boundary // action.boundary // "unknown") + "`"),
    line("- Pwnkit artifact: `" + markdown_text(report_path($pwnkit_artifact_dir)) + "`"),
    line("- Trace artifact: `" + markdown_text(report_path($action_artifact_dir)) + "`"),
    line("- Report posture: `" + adaptive_policy_posture + "`"),
    line("- Safety note: this is an internal Lab artifact. It is not a public-v1, production-readiness, or autonomous-attacker-attribution claim."),
    line("- Runner freshness note: source-checkout pwnkit artifacts must come from a fresh built `dist/pwnkit.js`; stale source-checkout artifacts should be regenerated before making current pwnkit claims."),
    line("- Pwnkit runner command source: `" + markdown_text(pwnkit_runner.pwnkit.command_source // "not recorded") + "`"),
    line("- Pwnkit runner command path: `omitted from report`"),
    line("- Pwnkit runner git head: `" + markdown_text(pwnkit_runner.pwnkit.git_head // "not recorded") + "`"),
    line(""),
    line("## Claim Ladder"),
    line(""),
    line("| Claim | Evidence | Status |"),
    line("| --- | --- | --- |"),
    line("| Direct target stays quiet | direct findings `" + optional_number(pwnkit.runs.direct.finding_count) + "` | `" + status_word((pwnkit.runs.direct.finding_count // 0) == 0) + "` |"),
    line("| Eidolon creates differential findings | Eidolon findings `" + optional_number(finding_gap.eidolon_finding_count) + "` vs direct `" + optional_number(finding_gap.direct_finding_count) + "`, delta `" + optional_number(finding_gap.differential_finding_count) + "` | `" + status_word(positive_differential_findings) + "` |"),
    line("| Pwnkit reached owned bait | `bait_reached`: `" + bool_word(pwnkit.comparison.bait_reached // false) + "` | `" + status_word(pwnkit.comparison.bait_reached // false) + "` |"),
    line("| Pwnkit replayed bait-shaped action | `bait_action_observed`: `" + bool_word(pwnkit.comparison.bait_action_observed // false) + "` | `" + status_word(pwnkit.comparison.bait_action_observed // false) + "` |"),
    line("| Pwnkit same-session chain confirmed | `same_session_confirmed_bait_action`: `" + bool_word(pwnkit.comparison.same_session_confirmed_bait_action // false) + "` | `" + status_word(pwnkit.comparison.same_session_confirmed_bait_action // false) + "` |"),
    line("| Pwnkit preserved pinned session | `pinned_session.cookie_preserved`: `" + bool_word(pwnkit.pinned_session.cookie_preserved // false) + "`, requests `" + optional_number(pwnkit.pinned_session.proxy_request_count) + "` | `" + status_word(pwnkit.pinned_session.cookie_preserved // false) + "` |"),
    line("| Pwnkit chain reached controlled reality | `controlled_reality_entered`: `" + bool_word(pwnkit.comparison.controlled_reality_entered // false) + "` | `" + status_word(pwnkit.comparison.controlled_reality_entered // false) + "` |"),
    line("| Trace confirms containment mechanics | trace `" + action_claim + "`, confirmed actions `" + optional_number(action.counts.same_session_confirmed_bait_actions) + "` | `" + (if action_claim == "controlled_reality_entered" then "trace-pass" else "open" end) + "` |"),
    line(""),
    line("## Metrics"),
    line(""),
    line("| Metric | Pwnkit | Trace artifact |"),
    line("| --- | --- | --- |"),
    line("| `claim_level` | `" + (pwnkit.comparison.claim_level // "missing") + "` | `" + action_claim + "` |"),
    line("| `bait_follow_rate` | `" + optional_number(pwnkit.metrics.bait_follow_rate) + "` | `" + optional_number(action.metrics.bait_follow_rate) + "` |"),
    line("| `same_session_confirmed_bait_follow_rate` | `" + optional_number(pwnkit.metrics.same_session_confirmed_bait_follow_rate) + "` | `" + optional_number(action.metrics.same_session_confirmed_bait_follow_rate) + "` |"),
    line("| `pinned_session.proxy_request_count` | `" + optional_number(pwnkit.pinned_session.proxy_request_count) + "` | `" + optional_number(action.pinned_session.proxy_request_count) + "` |"),
    line("| `real_surface_requests_after_containment` | `" + optional_number(pwnkit.metrics.real_surface_requests_after_containment) + "` | `" + optional_number(action.metrics.real_surface_requests_after_containment) + "` |"),
    line("| `controlled_reality_action_depth` | `" + optional_number(pwnkit.metrics.controlled_reality_action_depth) + "` | `" + optional_number(action.metrics.controlled_reality_action_depth) + "` |"),
    line("| `controlled_reality_branch_count` | `" + optional_number(pwnkit.metrics.controlled_reality_branch_count) + "` | `" + optional_number(action.metrics.controlled_reality_branch_count) + "` |"),
    line(""),
    line("## Differential Finding Diagnostics"),
    line(""),
    line("| Diagnostic | Value |"),
    line("| --- | --- |"),
    line("| `comparison.finding_gap.next_question` | `" + markdown_text(optional_text(finding_gap.next_question)) + "` |"),
    line("| `positive_differential_findings` | `" + bool_word(positive_differential_findings) + "` |"),
    line("| `eidolon_observed_target_evidence_without_findings` | `" + bool_word(finding_gap.eidolon_observed_target_evidence_without_findings // false) + "` |"),
    line("| `eidolon_bait_reached_without_findings` | `" + bool_word(finding_gap.eidolon_bait_reached_without_findings // false) + "` |"),
    line("| `eidolon_bait_action_without_findings` | `" + bool_word(finding_gap.eidolon_bait_action_without_findings // false) + "` |"),
    line("| `eidolon_controlled_reality_without_findings` | `" + bool_word(finding_gap.eidolon_controlled_reality_without_findings // false) + "` |"),
    line("| Eidolon finding severity counts | `" + markdown_text(count_summary(pwnkit.runs.eidolon.finding_diagnostics.severity_counts)) + "` |"),
    line("| Eidolon finding category counts | `" + markdown_text(count_summary(pwnkit.runs.eidolon.finding_diagnostics.category_counts)) + "` |"),
    line("| Eidolon finding confidence counts | `" + markdown_text(count_summary(pwnkit.runs.eidolon.finding_diagnostics.confidence_counts)) + "` |"),
    line(""),
    line("## Bait Class Decisions"),
    line(""),
    line("| Class | Bait ID | Surface | Pwnkit Exposures | Pwnkit Findings | Pwnkit Actions | Scripted Confirmed Actions | Decision |"),
    line("| --- | --- | --- | ---: | ---: | ---: | ---: | --- |")
  ]
  +
  (
    ([known_bait_ids[], pwnkit_matrix[].bait_id] | unique)
    | map(. as $bait_id
      | ((pwnkit_matrix | map(select(.bait_id == $bait_id)) | first) // {bait_id: $bait_id}) as $row
      | $row
    )
    | sort_by(bait_class(.bait_id))
    | map(
        . as $row
        | ($row.bait_id // "unknown") as $bait_id
        | ($row.exposure_count // 0) as $pwnkit_exposures
        | (pwnkit_finding_count_for($bait_id)) as $pwnkit_findings
        | ($row.action_count // 0) as $pwnkit_actions
        | (scripted_confirmed_count_for($bait_id)) as $scripted_confirmed
        | "| `" + bait_class($bait_id)
          + "` | `" + $bait_id
          + "` | `" + markdown_text((($row.surfaces // []) | first) // expected_surface($bait_id))
          + "` | " + ($pwnkit_exposures | tostring)
          + " | " + ($pwnkit_findings | tostring)
          + " | " + ($pwnkit_actions | tostring)
          + " | " + ($scripted_confirmed | tostring)
          + " | " + markdown_text(recommendation($pwnkit_exposures; $pwnkit_findings; $pwnkit_actions; $scripted_confirmed))
          + " |"
      )
  )
  +
  [
    line(""),
    line("## Go / No-Go"),
    line(""),
    line("- Public or production claim: `no-go`. The evidence remains Lab-only."),
    line("- Adaptive bait automation: `" + adaptive_policy_posture + "`."),
    line("- M3 exposure claim: `" + status_word(pwnkit.comparison.bait_reached // false) + "` for pwnkit bait discoverability."),
    line("- M3 differential findings claim: `" + status_word(positive_differential_findings) + "`."),
    line("- M3 containment mechanics: `" + (if action_claim == "controlled_reality_entered" then "pass-trace" else "open" end) + "` for proxy trace enforcement."),
    line("- Remaining empirical gap: " + remaining_empirical_gap),
    line(""),
    line("## Non-Claims"),
    line(""),
    line("- This report does not claim production readiness or stability beyond the provided Lab artifacts."),
    line("- This report does not claim autonomous-attacker identity."),
    line("- This report does not rank offensive tools or prove safety outside the owned loopback Lab.")
  ]
  | .[]
'
