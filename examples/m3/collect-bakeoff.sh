#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-/dev/stdin}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/collect-bakeoff.sh [m3-bakeoff-jsonl]

Reads JSONL emitted by examples/m3/bakeoff.sh and emits a small M3 bakeoff
summary. The summary compares Eidolon boundary behavior and static baselines;
it is not an agent ranking or offensive solve-rate benchmark.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$INPUT" != "/dev/stdin" && ! -f "$INPUT" ]]; then
  echo "error: input file not found: $INPUT" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: required command not found: jq" >&2
  exit 2
fi

jq -s '
  def ordered_unique:
    reduce .[] as $item ([]; if index($item) then . else . + [$item] end);

  def json_key:
    gsub("-"; "_");

  def bool($name):
    .[$name] == true;

  def num($name):
    .[$name] // 0 | if type == "number" then . else tonumber? // 0 end;

  def status_bucket:
    if bool("request_sent") and num("status") >= 200 and num("status") < 300 then
      "successful"
    elif bool("blocked") then
      "blocked"
    elif bool("request_sent") then
      "failed"
    else
      "skipped"
    end;

  def count_bucket($items; $bucket):
    [$items[] | select(status_bucket == $bucket)] | length;

  def round6:
    . * 1000000 | round / 1000000;

  def confidence_score($mode; $actions; $exposures):
    if $actions == 0 or $exposures == 0 then
      0
    elif $mode == "eidolon-mvp" then
      85
    elif $mode == "static-token" or $mode == "static-honeypot" then
      50
    else
      0
    end;

  def bait_action_delta($items):
    ([$items[] | select(bool("bait_exposed")) | num("elapsed_seconds")][0]) as $first_exposure
    | ([$items[] | select(bool("bait_action")) | num("elapsed_seconds")][0]) as $first_action
    | if $first_exposure == null or $first_action == null then
        null
      else
        ($first_action - $first_exposure | round6)
      end;

  def protected_after_decision($items):
    [
      $items[]
      | select(
          bool("after_decision")
          and bool("real_surface")
          and bool("protected_upstream_reached")
        )
    ] | length;

  def class_summary($items; $mode; $bait_class):
    ($items | map(select(.bait_class == $bait_class))) as $class_items
    | ($class_items | map(select(bool("bait_exposed"))) | length) as $exposures
    | ($class_items | map(select(bool("bait_action"))) | length) as $actions
    | ($class_items | map(select(.step == "exposure")) | length) as $scenarios
    | ($class_items | map(select(bool("false_positive"))) | length) as $false_positives
    | (protected_after_decision($class_items)) as $protected
    | {
        event_count: ($class_items | length),
        counts: {
          bait_exposures: $exposures,
          bait_actions: $actions,
          protected_upstream_after_decision: $protected
        },
        metrics: {
          time_to_first_bait_action_seconds: bait_action_delta($class_items),
          bait_follow_rate: (if $exposures > 0 then $actions / $exposures | round6 else 0 end),
          false_positive_rate: (if $scenarios > 0 then $false_positives / $scenarios | round6 else 0 end),
          trace_confidence_score: confidence_score($mode; $actions; $exposures),
          real_surface_requests_after_containment: (
            if $actions > 0 or count_bucket($class_items; "blocked") > 0 then
              $protected
            else
              null
            end
          )
        }
      };

  def mode_summary($events; $mode):
    ($events | map(select(.defense_mode == $mode))) as $items
    | ($items | map(select(bool("request_sent"))) | length) as $requests
    | ($items | map(select(bool("bait_exposed"))) | length) as $exposures
    | ($items | map(select(bool("bait_action"))) | length) as $actions
    | ($items | map(select(.step == "exposure")) | length) as $scenarios
    | ($items | map(select(bool("false_positive"))) | length) as $false_positives
    | (protected_after_decision($items)) as $protected
    | ($items | map(.bait_class) | ordered_unique) as $classes
    | {
        source_mode: $mode,
        event_count: ($items | length),
        request_count: $requests,
        status_counts: {
          successful: count_bucket($items; "successful"),
          failed: count_bucket($items; "failed"),
          blocked: count_bucket($items; "blocked"),
          skipped: count_bucket($items; "skipped")
        },
        counts: {
          bait_exposures: $exposures,
          bait_actions: $actions,
          protected_upstream_after_decision: $protected
        },
        metrics: {
          time_to_first_bait_action_seconds: bait_action_delta($items),
          bait_follow_rate: (if $exposures > 0 then $actions / $exposures | round6 else 0 end),
          false_positive_rate: (if $scenarios > 0 then $false_positives / $scenarios | round6 else 0 end),
          trace_confidence_score: confidence_score($mode; $actions; $exposures),
          real_surface_requests_after_containment: (
            if $actions > 0 or count_bucket($items; "blocked") > 0 then
              $protected
            else
              null
            end
          ),
          controlled_reality_dwell_seconds: (
            if $mode == "eidolon-mvp" and $actions > 0 then 0 else null end
          ),
          controlled_reality_action_depth: (
            if $mode == "eidolon-mvp" then $actions else 0 end
          ),
          controlled_reality_branch_count: (
            if $mode == "eidolon-mvp" and $actions > 0 then 1 else 0 end
          )
        },
        bait_classes: (
          reduce $classes[] as $bait_class ({};
            . + {($bait_class): class_summary($items; $mode; $bait_class)}
          )
        )
      };

  . as $events
  | if length == 0 then
      "error: no M3 bakeoff events provided" | halt_error(2)
    elif any(.[]; ((.defense_mode // "") == "" or (.bait_class // "") == "")) then
      "error: M3 bakeoff events missing defense_mode or bait_class" | halt_error(2)
    else
      ($events | map(.defense_mode) | ordered_unique) as $modes
      | if ($modes | length) == 0 then
          "error: no M3 bakeoff events provided" | halt_error(2)
        else
          ($events | [ .[] | (.runner_kind // "") | select(. != "") ][0] // "unknown") as $runner_kind
          | {
              schema_version: 0,
              run_kind: "m3_bakeoff_comparison",
              boundary: "owned_loopback_lab",
              runner_kind: $runner_kind,
              defense_modes: (
                reduce $modes[] as $mode ({};
                  . + {($mode | json_key): mode_summary($events; $mode)}
                )
              ),
              notes: [
                "M3 scripted bakeoff summaries compare boundary behavior across the same owned Lab target and five bait classes.",
                "This artifact is runner plumbing; final M3 uniqueness claims require authorized agentic/scanner runs and proxy trace artifacts."
              ]
            }
        end
    end
' "$INPUT"
