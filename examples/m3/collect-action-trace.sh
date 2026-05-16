#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR="${1:-${EIDOLON_M3_ARTIFACT_DIR:-}}"
RUN_KIND="${EIDOLON_M3_TRACE_RUN_KIND:-m3_scripted_action_trace}"
EVIDENCE_SOURCE="${EIDOLON_M3_TRACE_EVIDENCE_SOURCE:-proxy_trace}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/collect-action-trace.sh <artifact-dir>

Summarizes an Eidolon proxy event log for M3 scripted bait-action evidence.
The artifact directory must contain proxy-events.jsonl from an eidolon-proxy
run. This collector reads the proxy trace itself; it does not infer action or
containment from the scripted runner's JSONL.

Requires jq.

Environment:
  EIDOLON_M3_TRACE_RUN_KIND         Output run_kind. Defaults to m3_scripted_action_trace.
  EIDOLON_M3_TRACE_EVIDENCE_SOURCE  Output evidence_source. Defaults to proxy_trace.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$ARTIFACT_DIR" || ! -d "$ARTIFACT_DIR" ]]; then
  echo "error: artifact directory not found; pass it as the first argument" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: missing required tool: jq" >&2
  exit 2
fi

PROXY_LOG="$ARTIFACT_DIR/proxy-events.jsonl"
if [[ ! -s "$PROXY_LOG" ]]; then
  echo "error: proxy event log is missing or empty: $PROXY_LOG" >&2
  exit 2
fi

PINNED_SESSION_ID=""
PINNED_SESSION_FILE="$ARTIFACT_DIR/pinned-eidolon-session-id.txt"
if [[ -s "$PINNED_SESSION_FILE" ]]; then
  read -r PINNED_SESSION_ID < "$PINNED_SESSION_FILE"
fi

jq -s \
  --arg artifact_dir "$ARTIFACT_DIR" \
  --arg run_kind "$RUN_KIND" \
  --arg evidence_source "$EVIDENCE_SOURCE" \
  --arg pinned_session_id "$PINNED_SESSION_ID" '
  def observed_at_ms($event):
    (($event.observed_at // "")
     | sub("\\.[0-9]+Z$"; "Z")
     | fromdateiso8601?) as $seconds
    | if $seconds == null then null else ($seconds * 1000) end;

  def indexed_events:
    to_entries | map({event_index: .key, event: .value});

  def containment_policy_state($state):
    $state == "controlled_reality" or $state == "rate_limited";

  def containment_routing_decision($decision):
    $decision == "controlled_reality" or $decision == "rate_limited";

  def real_surface_routing_decision($decision):
    $decision == "protected_upstream" or $decision == "rewritten_upstream";

  def normalized_branch_path($path):
    (($path // "") | split("#")[0] | split("?")[0]);

  def exposures:
    [
      indexed_events[]
      | select(.event.kind.type == "bait_exposed")
      | {
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: observed_at_ms(.event),
          session_id: .event.session_id,
          bait_id: .event.kind.bait_id,
          exposure_id: .event.kind.exposure_id,
          surface: .event.kind.surface
        }
    ];

  def actions:
    [
      indexed_events[]
      | select(.event.kind.type == "bait_action_observed")
      | {
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: observed_at_ms(.event),
          session_id: .event.session_id,
          bait_id: .event.kind.bait_id,
          exposure_id: (.event.kind.exposure_id // null),
          method: .event.kind.method,
          path: .event.kind.path
        }
    ];

  def controlled_reality_entries:
    [
      indexed_events[]
      | select(.event.kind.type == "controlled_reality_entered")
      | {
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: observed_at_ms(.event),
          session_id: .event.session_id,
          reason: .event.kind.reason
        }
    ];

  def request_events:
    [
      indexed_events[]
      | select(.event.kind.type == "request_seen")
      | {
          event_index,
          observed_at: .event.observed_at,
          observed_at_ms: observed_at_ms(.event),
          session_id: .event.session_id,
          policy_state: .event.policy_state,
          method: .event.kind.method,
          path: .event.kind.path,
          routing_decision: .event.kind.routing_decision
        }
    ];

  def confirmed_actions($exposures):
    [
      actions[] as $action
      | select(
          ($action.exposure_id != null)
          and any(
            $exposures[];
            .session_id == $action.session_id
            and .bait_id == $action.bait_id
            and .exposure_id == $action.exposure_id
            and ((.event_index // -1) < ($action.event_index // -1))
          )
        )
      | $action
    ];

  def controlled_reality_entries_after_confirmed_action($confirmed_actions):
    [
      controlled_reality_entries[] as $entry
      | select(
          any(
            $confirmed_actions[];
            .session_id == $entry.session_id
            and ((.event_index // -1) < ($entry.event_index // -1))
          )
        )
      | $entry
    ];

  def containment_marker($entry):
    ($entry.event.policy_state | containment_policy_state(.))
    or (
      ($entry.event.kind.routing_decision // null) as $decision
      | if $decision == null then false else containment_routing_decision($decision) end
    )
    or (
      $entry.event.kind.type == "policy_changed"
      and (
        ($entry.event.kind.from | containment_policy_state(.))
        or ($entry.event.kind.to | containment_policy_state(.))
      )
    )
    or ($entry.event.kind.type == "controlled_reality_entered")
    or ($entry.event.kind.type == "rate_limit_applied");

  def containment_bounds:
    [ indexed_events[] | select(containment_marker(.)) ]
    | if length == 0 then null else {first: .[0], last: .[-1]} end;

  def containment_markers:
    [ indexed_events[] | select(containment_marker(.)) ];

  def controlled_reality_action_depth:
    reduce indexed_events[] as $entry (
      {depth: 0, pending_request_was_containment: null};
      if $entry.event.kind.type == "request_seen" then
        (
          (($entry.event.policy_state | containment_policy_state(.))
           or ($entry.event.kind.routing_decision | containment_routing_decision(.))) as $contained
          | {
              depth: (.depth + (if $contained then 1 else 0 end)),
              pending_request_was_containment: $contained
            }
        )
      elif $entry.event.kind.type == "response_served" then
        (
          ($entry.event.kind.routing_decision | containment_routing_decision(.)) as $contained_response
          | {
              depth: (
                .depth
                + if $contained_response and .pending_request_was_containment != true
                  then 1
                  else 0
                  end
              ),
              pending_request_was_containment: null
            }
        )
      else
        .
      end
    )
    | .depth;

  def controlled_reality_branch_count:
    reduce indexed_events[] as $entry (
      {branches: {}, pending_request: null};
      if $entry.event.kind.type == "request_seen" then
        (
          (($entry.event.policy_state | containment_policy_state(.))
           or ($entry.event.kind.routing_decision | containment_routing_decision(.))) as $contained
          | (normalized_branch_path($entry.event.kind.path)) as $path
          | {
              branches: (
                if $contained then (.branches + {($path): true}) else .branches end
              ),
              pending_request: {path: $path, contained: $contained}
            }
        )
      elif $entry.event.kind.type == "response_served" then
        (
          ($entry.event.kind.routing_decision | containment_routing_decision(.)) as $contained_response
          | {
              branches: (
                if $contained_response and (.pending_request.contained // null) == false
                then (.branches + {(.pending_request.path): true})
                else .branches
                end
              ),
              pending_request: null
            }
        )
      else
        .
      end
    )
    | (.branches | keys | length);

  def real_surface_requests_after_containment:
    containment_markers as $markers
    | if ($markers | length) == 0 then null
      else
        request_events
        | map(. as $request
          | select(
              ($request.routing_decision | real_surface_routing_decision(.))
              and any(
                $markers[];
                .event.session_id == $request.session_id
                and (.event_index < $request.event_index)
              )
            )
        )
        | length
      end;

  def dwell_seconds:
    containment_bounds as $bounds
    | if $bounds == null then null
      elif ($bounds.first.event | observed_at_ms(.)) == null
        or ($bounds.last.event | observed_at_ms(.)) == null then null
      else (
        (($bounds.last.event | observed_at_ms(.)) - ($bounds.first.event | observed_at_ms(.)))
        | if . < 0 then 0 else . end
        | . / 1000
      )
      end;

  def first_action_seconds($confirmed_actions):
    [
      $confirmed_actions[] as $action
      | exposures[] as $exposure
      | select(
          $exposure.session_id == $action.session_id
          and $exposure.bait_id == $action.bait_id
          and $exposure.exposure_id == $action.exposure_id
          and $exposure.observed_at_ms != null
          and $action.observed_at_ms != null
        )
      | (($action.observed_at_ms - $exposure.observed_at_ms) / 1000)
    ]
    | if length == 0 then null else min end;

  def claim_level($exposures; $actions; $confirmed_actions; $controlled_after_confirmed):
    if ($controlled_after_confirmed | length) > 0 then
      "controlled_reality_entered"
    elif ($confirmed_actions | length) > 0 then
      "same_session_bait_action_confirmed"
    elif ($actions | length) > 0 then
      "bait_action_observed_without_same_session"
    elif ($exposures | length) > 0 then
      "bait_exposed_without_action"
    else
      "no_bait_activity"
    end;

  def session_summaries($exposures; $actions; $confirmed_actions; $controlled_after_confirmed):
    ([ $exposures[].session_id, $actions[].session_id, $controlled_after_confirmed[].session_id ] | unique)
    | map(. as $session_id
      | ($exposures | map(select(.session_id == $session_id))) as $session_exposures
      | ($actions | map(select(.session_id == $session_id))) as $session_actions
      | ($confirmed_actions | map(select(.session_id == $session_id))) as $session_confirmed_actions
      | ($controlled_after_confirmed | map(select(.session_id == $session_id))) as $session_controlled
      | {
          session_id: $session_id,
          bait_exposures: ($session_exposures | length),
          bait_actions: ($session_actions | length),
          same_session_confirmed_bait_actions: ($session_confirmed_actions | length),
          controlled_reality_entries: ($session_controlled | length),
          claim_level: claim_level($session_exposures; $session_actions; $session_confirmed_actions; $session_controlled)
        }
    );

  def pinned_session_summary($exposures; $actions; $confirmed_actions; $controlled_after_confirmed):
    if $pinned_session_id == "" then
      {
        present: false,
        session_id: null,
        proxy_request_count: 0,
        bait_exposure_count: 0,
        bait_action_count: 0,
        same_session_confirmed_bait_action_count: 0,
        controlled_reality_entry_count: 0,
        same_session_confirmation_possible: false
      }
    else
      (request_events | map(select(.session_id == $pinned_session_id))) as $session_requests
      | ($exposures | map(select(.session_id == $pinned_session_id))) as $session_exposures
      | ($actions | map(select(.session_id == $pinned_session_id))) as $session_actions
      | ($confirmed_actions | map(select(.session_id == $pinned_session_id))) as $session_confirmed_actions
      | ($controlled_after_confirmed | map(select(.session_id == $pinned_session_id))) as $session_controlled
      | {
          present: true,
          session_id: $pinned_session_id,
          proxy_request_count: ($session_requests | length),
          bait_exposure_count: ($session_exposures | length),
          bait_action_count: ($session_actions | length),
          same_session_confirmed_bait_action_count: ($session_confirmed_actions | length),
          controlled_reality_entry_count: ($session_controlled | length),
          same_session_confirmation_possible: (
            ($session_exposures | length) > 0 and ($session_actions | length) > 0
          )
        }
    end;

  def source_note:
    if $run_kind == "m3_agent_replay_trace" then
      "This collector reads Eidolon proxy trace events from an authorized agent/scanner run. Agent-derived claims require the companion agent/tool artifact, not proxy trace alone."
    else
      "This collector reads Eidolon proxy trace events. It is suitable for scripted harness evidence, not for claiming autonomous agent behavior."
    end;

  exposures as $bait_exposures
  | actions as $bait_actions
  | confirmed_actions($bait_exposures) as $confirmed_bait_actions
  | controlled_reality_entries_after_confirmed_action($confirmed_bait_actions) as $controlled_after_confirmed
  | {
      schema_version: 1,
      run_kind: $run_kind,
      boundary: "owned_loopback_lab",
      evidence_source: $evidence_source,
      artifact_dir: $artifact_dir,
      claim_level: claim_level($bait_exposures; $bait_actions; $confirmed_bait_actions; $controlled_after_confirmed),
      counts: {
        events: length,
        requests: (request_events | length),
        bait_exposures: ($bait_exposures | length),
        bait_actions: ($bait_actions | length),
        same_session_confirmed_bait_actions: ($confirmed_bait_actions | length),
        controlled_reality_entries_after_confirmed_action: ($controlled_after_confirmed | length)
      },
      metrics: {
        time_to_first_bait_action_seconds: first_action_seconds($confirmed_bait_actions),
        bait_follow_rate: (
          if ($bait_exposures | length) > 0
          then (($bait_actions | length) / ($bait_exposures | length))
          else 0
          end
        ),
        same_session_confirmed_bait_follow_rate: (
          if ($bait_exposures | length) > 0
          then (($confirmed_bait_actions | length) / ($bait_exposures | length))
          else 0
          end
        ),
        real_surface_requests_after_containment: real_surface_requests_after_containment,
        controlled_reality_dwell_seconds: dwell_seconds,
        controlled_reality_action_depth: controlled_reality_action_depth,
        controlled_reality_branch_count: controlled_reality_branch_count
      },
      pinned_session: pinned_session_summary($bait_exposures; $bait_actions; $confirmed_bait_actions; $controlled_after_confirmed),
      sessions: session_summaries($bait_exposures; $bait_actions; $confirmed_bait_actions; $controlled_after_confirmed),
      bait_events: {
        exposures: $bait_exposures,
        actions: $bait_actions,
        same_session_confirmed_actions: $confirmed_bait_actions,
        controlled_reality_entries_after_confirmed_action: $controlled_after_confirmed
      },
      notes: [
        source_note,
        "same_session_confirmed_bait_actions require matching session_id, bait_id, exposure_id, and prior exposure event order.",
        "controlled_reality_entered is claimed only when a controlled-reality entry follows a same-session confirmed bait action."
      ]
    }
' "$PROXY_LOG"
