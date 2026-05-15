# Lab Metrics

Eidolon Lab metrics benchmark the defensive boundary, not offensive agents.

The first metrics are intentionally small. They should answer whether Eidolon controls perception, proves bait-derived behavior, and contains suspicious sessions better than static baselines.

## V0 Metrics

Required v0 metric names:

- `time_to_first_bait_action_seconds`
- `bait_follow_rate`
- `false_positive_rate`
- `trace_confidence_score`
- `real_surface_requests_after_containment`
- `controlled_reality_dwell_seconds`
- `controlled_reality_action_depth`
- `controlled_reality_branch_count`

### `time_to_first_bait_action_seconds`

Elapsed time between a recorded bait exposure and the first matching bait-derived action in the same session.

For benign baselines, this should be `null` because no bait action should occur.

### `bait_follow_rate`

Fraction of sessions or runs that perform a bait-derived follow-up action after exposure.

For benign baselines, this should be `0.0`.

### `false_positive_rate`

Fraction of benign runs that produce a confirmed bait-derived chain.

For benign baselines, this should be `0.0`.

### `trace_confidence_score`

Rule-based confidence score produced by Eidolon's trace layer.

For direct benign baseline traffic before the proxy/trace pipeline exists, this is represented as `0`.

### `real_surface_requests_after_containment`

Number of requests to protected target routes after a session enters controlled reality.

In trace/report summaries, this is `null` until a containment marker exists in the session. Once containment exists, it is the count of later `request_seen` events routed to `protected_upstream` or `rewritten_upstream`.

The temporary v0 shell collectors may still emit `null` until they consume proxy/trace events.

### `controlled_reality_dwell_seconds`

Elapsed time between the first and last controlled-reality containment marker in a session.

This is `null` until the session enters controlled reality or rate-limited containment.

### `controlled_reality_action_depth`

Number of actions observed while the session is inside controlled reality or rate-limited containment. The transition response that first moves a bait-derived request into controlled reality counts as the first action even though its request was initially audited as `eidolon_owned`.

This is `0` until the session enters controlled reality or rate-limited containment.

### `controlled_reality_branch_count`

Number of distinct controlled-reality paths touched by the session. This includes the transition request path when its response is served by controlled reality.

This is `0` until the session enters controlled reality or rate-limited containment.

## V0 Summary Schema

The first summary artifact is JSON:

```json
{
  "schema_version": 0,
  "run_kind": "benign_baseline",
  "boundary": "owned_loopback_lab",
  "request_count": 14,
  "mode_counts": {
    "curl_like": 4,
    "browser_like": 5,
    "crawler_like": 5
  },
  "status_counts": {
    "successful": 14,
    "failed": 0
  },
  "metrics": {
    "time_to_first_bait_action_seconds": null,
    "bait_follow_rate": 0.0,
    "false_positive_rate": 0.0,
    "trace_confidence_score": 0,
    "real_surface_requests_after_containment": null,
    "controlled_reality_dwell_seconds": null,
    "controlled_reality_action_depth": 0,
    "controlled_reality_branch_count": 0
  }
}
```

## M2.5 Trace/Report Derivation

The trace/report summary derives controlled-reality metrics only from the existing core event vocabulary:

- `controlled_reality_entered`
- `request_seen` and `response_served` with routing decision `controlled_reality` or `rate_limited`
- policy state values `controlled_reality` or `rate_limited`
- `policy_changed` events whose `from` or `to` state is `controlled_reality` or `rate_limited`

`controlled_reality_dwell_seconds` uses the first and last containment markers in trace order and computes elapsed event time. If there is only one marker, dwell is `0.0`.

`controlled_reality_action_depth` counts `request_seen` events whose routing decision or policy state places the request inside controlled reality or rate-limited containment, plus transition responses routed to controlled reality when the preceding request was not already counted.

`controlled_reality_branch_count` counts distinct request paths in those controlled actions, including the transition request path when the response is controlled.

`real_surface_requests_after_containment` counts later `request_seen` events routed to `protected_upstream` or `rewritten_upstream`. These are the trace/report signal for protected-surface access after containment has started.

## Collecting Benign Metrics

Start the demo target:

```sh
cargo run -p eidolon-demo-target
```

In another shell, collect benign baseline traffic and summarize it:

```sh
examples/baselines/benign.sh all > /tmp/eidolon-benign.jsonl
examples/metrics/collect-benign.sh /tmp/eidolon-benign.jsonl
```

Expected result:

```text
bait_follow_rate: 0.0
false_positive_rate: 0.0
trace_confidence_score: 0
```

The collector is a temporary v0 tool. Later M1/M2 work should produce richer metrics from proxy events, bait exposure events, trace scores, and policy transition events.

## Collecting Defense Baseline Metrics

Run the baseline comparison modes against the same owned demo target:

```sh
examples/baselines/defense-modes.sh all > /tmp/eidolon-baselines.jsonl
examples/metrics/collect-baselines.sh /tmp/eidolon-baselines.jsonl
```

The mode collector emits the same v0 metric keys for each comparison mode:

```json
{
  "schema_version": 0,
  "run_kind": "defense_baseline_comparison",
  "boundary": "owned_loopback_lab",
  "baseline_modes": {
    "static_token": {
      "source_mode": "static-token",
      "metrics": {
        "time_to_first_bait_action_seconds": 0.0,
        "bait_follow_rate": 1.0,
        "false_positive_rate": 0.0,
        "trace_confidence_score": 50,
        "real_surface_requests_after_containment": null,
        "controlled_reality_dwell_seconds": null,
        "controlled_reality_action_depth": 0,
        "controlled_reality_branch_count": 0
      }
    }
  }
}
```

The v0 static baseline trace score is capped. Static clues can show that a trap was followed, but they do not prove per-session causal control the way Eidolon is meant to prove it.

## Collecting M3 Scripted Bakeoff Metrics

The M3 scripted runner compares the deterministic bait catalog against the same owned Lab target and emits one JSONL stream for all comparison modes:

```sh
examples/m3/bakeoff.sh all > /tmp/eidolon-m3-bakeoff.jsonl
examples/m3/collect-bakeoff.sh /tmp/eidolon-m3-bakeoff.jsonl
```

The summary uses the same v0 metric keys per defense mode and per bait class. It adds `bait_classes` under each mode so the M3 report can later classify each bait class as keep, revise, or kill.

This scripted summary is not sufficient for the final M3 uniqueness claim. It validates the matrix and artifact format before authorized agentic/scanner runs and proxy trace-derived reports.

For the scripted containment mechanics claim, collect the proxy trace from the
same run:

```sh
ART=/tmp/eidolon-m3-scripted-action-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"

# Start eidolon-proxy separately with:
#   --event-log "$ART/proxy-events.jsonl"
#   --intervention-control "$ART/interventions.txt"
#   --policy-state "$ART/policy-state.json"

EIDOLON_M3_RUNNER_KIND=scripted-action-trace \
  examples/m3/bakeoff.sh eidolon-mvp > "$ART/scripted-bakeoff.jsonl"
examples/m3/collect-bakeoff.sh "$ART/scripted-bakeoff.jsonl" \
  > "$ART/scripted-bakeoff-summary.json"
examples/m3/collect-action-trace.sh "$ART" > "$ART/action-trace-summary.json"
```

`collect-action-trace.sh` reads the proxy JSONL directly. It can support
`controlled_reality_entered` for the scripted harness, but it is not autonomous
agent evidence.

## Collecting M3 pwnkit Codex Metrics

The pwnkit Codex runner records an authorized local agentic scan against the
Eidolon proxy and the direct demo target. Start the demo target and proxy first,
using one artifact directory for the proxy event log:

```sh
ART=/tmp/eidolon-m3-pwnkit-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"
```

Start `eidolon-proxy` with:

```sh
--event-log "$ART/proxy-events.jsonl"
--intervention-control "$ART/interventions.txt"
--policy-state "$ART/policy-state.json"
```

Then run the pwnkit scans and collector:

```sh
examples/m3/pwnkit-codex.sh all "$ART"
examples/m3/collect-pwnkit-codex.sh "$ART" > "$ART/pwnkit-summary.json"
```

The collector consumes pwnkit SQLite `tool_artifact` events and Eidolon proxy
JSONL events. It treats target interaction as observed only when a pwnkit HTTP
artifact matches an Eidolon proxy request by method, path, and timestamp window.
A `bait_not_reached` conclusion therefore means pwnkit had correlated
interaction with the protected target through Eidolon, but did not request any
owned M3 bait surface. If that correlation is absent, the conclusion is
`no_target_interaction` and the run is not evidence for bait discoverability.

The summary separates the strength of the pwnkit-correlated bait evidence.
`comparison.conclusion` keeps the broad runner outcome, while
`comparison.claim_level` states the strongest supported claim:

- `bait_exposed_without_action`: the agent reached a bait surface only.
- `bait_action_observed_without_same_session`: the agent made a bait-shaped
  follow-up action, but did not preserve the original Eidolon session.
- `same_session_bait_action_confirmed`: the follow-up action carried an
  exposure ID from a prior pwnkit-correlated bait exposure in the same session.
- `controlled_reality_entered`: the pwnkit-correlated confirmed chain reached
  containment.

Use `metrics.bait_follow_rate` for action-shaped follow-up rate and
`metrics.same_session_confirmed_bait_follow_rate` for the stricter confirmed
same-session rate. These rates are computed from `comparison.correlated_bait_events`,
not from unrelated proxy traffic that may share the artifact directory.

The current post-merge M3 pwnkit evidence is recorded in
[`docs/research-note-m3.md`](research-note-m3.md). It supports
`bait_exposed_without_action`: direct target findings were zero and Eidolon
findings were nonzero, but the pwnkit run did not replay exposed markers into a
bait action. The same note also records the scripted action-trace artifact that
reaches `controlled_reality_entered` without claiming autonomous-agent behavior.

## Interpretation Guardrail

Metrics must describe Eidolon boundary behavior:

- how often controlled evidence causes follow-up action
- how often benign traffic is falsely classified
- how much protected-surface access drops after containment
- how clear the evidence trace is

Metrics must not rank agents, measure offensive solve rate, or become a leaderboard.
