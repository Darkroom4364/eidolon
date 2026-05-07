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

This is `null` until policy routing and controlled reality exist.

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
    "real_surface_requests_after_containment": null
  }
}
```

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
        "real_surface_requests_after_containment": null
      }
    }
  }
}
```

The v0 static baseline trace score is capped. Static clues can show that a trap was followed, but they do not prove per-session causal control the way Eidolon is meant to prove it.

## Interpretation Guardrail

Metrics must describe Eidolon boundary behavior:

- how often controlled evidence causes follow-up action
- how often benign traffic is falsely classified
- how much protected-surface access drops after containment
- how clear the evidence trace is

Metrics must not rank agents, measure offensive solve rate, or become a leaderboard.
