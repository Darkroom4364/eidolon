# MVP Plan

## MVP Goal

Prove the smallest useful mechanism:

```text
serve clue -> observe action -> correlate -> report
```

The first demo should show:

```text
an autonomous pentesting agent consumes controlled evidence,
acts on it,
gets correlated,
and is routed into controlled reality.
```

This is the Blackwall loop:

```text
controlled perception -> causal proof -> containment -> protected reality stays protected
```

The MVP should not become an agent benchmark. Lab runs exist only to benchmark Eidolon's boundary behavior: whether Eidolon changes, proves, and contains agent behavior.

## V0 Scope

Build a Rust reverse proxy and lab harness with:

- session IDs
- stable v0 event contract
- surface controller boundary
- one fake docs route
- one fake OpenAPI operation
- one fake endpoint
- one expected header/value pair
- event logging
- trace scoring
- initial policy state model
- report generation

No ML.

No production deployment.

No generic WAF.

## First Bait Chain

```text
robots.txt
  -> /docs/legacy-import
  -> fake OpenAPI operation
  -> /api/v2/import/reconcile
  -> X-Migration-Trace: rel_2025_04_b7f2
  -> decoy response
  -> trace report
```

Normal baseline:

- browser user should not hit it
- simple crawler may fetch docs but should not synthesize the custom request
- DAST may probe paths but should not produce the exact bait-derived header/path combination
- agentic pentester is more likely to connect the clue to action

Lab guardrails:

- no leaderboard
- no benchmark corpus
- no agent ranking
- no solve-rate competition
- benchmark Eidolon, not the agents
- only enough agent/baseline traffic to validate causal lift, false positives, and containment

## First Two Weeks

Week 1:

- scaffold Rust workspace
- define v0 event contract
- implement basic proxy
- implement JSONL event logging
- define surface controller boundary
- implement bait registry
- implement first docs/header/path bait chain
- create local target fixture

Week 2:

- define initial policy state model
- implement trace builder
- implement behavior score
- add OpenAPI injection
- route one confirmed bait-derived action to decoy response
- run pwnkit-style demo
- run browser/crawler baseline
- generate Markdown/HTML report
- document results and failures

## Success Metrics

- `time_to_first_bait_action`
- `bait_follow_rate`
- `false_positive_rate`
- `trace_confidence_score`
- `real_surface_requests_after_containment`
- `agent_budget_wasted`
- `false_finding_rate` in lab reports when available

## Implementation Bias

Start simple:

```text
axum/hyper/tower
JSONL event log first
SQLite once queries matter
rule-based scoring
one bait chain
one report
```

Avoid:

- high-performance proxy work before proof
- proxy-special-case logic that bypasses the surface controller
- scoring logic hidden inside request forwarding
- LLM in hot path
- large deception catalogs
- production-grade policy engine
- vague "AI firewall" positioning
