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

## V0 Scope

Build a Rust reverse proxy and lab harness with:

- session IDs
- one fake docs route
- one fake OpenAPI operation
- one fake endpoint
- one expected header/value pair
- event logging
- trace scoring
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

## First Two Weeks

Week 1:

- scaffold Rust workspace
- implement basic proxy
- implement event model
- implement bait registry
- implement first docs/header/path bait chain
- create local target fixture
- log events to JSONL or SQLite

Week 2:

- implement trace builder
- implement behavior score
- add OpenAPI injection
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
- LLM in hot path
- large deception catalogs
- production-grade policy engine
- vague "AI firewall" positioning

