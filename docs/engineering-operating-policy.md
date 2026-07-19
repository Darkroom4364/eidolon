# Engineering Operating Policy

Status: advisory engineering guidance

This document defines Eidolon's default engineering order, safety invariants,
evidence discipline, and review standard. It prioritizes and reviews work; it
does not block work. It applies to runtime, Lab, Shield, deployment, export,
pwnkit integration, and benchmark work.

## Product Center

Eidolon's defensible product center is narrow:

```text
owned semantic bait
  -> same-session observed action
  -> request-linked evidence
  -> controlled target-side routing
  -> minimized operator narrative
```

Research, infrastructure, telemetry, and benchmark work support this chain.
They do not replace it and must not redefine its claims.

## Non-Negotiable Invariants

1. Eidolon operates only on owned or explicitly authorized systems.
2. A recognized unsafe bait action shape never reaches the protected upstream.
   Proof failure changes evidence confidence, not the routing safety boundary.
3. Replayed, expired, malformed, mismatched, or unlinked observations never
   count as confirmed bait-derived evidence.
4. Session identity used for policy and evidence is integrity protected.
   Attacker-selected session rotation must not reset enforcement state.
5. Every policy, bait-action, routing, and export decision is linked to the
   request that caused it. Session-level temporal proximity is not causality.
6. Runtime state and logs are bounded, recoverable after partial writes, and
   explicit about retention and eviction.
7. Runtime bait-derived evidence outranks advisory ingress identity or
   behavior classification. Trusted ingress may soften early policy, never
   erase later direct evidence.
8. Raw facts and inferred claims remain distinguishable. Integrity signatures
   prove bytes and provenance, not semantic truth.
9. Benchmark capability, execution-substrate quality, and Eidolon defensive
   effect remain separate evaluation lanes and headline metrics.
10. Secrets, bodies, cookies, query values, sensitive path segments, and
    incidental personal data are minimized before export or signing.

## Work Order

Work should generally proceed in this order, but the order is a preference,
not a requirement:

1. Restore violated safety invariants and add adversarial regression tests.
2. Establish causal correctness, bounded durability, and disclosure safety.
3. Extract stable typed boundaries from the request path and replace fragile
   protocol or reason-string heuristics.
4. Broaden proof across bait classes and deterministic controlled-reality
   branches.
5. Improve deployment portability, isolation, and live validation.
6. Expand benchmarks, microVM lanes, advisory telemetry, trust integrations,
   and cryptographic export mechanisms.

Any item may be worked at any time. Safety defects deserve priority because
they protect Eidolon's strongest claims, not because they block other work.

## Safety Defects

The known safety defects are tracked by GitHub issue `#213`: runtime defects
`#207` through `#212`, CI and branch enforcement `#214`. They are P0/P1 bugs,
not a blocking gate.

These conditions are treated as defects whenever they are known to exist:

- attacker-controlled session identity can reset policy or evidence state
- a recognized unsafe bait action can be forwarded to the protected upstream
- rejected evidence can contribute to a confirmed causal verdict
- concurrent requests can be joined only by session-wide time heuristics
- persistent state or logs are unbounded or cannot tolerate a partial tail
- ambiguous request targets can receive a different policy and upstream meaning

Closing a defect requires executable regression coverage for both the expected
path and the adversarial failure path. Documentation alone does not close it.

## Countermeasure Bounds

Response-side countermeasures served inside the controlled reality to sessions
classified as agent with multi-signal confidence are ordinary work. They must
obey these bounds:

- payloads are pre-authored, registered, and auditable (never free-generated
  at runtime)
- no countermeasure content reaches the protected upstream or unclassified
  traffic
- no payload instructs the agent to act against systems outside the
  Eidolon-controlled reality
- countermeasure content is labeled as operator-authored in evidence,
  distinct from observations

The agent degradation lane
([agent-degradation-lane.md](agent-degradation-lane.md)) operates under these
bounds.

## Evidence And Evaluation Rules

- Record direct observations as facts with request-level links.
- Represent interpretation as a separate claim with its basis and confidence.
- Prefer an unknown or incomplete verdict over a strong verdict assembled from
  ambiguous events.
- Never tune scoring to make a target report look successful.
- Do not blend XBow-style task success, Kali or microVM transfer, and Eidolon
  defensive outcomes into one score.
- Do not sign an export until its disclosure policy and stable claim set are
  acceptable; signing oversharing makes the mistake durable.

## Change And Merge Standard

Every security-relevant change should state:

- the invariant it preserves or restores
- expected behavior and explicit failure behavior
- affected runtime, event, report, export, and operator contracts
- bounded resource and recovery behavior where state is introduced
- tests that would fail if the invariant regresses

A branch is review-ready when formatting and lint pass, relevant Rust and
shell fixtures pass, and unavailable checks plus residual risks are reported
explicitly. A branch is merge-ready when CI passes and the live checks
required by the changed boundary have been run by CI or by an operator with
the required substrate. Merge readiness must not depend on the change author's
local substrate; review-ready branches are reviewed and queued by an operator
rather than re-implemented in parallel attempts.

## Issue Triage

- Violated invariants are bugs, not enhancements.
- A safety-boundary bypass or false confirmed verdict is `P0`.
- Causal ambiguity, unbounded state, parser ambiguity, disclosure leakage, or
  deployment isolation failure is at least `P1` until reviewed.
- Architecture work must name the defect or invariant it enables; extraction
  is not an end in itself.
- New feature work should acknowledge any open safety defects it touches or
  risks.
- Milestones and README status must describe merged, verified behavior rather
  than branch-local or planned behavior.

## Decision Rule

When priorities compete, choose the work that makes Eidolon's strongest claim
more difficult to falsify. Prefer a smaller truthful mechanism over a larger
system that produces stronger-looking but less defensible conclusions.
