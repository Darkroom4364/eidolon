# Engineering Operating Policy

Status: active project policy; automated repository enforcement is incomplete
and tracked by `#214`

This document defines Eidolon's default engineering order, safety invariants,
evidence discipline, and merge gate. It applies to runtime, Lab, Shield,
deployment, export, pwnkit integration, and benchmark work.

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

## Required Safety Invariants

These are merge requirements and target properties. They are not claims about
current `main`; known violations are tracked by the safety gate below.

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

Work proceeds in this order unless a documented emergency requires otherwise:

1. Restore violated safety invariants and add adversarial regression tests.
2. Establish causal correctness, bounded durability, and disclosure safety.
3. Extract stable typed boundaries from the request path and replace fragile
   protocol or reason-string heuristics.
4. Broaden proof across bait classes and deterministic controlled-reality
   branches.
5. Improve deployment portability, isolation, and live validation.
6. Expand benchmarks, microVM lanes, advisory telemetry, trust integrations,
   and cryptographic export mechanisms.

An item lower in this list may be researched or documented while the safety
gate is open, but it must not displace gate work or be presented as the current
product priority.

## Safety Gate

The active gate is tracked by GitHub issue `#213`. Its runtime defects are
`#207` through `#212`; CI and branch enforcement are tracked by `#214`.

Feature expansion is blocked while any of these conditions is known to exist:

- attacker-controlled session identity can reset policy or evidence state
- a recognized unsafe bait action can be forwarded to the protected upstream
- rejected evidence can contribute to a confirmed causal verdict
- concurrent requests can be joined only by session-wide time heuristics
- persistent state or logs are unbounded or cannot tolerate a partial tail
- ambiguous request targets can receive a different policy and upstream meaning

Current gate work proceeds as follows:

1. Make every configured unsafe bait-action shape fail closed in `#208`, then
   add the minimum replay and expiry outcome model required to complete it.
2. Exclude rejected observations from confirmed evidence in `#209`.
3. Design session identity in `#207` together with the lifetime, rotation, and
   storage bounds required by `#211`.
4. Define the canonical request-target contract required by `#212` before
   freezing request-level event linkage in `#210`.
5. Finish `#211`, `#212`, and repository enforcement in `#214` before resuming
   feature expansion.

Closing the gate requires executable regression coverage for both the expected
path and the adversarial failure path. Documentation alone does not close it.

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

Every security-relevant change must state:

- the invariant it preserves or restores
- expected behavior and explicit failure behavior
- affected runtime, event, report, export, and operator contracts
- bounded resource and recovery behavior where state is introduced
- tests that would fail if the invariant regresses

A security-relevant branch is merge-ready only after applicable formatting,
lint, Rust, shell fixture, and boundary-specific live checks pass. Any check
that is not applicable or cannot run in CI must be identified with the reason,
compensating evidence, and residual risk. CI and branch-protection parity are
tracked by `#214`; until it closes, reviewers must enforce this gate manually
rather than treating absent branch rules as approval.

## Issue Triage

- Violated invariants are bugs, not enhancements.
- A safety-boundary bypass or false confirmed verdict is `P0`.
- Causal ambiguity, unbounded state, parser ambiguity, disclosure leakage, or
  deployment isolation failure is at least `P1` until reviewed.
- Architecture work must name the defect or invariant it enables; extraction
  is not an end in itself.
- New feature work must explain why all open higher-priority safety defects do
  not block it.
- Milestones and README status must describe merged, verified behavior rather
  than branch-local or planned behavior.

## Decision Rule

When priorities compete, choose the work that makes Eidolon's strongest claim
more difficult to falsify. Prefer a smaller truthful mechanism over a larger
system that produces stronger-looking but less defensible conclusions.
