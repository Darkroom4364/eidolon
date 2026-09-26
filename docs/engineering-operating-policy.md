# Engineering Operating Policy

Status: active engineering guidance

This document defines Eidolon's default priority guidance, safety invariants,
evidence discipline, and review standards. It applies to runtime, Lab, Shield,
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

## Safety Invariants

These are design and review standards for relevant changes. They are not
claims that current `main` exhaustively satisfies every target, and they do
not create a repository-wide feature freeze. Violations are tracked and
prioritized independently.

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
11. Semantic similarity, classification, or equivalence scores are offline
    benchmark inferences only. They do not alter served content, routing,
    containment, policy, protected state, `EventKind::BaitActionObserved`, or
    `ProofOutcome::Accepted`; only same-session, request-linked, accepted bait
    proof may support a confirmed runtime causal chain.

## Priority Guidance

When choosing among otherwise comparable work, prefer this order:

1. Restore violated safety invariants and add adversarial regression tests.
2. Establish causal correctness, bounded durability, and disclosure safety.
3. Extract stable typed boundaries from the request path and replace fragile
   protocol or reason-string heuristics.
4. Broaden proof across bait classes and deterministic controlled-reality
   branches.
5. Improve deployment portability, isolation, and live validation.
6. Expand benchmarks, microVM lanes, advisory telemetry, trust integrations,
   and cryptographic export mechanisms.

An item lower in this list may proceed in parallel when it does not weaken,
bypass, or misrepresent a known invariant. It should not displace an urgent
related defect or be presented as the current product priority without
roadmap support.

## Historical Advisory Review

GitHub issue `#213` recorded a one-time advisory engineering review. It was
not a release, feature, or merge gate. Findings `#207` through `#212` were
tracked independently and closed after their regression work merged. Proposed
repository-wide enforcement in `#214` was retired as not planned.

The review identified durable regression boundaries:

- attacker-controlled session identity can reset policy or evidence state
- a recognized unsafe bait action can be forwarded to the protected upstream
- rejected evidence can contribute to a confirmed causal verdict
- concurrent requests can be joined only by session-wide time heuristics
- persistent state or logs are unbounded or cannot tolerate a partial tail
- ambiguous request targets can receive a different policy and upstream meaning

A future regression against one of these boundaries should be tracked and
prioritized by its scope and severity. It does not automatically freeze
unrelated development.

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
compensating evidence, and residual risk. Issues `#213` and `#214` add no
separate manual or repository-wide gate beyond applicable normal review and
CI.

## Issue Triage

- Violated invariants are bugs, not enhancements.
- A safety-boundary bypass or false confirmed verdict is `P0`.
- Causal ambiguity, unbounded state, parser ambiguity, disclosure leakage, or
  deployment isolation failure is at least `P1` until reviewed.
- Architecture work must name the defect or invariant it enables; extraction
  is not an end in itself.
- New feature work should identify related higher-priority safety defects and
  explain why parallel work will not weaken, bypass, or overstate them.
  Unrelated defects do not automatically block it.
- Milestones and README status must describe merged, verified behavior rather
  than branch-local or planned behavior.

## Decision Rule

When priorities compete, choose the work that makes Eidolon's strongest claim
more difficult to falsify. Prefer a smaller truthful mechanism over a larger
system that produces stronger-looking but less defensible conclusions.
