# M5 Multi-Signal Policy And Graduated Enforcement

This note is the design anchor for `#48` and the staging document for `#175`.

The objective is to harden Shield policy without collapsing Eidolon into a
generic bot-score gate or making confirmed bait action the only serious
escalation primitive.

## Invariants

- Trusted ingress identity is distinct from runtime suspicious evidence.
- Trusted ingress may soften selected discovery bait while confidence is still
  low.
- Runtime bait-derived evidence outranks ingress trust once confidence is high.
- Policy state, routing decision, and evidence provenance stay separate in the
  contract and in operator reports.

## Signal Families

Policy should aggregate signals from five families.

1. Ingress advisory signals
   - normalized identity source and trust tier
   - verification strength
   - actor kind and verified category
   - raw vendor score, detection IDs, and edge action hint

2. Session recon signals
   - discovery-surface fanout
   - path churn and repeated probes
   - bait-shaped near misses
   - retry behavior after soft denial or rewrite

3. Causal bait signals
   - bait exposure
   - exact bait-derived follow-up action
   - same-bait post-exposure near miss

4. Containment signals
   - entry into controlled reality
   - reality-escape attempts
   - contained branch depth and branch count
   - post-containment real-surface requests

5. Operator signals
   - local allowlist identity
   - operator override identity
   - emergency intervention disable

No single weak signal should force irreversible enforcement. Stronger automated
escalation requires multiple contributing signals with recorded provenance.

## Enforcement Ladder

The ladder is intentionally broader than `observe -> controlled_reality`.

1. `normal` / `observe`
   Protected upstream. Trusted ingress may soften configured discovery bait.

2. `suspicious`
   Still protected upstream, but no trusted bait softening and stronger shaping
   on discovery surfaces. This is the first graduated step below containment.

3. Per-request shaping
   `rewritten_upstream` and `eidolon_owned` remain routing decisions, not policy
   states. They are the main tools for soft intervention while a session is
   suspicious but not yet contained.

4. `rate_limited`
   Tarpit or throttle with explicit retry semantics and audit.

5. `controlled_reality`
   Limited or full controlled reality. Future M5 work can vary containment scope
   without inventing a new evidence model.

6. `blocked`
   Highest-friction step. Prefer operator approval or strong post-containment
   justification before using it automatically.

## Decision Provenance

Every automated promotion should carry:

- contributing signal family
- concrete signal facts
- human-readable reason
- whether the action is advisory, shaping, or containment

Examples:

- `edge_verified discovery session requested 6 distinct discovery paths with low
  vendor score; promoted to suspicious`
- `same-bait post-exposure near miss plus repeated retries; promoted to
  rate_limited`
- `confirmed bait-derived action with matched exposure id; promoted to
  controlled_reality`

## Safety Constraints

- Bot score alone must not create trust or force containment.
- Trusted ingress must not bypass containment after strong runtime evidence.
- `blocked` should remain rare and explainable.
- Reports must stay free of request bodies, secret header values, and raw query
  values.
- Operator disable and operator override remain explicit, auditable controls.

## Measurement

Evaluate the ladder against:

- false-positive rate for verified or allowlisted automation
- time to first suspicious promotion
- time to containment after strong runtime evidence
- protected-surface leakage after suspicious promotion
- protected-surface leakage after containment
- operator burden for high-friction actions

These should be compared against the current M3/M4 baseline rather than an
abstract bot-defense target.

## Current Implementation Slice

The current M5 slice is intentionally narrow:

- authenticated advisory ingress signals are now first-class request-audit data
- those signals remain separate from ingress identity and from runtime evidence
- reports and edge-decision export now preserve the latest authenticated
  advisory ingress signal snapshot when present
- one conservative `observe -> suspicious` promotion now exists for authenticated
  discovery-surface requests that combine a low inverse vendor score with an
  explicitly agentic actor kind, while stronger trusted identities still keep
  their low-confidence bait-softening behavior
- one conservative session-recon promotion now exists for same-session
  discovery-surface fanout across `/docs` and `/openapi.json`, while stronger
  trusted identities still suppress that low-confidence runtime promotion
- suspicious `GET /docs` and `GET /openapi.json` discovery requests now receive
  Eidolon-owned bait surfaces instead of rewritten upstream discovery views,
  and those owned responses record normal bait exposure so same-session causal
  correlation still works while edge export recommends
  `preserve_eidolon_routing`
- one conservative `suspicious -> rate_limited` path now exists for a
  same-session, same-bait action near miss after prior exposure on
  `/api/v2/import/reconcile`; the unmatched bait-shaped action is preserved as
  evidence, but only already-suspicious sessions are throttled
- one conservative `rate_limited -> blocked` path now exists for repeating
  that same-bait near miss again after Eidolon has already throttled the
  session once, keeping blocked rare and tied to explicit retry behavior
- near-miss matching on the shared reconcile path is now header-aware, so
  `X-Migration-Trace` and `X-OpenAPI-Trace` requests are attributed to the
  correct bait family instead of collapsing onto the first registered decoy

That keeps the current containment invariants stable while giving `#175` a
typed signal plane to build on.
