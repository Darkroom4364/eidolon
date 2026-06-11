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
- one weaker aggregated `observe -> suspicious` path now exists for repeated
  same-session medium-score authenticated discovery requests when the session
  has also shown query-bearing discovery recon, so one lower-confidence
  advisory signal plus two weaker recon contributors can promote without
  requiring a strong single-request score
- those aggregated suspicious-promotion paths now run through a small weighted
  recon score instead of a flat weak-signal count, so repeated discovery,
  query-bearing recon, legacy OpenAPI query shape, linked bait traversal, and
  authenticated detections can be tuned as explicit contributors without
  collapsing identity, evidence, and enforcement together
- that weighted recon score now rides in `request_seen` audit events and edge
  export as structured `discovery_recon_score` fields, so operators do not need
  to recover it from debug logs or freeform policy reasons
- one adjacent target-side aggregated `observe -> suspicious` path now exists
  for one medium-score query-bearing docs request plus a blind unsafe probe to
  `/api/v2/import/reconcile` without any expected bait header, so known decoy
  write-path interest contributes as weak recon without creating
  `bait_action_observed` evidence
- that weighted recon score now has a first conservative higher-threshold use
  above promotion: an already-`suspicious` medium-score top-level discovery
  follow-up moves to `rate_limited` once the structured recon score reaches `5`
  from sustained discovery churn, without treating the request itself as a
  bait-derived action; that higher-threshold path is now also proven with the
  blind decoy-write contributor in the score, so one query-bearing discovery
  request plus a same-session unsafe probe to `/api/v2/import/reconcile`
  without a bait header can still accumulate into a later throttled
  top-level-discovery follow-up
- that blind decoy-write contributor is no longer a seen/not-seen bit; it is
  now tracked as a small capped count, so a second same-session unsafe probe
  raises the decoy-write recon component from `2` to `3` without creating
  `bait_action_observed`, and the stronger score is visible in the same later
  top-level discovery rate-limit path
- that blind decoy-write contributor is also no longer hard-wired to the
  default reconcile route; it now applies to any constrained unsafe bait action
  path from the active bait profile when the request matches method/path but no
  expected bait header name is present
- that generalized blind decoy-write contributor now also tracks a coarse
  write-target fanout class, so probing both the canonical reconcile route and
  a different constrained unsafe bait action path adds one more weak recon
  point without creating `bait_action_observed`; the structured recon score and
  debug/export path now surface that as
  `decoy_write_probe_path_fanout_bonus`
- that write-target fanout is no longer scorer-only: an already-`suspicious`
  medium-score session can now move straight to `rate_limited` on the second
  distinct blind unsafe probe when the existing `query_score` plus
  `decoy_write_probe_score` plus `decoy_write_probe_path_fanout_bonus` is what
  reaches the recon persistence threshold of `5`, even before another
  top-level discovery follow-up happens
- that same blind write-target fanout can now also drive the next hard-fail
  rung directly: after Eidolon has already rate-limited the session on that
  second distinct unsafe probe, repeating the blind probe again can move the
  session to `blocked` under the same pre-containment persistence family,
  without turning the request into `bait_action_observed`
- one adjacent `rate_limited -> blocked` path now exists for repeating that
  same medium-score top-level discovery churn again after Eidolon has already
  throttled the session once, keeping the hard-fail tied to explicit
  persistence before any bait-derived action is confirmed; that blocked retry
  rung is now also proven with the blind decoy-write contributor in the score,
  so the same session can move from one query-bearing discovery request, to an
  unattributed unsafe probe, to `rate_limited`, and then to `blocked` on a
  repeated top-level discovery retry without creating `bait_action_observed`
  evidence
- one adjacent aggregated `observe -> suspicious` path now exists for one
  query-bearing medium-score authenticated discovery request when authenticated
  detection IDs also contribute, so multiple weak advisory and recon facts can
  promote on first contact without requiring a strong single-request score
- one adjacent target-side aggregated `observe -> suspicious` path now exists
  for one medium-score legacy-query OpenAPI discovery request, so multiple weak
  recon facts can promote on first contact without depending on edge-provided
  detection IDs
- one adjacent target-side aggregated `observe -> suspicious` path now exists
  for one medium-score linked bait-surface follow-up after query-bearing docs
  discovery, so moving from top-level discovery into a linked bait surface like
  `/docs/legacy-import`, `/customer/import-recovery-checklist`, or
  `/assets/import-helper.js` contributes as target-side recon without treating
  the follow-up as a confirmed bait-derived action
- one adjacent target-side aggregated `observe -> suspicious` path now exists
  for one medium-score `/docs` discovery request plus churn across two linked
  bait classes, so a same-session move from `/docs/legacy-import` into
  `/assets/import-helper.js` can now promote without query-bearing discovery or
  edge-provided detections once the linked recon fanout itself is strong enough
- one adjacent target-side aggregated `observe -> suspicious` path now exists
  for one medium-score `/openapi.json` discovery request plus churn across two
  linked bait classes, so the same linked recon fanout now works from the
  OpenAPI side instead of assuming `/docs` is always the first discovery anchor
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
  evidence, but only already-suspicious sessions are throttled, and the
  rate-limited reason now carries the shared pre-containment
  `persistence_class`
- edge export now carries that same `pre_containment_persistence` family for
  rate-limited sessions too, with class-level detail like `discovery_recon`
  or `same_bait_near_miss`, so operators can group persistence before the
  blocked retry rung
- edge export now also exposes that persistence class as a structured
  `policy.pre_containment_persistence_class` field, so SIEM consumers do not
  need to infer it from `edge_recommendation.reason_codes`
- blocked pre-containment exports now also expose the retry detail as a
  structured `policy.pre_containment_persistence_kind` field, so downstream
  consumers can distinguish `discovery_recon_retry`,
  `same_bait_near_miss_retry`, and `write_recon_retry` without scraping
  `reason_codes`
- one conservative `rate_limited -> blocked` path now exists for repeating
  that same-bait near miss again after Eidolon has already throttled the
  session once, keeping blocked rare and tied to explicit retry behavior
- edge export now groups that pre-containment blocked path under the shared
  `pre_containment_persistence` reason-code family with the detail code
  `same_bait_near_miss_retry`, and the proxy now stamps both the shared
  `persistence_class` and the blocked-only `persistence_kind` directly into the
  blocked reason instead of relying on export-side heuristics
- edge export now groups the adjacent recon-driven blocked retry under that
  same `pre_containment_persistence` family with the detail code
  `discovery_recon_retry` from those same explicit reason markers
- edge export now splits the direct blind write-target retry case out of that
  generic recon bucket: when a blocked decision comes from repeating the
  rate-limited blind unsafe write path itself, the shared family stays
  `pre_containment_persistence` but the detail code becomes
  `write_recon_retry`
- one conservative `rate_limited -> controlled_reality` path now exists for a
  confirmed same-session exact bait-derived action after throttling, so stronger
  runtime evidence still moves the session into containment instead of stopping
  at a synthetic intercept
- one conservative `controlled_reality -> blocked` path now exists for repeated
  reality-escape attempts outside the configured controlled-reality branch,
  keeping automatic blocking tied to explicit persistence after containment
- one adjacent `controlled_reality -> blocked` path now exists for continuing
  to probe the same controlled branch after Eidolon has already depth-throttled
  the session once, keeping the hard-fail tied to explicit post-containment
  persistence rather than the first over-limit request
- edge export now groups both post-containment blocked paths under the shared
  `post_containment_persistence` reason-code family while preserving distinct
  detail codes for branch-escape versus depth-limit persistence
- near-miss matching on the shared reconcile path is now header-aware, so
  `X-Migration-Trace` and `X-OpenAPI-Trace` requests are attributed to the
  correct bait family instead of collapsing onto the first registered decoy

That keeps the current containment invariants stable while giving `#175` a
typed signal plane to build on.
