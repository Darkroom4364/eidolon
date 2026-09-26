# Roadmap

This roadmap turns the Eidolon vision into GitHub milestones and issue-sized chunks.

The M0-M5 milestones below record the research and prototype lineage. They are
not the full-release gate. The governing production release track is
[Eidolon v1.0 Full Release Definition](v1-release-definition.md).

The intended order was revised after the 2026-05-03 landscape validation.

The main change:

```text
prove uniqueness early, then harden Shield
```

The intended order is now:

```text
M0 Defensive Scope and Foundations
M0.5 Eidolon Evaluation Harness
M1 Observation and Intervention Proxy
M1.5 Correlated Bait Primitives
M2 Causal Evidence and Scoring
M2.5 Micro Controlled Reality
M3 Uniqueness Bakeoff
M4 Edge/CDN Integration
M5 Adaptive Bait Policy and Shield Hardening
```

## v1.0 Full Release Track

Full release means a supported production Eidolon Shield inside a bounded
deployment envelope, not completion of every M5 or research feature.

The release work is bundled into five streams:

1. production Hyper/Tower HTTP boundary
2. restart-safe identity, durable state, and replay correctness
3. production Kubernetes isolation, upgrade, rollback, and recovery
4. stable contracts, operator evidence, privacy, and observability
5. reliability, supply-chain, and final release qualification

New policy ladders, benchmark breadth, microVMs, behavior telemetry, broad
controlled reality, and cryptographic export are post-v1 unless needed to fix
a release invariant. Exact acceptance criteria and no-go conditions live in
[v1-release-definition.md](v1-release-definition.md).

## North Star

Eidolon is a target-side Blackwall for autonomous cyber agents.

Every roadmap item should strengthen the same defensive loop:

```text
control perception
  -> prove bait-derived behavior
  -> contain suspicious sessions
  -> protect real assets
```

The product center is the boundary, not the benchmark.

Lab exists to calibrate and validate the boundary. Benchmarking is allowed only when it measures Eidolon's defensive outcomes. It must not become a leaderboard, benchmark corpus, offensive-agent ranking system, or general cyber-range project.

When prioritizing work, ask whether it improves at least one of these:

- control what unknown or suspicious agents observe
- create safe causal evidence from target-side behavior
- reconstruct behavior without needing the agent's internals
- route suspicious sessions away from protected reality
- reduce access to real assets after confidence rises
- prove the boundary beats static deception and blocking baselines

If not, it is secondary.

## Architectural Spine

The roadmap is organized around one runtime loop:

```text
observe request
  -> append event
  -> reconstruct trace
  -> score evidence
  -> update policy
  -> choose next surface
```

Three contracts should be made explicit before the system grows:

1. Event contract
   The proxy, bait engine, trace engine, reports, and integrations communicate through versioned structured events. JSONL is the first storage format, but event names and fields are the durable interface.

2. Surface controller boundary
   The proxy should ask a surface controller what to serve or rewrite. Bait docs, OpenAPI injection, decoy endpoints, and controlled reality should not become unrelated proxy special cases.

3. Policy state model
   Policy states should be defined early so events and reports can reference them consistently. Full controlled-reality enforcement can wait until M2.5.

## M0 Defensive Scope And Foundations

Goal:

Establish repo hygiene, safety boundaries, the initial event contract, and a testable Rust baseline.

Issues:

1. Add license, security policy, and defensive-use disclaimer
2. Add CI for fmt, build, clippy, and tests
3. Add issue and PR templates with safety boundaries
4. Define the stable v0 event contract and add first unit tests for core bait/event/score types
5. Confirm Eidolon public naming and positioning
6. Document landscape validation and uniqueness risks

## M0.5 Eidolon Evaluation Harness

Goal:

Create a local, owned, authorized evaluation environment that validates Eidolon's defensive boundary before overbuilding product features.

Constraint:

M0.5 is not a benchmark product. Keep it small enough to benchmark Eidolon's boundary behavior: causal lift, false-positive behavior, controlled-reality containment, and reduction of real-surface access after confidence rises.

Issues:

1. Add local demo target app
2. Add benign baseline runners
3. Add pwnkit-style lab run documentation
4. Define and collect first evaluation metrics
5. Add baseline modes: no defense, static token, static honeypot, WAF-style block
6. Add owned-target-only safety guardrail
7. Define the offline semantic-canary benchmark contract, evidence taxonomy,
   prohibited claims, data-handling rules, and owner/reviewer expectations.
8. Add a synthetic semantic-canary corpus with paraphrase, contradiction,
   unrelated lexical-overlap hard-negative, benign near-neighbor, exact-copy,
   malformed, and oversize controls.
9. Add an offline scorer with an explicit dependency/capability allowlist that
   rejects unknown or oversized inputs, reports deterministic per-class confusion
   and abstention metrics with corpus version and hash metadata, exports summaries
   without raw text by default, imports nothing from proxy/runtime crates, and
   cannot obtain outbound, DNS, tool, browser, subprocess, credential, or runtime
   control capabilities.

## M1 Observation And Intervention Proxy

Goal:

Turn the current demo binary into a minimal HTTP reverse proxy that can observe traffic, emit structured events, enforce the initial policy state model, and safely alter selected responses through a surface controller.

Issues:

1. Add CLI/config for listen address, upstream target, and event log path
2. Implement basic HTTP reverse proxy forwarding
3. Add session identification strategy
4. Emit JSONL request events from the proxy
5. Define surface controller interface and add safe response rewriter for HTML, robots.txt, OpenAPI, and JSON
6. Define initial policy state model for observe, controlled reality, and rate-limit decisions
7. Add intervention kill switch and audit log

## M1.5 Correlated Bait Primitives

Goal:

Implement a small set of concrete bait primitives that plug into the surface controller before building a general bait engine.

Issues:

1. Define bait registry and expected-action matching
2. Serve the first docs bait surface
3. Inject the first OpenAPI bait operation
4. Detect the first bait-derived action
5. Implement five correlated bait primitives
6. Add sham baits and negative controls for causal measurement
7. Attach bait exposure IDs to follow-on requests

## M2 Causal Evidence And Scoring

Goal:

Convert raw proxy events into evidence bundles proving or rejecting bait-induced action chains, without depending on proxy internals.

Issues:

1. Implement event store reader and session timeline builder
2. Implement rule-based trace scoring
3. Generate Markdown trace reports
4. Add correlation tests for bait exposure to follow-up action
5. Generate causal evidence bundle per agent session
6. Add replay view for bait exposure to follow-on action

## M2.5 Micro Controlled Reality

Goal:

Build one narrow Lab-only controlled-reality branch early enough to avoid becoming only a honeypot dashboard, using the policy state model defined in M1.

Issues:

1. Implement policy state transitions and persistence
2. Implement controlled-reality decoy responder
3. Add rate-limit and tarpit policies
4. Prepare Lab-only v1-candidate checklist and research note
5. Build controlled reality v0 for one decoy admin/API path
6. Add synthetic data boundary and no-write enforcement
7. Measure dwell time, action depth, and branch count inside controlled reality
8. Add reality escape detection and emergency disable

Acceptance criteria:

- The feature runs only in the owned loopback Lab against synthetic data and an owned demo target.
- A session can move from observation to controlled reality only through documented policy-state transitions backed by auditable events.
- The first controlled-reality branch covers one decoy admin/API path and does not forward bait-derived writes to the protected upstream.
- Controlled-reality responses use synthetic, non-sensitive data that is safe if copied, indexed, or disclosed.
- No controlled-reality path writes to the protected upstream, mutates real target state, or depends on real secrets, customer data, or internal hostnames.
- Ordinary traffic and negative controls remain outside controlled reality unless the documented confidence conditions are met.
- Reality escape attempts and operator emergency-disable behavior are observable in the event log.
- The M2.5 research note and checklist are explicitly Lab-only v1-candidate artifacts and make no public-v1 or production-ready claim.

Issue `#176` moved response rendering across the separate authenticated
process boundary and closed the local kind/Calico isolation slice. OrbStack
remains an in-process behavioral harness with a direct-target NodePort; the
pinned kind/Calico path proves remote rendering, default-deny isolation,
negative egress, bounded capacity, and fail-closed proxy integration. A
production-cluster proof and lifecycle hardening remain on the v1.0 track.

## M3 Uniqueness Bakeoff

Goal:

Prove whether Eidolon is meaningfully better than static deception and generic bot/WAF responses.

Current status:

- historical pwnkit Codex exposure artifact collected; see
  `docs/research-note-m3.md`
- that pwnkit artifact was later traced to a stale ignored source-checkout
  `dist/pwnkit.js`; it no longer supports current-pwnkit claims
- the stale pwnkit run produced owned bait findings and replayed
  hidden-route/static-header bait into a bait-shaped action, but it no longer
  supports current pwnkit claims
- the stale pinned-session probe recorded `pinned_session.proxy_request_count: 0`;
  do not interpret that as current pwnkit cookie behavior
- scripted proxy trace reaches `controlled_reality_entered`; see `docs/research-report-m3.md`
- current canonical M3 pwnkit evidence is archived at
  `docs/evidence/m3/pwnkit-local-patched-canonical-2026-06-02/`
- strict pwnkit-correlated same-session confirmation, pinned-session
  preservation, controlled-reality entry, and positive differential findings
  now pass in `3/3` canonical runs, with
  `strict_stability.ready_for_stability_claim: true`
- the current canonical evidence track is `local_patched_pwnkit`; the May 31
  upstream-current sample remains the historical unpatched baseline
- issue `#202` adds a separate `3/3` target-runtime proof for one session-minted
  `docs` profile at
  `docs/evidence/m3/pwnkit-docs-session-minted-2026-07-23/`; strict
  pwnkit-internal attribution remains false for that sample

Issues:

1. Run Eidolon MVP bakeoff against baselines
2. Produce internal uniqueness report with metrics table - initial report exists in `docs/research-report-m3.md`
3. Identify bait classes that actually influence agent plans - initial class decisions are in the internal report
4. Keep upstream-current drift checks separate from the canonical local-patched M3 fixture, and decide whether further parity work is worth the churn
5. Decide go/no-go criteria for adaptive bait policy - current posture remains
   no-go for automation; issue `#202` broadens stable target-runtime action
   proof from `open_api` to one `docs` lure profile, but one profile using the
   existing reconcile action path does not establish general class stability

## M4 Edge/CDN Integration

Status: historical integration milestone. Its remaining optional export work is
post-v1 unless required by the full-release privacy or operator-evidence gates.

Goal:

Treat WAF/CDN/bot-defense vendors as deployment surfaces rather than pretending they do not exist.

Issues:

1. Spike Cloudflare Worker deployment model
2. Define integration contract for WAF/CDN bot scores
3. Export Eidolon decisions as webhook/SIEM/WAF events
4. Document SEO, accessibility, verified crawler, Tor/VPN, and analytics-safety constraints

The contract work for issue 2 lives in
`docs/trusted-ingress-signal-contract.md`. The current runtime already
normalizes ingress identity and local allowlist trust behind a transport-auth
gate for explicit edge headers, but raw vendor score and attestation fields
remain a contract-first follow-on rather than ad hoc runtime glue.

The current Worker spike lives in
`examples/edge/cloudflare/eidolon-ingress-worker.mjs`.

The current OrbStack deployment and Kali validation contract lives in
`docs/m4-edge-operations.md`.

Acceptance criteria:

- Cloudflare Worker and Transform Rules examples exist and are tested.
- Trusted ingress contract is documented and reflected in current runtime trust
  handling.
- Eidolon edge decisions can be exported live from OrbStack state as concrete
  webhook/SIEM payloads.
- OrbStack Kubernetes exposes both the shield edge and a direct baseline target
  path.
- Kali VM validation against OrbStack NodePorts is documented and scripted.
- SEO, accessibility, verified crawler, Tor/VPN, and analytics-safety
  constraints are documented.

## M5 Adaptive Bait Policy And Shield Hardening

Status: historical prototype milestone. Remaining adaptive-policy, benchmark,
and adversarial-agent research is post-v1; it is not the production release
gate.

Goal:

Only after the bakeoff succeeds, harden Eidolon Shield toward deployment-grade adaptive deception.

Issues:

1. Design adaptive bait policy from measured bait classes
2. Add per-session polymorphic bait generation
3. Add deployment-safe allowlists and verified crawler handling
4. Prepare external-readiness research note and release checklist

Current design note:

- `docs/m5-multi-signal-policy.md`

Status checklist:

- [x] Design anchor exists in `docs/m5-multi-signal-policy.md` (`main`)
- [x] Authenticated ingress advisory signals are captured, audited, and exported (`main`)
- [x] Trusted ingress remains distinct from runtime suspicion (`main`)
- [x] Narrow `observe -> suspicious` promotion exists for low-score authenticated
  agentic discovery (`main`)
- [x] Suspicious owned shaping exists for `/docs` and `/openapi.json` (`main`)
- [x] First weak aggregated suspicious-promotion path exists for repeated
  medium-score authenticated discovery plus query-bearing recon
  (`main`)
- [x] Aggregated suspicious-promotion paths now use an explicit weighted recon
  score instead of a flat weak-signal count (`main`)
- [x] Weighted recon suspicious-promotion scores now flow through `request_seen`
  audit events and edge export as structured `discovery_recon_score` data
  (`main`)
- [x] Weighted recon now has one conservative higher-threshold
  `suspicious -> rate_limited` path for sustained medium-score top-level
  discovery churn
  and the blind decoy-write contributor is now a capped repeated-probe count,
  and it now keys off constrained unsafe bait action paths from the active bait
  profile instead of only the default reconcile route
  and distinct unattributed write targets now add a coarse path-fanout bonus
  in structured recon score/export
  and that same fanout can now trigger the existing rate-limit threshold on the
  second distinct blind probe for already-suspicious medium-score sessions,
  without waiting for another top-level discovery request
  not just a seen/not-seen bit
  (`main`)
- [x] Weighted recon now has one adjacent `rate_limited -> blocked` path for
  repeated medium-score top-level discovery churn after the first throttle
  and that blocked rung is now also proven with the blind decoy-write
  contributor in the score
  and authenticated detection IDs are now also proven through that same
  blocked rung for discovery-recon persistence
  and the pre-containment weighted recon ladder now shares one explicit
  runtime signal/persistence profile across its rate-limit and blocked rungs
  instead of re-deriving those medium-score recon gates independently
  and repeated blind write-target fanout persistence can now also hit that
  same blocked rung directly after the second distinct unsafe probe caused
  rate limiting
  and the `suspicious -> rate_limited` rung now stamps shared typed persistence
  metadata so the rate-limit and blocked transitions reuse the same
  pre-containment classifier
  and edge export now surfaces that same shared family for rate-limited
  sessions with class-level detail before sessions ever hit the blocked rung
  and `EidolonEdgeDecisionExport.policy` now carries that pre-containment
  persistence class as a structured field instead of forcing downstream
  consumers to scrape `reason_codes`
  and blocked pre-containment exports now also carry the retry detail as a
  structured `pre_containment_persistence_kind` field instead of requiring
  downstream consumers to scrape `reason_codes`
  and edge export now distinguishes that direct blind write retry as
  `write_recon_retry` instead of the broader `discovery_recon_retry`
  and those pre-containment blocked detail codes now come from explicit
  proxy-stamped event metadata rather than report-side string heuristics
  and blocked post-containment exports now also carry a structured
  `post_containment_persistence_kind` field for branch-escape versus
  depth-limit persistence instead of forcing downstream consumers to scrape
  `reason_codes`
  and runtime events, evidence bundles, reports, and edge exports now share
  that typed persistence contract without parsing free-form reason text
  (`main`)
- [x] First advisory-assisted aggregated suspicious-promotion path exists for
  medium-score query-bearing discovery plus authenticated detection IDs
  and the same advisory detection input is now also proven on the
  higher-threshold `suspicious -> rate_limited` weighted recon path
  (`main`)
- [x] First target-side-only aggregated suspicious-promotion path exists for
  medium-score legacy-query OpenAPI discovery (`main`)
- [x] First target-side aggregated suspicious-promotion path exists for
  medium-score query-bearing discovery plus a blind decoy write probe without
  bait-derived attribution (`main`)
- [x] Adjacent target-side-only aggregated suspicious-promotion path exists for
  medium-score linked bait-surface follow-up after query-bearing discovery,
  including hidden-route and JS-helper follow-up outside the top-level
  discovery prefixes
  (`main`)
- [x] Adjacent target-side-only aggregated suspicious-promotion path exists for
  medium-score linked bait-class fanout after plain `/docs` discovery, so two
  distinct linked follow-up classes can promote without query-bearing recon or
  edge-provided detections
  (`main`)
- [x] Adjacent target-side-only aggregated suspicious-promotion path exists for
  medium-score linked bait-class fanout after plain `/openapi.json` discovery,
  so the same linked follow-up classes now promote from either top-level
  discovery anchor
  (`main`)
- [x] Same-session discovery fanout promotion across `/docs` and
  `/openapi.json` exists (`main`)
- [x] `suspicious -> rate_limited` exists for same-bait near misses
  (`main`)
- [x] `rate_limited -> blocked` exists for repeated same-bait near misses
  (`main`)
- [x] `rate_limited -> controlled_reality` exists for exact bait-derived
  follow-up actions (`main`)
- [x] `controlled_reality -> blocked` exists for repeated branch-escape
  attempts (`main`)
- [x] `controlled_reality -> blocked` exists for repeated same-branch
  depth-limit persistence (`main`)
- [x] Post-containment blocked exports now use a shared grouped reason-code
  family with live OrbStack smoke coverage (`main`)
- [x] Pre-containment blocked exports now use a shared grouped reason-code
  family with live OrbStack smoke coverage (`main`)
- [x] First defensible `#175` runtime plane is merged on `main` and satisfies
  the issue acceptance criteria (`main`)
- [ ] Broaden the narrow hand-tuned transitions into a more general
  multi-signal aggregation plane
- [x] Per-session signed polymorphic bait generation exists on `main`:
  HMAC-minted bait values verify deterministically as expiring single-use
  proofs, replay and mismatch outcomes remain audited and request-linked in
  export, and generated proof responses are private, non-storable, and free of
  stale validators or overriding CDN cache controls. Default OrbStack enables
  session-minted docs, OpenAPI, and service-token surfaces, while hidden-route
  and JS-helper classes remain static negative controls
  (`main`)
- [ ] Expand deployment-safe allowlists and verified crawler handling beyond
  the current trusted-ingress slice; per-entry local allowlist
  `bait_soften_path_prefixes` now exist on `main` and optional per-entry
  `source_cidrs`, `hosts`, stale-claim freshness handling, optional
  `not_before` rollout windows, and
  `user_agent_substrings` and request-scoped `authenticated_entries` now exist
  on `main` as narrower deployment-safe trust primitives for
  transport-authenticated strong explicit claims such as `signed_agent`
- [ ] Prepare the external-readiness note and release checklist

## 2026 Engineering Review

GitHub issue `#213` recorded a one-time advisory engineering review, not a
global release, feature, or merge gate. Its findings were tracked and resolved
independently in `#207` through `#212`. Proposed repository-wide enforcement
in `#214` was retired as not planned.

The merged follow-up covers:

1. fail-closed handling for every recognized unsafe bait action (`#208`)
2. rejected evidence remaining visible without confirmed-chain scoring (`#209`)
3. protected session identity and rotation-resistant state (`#207`)
4. request-level causal links across runtime and export (`#210`)
5. bounded, recoverable runtime state and event logs (`#211`)
6. canonical or rejected ambiguous request targets (`#212`)

This review does not globally sequence the remaining roadmap. New work follows
open issue priorities and the applicable invariants above.
