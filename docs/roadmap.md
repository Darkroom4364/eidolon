# Roadmap

This roadmap turns the Eidolon vision into GitHub milestones and issue-sized chunks.

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

## M3 Uniqueness Bakeoff

Goal:

Prove whether Eidolon is meaningfully better than static deception and generic bot/WAF responses.

Current status:

- pwnkit Codex exposure artifact collected; see `docs/research-note-m3.md`
- direct target baseline is quiet after the demo import-status cleanup
- Eidolon produces owned bait findings in the pwnkit run
- scripted proxy trace reaches `controlled_reality_entered`; see `docs/research-report-m3.md`
- pwnkit-derived bait action, same-session confirmation, and controlled-reality entry remain open evidence targets

Issues:

1. Run Eidolon MVP bakeoff against baselines
2. Produce internal uniqueness report with metrics table - initial report exists in `docs/research-report-m3.md`
3. Identify bait classes that actually influence agent plans - initial class decisions are in the internal report
4. Decide go/no-go criteria for adaptive bait policy - current posture is no-go for automation until agent marker replay is observed

## M4 Edge/CDN Integration

Goal:

Treat WAF/CDN/bot-defense vendors as deployment surfaces rather than pretending they do not exist.

Issues:

1. Spike Cloudflare Worker deployment model
2. Define integration contract for WAF/CDN bot scores
3. Export Eidolon decisions as webhook/SIEM/WAF events
4. Document SEO, accessibility, verified crawler, Tor/VPN, and analytics-safety constraints

## M5 Adaptive Bait Policy And Shield Hardening

Goal:

Only after the bakeoff succeeds, harden Eidolon Shield toward deployment-grade adaptive deception.

Issues:

1. Design adaptive bait policy from measured bait classes
2. Add per-session polymorphic bait generation
3. Add deployment-safe allowlists and verified crawler handling
4. Prepare external-readiness research note and release checklist
