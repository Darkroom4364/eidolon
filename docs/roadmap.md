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

## M0 Defensive Scope And Foundations

Goal:

Establish repo hygiene, safety boundaries, and a testable Rust baseline.

Issues:

1. Add license, security policy, and defensive-use disclaimer
2. Add CI for fmt, build, clippy, and tests
3. Add issue and PR templates with safety boundaries
4. Add first unit tests for core bait/event/score types
5. Confirm Eidolon public naming and positioning
6. Document landscape validation and uniqueness risks

## M0.5 Eidolon Evaluation Harness

Goal:

Create a local, owned, authorized evaluation environment before overbuilding product features.

Issues:

1. Add local demo target app
2. Add benign baseline runners
3. Add pwnkit-style lab run documentation
4. Define and collect first evaluation metrics
5. Add baseline modes: no defense, static token, static honeypot, WAF-style block
6. Add owned-target-only safety guardrail

## M1 Observation And Intervention Proxy

Goal:

Turn the current demo binary into a minimal HTTP reverse proxy that can observe traffic, emit structured events, and safely alter selected responses.

Issues:

1. Add CLI/config for listen address, upstream target, and event log path
2. Implement basic HTTP reverse proxy forwarding
3. Add session identification strategy
4. Emit JSONL request events from the proxy
5. Add safe response rewriter for HTML, robots.txt, OpenAPI, and JSON
6. Add intervention kill switch and audit log

## M1.5 Correlated Bait Primitives

Goal:

Implement a small set of concrete bait primitives before building a general bait engine.

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

Convert raw proxy events into evidence bundles proving or rejecting bait-induced action chains.

Issues:

1. Implement event store reader and session timeline builder
2. Implement rule-based trace scoring
3. Generate Markdown trace reports
4. Add correlation tests for bait exposure to follow-up action
5. Generate causal evidence bundle per agent session
6. Add replay view for bait exposure to follow-on action

## M2.5 Micro Controlled Reality

Goal:

Build one narrow controlled-reality branch early enough to avoid becoming only a honeypot dashboard.

Issues:

1. Implement policy state machine
2. Implement controlled-reality decoy responder
3. Add rate-limit and tarpit policies
4. Prepare v1 release checklist and research note
5. Build controlled reality v0 for one decoy admin/API path
6. Add synthetic data boundary and no-write enforcement
7. Measure dwell time and action depth inside controlled reality
8. Add reality escape detection and emergency disable

## M3 Uniqueness Bakeoff

Goal:

Prove whether Eidolon is meaningfully better than static deception and generic bot/WAF responses.

Issues:

1. Run Eidolon MVP bakeoff against baselines
2. Produce internal uniqueness report with metrics table
3. Identify bait classes that actually influence agent plans
4. Decide go/no-go criteria for adaptive bait policy

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

Only after the bakeoff succeeds, harden Eidolon Shield toward production-safe adaptive deception.

Issues:

1. Design adaptive bait policy from measured bait classes
2. Add per-session polymorphic bait generation
3. Add production-safe allowlists and verified crawler handling
4. Prepare public v1 research note and release checklist
