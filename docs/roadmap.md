# Roadmap

This roadmap turns the Agentwall vision into GitHub milestones and issue-sized chunks.

The intended order is:

```text
M0 Foundations
M1 Proxy and Event Spine
M2 Causal Bait Engine
M3 Trace, Scoring, and Reports
M4 Lab Harness and Evaluation
M5 Controlled Reality and V1 Cut
```

## M0 Foundations

Goal:

Establish repo hygiene, safety boundaries, and a testable Rust baseline.

Issues:

1. Add license, security policy, and defensive-use disclaimer
2. Add CI for fmt, build, clippy, and tests
3. Add issue and PR templates with safety boundaries
4. Add first unit tests for core bait/event/score types

## M1 Proxy And Event Spine

Goal:

Turn the current demo binary into a minimal HTTP reverse proxy that can observe traffic and emit structured events.

Issues:

1. Add CLI/config for listen address, upstream target, and event log path
2. Implement basic HTTP reverse proxy forwarding
3. Add session identification strategy
4. Emit JSONL request events from the proxy

## M2 Causal Bait Engine

Goal:

Implement the first live causal-bait chain.

Issues:

1. Define bait registry and expected-action matching
2. Serve the first docs bait surface
3. Inject the first OpenAPI bait operation
4. Detect the first bait-derived action

## M3 Trace, Scoring, And Reports

Goal:

Convert raw proxy events into evidence that a session followed a bait-induced action chain.

Issues:

1. Implement event store reader and session timeline builder
2. Implement rule-based trace scoring
3. Generate Markdown trace reports
4. Add correlation tests for bait exposure to follow-up action

## M4 Lab Harness And Evaluation

Goal:

Create a local, authorized evaluation environment for testing Agentwall against benign clients and agentic scanners.

Issues:

1. Add local demo target app
2. Add benign baseline runners
3. Add pwnkit-style lab run documentation
4. Define and collect first evaluation metrics

## M5 Controlled Reality And V1 Cut

Goal:

Route high-confidence bait-derived sessions into controlled reality and prepare the first credible v1 release.

Issues:

1. Implement policy state machine
2. Implement controlled-reality decoy responder
3. Add rate-limit and tarpit policies
4. Prepare v1 release checklist and research note

