# Eidolon

Eidolon is a Rust-first active defense project for autonomous cyber agents.

An eidolon is a phantom or constructed likeness. The name fits the core mechanism: show hostile autonomous agents a controlled likeness of the target, then trace whether they act on that synthetic evidence.

The core idea:

```text
Control what an autonomous pentesting agent observes,
watch what it does with that evidence,
and route suspicious sessions away from real assets.
```

Short framing:

```text
Eidolon is a Blackwall for autonomous cyber agents.
```

Precise framing:

```text
Eidolon is target-side active defense for agentic reconnaissance and exploitation loops.
```

## What It Does

Eidolon sits in front of a web app, API, docs site, repo mirror, or other exposed developer surface.

It can:

- serve normal traffic to the real target
- expose controlled false affordances to suspicious sessions
- generate per-session causal bait
- detect bait-derived follow-up actions
- reconstruct target-side behavioral traces
- route suspicious sessions into controlled reality
- produce evidence reports

The first proof-of-concept is deliberately narrow:

```text
agentic scanner -> Eidolon proxy -> local target app
```

Eidolon adds safe fake surfaces such as docs, OpenAPI routes, and sterile debug endpoints. If a scanner consumes the fake evidence and acts on it, Eidolon can correlate the chain.

## What It Is Not

Eidolon is not:

- a hack-back tool
- malware
- an exploit framework
- another autonomous pentester
- a generic WAF
- a generic honeypot
- an MCP firewall
- a prompt-injection scanner
- a promise to perfectly detect "AI attackers"

The project is defensive. It may degrade hostile behavior inside a protected boundary, but it must not compromise infrastructure outside that boundary.

## Core Primitive

The important primitive is **causal bait**.

```text
bait A can plausibly cause action B
therefore action B implies the actor consumed bait A
```

Example:

```text
/docs/legacy-import
  says: "Legacy import accepts X-Debug-Bypass: rel_2025_04_b7f2"
  points to: POST /api/v2/import/reconcile

later:
  POST /api/v2/import/reconcile
  X-Debug-Bypass: rel_2025_04_b7f2
```

Eidolon does not need the agent's chain of thought. It infers behavior from target-side observations.

## Project Modes

Eidolon has two related modes.

```text
Eidolon Lab
```

A research harness for evaluating autonomous pentesting systems under controlled deception.

```text
Eidolon Shield
```

A deployable target-side defense layer for web/API surfaces.

Lab comes first. Shield comes after the mechanism is proven.

## Repository Layout

```text
crates/
  eidolon-core/   shared event, bait, policy, and scoring types
  eidolon-bait/   bait generation and verification primitives
  eidolon-trace/  event correlation and trace reconstruction
  eidolon-proxy/  reverse proxy entrypoint

docs/
  completed-project.md
  name.md
  landscape-validation-2026-05-03.md
  proposal.md
  architecture.md
  learning-hardness.md
  threat-model.md
  mvp-plan.md
  safety.md
  research-anchors.md
  roadmap.md

examples/
  scenarios/
```

## Current Status

This repository is a project scaffold and documentation base. The first implementation target is a minimal Rust reverse proxy with:

- session IDs
- bait registry
- one docs/header/path bait chain
- event logging
- trace report

For the end-state definition, see [docs/completed-project.md](docs/completed-project.md).
