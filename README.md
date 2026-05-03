# Agentwall

Agentwall is a Rust-first active defense project for autonomous cyber agents.

The core idea:

```text
Control what an autonomous pentesting agent observes,
watch what it does with that evidence,
and route suspicious sessions away from real assets.
```

Short framing:

```text
Agentwall is a Blackwall for autonomous cyber agents.
```

Precise framing:

```text
Agentwall is target-side active defense for agentic reconnaissance and exploitation loops.
```

## What It Does

Agentwall sits in front of a web app, API, docs site, repo mirror, or other exposed developer surface.

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
agentic scanner -> Agentwall proxy -> local target app
```

Agentwall adds safe fake surfaces such as docs, OpenAPI routes, and sterile debug endpoints. If a scanner consumes the fake evidence and acts on it, Agentwall can correlate the chain.

## What It Is Not

Agentwall is not:

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

Agentwall does not need the agent's chain of thought. It infers behavior from target-side observations.

## Project Modes

Agentwall has two related modes.

```text
Agentwall Lab
```

A research harness for evaluating autonomous pentesting systems under controlled deception.

```text
Agentwall Shield
```

A deployable target-side defense layer for web/API surfaces.

Lab comes first. Shield comes after the mechanism is proven.

## Repository Layout

```text
crates/
  agentwall-core/   shared event, bait, policy, and scoring types
  agentwall-bait/   bait generation and verification primitives
  agentwall-trace/  event correlation and trace reconstruction
  agentwall-proxy/  reverse proxy entrypoint

docs/
  completed-project.md
  proposal.md
  architecture.md
  learning-hardness.md
  threat-model.md
  mvp-plan.md
  safety.md
  research-anchors.md

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
