# Eidolon

Eidolon is a Rust-first active defense project for autonomous cyber agents.

> **Release status:** Eidolon `v0.1.0` is a research alpha for owned,
> authorized lab environments. It is not production-ready, a security
> boundary, or a general AI-attacker detector.

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
- a way to attribute actor identity, intent, autonomy, model, vendor, or model
  family from semantic similarity or benchmark behavior

The project is defensive. It may degrade hostile behavior inside a protected boundary, but it must not compromise infrastructure outside that boundary.

## License And Defensive Use

Eidolon is licensed under the Apache License, Version 2.0.

This project is intended for defensive use on owned or authorized systems. Contributions and reports must stay within that boundary: no hack-back, malware, real exploit bait, real secrets, third-party targeting, or attacker infrastructure compromise.

For details, see [SECURITY.md](SECURITY.md), [docs/safety.md](docs/safety.md), and [docs/threat-model.md](docs/threat-model.md).

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
Eidolon Shield (future)
```

The planned deployable target-side defense layer for web/API surfaces.

Lab comes first. Shield comes after the mechanism is proven.

## Quick Start

The v0.1 release is run from a source checkout. It requires Rust 1.95 or newer
and `curl`. The release targets Linux x86_64 and macOS arm64; Windows is not
currently tested or supported.

Start the owned demo target:

```sh
cargo run -p eidolon-demo-target
```

In a second shell, start the proxy:

```sh
cargo run -p eidolon-proxy -- \
  --listen-addr 127.0.0.1:8080 \
  --upstream http://127.0.0.1:9001 \
  --event-log /tmp/eidolon-events.jsonl \
  --debug-log /tmp/eidolon-debug.jsonl \
  --intervention-control /tmp/eidolon-interventions.txt \
  --policy-state /tmp/eidolon-policy-state.json
```

Exercise the local Lab surface:

```sh
curl -i -c /tmp/eidolon-cookies.txt http://127.0.0.1:8080/docs
```

The complete owned-target walkthrough, evidence commands, and cleanup steps
are in [docs/lab-runbook.md](docs/lab-runbook.md).

## Repository Layout

```text
crates/
  eidolon-core/   shared event, bait, policy, and scoring types
  eidolon-bait/   bait generation and verification primitives
  eidolon-trace/  event correlation and trace reconstruction
  eidolon-semantic-canary/  bounded offline synthetic benchmark scorer
  eidolon-proxy/  reverse proxy entrypoint

docs/
  completed-project.md
  name.md
  ai-labyrinth-vs-eidolon.md
  landscape-validation-2026-05-03.md
  proposal.md
  architecture.md
  learning-hardness.md
  threat-model.md
  engineering-operating-policy.md
  mvp-plan.md
  safety.md
  lab.md
  lab-runbook.md
  lab-metrics.md
  research-anchors.md
  roadmap.md
  trusted-ingress-signal-contract.md
  m4-edge-operations.md

examples/
  baselines/
  demo-target/
  edge/
  m3/
  metrics/
  qualification/
  semantic-canary/
  shield-lab/
```

## Current Status

The `v0.1.0` release is a source-only Eidolon Lab research alpha. It establishes
the causal-bait, request-linked evidence, fail-closed unsafe-action routing,
and controlled-reality research baseline. Issue `#213` recorded a one-time
advisory engineering review; findings `#207` through `#212` were resolved
independently, and proposed repository-wide enforcement in `#214` was retired.

Semantic-canary/GDOP-style work is currently an offline, synthetic benchmark
lane only. It is not production routing, actor attribution, model fingerprinting,
or accepted bait proof. Any future runtime work requires separate review under
`docs/semantic-canary-benchmark.md`; this benchmark does not authorize it.

Run the deterministic embedded held-out qualification and emit its summary-only
artifact with:

```sh
cargo run -p eidolon-semantic-canary --bin eidolon-semantic-canary-qualify --locked
```

The repository already includes:

- a Rust reverse proxy with per-session policy state, controlled reality, and
  replayable JSONL evidence
- a correlated M3 bait catalog plus bait-profile overrides for owned validation
  runs
- offline trace scoring, Markdown reporting, and edge-decision export
- trusted-ingress normalization with transport-auth gating and scoped bait
  softening
- an OrbStack shield-lab deployment with live status, evidence export,
  edge-decision export, trusted-ingress smoke checks, and Kali VM validation
- an authenticated standalone controlled-reality renderer wired into the
  pinned kind/Calico Lab profile with default-deny network policy, bounded
  capacity, outage, kill-switch, and escape-path validation

The `#213` review strengthened the merged baseline through fail-closed
bait-action routing, correct evidence classification, protected session
identity, request-linked causality, bounded state, and canonical request
targets. Those corrections do not by themselves make a production-readiness
claim.

Known v0.1 limits:

- OrbStack is a behavioral harness, not an isolation proof.
- The kind/Calico proof is local, stateless, and single-replica.
- Managed-cluster portability, high availability, restart-safe renderer state,
  and multi-replica aggregation are not proven.
- No crates, container images, or hosted service are published as part of this
  source release.

For the recommended work order and review standards, see
[docs/engineering-operating-policy.md](docs/engineering-operating-policy.md).

For the exact meaning, supported envelope, objective gates, and no-go
conditions of a full `v1.0` release, see
[docs/v1-release-definition.md](docs/v1-release-definition.md).

For the controlled-reality process boundary, verified Lab claims, and residual
limitations, see
[docs/controlled-reality-isolation.md](docs/controlled-reality-isolation.md).

For the end-state definition, see [docs/completed-project.md](docs/completed-project.md).

For naming and positioning, see [docs/name.md](docs/name.md).

For the local owned-target Lab guardrails and demo target, see [docs/lab.md](docs/lab.md).

For the current local Lab runbook, see [docs/lab-runbook.md](docs/lab-runbook.md).

For the first Lab metric definitions and summary schema, see [docs/lab-metrics.md](docs/lab-metrics.md).

For landscape validation, uniqueness risks, and go/no-go criteria, see [docs/landscape-validation-2026-05-03.md](docs/landscape-validation-2026-05-03.md).

For the key distinction from crawler mazes such as Cloudflare AI Labyrinth, see [docs/ai-labyrinth-vs-eidolon.md](docs/ai-labyrinth-vs-eidolon.md).

## Support

This research alpha is maintained on a best-effort basis. Use GitHub Issues for
reproducible bugs and focused feature proposals. Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).
