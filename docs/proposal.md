# Eidolon Target Shield Proposal

## One-Line Thesis

Build a Rust-first active defense layer that protects web apps, APIs, docs, repos, and exposed developer surfaces from autonomous pentesting agents by controlling what they observe, correlating bait-derived actions, and routing suspicious sessions into controlled reality.

Short version:

```text
Eidolon is a Blackwall for autonomous cyber agents.
```

More precise version:

```text
Eidolon is target-side active defense for agentic reconnaissance and exploitation loops.
```

The public project name is `Eidolon`. `Agentwall` is the retired legacy codename.

## Ausgangslage

Autonomous pentesting is becoming real enough to deserve a dedicated defensive primitive.

The relevant shift is not merely that language models can write exploit code. The shift is that offensive systems increasingly combine:

- LLM reasoning
- shell/browser/API tools
- scanners and crawlers
- memory and task state
- retries and parallel exploration
- validation loops
- report generation

That creates a different defensive surface. Traditional tools mostly look at packets, payloads, signatures, indicators, users, endpoint behavior, or known exploit patterns.

Eidolon focuses on the agent loop:

```text
observe -> hypothesize -> act -> interpret -> continue
```

The project starts from a simple question:

> Can we degrade and contain a malicious autonomous pentesting agent by controlling the evidence it is allowed to reason over?

## Full Project Picture

Eidolon is not just a proxy with fake routes.

The full project is a defensive boundary that controls the reality an autonomous cyber agent is allowed to observe.

There are three worlds:

```text
1. Protected reality
   The actual application, APIs, docs, routes, data, and infrastructure.

2. Controlled reality
   Fake but plausible surfaces: decoy docs, decoy APIs, canary tokens,
   sterile endpoints, fake legacy systems, sandbox targets, and tarpits.

3. Observation layer
   The boundary that decides which actor sees which reality.
```

Eidolon is the observation layer.

```text
external actor
      |
      v
+----------------+
|   Eidolon    |
+----------------+
   |          |
   v          v
real app   controlled reality
```

The goal is not just to catch agents.

The goal is to move suspicious autonomous agents out of the real world and into a controlled world before they get useful access.

## What Eidolon Does

Eidolon does four things:

```text
observe
deceive
correlate
contain
```

### Observe

Detect agent-like behavior from target-side signals:

- rapid recon across docs, APIs, routes, sitemaps, and OpenAPI specs
- debug/admin/config probing
- tool-like request cadence
- repeated hypothesis testing
- suspicious header or fake credential use
- bait-derived follow-up actions
- transition from recon into exploit-like behavior

This does not prove "LLM." It proves autonomous or semi-autonomous recon/action behavior.

### Deceive

Expose controlled false affordances:

- fake legacy docs
- fake debug headers
- fake OpenAPI routes
- fake staging/internal hostnames
- fake admin paths
- fake leaked credentials
- fake cloud metadata hints
- fake changelog entries
- fake CVE references
- fake CI/CD artifacts

Every bait item must be:

```text
safe
unique
traceable
plausible
non-useful against real systems
```

### Correlate

Build an evidence trace:

```text
10:02:11 GET /openapi.json
10:02:18 GET /docs/legacy-import
10:02:41 POST /api/v2/import/reconcile
10:02:42 header X-Migration-Trace: rel_2025_04_b7f2
10:03:05 retry with modified body
10:03:20 probe /api/v2/import/status
```

The useful claim is not:

```text
someone touched a fake thing
```

The useful claim is:

```text
this session followed a bait-induced action chain
```

### Contain

Once confidence rises, Eidolon changes the environment:

- observe only
- slow down
- serve more decoys
- increase proof-of-work
- route to sandbox clone
- hide sensitive real surfaces
- return sterile-but-plausible responses
- alert SIEM / webhook
- block only at high confidence

The strongest mode is not immediate blocking. Blocking teaches the actor. Containment lets the agent keep working inside a false world.

## Core Primitive: Causal Bait

The important primitive is causal bait:

```text
bait A can only plausibly cause action B
therefore action B implies the actor consumed bait A
```

Example:

```text
/docs/legacy-import
  says: "Legacy import accepts X-Migration-Trace: rel_2025_04_b7f2"
  points to: POST /api/v2/import/reconcile

later:
  POST /api/v2/import/reconcile
  X-Migration-Trace: rel_2025_04_b7f2
```

That sequence proves the actor consumed the planted clue and acted on it. Eidolon does not need access to the agent's chain of thought.

## Definition Of Sabotage

Eidolon may sabotage a hostile agent's attack loop inside the protected boundary.

Allowed:

- degrade the agent's belief state
- waste its tool budget
- route it into a sandbox
- expose fake-but-safe evidence
- make it verify non-existent issues
- force it to reveal behavior through causal bait
- slow or redirect suspicious sessions

Not allowed:

- compromise the agent runner
- steal the operator's keys
- corrupt external memory or files
- make the agent attack third parties
- deliver malware
- exploit the attacker's infrastructure

The rule:

```text
Eidolon may degrade hostile behavior inside our boundary.
Eidolon may not compromise infrastructure outside our boundary.
```

## Why This Is Not Just A Honeypot

A classic honeypot or canary says:

```text
someone touched a fake thing
```

Eidolon should say:

```text
this actor consumed controlled evidence, selected a hypothesis from it,
acted on that hypothesis, ignored or handled contradictions, and continued the chain
```

The novelty is not fake endpoints. That part is old.

The novelty must be:

- causal bait design
- black-box trace reconstruction
- agentic behavior scoring
- adaptive routing into controlled reality
- measurement of verification discipline
- comparison of autonomous pentesting agents under deception

If Eidolon does not build the trace/correlation layer, it collapses into a normal deception tool.

## Product Modes

### Eidolon Lab

A research and evaluation harness.

Purpose:

- test autonomous pentesting agents
- measure gullibility
- measure verification discipline
- compare pwnkit/XBOW-style systems
- publish evidence

Lab comes first because it is easier to prove safely.

### Eidolon Shield

A deployable target-side defense layer.

Purpose:

- protect real web/API surfaces from agentic recon
- detect bait-derived behavior
- route suspicious sessions into controlled reality
- produce security evidence

Shield comes after Lab proves the core mechanism.

## Current Decision

Build first as:

```text
Eidolon Lab + Target Shield MVP
```

Do not start with:

- enterprise MCP firewall
- generic WAF
- generic honeypot
- AI governance dashboard
- another autonomous pentester

The first proof should show:

```text
an autonomous pentesting agent consumes controlled evidence,
acts on it,
gets correlated,
and is routed into controlled reality.
```
