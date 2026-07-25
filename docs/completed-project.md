# Completed Project Vision

Status: directional product vision

The exact full-release contract is defined in
[v1-release-definition.md](v1-release-definition.md). Where this historical
vision uses "v1 candidate," "completed v1," or "v2," the release definition
governs.

## Final Shape

The completed project is:

```text
Eidolon: an open-source active defense system for autonomous pentesting agents.
```

`Eidolon` replaces the previous working name `Agentwall`, which was too close to existing AgentWall / Agent Wall projects in AI-agent security, MCP firewalling, and anti-scraping.

It is not:

- an AI honeypot
- a generic WAF
- a pentesting bot
- an LLM-vs-LLM wrapper
- a hack-back tool

The finished system controls the reality autonomous cyber agents are allowed to observe, detects when they act on controlled evidence, and redirects, slows, measures, or contains them before they reach real assets.

## Core Claim

Eidolon exists because autonomous pentesting agents depend on target-side evidence.

If a defender can safely control part of that evidence, the defender can:

- reveal agentic behavior
- measure verification discipline
- waste hostile tool budget
- redirect suspicious sessions
- protect real assets
- generate evidence reports

The complete system should make agentic reconnaissance measurable, misdirectable, and containable.

After the 2026-05-03 landscape validation, the project should not claim novelty as generic cyber deception or active defense. The narrow claim is:

```text
target-side causal evidence and controlled-reality routing
evaluated against modern autonomous pentesting agents
```

## Completed Products

### Eidolon Lab

Eidolon Lab is the research and evaluation harness.

It tests pwnkit/XBOW-style systems against instrumented targets and answers:

- Does the agent blindly trust target docs?
- Does it follow fake OpenAPI operations?
- Does it verify before acting?
- Does it detect canaries?
- Does it burn budget on decoys?
- Can it distinguish real surfaces from controlled ones?

Outputs:

- agent robustness reports
- bait-follow metrics
- verification-discipline scores
- false-finding rates
- trace timelines

Lab is the scientific core of the project.

### Eidolon Shield

Eidolon Shield is the deployable defensive boundary.

Runtime shape:

```text
internet / scanner / agent
        |
        v
Eidolon Shield
        |
        +--> real target
        |
        +--> controlled reality
```

Capabilities:

- reverse proxy
- bait registry
- per-session polymorphic decoys
- fake docs/OpenAPI/routes/tokens
- causal trace reconstruction
- risk scoring
- controlled-reality routing
- rate limiting
- tarpitting
- evidence reports
- SIEM/webhook export

Shield is the operational form of the research primitive proven in Lab.

## Completed Defense Flow

```text
1. Agent scans target.
2. Eidolon exposes plausible controlled evidence.
3. Agent acts on that evidence.
4. Eidolon correlates action to bait.
5. Eidolon raises confidence.
6. Session is moved into controlled reality.
7. Real assets are shielded.
8. Defender gets a trace report.
```

## Key Differentiator

The key feature is causal bait:

```text
bait clue -> unique expected action -> observed follow-up
```

That is what makes Eidolon different from a normal honeypot.

A honeypot says:

```text
someone touched a fake thing
```

Eidolon should say:

```text
this actor consumed controlled evidence, acted on it,
and followed a bait-induced action chain
```

## Attacker-Side Learning Hardness

The deeper moat is not secrecy of implementation.

Assume attackers know Eidolon exists and can read the source.

The completed system should still be difficult to bypass because the attacker does not know:

- which surfaces are real
- which surfaces are controlled
- which values are bait-linked
- which session-specific variants were generated
- which behavior threshold routes them into controlled reality

Eidolon should force agents into a trilemma:

```text
1. Gullible
   Trust target evidence -> follow bait -> get contained.

2. Paranoid
   Distrust target evidence -> miss real findings -> become worse.

3. Expensive
   Verify everything carefully -> burn time, tokens, and tool calls.
```

That trilemma is the practical "Blackwall" effect.

## Release Contract

The historical Lab-oriented "completed v1" and later Shield-oriented "v2"
split is retired. A full `v1.0` now means a supported Eidolon Shield release
inside a narrow declared deployment envelope.

Lab remains the scientific validation layer. Benchmarks, more bait families,
microVMs, behavior fingerprinting, and broad deception are optional research,
not substitutes for production transport, durable state, isolation,
operations, and security qualification.

See [v1-release-definition.md](v1-release-definition.md) for the objective
gates and hard no-go conditions.
