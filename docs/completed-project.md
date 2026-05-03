# Completed Project Vision

## Final Shape

The completed project is:

```text
Agentwall: an open-source active defense system for autonomous pentesting agents.
```

It is not:

- an AI honeypot
- a generic WAF
- a pentesting bot
- an LLM-vs-LLM wrapper
- a hack-back tool

The finished system controls the reality autonomous cyber agents are allowed to observe, detects when they act on controlled evidence, and redirects, slows, measures, or contains them before they reach real assets.

## Core Claim

Agentwall exists because autonomous pentesting agents depend on target-side evidence.

If a defender can safely control part of that evidence, the defender can:

- reveal agentic behavior
- measure verification discipline
- waste hostile tool budget
- redirect suspicious sessions
- protect real assets
- generate evidence reports

The complete system should make agentic reconnaissance measurable, misdirectable, and containable.

## Completed Products

### Agentwall Lab

Agentwall Lab is the research and evaluation harness.

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

### Agentwall Shield

Agentwall Shield is the deployable defensive boundary.

Runtime shape:

```text
internet / scanner / agent
        |
        v
Agentwall Shield
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
2. Agentwall exposes plausible controlled evidence.
3. Agent acts on that evidence.
4. Agentwall correlates action to bait.
5. Agentwall raises confidence.
6. Session is moved into controlled reality.
7. Real assets are shielded.
8. Defender gets a trace report.
```

## Key Differentiator

The key feature is causal bait:

```text
bait clue -> unique expected action -> observed follow-up
```

That is what makes Agentwall different from a normal honeypot.

A honeypot says:

```text
someone touched a fake thing
```

Agentwall should say:

```text
this actor consumed controlled evidence, acted on it,
and followed a bait-induced action chain
```

## Attacker-Side Learning Hardness

The deeper moat is not secrecy of implementation.

Assume attackers know Agentwall exists and can read the source.

The completed system should still be difficult to bypass because the attacker does not know:

- which surfaces are real
- which surfaces are controlled
- which values are bait-linked
- which session-specific variants were generated
- which behavior threshold routes them into controlled reality

Agentwall should force agents into a trilemma:

```text
1. Gullible
   Trust target evidence -> follow bait -> get contained.

2. Paranoid
   Distrust target evidence -> miss real findings -> become worse.

3. Expensive
   Verify everything carefully -> burn time, tokens, and tool calls.
```

That trilemma is the practical "Blackwall" effect.

## Strong Completed V1

A strong completed v1 includes:

- open-source Rust proxy
- local demo target
- pwnkit-style benchmark harness
- one or more polymorphic bait chains
- trace engine
- risk scoring
- HTML/Markdown reports
- clear safety model

The project is credible at v1 when it can show:

```text
an autonomous pentesting agent interacts with a protected target,
Agentwall infers its attack loop from black-box behavior,
and the agent is contained without exposing real assets.
```

## Strong Completed V2

A strong completed v2 includes:

- deployable Shield mode
- multiple bait families
- OpenAPI/docs/repo/CI canaries
- controlled-reality router
- SIEM integrations
- benchmark suite for autonomous pentesting agents
- published research results

At v2, Agentwall becomes active defense infrastructure for autonomous cyber agents.

