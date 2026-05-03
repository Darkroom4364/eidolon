# Attacker Learning Hardness

## Goal

Eidolon should be cheap for the defender and expensive for the attacker to learn.

This is not literal NP-completeness. The better target is:

```text
learning-resistant under black-box interaction
```

The attacker-side problem:

```text
Given only target-side observations, classify which surfaces are real
and which surfaces are Eidolon-controlled.
```

We want that classification to be hard because:

- there are no labels
- probes are limited
- concrete bait changes per deployment and session
- decoys are plausible
- generation is secret-keyed
- feedback is delayed and noisy
- policy shifts are gradual

## Desired Asymmetry

For the defender:

```text
generate bait from secret seed
log exposure
verify later action
correlate with session state
```

This should be cheap.

For the attacker:

```text
determine whether /api/v2/import/reconcile is real, obsolete,
vulnerable, fake, canary, or harmless
```

This should be expensive.

## The Trilemma

Eidolon should force autonomous pentesting agents into one of three bad modes:

```text
1. Gullible
   Trust target evidence -> follow bait -> get contained.

2. Paranoid
   Distrust target evidence -> miss real findings -> become worse.

3. Expensive
   Verify everything carefully -> burn time, tokens, and tool calls.
```

That trilemma is the real "Blackwall" effect.

## Public Algorithm, Private Seed

Assume the attacker knows Eidolon exists.

Assume the source code is public.

The system should still work because the attacker does not know:

- which surfaces are real
- which surfaces are controlled
- which values are bait-linked
- which session-specific variants were generated
- which threshold routes them into controlled reality

The design should look more like cryptographic asymmetry than obscurity:

```text
public algorithm
private deployment/session seed
cheap generation
cheap verification
hard classification for attacker
```

## No Static Fingerprints

Avoid:

- fixed `/eidolon` paths
- fixed `aw-*` markers
- repeated fake debug docs
- obvious fake admin panels
- globally recognizable decoy response style
- immediate block after bait interaction

Prefer:

- target-style naming
- per-session paths/headers/tokens
- native-looking OpenAPI schemas
- plausible response bodies
- decoy state machines
- gradual containment
- noisy feedback

## Runtime Should Not Require An LLM

Eidolon Shield should not call an LLM on every request.

The production path should use:

- HMAC or signed bait values
- templates
- procedural generation
- session state
- event graph correlation
- rules and scoring
- state machines

LLMs may be useful offline for:

- generating realistic decoy docs
- mutating OpenAPI descriptions
- building lab scenarios
- evaluating whether bait looks plausible
- testing agent robustness

Lab may use LLMs. Shield should not require them.

## Design Principle

The defender should not face a hard computation problem.

The attacker should face a hard epistemic problem:

```text
distinguishing real target evidence from controlled evidence
under limited budget
without losing pentest effectiveness
```

