# Semantic-Canary Benchmark

Status: proposed offline benchmark contract

This document defines the safety and evidence boundary for semantic-canary
benchmark work. It extends Eidolon's existing semantic-bait research vocabulary
with an offline corpus-and-scorer lane. It does not describe shipped runtime
semantic-canary, GDOP, obfuscation, routing, containment, attribution, or policy
capability.

## Purpose

Semantic canaries are synthetic, inert benchmark fixtures for measuring whether
meaning survives controlled paraphrase and whether negative controls remain
distinguishable. They are useful for evaluating benchmark substrates and scorer
behavior before any runtime design is considered.

The first phase answers narrow offline questions:

- Does a scorer preserve an intended semantic label across controlled paraphrase?
- Does it reject contradiction, negation, unrelated lexical overlap, malformed
  input, and benign near-neighbor controls?
- Does it abstain when the fixture or prediction is ambiguous?
- Are benchmark capability, substrate quality, and Eidolon defensive effect kept
  separate in reports?

## Normative Safety Contract

1. Scope is offline evaluation over checked-in, synthetic fixtures in an owned or
   authorized environment.
2. The evaluator performs no network, DNS, callbacks, browser or tool execution,
   credential use, target discovery, runtime routing, or protected-state change.
3. Inputs and outputs are bounded, schema-versioned, deterministic where
   feasible, and reject unknown schema versions, oversize payloads, malformed
   records, invalid labels, and excessive cardinality.
4. Canary text is synthetic, non-sensitive, non-exploitable, safe if copied,
   indexed, logged, or disclosed, and contains no real hosts, secrets, customer
   data, bypasses, or exploit recipes.
5. Benchmark labels and similarity scores are inference only. They are never
   `EventKind::BaitActionObserved`, `ProofOutcome::Accepted`, policy input,
   routing input, containment input, or protected-state input.
6. Direct observations, fixture labels, scorer or model outputs, derived
   evaluations, and causal runtime evidence remain distinct evidence classes.
7. Ambiguity means abstain or unknown, never confirmation.
8. Mandatory controls cover benign near-neighbor, paraphrase, contradiction or
   negation, unrelated lexical overlap, exact-copy, malformed input, and oversize
   input.
9. Reports omit raw fixture and prediction text by default, minimize exported
   text, and identify scorer version, corpus version, fixture hash, and run
   configuration.
10. Reports do not claim actor identity, actor intent, autonomy, model, vendor,
    model family, maliciousness, production efficacy, or public-target behavior.
11. The benchmark takes no action beyond the protected boundary and performs no
    hack-back, attacker-host interaction, or third-party targeting.
12. Runtime integration is a separately reviewed future change. If ever pursued,
    it starts disabled by default and shadow-only, with a separate event and
    metric namespace, resource ceilings, a kill switch, privacy review, benign
    regression tests, and no `SurfaceAction` or policy input.

## Non-Goals

This benchmark is not:

- production obfuscation or evasion
- actor fingerprinting or attribution
- intent inference
- prompt injection
- model exploitation
- attacker-host interaction
- tool triggering
- third-party targeting
- replacement for same-session request-linked bait proof
- routing, blocking, containment, or protected-state authority
- a source of reusable exploit material

## Evidence Taxonomy

| Evidence class | Type | Allowed meaning |
| --- | --- | --- |
| `fixture_validated` | direct | A checked-in fixture passed schema, size, label, and synthetic-content validation. |
| `prediction_observed` | direct | A bounded prediction record was parsed from an offline input file. |
| `semantic_equivalence_supported` | benchmark inference | The scorer matched the expected semantic-equivalence label within the configured threshold. |
| `contradiction_supported` | benchmark inference | The scorer matched the expected contradiction or negation label within the configured threshold. |
| `ambiguous_or_abstained` | benchmark inference | The scorer did not have enough signal or received ambiguous input and abstained. |
| `action_shape_observed` | direct, non-causal | A prediction described an action shape, but no runtime request-linked proof exists. |
| `request_linked_accepted_bait_action` | runtime causal evidence | Existing Eidolon same-session accepted bait proof linked to a request. This is outside the offline benchmark lane. |
| `attribution` | unsupported/prohibited | Actor, model, vendor, intent, autonomy, and maliciousness claims are not supported. |

Semantic benchmark results must never be silently promoted to runtime causal
evidence. Only existing same-session, request-linked, accepted bait proof may
support a confirmed causal chain.

## Threat Model

Assets:

- truthful fixture labels and benchmark results
- disclosure-safe synthetic fixture corpus
- separation from runtime policy, routing, containment, and evidence

Failure and adversarial inputs:

- malicious or malformed fixture text
- lexical-overlap shortcuts
- negation and contradiction
- paraphrase drift
- scorer nondeterminism and version drift
- corpus leakage or memorization
- prompt-injection-like text that tries to induce tool use, network use, or role
  changes
- oversized or high-cardinality manifests
- report oversharing
- operator promotion of similarity into causal or attribution claims

Controls:

- inert-data parsing only
- no network, DNS, callback, browser, credential, or tool contract
- strict schema, size, count, and time bounds
- held-out templates and benign near-neighbor controls
- repeated fixed-seed runs with scorer, corpus, fixture-hash, and configuration
  metadata
- abstention band and false-positive breakdown
- allowlisted summary export that omits raw text by default
- explicit non-causality labels

The benchmark does not model, identify, or attribute an external attacker.
Scanner, actor, model, vendor, intent, autonomy, and maliciousness attribution
remain unsupported.

## Phased Acceptance

### P0 Contract

Accepted when the documentation names the offline-only and no-runtime invariant,
evidence taxonomy, prohibited claims, data-handling rules, and owner/reviewer
expectations.

### P1 Corpus And Scorer Skeleton

Accepted when:

- schema validation rejects unknown, oversized, malformed, or invalid-label input
- fixtures are synthetic and disclosure-safe
- the corpus includes semantic-equivalent, contradiction, unrelated,
  lexical-overlap hard-negative, benign-control, exact-copy, malformed, and
  oversize cases
- deterministic metrics include per-class confusion and abstention
- reports include corpus version and hash metadata
- implementation imports or calls nothing from proxy/runtime crates
- implementation has an explicit dependency and capability allowlist that excludes
  HTTP clients, DNS resolvers, subprocess or shell execution, browser/tool
  automation, credential providers, and outbound transports
- automated regression checks fail if the scorer obtains an outbound, tool, or
  runtime-control capability

### P2 Benchmark Qualification

Accepted only with repeated fixed-seed results, held-out templates, zero unsafe
fixture content, explicit limitations, and an artifact exporter that omits raw
fixture and prediction text by default. Qualification metadata records the held-out
corpus version and SHA-256, scorer version, repetition count, and fixed seed.
The exported qualification envelope has its own versioned contract identifier,
and the fixed seed is encoded as a canonical hexadecimal string so JSON
consumers do not lose integer precision.

## Future Runtime Work Is Outside This Contract

A separate design and review may consider a disabled-by-default, shadow-only Lab
experiment. That work is not a phase of this offline benchmark, is not authorized
by this document, and must establish its own event namespace, resource ceilings,
kill switch, privacy review, benign regression evidence, typed safe rendering,
request/exposure proof rules, malformed-state handling, restart/replay tests, and
direct-target control. It must have no `SurfaceAction` or policy input unless a
separate release-contract amendment explicitly authorizes it.

### Production

No-go until an explicit release-contract amendment, threat review, independent
review, all HTTP, state, privacy, and recovery gates, and evidence that shadow
mode is benign. Similarity must never be silently promoted to
`EventKind::BaitActionObserved` or `ProofOutcome::Accepted`.

## Ownership And Review

Semantic-canary benchmark changes need an explicit owner and reviewer for:

- safety contract and fixture content
- schema and bounds
- scorer determinism and abstention behavior
- report minimization
- non-causality and non-attribution wording
- separation from proxy/runtime imports and event semantics
