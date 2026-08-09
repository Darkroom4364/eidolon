# Eidolon v1.0 Full Release Definition

Status: governing release contract

This document defines what "full release" means for Eidolon. It replaces
earlier uses of "v1 candidate" that referred only to Lab research milestones.

## Meaning Of v1.0

Eidolon v1.0 is a supported, single-replica, self-hosted production release of
Eidolon Shield within a narrow, declared operating envelope. It is not a claim
that every roadmap or research feature is complete.

The release promise is:

```text
For traffic routed through a supported Eidolon deployment:

- recognized unsafe bait actions never reach the protected upstream
- confirmed bait evidence is same-session and request-linked
- contained sessions receive only Eidolon-owned controlled reality
- failures preserve the safety boundary and remain operator-visible
- installation, upgrade, rollback, recovery, and normal operation are supported
```

Eidolon Lab remains the validation harness. Lab results support the Shield
release but are not themselves a production-readiness claim.

Open-source publication is a separate release action. Eidolon may reach a
private full `v1.0` release while the development repository remains private.
A later public `v1.0.0` tag and announcement happen only after the publication
decision and a clean public-repository verification run.

## Supported Envelope

The final release must name exact versions, but its minimum supported envelope
is fixed now:

- owned or explicitly authorized web and HTTP API targets only
- Linux x86_64 OCI runtime images
- one explicitly named Kubernetes distribution and Calico version matrix
- one production-shaped Linux cluster used for release validation
- kind with an enforcing CNI as the repeatable CI/reference environment
- one explicitly named ingress implementation terminating TLS before Eidolon
- one named storage class and persistent-volume profile
- forwarded and trusted-ingress headers accepted only from configured ingress
  identities and source networks
- HTTP/1.1 on the Eidolon proxy hop
- one proxy instance/writer and one controlled-reality renderer instance
- persistent signing keys and bounded durable state on one documented storage
  profile
- one documented ingress path with no direct protected-target bypass
- a production profile distinct from Lab presets, with secure session cookies
  and fail-closed dependency handling
- planned restart and upgrade downtime
- macOS arm64 and Linux x86_64 for local Eidolon Lab workflows

Anything outside that envelope is unsupported unless the release notes add it.
In particular, v1.0 does not imply support for Windows, direct TLS termination,
HTTP/2 or HTTP/3 proxy hops, WebSocket upgrades, arbitrary TCP proxying,
non-Kubernetes production installs, high availability, zero-downtime upgrades,
or every cloud/CNI/ingress combination.

## Release Stages

### Alpha

The current `v0.x` line. Lab behavior is usable, but production support is not
claimed.

### Beta

The production transport, durable state, release deployment, and operator
contracts exist. Restart, rollback, load, and security testing may still be
incomplete. Beta is not a supported production release.

### Release Candidate

Every gate below passes against one immutable artifact set. No known P0 or P1
release defect remains. Only release-note, packaging, or blocker fixes may land
after the candidate is cut.

### Full Release

The exact release-candidate artifacts are promoted after:

- all required CI and live validation remain green
- a seven-day candidate observation period finds no P0 or P1 defect
- continuous health traffic and one mixed benign/adversarial synthetic scenario
  run successfully on every day of that observation period
- all supported-version, security, operations, and release notes are final

## Required Gates

All gates are mandatory. A linked issue, pull request, test run, or release
artifact must provide the evidence for every checked item.

### Gate 1: Stable Product And Compatibility Contract

- Shield and Lab responsibilities, supported environments, and non-goals are
  documented without autonomous-attacker attribution claims.
- CLI/config, event, evidence, and edge-export contracts are versioned.
- The compatibility policy states what is stable under semantic versioning.
  The policy lives in `docs/compatibility-policy.md`.
- Upgrade from the one exact beta artifact named by the release candidate
  succeeds without losing enforcement, replay, workflow, or
  request-correlation state. Arbitrary alpha and development state is not
  supported.
- Unknown future schema/config versions fail closed with actionable errors.
- CLI help, examples, manifests, runbooks, and actual defaults agree.
- The production profile cannot silently inherit Lab-only flags or insecure
  cookie defaults.

### Gate 2: Production HTTP Boundary

- The production path uses a maintained Hyper/Tower-class HTTP stack; the
  custom blocking parser is removed from the production profile.
- Request targets, authorities, framing, hop-by-hop headers, body limits,
  deadlines, connection limits, and upstream responses have adversarial tests.
- Malformed, ambiguous, oversized, timed-out, or unsupported traffic creates
  no protected-upstream request.
- Unsupported upgrades and protocol features are rejected explicitly.
- Fuzz or differential tests cover request parsing and canonicalization.
- `SIGTERM` stops new production admission, uses HTTP/1 graceful shutdown to
  drain accepted connections, and syncs final audit output before a successful exit.
  The production-only `--shutdown-grace-secs` is a 1–300 second (default 60)
  successful-drain grace period. Deadline expiry establishes a nonzero failure,
  waits for non-cancellable accepted work to quiesce, then returns that failure;
  it is not a hard
  process-exit deadline.

### Gate 3: Safety And Causal Correctness

- Every invariant in
  [engineering-operating-policy.md](engineering-operating-policy.md) has a
  regression test across every release profile and intervention mode.
- Every configured unsafe action shape is registered as Eidolon-owned before
  its proof is validated or any upstream route is considered.
- Missing, malformed, mismatched, expired, replayed, disabled, or unavailable
  bait proof never reaches protected upstream.
- Rejected or unlinked evidence remains visible but never produces a confirmed
  chain.
- Trusted ingress can soften early exposure only; runtime bait evidence always
  wins.
- Concurrent and reordered requests cannot be joined by session-level timing
  heuristics.
- There are no open P0 or P1 safety, causality, disclosure, parser, state, or
  isolation defects.

### Gate 4: Restart-Safe Identity And Durable State

- The release deployment enforces one proxy writer and rejects unsupported
  multi-writer configuration.
- Deployment uses `Recreate` or an equivalent `maxSurge: 0` strategy, and a
  durable lock or lease makes a second writer fail startup.
- Session continuity behind shared ingress cannot merge unrelated clients and
  does not depend only on the direct TCP peer address.
- Persistent signing keys, restart, upgrade, rollback, and key rotation do not
  reset enforcement or accept an already consumed proof.
- The renderer remains stateless and deterministic: replay after a renderer
  restart can reproduce only the same bounded synthetic response and cannot
  mutate policy, evidence, or protected state.
- State has explicit size, TTL, retention, compaction, and migration bounds.
- Partial writes, unavailable storage, stale reads, and version mismatch have
  deterministic fail-closed behavior.
- Backup and restore are exercised against a non-empty contained session and
  preserve the last durable evidence-backed state.

### Gate 5: Controlled-Reality Isolation

- The release profile always uses the separate authenticated renderer and has
  no in-process fallback.
- The renderer receives no raw request, session credential, protected data, or
  protected-upstream connector.
- Workloads run non-root with read-only filesystems, dropped capabilities,
  seccomp, resource limits, dedicated identities, and default-deny networking.
- Only the proxy can reach the renderer; the renderer cannot reach the target,
  cluster API, metadata service, or internet.
- A live network test proves the protected target has no route that bypasses
  Eidolon from the supported ingress path.
- Release-cluster live tests prove normal routing, outage, saturation, escape,
  replay, restart, and operator kill-switch behavior with zero protected
  writes.
- Isolation and safety remain true during proxy or renderer unavailability.

### Gate 6: Install, Upgrade, Rollback, And Recovery

- One versioned production deployment package configures images, ingress,
  durable storage, secrets, security contexts, resources, and retention without
  editing base manifests.
- Release images in the supported registry are digest-pinned and available for
  Linux x86_64.
- Fresh install reaches ready state through a documented procedure.
- Upgrade from the exact beta artifact named by the candidate and rollback to
  that version are live-tested with retained state. Planned downtime is
  permitted and measured.
- Secret and signing-key rotation is documented and live-tested.
- Backup, restore, emergency disable, and renderer outage runbooks are tested.
- Readiness, liveness, startup, shutdown, and dependency health have distinct
  semantics and do not report ready while the safety boundary is unavailable.
- `SIGTERM` stops admission before listener teardown, drains accepted work through
  HTTP/1 graceful shutdown, persists final audit output, and exits successfully
  only within the documented successful-drain grace period. On expiry it reports
  failure and waits for non-cancellable accepted work to quiesce before returning.

### Gate 7: Operator Evidence, Privacy, And Observability

- Events and reports keep direct observations separate from inferred claims.
- Every decision and controlled response is request-linked end to end.
- Export defaults omit secrets, bodies, cookies, query values, sensitive path
  segments, and incidental personal data.
- Retention and deletion are configurable and bounded for state, logs, and
  exported evidence.
- Metrics expose traffic, routing, policy transitions, proof outcomes, storage
  health, dropped events, renderer saturation, and fail-closed responses.
- Runbooks define actionable alerts for state loss, audit failure, renderer
  outage, capacity exhaustion, and unexpected protected-upstream activity.
- One operator command produces a minimized session narrative and identifies
  any missing or uncertain evidence.

Cryptographic receipts, SCITT, and broad telemetry fusion are not v1 blockers.

### Gate 8: Benign-Safety And Defensive Validation

- A checked-in benign corpus covers browsers, monitoring, accessibility tools,
  crawlers, internal scanners, and explicitly trusted automation, with at least
  500 requests from each class and a recorded generator/version manifest.
- At least 10,000 benign requests produce zero containment or blocking in the
  absence of a deliberate bait-derived action.
- Every configured trusted-automation case has spoofed, expired, mismatched,
  and valid controls.
- Owned adversarial scenarios prove same-session bait action, containment, and
  zero protected-upstream writes.
- At least two session-minted bait chains with different action shapes,
  including one non-OpenAPI chain, pass the deterministic release suite.
- Negative controls prove wrong-session, wrong-proof, static bait, ordinary
  application traffic, and ambiguous request behavior.
- Scanner capability, substrate quality, and Eidolon defensive effect remain
  separate result sets.

No pwnkit, XBow, model-family, or benchmark score is required to pass this
gate.

### Gate 9: Reliability And Performance

The minimum reference profile is:

- 100 requests/second at 25 concurrent connections for four hours
- no safety-invariant violation or unbounded queue/state growth
- no more than 25 ms p95 added proxy latency against the direct baseline
- less than 0.1% Eidolon-induced request errors while dependencies are healthy
- no more than 15% resident-memory growth after the first warm-up hour
- a five-minute burst at twice the reference rate without violating safety or
  requiring manual recovery
- dependency or pod loss preserves safety and the documented recovery
  procedure restores service within five minutes

The load generator, hardware profile, request mix, configuration, raw results,
and summary must be checked in or attached to the release. Meeting this profile
is a minimum supported sizing claim, not a universal capacity claim.

### Gate 10: Security And Release Qualification

- Formatting, lint, unit, fixture, fuzz, integration, upgrade, rollback,
  release-cluster, and supported-platform checks pass on the exact candidate.
- Each release-critical HTTP, config, state, and event parser fuzz target runs
  for at least 60 minutes against the candidate with its seed corpus recorded.
- Dependency, license, secret, and container scans have no unaccepted critical
  or high finding.
- Release images and source archives have SBOMs, checksums, signatures, and
  provenance tied to the candidate commit.
- GitHub Actions, builder images, runtime bases, and release dependencies are
  version or digest pinned.
- An independent security review covers the HTTP boundary, state transitions,
  isolation, secret handling, and export disclosure.
- The production threat model explicitly covers ingress trust, storage failure,
  renderer compromise, denial of service, direct-target bypass, and the
  cluster/node trust boundary.
- No critical or high review finding remains open; lower findings are
  documented with owners and target versions.
- Vulnerability reporting, supported-version policy, patch process, changelog,
  upgrade notes, rollback notes, and release notes are operational.
- The final tag points to the already-tested candidate; release artifacts are
  promoted rather than rebuilt from a different source state.

## Hard No-Go Conditions

Eidolon cannot be called a full release if any of these is true:

- a recognized unsafe action can reach protected upstream
- rejected or unlinked evidence can become a confirmed chain
- cookie rotation, restart, upgrade, rollback, or storage error can reset
  enforcement
- shared-ingress session continuity can merge unrelated clients
- ambiguous request meaning differs between policy and upstream routing
- controlled reality can reach protected data or protected upstream
- the release profile depends on the custom Lab HTTP parser
- the protected target has a route that bypasses Eidolon
- the production profile lacks persistent keys or restart-safe state
- state, logs, queues, or replay tracking are unbounded
- supported upgrade, rollback, backup, or restore is untested
- exports can disclose default-sensitive request data
- an open P0/P1 or critical/high security finding affects the release envelope
- the exact release artifacts have not passed the required gates

## Explicitly Post-v1

These may proceed when useful, but they do not block v1.0:

- more adaptive policy states or ML scoring
- high availability, active-active state, and zero-downtime upgrades
- Linux arm64 production images and multi-architecture release matrices
- managed-cloud, multi-cluster, and multi-region deployment
- broad controlled-reality worlds or LLM-generated deception
- pwnkit, XBow, or other offensive-agent benchmark expansion
- Kali-to-microVM transfer and Firecracker execution lanes
- browser-agent fingerprinting or model-family attribution
- prompt flooding or adversarial nonsense generation
- SPIFFE, WebAuthn, or vendor-specific verified-agent breadth beyond the one
  supported ingress path
- eBPF, Tetragon, Hubble, or Falco telemetry fusion
- SCITT/COSE receipts, transparency logs, or RFC3161 timestamps
- multi-cloud, multi-CNI, and every-ingress portability

## Current Readiness Snapshot

As of 2026-07-25:

Already strong:

- fail-closed recognized bait-action routing
- rejected-evidence classification
- HMAC-protected Lab session cookies with direct-peer rotation safeguards
- request-linked causal evidence
- bounded recoverable single-process policy state and event logs
- local kind/Calico renderer isolation, outage, saturation, escape, and
  kill-switch proofs
- broad Rust and shell fixture coverage

Partial:

- versioned event/export contracts and redaction
- deployment packaging and trusted ingress
- local non-root Kubernetes hardening
- operator evidence and runbooks

Missing release blockers:

- production Hyper/Tower HTTP transport
- restart-safe single-writer state and replay handling
- one production profile with secure cookies, shared-ingress-safe sessions,
  persistent keys, and no target bypass
- release-cluster deployment and restart proof
- supported upgrade, rollback, backup, and restore
- release metrics, alerting, SLO, load, and soak evidence
- signed Linux x86_64 artifacts, SBOMs, and independent security review

## Workstream Order

Five bundled workstreams are sufficient:

1. Production HTTP boundary.
2. Restart-safe identity, durable state, and replay correctness.
3. Production Kubernetes isolation and lifecycle operations.
4. Stable contracts, operator evidence, privacy, and observability.
5. Reliability, supply-chain, and final release qualification.

Workstreams 1 and 2 can proceed in parallel. Workstream 4 can proceed alongside
them where it does not freeze an unstable state contract. Workstream 3 consumes
the first two, and workstream 5 closes the release.
