# Controlled-Reality Isolation

Status: issue `#176` foundation; not an isolation or production-readiness claim

## Current boundary

The proxy defaults to in-process rendering. Operators can instead configure
the standalone `eidolon-controlled-reality` process with
`--controlled-reality-backend-addr` and
`--controlled-reality-backend-auth-secret-file`. Remote mode has no local
rendering fallback.

Policy state, request correlation, durable workflow state, evidence, depth
limits, response headers, and protected-upstream routing remain proxy-owned.
The kind Shield Lab overlay deploys the renderer in
`shield-controlled-reality`, routes the proxy through Service DNS, and gives
the renderer default-deny egress. OrbStack does not deploy it. This remains a
manifested isolation boundary, not a hard-isolation claim, until live deny
tests and denied-flow evidence pass.

The renderer protocol is deliberately closed:

- requests contain only a request ID, a classified action kind, workflow
  progress, and precomputed synthetic resource references
- requests omit the raw HTTP request, session ID, cookies, bait proofs,
  credentials, protected data, and protected-upstream address
- responses contain only request-correlated synthetic status and JSON body
- responses cannot choose routing, policy state, evidence interactions,
  response headers, cache policy, or artifact identity
- request and response frames are versioned, size bounded, freshness checked,
  and authenticated with a dedicated HMAC secret
- each response is bound to the exact authenticated request tag, not only its
  request ID
- authenticated request IDs are checked against a process-local replay cache
  capped at 4,096 live entries

The current renderer implementation has I/O deadlines, 32 fixed connection
workers, and a 32-entry application queue. Connections above that combined
capacity are dropped with a quota outcome; the operating system's listen
backlog remains outside the application limit. Audit output uses a separate
128-entry nonblocking queue. Backpressure drops audit records instead of
occupying connection workers, and a later record reports the number dropped.

The implementation currently contains no outbound connector and writes no
persistent filesystem state after loading its dedicated secret. The ordinary
Debian image does not enforce either property by itself. The kind Deployment
adds a read-only root filesystem, dropped capabilities, `RuntimeDefault`
seccomp, no service-account token, resource limits, and a dedicated secret
mount. NetworkPolicy supplies the no-egress boundary.

Within one backend process, the first authenticated request ID is retained
through its 30-second freshness window and a duplicate is rejected. Saturation
or loss of the bounded cache fails closed. The cache is in-memory and
process-local, so a restart or a future multi-replica deployment can accept the
same otherwise-fresh frame again. Rendering is currently stateless and
deterministic; restart-safe or replica-coordinated replay semantics must be
defined before a stateful renderer is deployed.

The secret file path must be absolute and contain no `..` component. The file
contains exactly 64 hexadecimal characters encoding 32 bytes, with one
optional trailing newline.

JSON audit records contain reason codes, peer addresses, and request
correlation, not raw frames or secrets. Authenticated rejections retain their
request ID. Malformed or unauthenticated frames intentionally do not trust a
supplied request ID.

## Deployment status

The local profiles still cannot support an honest hard-isolation claim:

- the OrbStack deploy and status paths do not verify NetworkPolicy
  enforcement; the local validation node inspected on 2026-07-24 was started
  with `--disable-network-policy`
- the OrbStack overlay exposes the owned target through NodePort `31081`,
  which creates a host-level bypass around a pod-only policy boundary
- kind pins its node image, disables kindnet, installs Calico `v3.32.1`, and
  deploys the remote renderer without NodePorts
- kind still lacks a checked-in live allow/deny smoke and denied-flow capture
- the kind path was not run locally for this slice because `kind` was not
  installed
- NetworkPolicy objects and cluster-free rendering do not prove enforcement

## Required deployment slice

Before issue `#176` can claim the enforced boundary:

1. Prove live negative access to the protected target ClusterIP, node
   NodePorts, Kubernetes API, metadata destinations, and internet.
2. Capture denied-flow evidence from the enforcing CNI.
3. Live-test worker, audit, and replay-cache saturation; expose drop and
   saturation counters to operators.
4. Define restart and multi-replica replay behavior before allowing stateful
    rendering.

## Proxy integration contract

Remote proxy integration preserves these failure rules:

- no fallback to the in-process renderer after remote mode is selected
- timeout, disconnect, invalid authentication, stale frame, wrong request ID,
  malformed body, or oversized output rolls back the pending workflow step
- every backend failure returns a fixed private/no-store `503` and remains on
  an Eidolon-owned route
- backend network I/O is isolated by 64 bounded session-keyed lock shards
  rather than one global workflow mutex
- policy, evidence interaction, durable response expectations, headers, cache
  policy, and artifact digest remain proxy-owned

## Remaining acceptance work

Issue `#176` stays open until:

- the active controlled-reality response path crosses the enforced boundary
- synthetic application state is isolated from protected and proxy enforcement
  state
- quotas and an operator kill switch are live-tested
- boundary violations are auditable
- outage and escape tests prove zero protected writes

The standalone renderer is a prerequisite for that work, not proof that the
work is complete.
