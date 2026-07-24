# Controlled-Reality Isolation

Status: issue `#176` foundation; not an isolation or production-readiness claim

## Current boundary

The active proxy still renders controlled-reality responses in process. Its
policy state, request correlation, durable workflow state, evidence, depth
limits, and protected-upstream routing remain authoritative.

The standalone `eidolon-controlled-reality` binary establishes a future
separate-process rendering boundary. It is not selected by the proxy or
deployed by the Shield Lab overlays yet.

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
Debian image does not enforce either property: it has no network sandbox,
read-only root filesystem, or syscall policy beyond its non-root user. Those
restrictions remain deployment requirements, not properties proved by this
image.

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

## Why it is not deployed yet

The existing local cluster profiles cannot support an honest hard-isolation
claim:

- the OrbStack deploy and status paths do not verify NetworkPolicy
  enforcement; the local validation node inspected on 2026-07-24 was started
  with `--disable-network-policy`
- the OrbStack overlay exposes the owned target through NodePort `31081`,
  which creates a host-level bypass around a pod-only policy boundary
- kind supports NetworkPolicy in current releases, but this repo does not pin
  the kind/node versions or run live allow/deny checks
- neither profile captures denied-flow evidence
- NetworkPolicy objects alone do not prove that denied traffic is enforced or
  audited

Adding a backend Deployment to those overlays would look isolated in YAML
while remaining able to reach protected destinations in practice.

## Required deployment slice

Before the proxy can use the separate renderer in Kubernetes:

1. Pin a NetworkPolicy-capable cluster version and verify enforcement before
   deployment.
2. Remove or isolate the direct-target NodePort from that profile.
3. Run the backend in its own namespace and dedicated non-root image.
4. Disable its service-account token, use a read-only root filesystem, drop all
   capabilities, apply `RuntimeDefault` seccomp, and set CPU, memory, and
   ephemeral-storage limits.
5. Mount only a dedicated renderer authentication secret. Do not mount proxy,
   ingress, bait-signing, protected-target, or customer credentials.
6. Permit ingress only from the proxy on the renderer port and permit no
   backend egress.
7. Prove live negative access to the protected target ClusterIP, node
   NodePorts, Kubernetes API, metadata destinations, and internet.
8. Capture denied-flow evidence from the enforcing CNI.
9. Live-test worker, audit, and replay-cache saturation; expose drop and
   saturation counters to operators.
10. Define restart and multi-replica replay behavior before allowing stateful
    rendering.

## Required proxy integration slice

Proxy integration must preserve these failure rules:

- no fallback to the in-process renderer after remote mode is selected
- timeout, disconnect, invalid authentication, stale frame, wrong request ID,
  malformed body, or oversized output rolls back the pending workflow step
- every backend failure returns a bounded local response and makes zero
  protected-upstream requests
- backend network I/O must not run under the current global workflow mutex;
  concurrency must be isolated per session or by bounded lock sharding
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
