# Controlled-Reality Isolation

Status: issue `#176` enforced kind boundary; not a hard-isolation or
production-readiness claim

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
the renderer default-deny egress. OrbStack does not deploy it.

On 2026-07-24,
`examples/shield-lab/smoke-controlled-reality-isolation-kind.sh` passed against
the pinned local kind/Calico deployment. It correlated one minted bait action
from the proxy event log to the renderer's `served` audit by request ID,
required a synthetic `202` response with `write_committed:false`, and proved
the same probe image could reach the target, Kubernetes API, owned metadata
canary, and internet from `shield-system` while all four destinations were
denied from `shield-controlled-reality`. It also proved a non-proxy pod could
not reach the renderer and matched all five denials to Calico flow records.

`examples/shield-lab/smoke-controlled-reality-outage-kind.sh` adds the outage
contract. It removes every renderer Pod and Service endpoint, performs a valid
same-session minted action, and requires the fixed private/no-store synthetic
`503`, an Eidolon-owned request-linked response event, and one request-linked
`connect_failed` debug audit with no local fallback. A unique safe marker first
proves the target-side detector works. Any later protected reconcile audit,
even if an intermediary strips that marker, fails the smoke. A target Pod
replacement or container restart also invalidates the proof.

The owned demo target is stateless. This proves zero protected write-shaped
request arrival, not the absence of a storage mutation in a stateful target.
The backend failure reason currently remains in the debug audit rather than a
first-class durable event/export field.

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
- the checked-in kind smoke now proves the active renderer path, paired
  allow/deny behavior, and request/pod-correlated denied-flow evidence
- this proof does not cover managed-cluster networking, host compromise,
  saturation, restart, or multi-replica behavior

## Remaining deployment slice

The enforced kind network boundary is now proven. Issue `#176` still requires:

1. Live-test worker, audit, and replay-cache saturation; expose drop and
   saturation counters to operators.
2. Define restart and multi-replica replay behavior before allowing stateful
    rendering.
3. Keep the renderer-outage smoke green in a live gate and prove the operator
   kill switch preserves zero protected writes.

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
