# Shield Lab Template

This directory is a defensive-only template for a private Eidolon deployment
lab. It is meant to be extracted into a private repo and used for owned-target
qualification, scale testing, and hardening work.

It is not a place to carry private scanner or offensive tooling source code.
Keep those adapters external and point the lab at built artifacts or mounted
worktrees.

## Purpose

The current public repo is strong at:

- causal bait -> action -> containment evidence
- lab-scale replay and reporting
- controlled M3 evaluation

The next gap is deployment-grade validation:

- multi-namespace Kubernetes deployment
- ingress separation
- explicit controlled-reality isolation boundary
- event export and observability
- scale and failure testing against owned targets

## Private repo boundary

Recommended private repo contents:

- Kubernetes manifests and overlays
- Helm or Kustomize packaging
- image build and deploy automation
- owned target fixtures
- benign and adversarial workload generators
- redacted evidence packaging
- cluster-only secrets management
- internal dashboards and runbooks

Keep out of the private repo:

- third-party targets
- real credentials or customer data
- offensive scanner source code
- exploit payload collections
- any material that breaks the owned-target-only boundary

## Suggested private repo name

`eidolon-shield-lab`

## Layout

```text
  shield-lab/
  kind-config.yaml
  status-orbstack.sh
  metrics-orbstack.sh
  logs-orbstack.sh
  export-orbstack-evidence.sh
  export-edge-decisions-orbstack.sh
  smoke-trusted-ingress-orbstack.sh
  smoke-suspicious-promotion-orbstack.sh
  smoke-suspicious-openapi-orbstack.sh
  smoke-suspicious-discovery-fanout-orbstack.sh
  smoke-suspicious-rate-limit-orbstack.sh
  smoke-suspicious-openapi-rate-limit-orbstack.sh
  smoke-rate-limited-blocked-orbstack.sh
  smoke-rate-limited-controlled-reality-orbstack.sh
  smoke-controlled-reality-blocked-orbstack.sh
  collect-kali-vm-sample.sh
  run-pwnkit-kali-vm.sh
  kali-vm-pwnkit.md
  k8s/
    base/
      kustomization.yaml
      namespaces.yaml
      eidolon-configmap.yaml
      eidolon-proxy.yaml
      demo-target.yaml
      controlled-reality-networkpolicy.yaml
    orbstack/
      kustomization.yaml
      shield-edge-service.yaml
      target-edge-service.yaml
```

## Cluster model

```text
internet / workload generators
        |
        v
  [ ingress / edge ]
        |
        v
  [ eidolon proxy ]  ---->  events / exports / dashboards
        |
        +---- protected upstream target
        |
        +---- reserved controlled-reality namespace
```

Namespaces:

- `shield-system`: Eidolon runtime
- `shield-targets`: owned demo or qualification targets
- `shield-controlled-reality`: future isolated decoy backends
- `shield-observability`: logs, metrics, dashboards

## What this template does now

- sets up a multi-node `kind` cluster shape
- reserves namespaces and labels
- deploys a simple Eidolon proxy service and owned demo target
- wires the proxy to the target with a config map
- persists proxy event, debug, intervention, and policy state on a PVC
- reserves a default-deny policy for the controlled-reality namespace
- includes local image build and OrbStack deploy scripts
- includes operator scripts for status, logs, and redacted evidence export
- includes live edge-decision export for webhook/SIEM handoff
- includes a lightweight live metrics surface over cluster status and PVC-backed proxy state
- includes a dedicated Kali VM pwnkit wrapper for the OrbStack NodePort validation topology

## Explicit cluster-lab mode

The public binaries still default to the local loopback-only lab. Kubernetes
deployment is an explicit opt-in:

- `eidolon-proxy` must run with `--owned-cluster-lab`
- `eidolon-demo-target` must run with `EIDOLON_OWNED_CLUSTER_LAB=1`

That keeps the default safety posture intact while allowing owned cluster
deployment when you ask for it directly.

## Proxy state model

The shield proxy runs as a single replica in this lab template and mounts a
`ReadWriteOnce` volume claim at `/var/lib/eidolon`.

That is intentional:

- the event log, debug log, intervention control file, and policy state are
  single-writer file artifacts in the current runtime
- same-session evidence is easier to reason about with one proxy writer
- the local-path provisioner in small clusters is a good fit for this owned
  lab shape

If you later want multi-replica proxy scale, move those state paths out of
local files first.

## What it does not do yet

- deploy ingress controllers
- provision SIEM or webhook exporters
- isolate controlled reality beyond namespace and network-policy reservation
- run workload generators
- manage secrets

Those should live in the private repo as the next hardening steps.

## How to extract this into a private repo

1. Copy `examples/shield-lab/` into a new private repo root.
2. Add image build automation for:
   - `eidolon-shield-proxy:local`
   - `eidolon-owned-demo-target:local`
3. Add environment overlays for:
   - `kind`
   - `orbstack`
   - managed Kubernetes
4. Keep scanner integrations external:
   - mount a built CLI or binary
   - mount owned fixture repos
   - keep qualification artifacts in redacted bundle form
5. Add the Shield issues as the repo roadmap:
   - trusted ingress identity
   - multi-signal policy
   - signed polymorphic bait
   - tamper-evident export
   - hard-isolated controlled reality
   - adversarial agent hardening harness

## Example commands

Build local images for OrbStack Kubernetes:

```sh
examples/shield-lab/build-orbstack-images.sh
```

Deploy to the active OrbStack Kubernetes context:

```sh
examples/shield-lab/deploy-orbstack.sh
```

To rotate Shield-side bait semantics without changing `pwnkit`, redeploy with
an explicit bait profile:

```sh
EIDOLON_SHIELD_BAIT_PROFILE_PATH=examples/m3/bait-profiles/openapi-promotion-probe.json \
examples/shield-lab/deploy-orbstack.sh
```

The default OrbStack deployment profile is:

```text
examples/shield-lab/bait-profiles/default-m3-catalog.json
```

That profile preserves the built-in M3 bait catalog while making deployment
profile provenance explicit. This is the preferred way to make the same
external scanner face harder or different bait semantics without drifting this
repo into scanner development.

The deploy script also patches the proxy pod template with the selected bait
profile digest and waits for rollout status, so the next Kali run sees the
profile you just selected instead of a stale mounted file.

That applies the `k8s/orbstack` overlay, which adds a dedicated
`NodePort` service named `eidolon-shield-edge` for the proxy while keeping the
base manifests cluster-internal.

On OrbStack, the shield is then reachable at:

```text
http://127.0.0.1:31080
```

The direct baseline target is also exposed on the host at:

```text
http://127.0.0.1:31081
```

Treat those NodePorts as raw lab ingress only:

- they are useful for deployment and scanner-topology validation
- they are not a trusted edge adapter boundary on their own
- explicit `X-Eidolon-Ingress-*` identity headers are ignored there unless the
  proxy is explicitly configured with `--ingress-transport-auth-secret-file`
- the OrbStack overlay now enables that transport-auth path with a cluster-local
  shared secret so operators can smoke-test both the rejected raw path and the
  accepted authenticated path on the same deployment

Validate those two ingress-side runtime paths directly on the live OrbStack
shield:

```sh
examples/shield-lab/smoke-trusted-ingress-orbstack.sh
examples/shield-lab/smoke-suspicious-promotion-orbstack.sh
examples/shield-lab/smoke-suspicious-openapi-orbstack.sh
examples/shield-lab/smoke-suspicious-discovery-fanout-orbstack.sh
examples/shield-lab/smoke-suspicious-rate-limit-orbstack.sh
examples/shield-lab/smoke-suspicious-openapi-rate-limit-orbstack.sh
examples/shield-lab/smoke-rate-limited-blocked-orbstack.sh
examples/shield-lab/smoke-rate-limited-controlled-reality-orbstack.sh
examples/shield-lab/smoke-controlled-reality-blocked-orbstack.sh
```

The second smoke proves the first M5 graduated-enforcement slice: one
authenticated advisory discovery request is promoted from `observe` to
`suspicious`, stays baited, is served from an Eidolon-owned docs surface, and
exports the advisory signals with a `preserve_eidolon_routing` edge
recommendation.

The third smoke proves the next `#175` slice on `/openapi.json`: one
authenticated advisory OpenAPI discovery request is promoted from `observe` to
`suspicious`, is served from an Eidolon-owned OpenAPI surface instead of a
rewritten upstream schema, and exports the same
`preserve_eidolon_routing` recommendation.

The fourth smoke proves the first session-recon promotion slice: one session
first requests `/docs` and then `/openapi.json`, gets promoted from `observe`
to `suspicious` on the second request because it fanned out across both
discovery surfaces, and is then served from the owned OpenAPI path with the
same `preserve_eidolon_routing` export recommendation.

The fifth smoke proves the first `suspicious -> rate_limited` slice: a session
that was promoted on the owned docs surface and then performs a wrong-header
same-bait near miss on `/api/v2/import/reconcile` is throttled with
`Retry-After`, preserves unmatched bait-action evidence, and exports the
`rate_limited` runtime decision.

The sixth smoke proves the same rate-limit path for the owned OpenAPI bait:
after a suspicious `/openapi.json` exposure, a wrong-value
`X-OpenAPI-Trace` request on the shared reconcile path is attributed to the
OpenAPI bait rather than the docs bait and is throttled the same way.

The seventh smoke proves the first `rate_limited -> blocked` slice: after one
same-bait wrong-header retry has already moved the session into
`rate_limited`, repeating that same near miss again moves the session into
`blocked`, preserves the second unmatched bait-action observation, and exports
the blocked Eidolon-owned decision.

The eighth smoke proves the first `rate_limited -> controlled_reality` slice:
after a same-bait near miss has already throttled the session once, a confirmed
same-session exact bait-derived action on `/api/v2/import/reconcile` moves the
session into `controlled_reality`, preserves the matched exposure evidence, and
exports the contained runtime decision.

The ninth smoke proves the first `controlled_reality -> blocked` slice: after a
session has already entered containment, continuing to probe the same
controlled branch past the configured depth-limit throttle first triggers the
existing `429` tarpit and then moves the session into `blocked`, preserving the
post-containment hard-fail in edge export.

Create a `kind` cluster:

```sh
kind create cluster --name eidolon-shield --config kind-config.yaml
```

Apply the base to a non-OrbStack cluster:

```sh
kubectl apply -k k8s/base
```

Apply the OrbStack overlay manually:

```sh
kubectl apply -k k8s/orbstack
```

Port forward the proxy:

```sh
kubectl -n shield-system port-forward svc/eidolon-shield-proxy 9102:9102
```

Check the OrbStack edge service:

```sh
kubectl -n shield-system get svc eidolon-shield-edge
```

Check the direct target edge service:

```sh
kubectl -n shield-targets get svc eidolon-owned-demo-target-edge
```

Check the live lab status:

```sh
examples/shield-lab/status-orbstack.sh
```

Smoke-check the trusted-ingress transport-auth path:

```sh
examples/shield-lab/smoke-trusted-ingress-orbstack.sh
```

Summarize live shield metrics:

```sh
examples/shield-lab/metrics-orbstack.sh
```

Tail proxy logs:

```sh
examples/shield-lab/logs-orbstack.sh proxy --follow
```

Tail both workloads:

```sh
examples/shield-lab/logs-orbstack.sh all --follow
```

Export a redacted evidence bundle from the PVC-backed proxy state:

```sh
examples/shield-lab/export-orbstack-evidence.sh /private/tmp/eidolon-shield-bundle
```

Export host-side evidence, then copy a Kali scanner-side sample back onto the
host with linked hashes:

```sh
examples/shield-lab/export-orbstack-evidence.sh /private/tmp/eidolon-m4-orbstack-bundle
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --output /private/tmp/eidolon-m4-orbstack-edge-decisions.json
examples/shield-lab/collect-kali-vm-sample.sh \
  --host-bundle-dir /private/tmp/eidolon-m4-orbstack-bundle \
  --edge-decisions /private/tmp/eidolon-m4-orbstack-edge-decisions.json \
  /tmp/eidolon-m4-orbstack \
  /private/tmp/eidolon-m4-orbstack-kali
```

Export live edge decisions as JSON or webhook events:

```sh
examples/shield-lab/export-edge-decisions-orbstack.sh --format json
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format ndjson \
  --webhook-url https://collector.example.test/eidolon
```

Port forward the demo target:

```sh
kubectl -n shield-targets port-forward svc/eidolon-owned-demo-target 9101:9101
```

For the deployed Kali validation path, see
[kali-vm-pwnkit.md](./kali-vm-pwnkit.md).

## Defensive scope

This template is for testing Eidolon on owned or authorized systems. It is not
for private offensive tool development, third-party targeting, or bypass work.
