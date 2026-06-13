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
  smoke-trusted-ingress-scoped-softening-orbstack.sh
  smoke-suspicious-promotion-orbstack.sh
  smoke-suspicious-aggregated-recon-orbstack.sh
  smoke-suspicious-detection-aggregation-orbstack.sh
  smoke-suspicious-detection-recon-rate-limit-orbstack.sh
  smoke-rate-limited-detection-recon-blocked-orbstack.sh
  smoke-suspicious-openapi-aggregation-orbstack.sh
  smoke-suspicious-linked-bait-aggregation-orbstack.sh
  smoke-suspicious-hidden-route-aggregation-orbstack.sh
  smoke-suspicious-js-helper-aggregation-orbstack.sh
  smoke-suspicious-linked-fanout-aggregation-orbstack.sh
  smoke-suspicious-openapi-linked-fanout-aggregation-orbstack.sh
  smoke-suspicious-openapi-orbstack.sh
  smoke-suspicious-discovery-fanout-orbstack.sh
  smoke-suspicious-rate-limit-orbstack.sh
  smoke-suspicious-openapi-rate-limit-orbstack.sh
  smoke-suspicious-openapi-recon-rate-limit-orbstack.sh
  smoke-rate-limited-recon-blocked-orbstack.sh
  smoke-rate-limited-blocked-orbstack.sh
  smoke-rate-limited-controlled-reality-orbstack.sh
  smoke-controlled-reality-blocked-orbstack.sh
  smoke-controlled-reality-depth-limit-blocked-orbstack.sh
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
profile provenance explicit. It also enables session-minted docs,
fake-service-token, and OpenAPI baits on `/docs/legacy-import`,
`/docs/service-token`, and `/openapi.json`, so the default OrbStack lab now
exercises per-session signed bait on docs, token, and discovery surfaces while
keeping the surrounding shield-lab smoke matrix intact. This is the preferred
way to make the same external scanner face harder or different bait semantics
without drifting this repo into scanner development.

The deploy script also patches the proxy pod template with the selected bait
profile digest and waits for rollout status, so the next Kali run sees the
profile you just selected instead of a stale mounted file.

The same deploy step now creates a cluster-local bait-signing secret and mounts
it into the proxy, which is required for any mint-enabled bait profile.

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

Validate those ingress-side runtime paths directly on the live OrbStack shield:

```sh
examples/shield-lab/smoke-trusted-ingress-orbstack.sh
examples/shield-lab/smoke-session-minted-legacy-import-orbstack.sh
examples/shield-lab/smoke-session-minted-service-token-orbstack.sh
examples/shield-lab/smoke-session-minted-openapi-orbstack.sh
examples/shield-lab/smoke-suspicious-promotion-orbstack.sh
examples/shield-lab/smoke-suspicious-aggregated-recon-orbstack.sh
examples/shield-lab/smoke-suspicious-decoy-write-aggregation-orbstack.sh
examples/shield-lab/smoke-suspicious-detection-aggregation-orbstack.sh
examples/shield-lab/smoke-suspicious-detection-recon-rate-limit-orbstack.sh
examples/shield-lab/smoke-rate-limited-detection-recon-blocked-orbstack.sh
examples/shield-lab/smoke-suspicious-openapi-aggregation-orbstack.sh
examples/shield-lab/smoke-suspicious-decoy-write-recon-rate-limit-orbstack.sh
examples/shield-lab/smoke-suspicious-decoy-write-repeat-bonus-orbstack.sh
examples/shield-lab/smoke-suspicious-linked-bait-aggregation-orbstack.sh
examples/shield-lab/smoke-suspicious-hidden-route-aggregation-orbstack.sh
examples/shield-lab/smoke-suspicious-js-helper-aggregation-orbstack.sh
examples/shield-lab/smoke-suspicious-linked-fanout-aggregation-orbstack.sh
examples/shield-lab/smoke-suspicious-openapi-linked-fanout-aggregation-orbstack.sh
examples/shield-lab/smoke-suspicious-openapi-orbstack.sh
examples/shield-lab/smoke-suspicious-discovery-fanout-orbstack.sh
examples/shield-lab/smoke-suspicious-rate-limit-orbstack.sh
examples/shield-lab/smoke-suspicious-openapi-rate-limit-orbstack.sh
examples/shield-lab/smoke-suspicious-openapi-recon-rate-limit-orbstack.sh
examples/shield-lab/smoke-rate-limited-decoy-write-recon-blocked-orbstack.sh
examples/shield-lab/smoke-rate-limited-recon-blocked-orbstack.sh
examples/shield-lab/smoke-rate-limited-blocked-orbstack.sh
examples/shield-lab/smoke-rate-limited-controlled-reality-orbstack.sh
examples/shield-lab/smoke-controlled-reality-blocked-orbstack.sh
examples/shield-lab/smoke-controlled-reality-depth-limit-blocked-orbstack.sh
```

The legacy-import smoke proves the docs-side default-lab polymorphic bait
slice: the owned `/docs/legacy-import` surface now mints a distinct
`X-Migration-Trace` value per session, the same session sees a stable value
across repeated exposures, a different session gets a different value, a
cross-session replay stays uncorrelated and falls back to upstream behavior,
and the exact action export preserves only safe mint metadata, not the value
itself. Edge export now also records whether the latest minted legacy-import
bait-shaped action carried a `matched_session_value` or a
`session_value_mismatch`.

The service-token smoke proves the token-side default-lab polymorphic bait
slice: the `/docs/service-token` surface now mints a distinct `X-Api-Key`
value per session, the same session sees a stable value across repeated
exposures, a different session gets a different value, a cross-session replay
stays uncorrelated and falls back to upstream behavior, and the exact action
export preserves only safe mint metadata, not the value itself. Edge export now
also records whether the latest minted bait-shaped action carried a
`matched_session_value` or a `session_value_mismatch`.

The OpenAPI mint smoke proves the discovery-side default-lab polymorphic
slice: the owned `/openapi.json` surface now mints a distinct
`X-OpenAPI-Trace` example per session, the same session sees a stable value
across repeated discovery, a different session gets a different value, a
cross-session replay stays uncorrelated and falls back to upstream behavior,
and the exact action export again preserves only safe mint metadata, not the
value itself. Edge export now also records whether the latest minted OpenAPI
bait-shaped action carried a `matched_session_value` or a
`session_value_mismatch`.

The remaining hidden-route and JS-helper bait classes stay static on purpose as
negative controls. They keep fixed header values across sessions even when bait
signing is enabled, so the lab can still separate “session-minted polymorphism”
from “ordinary static bait” during evaluation.

The suspicious-promotion smoke proves the first M5 graduated-enforcement slice: one
authenticated advisory discovery request is promoted from `observe` to
`suspicious`, stays baited, is served from an Eidolon-owned docs surface, and
exports the advisory signals with a `preserve_eidolon_routing` edge
recommendation.

The aggregated recon smoke proves the first weaker `observe -> suspicious`
slice: a medium-score authenticated agentic discovery request stays in
`observe` on first contact, but after the session has shown query-bearing
discovery recon, a second same-session discovery request moves into
`suspicious` through multi-signal aggregation and serves the stronger owned
docs surface.

The adjacent blind-decoy-write smoke proves that the same weighted recon plane
can now use one non-discovery contributor too: after a medium-score
query-bearing docs request, a same-session unsafe probe to
`/api/v2/import/reconcile` without any expected bait header can move the
session into `suspicious`, while still preserving the important invariant that
no `bait_action_observed` evidence is recorded for that probe.

The adjacent decoy-write rate-limit smoke proves that this non-discovery
contributor also feeds the next rung up: after the blind probe has already
promoted the session to `suspicious`, one same-session top-level `/docs`
follow-up now reaches the weighted recon threshold for `rate_limited` without
requiring any exact bait-derived action.

The adjacent repeated-decoy-write smoke proves the next refinement of that same
non-discovery contributor: blind probes are now tracked as a small capped
count, so a second same-session unsafe probe raises the structured
`decoy_write_probe_score` from `2` to `3` without creating
`bait_action_observed`, and a later top-level `/docs` follow-up reaches
`rate_limited` at recon score `6` instead of `5`.

The adjacent decoy-write recon-blocked smoke proves that the same non-discovery
contributor carries one rung further too: after Eidolon has already throttled
that session once from weighted recon churn, repeating the same top-level
discovery retry now moves the session into `blocked` while still preserving the
important invariant that the blind probe created no `bait_action_observed`
evidence.

The advisory-assisted aggregated smoke proves the first
`observe -> suspicious` path: one query-bearing medium-score authenticated
discovery request carries detection IDs from the trusted edge adapter, reaches
the multi-signal threshold on first contact, and is served from the stronger
owned docs surface.

The adjacent detection-backed recon-blocked smoke proves that the same
advisory-assisted contributor carries through the next pre-containment rung
too: after one same-session top-level `/docs` follow-up has already moved the
session into `rate_limited`, a repeated `/docs` retry now moves it into
`blocked`, while edge export preserves the authenticated detection IDs plus the
structured `pre_containment_persistence_class=discovery_recon` and
`pre_containment_persistence_kind=discovery_recon_retry` fields.

An adjacent OpenAPI aggregation smoke proves the first target-side-only
aggregated `observe -> suspicious` path: one medium-score
`/openapi.json?eidolon_surface=legacy-import` request reaches the threshold on
first contact through the known legacy discovery query plus ordinary query
presence, and is served from the stronger owned OpenAPI surface without
depending on edge-provided detection IDs.

A companion linked-bait aggregation smoke proves the next target-side-only
aggregated `observe -> suspicious` path: one medium-score query-bearing
`/docs` discovery request stays in `observe`, but the same session's
follow-up probe into `/docs/legacy-import` reaches the threshold through the
earlier query-bearing recon plus the linked bait-surface request itself,
without depending on edge-provided detection IDs and without treating the
follow-up as a confirmed bait-derived action.

A hidden-route aggregation smoke proves the same path now works outside the
top-level `/docs` and `/openapi.json` prefixes: one medium-score query-bearing
`/docs` discovery request stays in `observe`, but the same session's follow-up
probe into `/customer/import-recovery-checklist` now reaches the threshold
through the earlier query-bearing recon plus the linked bait-surface request
itself.

A JS-helper aggregation smoke proves the same path for asset-linked discovery:
one medium-score query-bearing `/docs` discovery request stays in `observe`,
but the same session's follow-up probe into `/assets/import-helper.js` now
reaches the threshold through the earlier query-bearing recon plus the linked
helper asset request itself.

A linked-fanout aggregation smoke proves the next coarse target-side-only
recon path: one medium-score `/docs` discovery request without a query string
stays in `observe`, one same-session probe into `/docs/legacy-import` still
stays in `observe`, and the follow-up probe into `/assets/import-helper.js`
promotes only because the session has now churned across two linked bait
classes. That keeps the signal target-side and makes the recon plane less
dependent on query shape or edge-provided detections.

An adjacent OpenAPI-linked-fanout aggregation smoke proves the same coarse
path is not anchored to `/docs`: one medium-score `/openapi.json` discovery
request without a query string stays in `observe`, one same-session probe into
`/docs/legacy-import` still stays in `observe`, and the follow-up probe into
`/assets/import-helper.js` promotes only because the session has now churned
across two linked bait classes after starting from top-level OpenAPI
discovery.

An adjacent higher-threshold recon persistence smoke proves the first weighted
`suspicious -> rate_limited` use of that same score: one medium-score
`/openapi.json?eidolon_surface=legacy-import` request moves the session into
`suspicious`, and a same-session top-level `/docs` follow-up then hits
`rate_limited` once the weighted recon score reaches `5` from repeated
discovery plus the earlier query-bearing legacy OpenAPI signal.

An adjacent recon-blocked smoke proves the next persistence step: after that
same weighted recon path has already throttled the session once, repeating a
same-session top-level discovery request moves the session into `blocked`,
keeps the evidence target-side and structured, and exports the grouped
`pre_containment_persistence` plus `discovery_recon_retry` reason codes.

A dedicated OpenAPI suspicious smoke proves the next `#175` slice on
`/openapi.json`: one
authenticated advisory OpenAPI discovery request is promoted from `observe` to
`suspicious`, is served from an Eidolon-owned OpenAPI surface instead of a
rewritten upstream schema, and exports the same
`preserve_eidolon_routing` recommendation.

A separate fanout smoke proves the first session-recon promotion slice: one session
first requests `/docs` and then `/openapi.json`, gets promoted from `observe`
to `suspicious` on the second request because it fanned out across both
discovery surfaces, and is then served from the owned OpenAPI path with the
same `preserve_eidolon_routing` export recommendation.

The seventh smoke proves the first `suspicious -> rate_limited` slice: a session
that was promoted on the owned docs surface and then performs a wrong-header
same-bait near miss on `/api/v2/import/reconcile` is throttled with
`Retry-After`, preserves unmatched bait-action evidence, and exports the
`rate_limited` runtime decision.

The eighth smoke proves the same rate-limit path for the owned OpenAPI bait:
after a suspicious `/openapi.json` exposure, a wrong-value
`X-OpenAPI-Trace` request on the shared reconcile path is attributed to the
OpenAPI bait rather than the docs bait and is throttled the same way.

The ninth smoke proves the first `rate_limited -> blocked` slice: after one
same-bait wrong-header retry has already moved the session into
`rate_limited`, repeating that same near miss again moves the session into
`blocked`, preserves the second unmatched bait-action observation, and exports
the blocked Eidolon-owned decision. That export now groups the decision under
`pre_containment_persistence` with the detail code
`same_bait_near_miss_retry`.

The tenth smoke proves the first `rate_limited -> controlled_reality` slice:
after a same-bait near miss has already throttled the session once, a confirmed
same-session exact bait-derived action on `/api/v2/import/reconcile` moves the
session into `controlled_reality`, preserves the matched exposure evidence, and
exports the contained runtime decision.

The eleventh smoke proves the first `controlled_reality -> blocked` slice tied to
repeated reality-escape attempts: after a session has already entered
containment, requesting a path outside the configured controlled-reality branch
once records the escape signal, and repeating that same outside-branch probe
moves the session into `blocked` with the hard-fail preserved in edge export.
That export now groups the decision under
`post_containment_persistence` with the detail code
`controlled_reality_branch_escape`.

The twelfth smoke proves the adjacent post-containment depth-limit path: after a
session has already entered `controlled_reality`, continuing to probe the same
contained branch past the first throttle moves the session from
`controlled_reality` into `blocked`, preserving the depth-limit evidence and
the final Eidolon-owned hard fail in edge export. That export uses the same
`post_containment_persistence` family with the detail code
`controlled_reality_depth_limit`.

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

The status output now includes both the active `polymorphic-baits` matrix from
the live bait-profile ConfigMap and any active `trusted-soften-scopes` from the
mounted ingress-trust ConfigMap, so operators can see which default surfaces
are session-minted and which trusted identities are allowed to narrow bait
softening without manually opening either config file. When configured, those
trusted soften scopes now also surface their `source_cidrs`, so network-bound
allowlist narrowing is visible alongside path-bound narrowing.

Smoke-check the trusted-ingress transport-auth path:

```sh
examples/shield-lab/smoke-trusted-ingress-orbstack.sh
```

Smoke-check that an authenticated but expired explicit ingress identity no
longer softens bait:

```sh
examples/shield-lab/smoke-trusted-ingress-expired-claim-orbstack.sh
```

Smoke-check the local allowlist soften-scope path:

```sh
examples/shield-lab/smoke-trusted-ingress-scoped-softening-orbstack.sh
```

Smoke-check that the same trusted allowlisted session still gets contained once
runtime evidence becomes strong:

```sh
examples/shield-lab/smoke-trusted-ingress-contained-openapi-orbstack.sh
```

The default OrbStack deploy now also mounts a lab-local ingress-trust config at:

```text
examples/shield-lab/ingress-trust-configs/docs-crawler-soften-docs-only.json
```

That default entry trusts `X-Eidolon-Trusted-Actor: docs-crawler` for
`/docs` and `/openapi.json`, narrows bait softening to `/docs` only, and also
requires the direct peer to be inside OrbStack's NodePort gateway
`192.168.194.1/32`. The scoped smoke proves
that `/docs` is softened while `/openapi.json` stays baited for that same local
allowlist actor and loopback-bound source. The containment smoke then proves
that a session starting in that trusted softened path still enters controlled
reality on a later same-session exact OpenAPI bait action.

If you want to prove the negative side of the gate, redeploy with the checked-in
mismatched-source example and run the paired smoke:

```sh
EIDOLON_SHIELD_INGRESS_TRUST_CONFIG_PATH=examples/shield-lab/ingress-trust-configs/docs-crawler-soften-docs-mismatched-source.json \
  examples/shield-lab/deploy-orbstack.sh
examples/shield-lab/smoke-trusted-ingress-source-cidr-gate-orbstack.sh
```

That path proves the same trusted actor still receives the baited `/docs`
surface when the local allowlist source CIDR does not match the direct OrbStack
peer.

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

The exported bundle README now includes the active bait-profile id, the live
polymorphic bait matrix, and any active trusted-ingress soften scopes from
`cluster-status.json`, so offline review does not depend on access to the
running cluster.

Each bundle now also includes `edge-session-index.md`, a compact redacted
session index rendered from the enriched edge export path, including a minted
coverage column and latest mint-outcome column so operators can see how many
active session-minted baits each session actually touched and whether the most
recent minted bait-shaped action matched the same session or mismatched.

If you already know the session you want to review, the same bundle export can
also embed one redacted per-session edge summary rendered from the enriched edge
export path:

```sh
examples/shield-lab/export-orbstack-evidence.sh \
  --session 11111111-1111-4111-8111-111111111111 \
  /private/tmp/eidolon-shield-bundle
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
examples/shield-lab/export-edge-decisions-orbstack.sh --format json --top 10
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format json \
  --min-polymorphic-coverage 2
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format json \
  --latest-mint-outcome session_value_mismatch
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format json \
  --trusted-soften-label docs-crawler
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format json \
  --trusted-soften-path-softened false
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format ndjson \
  --webhook-url https://collector.example.test/eidolon
```

When the live bait-profile status is available, each exported decision now also
includes `deployment_context`, which carries the active bait-profile id, the
current polymorphic bait matrix, and any active trusted-ingress soften scopes
alongside the session-level evidence. That same context now also includes a
structured `polymorphic_bait_coverage` summary, so JSON consumers can see
observed-vs-active minted bait coverage without comparing the two lists
manually. When a request actually matched one of the local trusted soften
entries, the export now also carries a session-level
`trusted_ingress_soften_match` with the matched label/scope and whether the
current request path was inside the narrower soften subset. The export evidence
now also carries `trusted_ingress_soften_histories`, so later contained
sessions still show which trusted soften scopes were seen earlier in the same
session and whether they covered both softened and unsoftened paths. When
configured, the same deployment and session-level trusted soften context now
also includes `source_cidrs`, so operators can distinguish path-only
allowlisting from network-bound allowlisting in both live and offline review.
When
`evidence.latest_bait_header_value_mint` is present, the markdown summaries now
also show whether the latest minted bait-shaped action was a
`matched_session_value` or `session_value_mismatch`.

`--top <N>` ranks sessions by enforcement severity and recency first, so
operators can pull a compact high-signal slice before exporting a full bundle.
`--min-polymorphic-coverage <N>` narrows that set further to sessions that
observed at least `N` active session-minted bait surfaces. `--latest-mint-outcome
<matched_session_value|session_value_mismatch>` narrows the export to sessions
whose latest minted bait-shaped action either matched the same session or
mismatched, which is useful for replay triage. `--trusted-soften-label <label>`
narrows the export to sessions that actually matched one local trusted soften
scope, and `--trusted-soften-path-softened <true|false>` splits those sessions
into requests that were or were not inside that narrower bait-soften subset.
For post-containment review, `--trusted-soften-history-label <label>` and
`--trusted-soften-history-path-softened <true|false>` do the same thing against
the session-level trusted soften history, so contained sessions still show up
even when the final request itself is no longer trusted.

If you want the bundle-local `edge-session-index.md` to keep only sessions that
cross the same polymorphic threshold, set:

```sh
EIDOLON_SHIELD_EDGE_SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE=2 \
  examples/shield-lab/export-orbstack-evidence.sh /private/tmp/eidolon-shield-bundle
```

If you want the bundle-local `edge-session-index.md` to keep only sessions that
share one latest minted outcome, set:

```sh
EIDOLON_SHIELD_EDGE_SESSION_INDEX_LATEST_MINT_OUTCOME=session_value_mismatch \
  examples/shield-lab/export-orbstack-evidence.sh /private/tmp/eidolon-shield-bundle
```

If you want the bundle-local `edge-session-index.md` to keep only sessions that
matched one trusted soften label, or only requests that were still outside the
narrower soften subset, set:

```sh
EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_LABEL=docs-crawler \
  examples/shield-lab/export-orbstack-evidence.sh /private/tmp/eidolon-shield-bundle
EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED=false \
  examples/shield-lab/export-orbstack-evidence.sh /private/tmp/eidolon-shield-bundle
```

If you want the bundle-local `edge-session-index.md` to keep only sessions that
matched one trusted soften history label or saw one unsoftened request earlier
in the session, set:

```sh
EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_LABEL=docs-crawler \
  examples/shield-lab/export-orbstack-evidence.sh /private/tmp/eidolon-shield-bundle
EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED=false \
  examples/shield-lab/export-orbstack-evidence.sh /private/tmp/eidolon-shield-bundle
```

For a single-session operator summary that already combines session-level mint
evidence with the active deployment polymorphic matrix, trusted soften scopes,
matched trusted soften context, and a coverage summary, render markdown from
the same enriched export path:

```sh
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format markdown \
  --session 11111111-1111-4111-8111-111111111111
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
