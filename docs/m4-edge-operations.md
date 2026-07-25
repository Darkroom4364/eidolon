# M4 Edge/CDN Integration Operations

This note defines what "M4 complete" means in this repo and how to operate the
current deployment path safely.

## Scope

M4 is complete only when all four of these are true:

1. Edge trust inputs are normalized and testable.
2. Eidolon edge decisions are exportable as concrete webhook/SIEM/WAF payloads.
3. OrbStack Kubernetes is a real deployment target, not a hypothetical one.
4. A Kali VM can validate the deployed shield against both the direct baseline
   and the defended edge path.

This note is the operational companion to:

- [trusted-ingress-signal-contract.md](./trusted-ingress-signal-contract.md)
- [examples/edge/cloudflare/README.md](../examples/edge/cloudflare/README.md)
- [examples/shield-lab/README.md](../examples/shield-lab/README.md)

## Current M4 Artifacts

### Inbound trust

Runtime support:

- normalized ingress identity headers
- authenticated request-audit capture of advisory ingress signal headers
- transport-auth gate for explicit edge-provided identity
- local trust config
- precedence merging between explicit and local trust
- scoped bait softening for stronger trusted identities

Relevant code:

- [crates/eidolon-proxy/src/session.rs](../crates/eidolon-proxy/src/session.rs)
- [crates/eidolon-proxy/src/ingress_identity.rs](../crates/eidolon-proxy/src/ingress_identity.rs)
- [crates/eidolon-proxy/src/main.rs](../crates/eidolon-proxy/src/main.rs)
- [examples/shield-lab/deploy-orbstack.sh](../examples/shield-lab/deploy-orbstack.sh)

### Edge adapters

Cloudflare examples:

- Worker adapter:
  [examples/edge/cloudflare/eidolon-ingress-worker.mjs](../examples/edge/cloudflare/eidolon-ingress-worker.mjs)
- Request-header Transform Rules payload:
  [examples/edge/cloudflare/eidolon-request-header-transform-rules.json](../examples/edge/cloudflare/eidolon-request-header-transform-rules.json)

### Outbound decisions

Contract and export path:

- edge export types:
  [crates/eidolon-core/src/lib.rs](../crates/eidolon-core/src/lib.rs)
- trace builder:
  [crates/eidolon-trace/src/report.rs](../crates/eidolon-trace/src/report.rs)
- file-based exporter:
  [crates/eidolon-trace/src/bin/eidolon-edge-export.rs](../crates/eidolon-trace/src/bin/eidolon-edge-export.rs)
- live OrbStack wrapper:
  [examples/shield-lab/export-edge-decisions-orbstack.sh](../examples/shield-lab/export-edge-decisions-orbstack.sh)

### Deployment target

OrbStack Kubernetes shield-lab:

- [examples/shield-lab/README.md](../examples/shield-lab/README.md)
- [examples/shield-lab/k8s/orbstack/kustomization.yaml](../examples/shield-lab/k8s/orbstack/kustomization.yaml)
- [examples/shield-lab/k8s/orbstack/shield-edge-service.yaml](../examples/shield-lab/k8s/orbstack/shield-edge-service.yaml)
- [examples/shield-lab/k8s/orbstack/target-edge-service.yaml](../examples/shield-lab/k8s/orbstack/target-edge-service.yaml)

### Kali validation path

- Kali scanner wrapper against OrbStack NodePorts:
  [examples/shield-lab/run-pwnkit-kali-vm.sh](../examples/shield-lab/run-pwnkit-kali-vm.sh)
- Kali validation runbook:
  [examples/shield-lab/kali-vm-pwnkit.md](../examples/shield-lab/kali-vm-pwnkit.md)

## OrbStack Deployment Contract

The OrbStack overlay exposes two NodePort services on the macOS host:

- shield edge: `http://127.0.0.1:31080`
- direct target edge: `http://127.0.0.1:31081`

Inside an OrbStack Kali VM, the default validation contract is:

- shield edge: `http://host.internal:31080`
- direct target edge: `http://host.internal:31081`

This is a distinct topology from the older M3 same-VM loopback path.

Important trust boundary:

- these NodePorts are deployment-validation ingress, not a trusted adapter hop
- explicit `X-Eidolon-Ingress-*` identity headers are ignored there unless the
  proxy is configured with the shared transport-auth secret
- the Cloudflare Worker or Transform Rules adapter is the intended trusted edge
  boundary for explicit ingress identity
- the OrbStack and kind deployments mount a cluster-local trusted-ingress
  Secret containing separate `transport-auth.txt` and `continuity-key.txt`
  files; the proxy receives the latter through
  `--ingress-continuity-key-file`

Session identity on this deployment:

- the shield proxy is one replica with a `Recreate` rollout strategy; upgrades
  deliberately stop the old pod before starting the new pod, so planned
  downtime is expected but not yet measured; the PVC-backed process-lifetime
  lease is the fail-closed second layer against writer overlap
- the shield proxy authenticates `eidolon_session` cookies (HMAC-SHA256 over a
  versioned key) and rejects unsigned, forged, or expired values with
  deterministic `session_resolved` audit outcomes
- the current manifests do not pass `--session-signing-key-file`, so the proxy
  runs with an ephemeral per-process key: a pod restart rejects all
  outstanding cookies and clears process-local Lab peer continuity, while the
  PVC-backed policy store and HMAC-minimized authenticated-ingress continuity
  records survive in `<policy-state-path>.continuity.json`; raw continuity
  identities and Lab peer keys are never written there; the sidecar is
  HMAC-authenticated and admits at most 64 new durable mappings per rolling
  60-second window
- a newly created trusted-ingress Secret initializes `continuity-key.txt` with
  the same bytes as `transport-auth.txt`, preserving compatibility with state
  created before the keys were separated
- when an existing Secret lacks `continuity-key.txt`, the deployment scripts
  add it from the existing base64 transport value without changing
  `transport-auth.txt`; an existing continuity key is never overwritten
- `continuity-key.txt` is backup-critical state and must be backed up and
  restored with the PVC; losing or replacing it makes persisted continuity
  records unverifiable
- the compatibility bootstrap means rotating transport auth does not remediate
  compromise of the old key bytes now retained as the continuity key
- if that sidecar is missing while prior state exists, unknown authenticated
  identities fail closed for a bounded migration quarantine; corrupt or
  continuity-key-mismatched sidecar state prevents startup
- planned `Recreate` transport-auth rotation preserves continuity when
  `continuity-key.txt` stays fixed; overlap-window automation,
  continuity-key rotation, and live lifecycle proof remain tracked by issue
  `#254`; old-key state is never trusted merely because its unverified
  timestamps appear expired
- for restart-stable cookies, mount a JSON key ring (same
  secret pattern as the transport-auth secret) and pass
  `--session-signing-key-file`; rotate by adding the new version as active and
  dropping retired versions after the 7-day cookie lifetime
- the explicit-cookie smoke scripts mint their session cookies from the live
  edge instead of generating raw UUIDs; cookie-jar smokes are unaffected

This continuity persistence slice does not complete issue `#254` or establish
production readiness. Graceful request draining and measured rollout downtime
remain release qualification work, as does live overlapping-pod lease proof on
the supported PVC profile.

Recorded labels:

- `runner_environment = kali_vm`
- `network_topology = kali_vm_to_orbstack_nodeport`

## Operational Edge Export

There are two export layers:

1. offline/session export:
   `eidolon-edge-export`
2. live OrbStack cluster export:
   `examples/shield-lab/export-edge-decisions-orbstack.sh`

The live wrapper reads the proxy's PVC-backed `events.jsonl`, derives the latest
`EidolonEdgeDecisionExport` snapshot per session, and can either:

- print JSON/NDJSON
- rank and trim to a top-N high-signal session slice
- render a single-session markdown summary from the enriched export
- write JSON to a file
- POST each decision to a webhook or SIEM collector

When `status-orbstack.sh --json` is available, the live wrapper also enriches
each export with deployment context, including the active polymorphic bait
matrix and any active trusted-ingress soften scopes from the mounted
ingress-trust config.

Example:

```sh
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format ndjson \
  --webhook-url https://collector.example.test/eidolon

examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format json \
  --top 10

examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format markdown \
  --session 11111111-1111-4111-8111-111111111111
```

This is the current concrete M4 answer to "webhook/SIEM/WAF export" in the
public repo. It is a session-snapshot poller, not yet a cursor-based event
stream.

For deployment-side stress variation, the OrbStack deploy script now accepts
`EIDOLON_SHIELD_BAIT_PROFILE_PATH`, refreshes a cluster-local bait-profile
ConfigMap, patches the proxy pod template with the selected profile digest, and
waits for rollout status. That lets operators rerun the same external `pwnkit`
validation path against different Shield-side bait semantics without modifying
the scanner itself or guessing whether the live proxy has picked up the new
profile yet.

## Kali Validation Path

Use this sequence:

1. On the macOS host, deploy or refresh the OrbStack shield-lab.
2. Confirm both NodePort services are reachable.
3. Inside the Kali VM, run the dedicated wrapper against `host.internal`.
4. On the host, export the live cluster evidence and edge decisions.

Minimal sequence:

Host:

```sh
examples/shield-lab/build-orbstack-images.sh
examples/shield-lab/deploy-orbstack.sh
examples/shield-lab/status-orbstack.sh
```

Kali VM:

```sh
cd ~/Projects/eidolon
examples/shield-lab/run-pwnkit-kali-vm.sh --preflight 1 /tmp/eidolon-m4-orbstack
examples/shield-lab/run-pwnkit-kali-vm.sh 1 /tmp/eidolon-m4-orbstack
```

Host:

```sh
examples/shield-lab/export-orbstack-evidence.sh /tmp/eidolon-m4-orbstack-bundle
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --output /tmp/eidolon-m4-orbstack-edge-decisions.json
examples/shield-lab/collect-kali-vm-sample.sh \
  --host-bundle-dir /tmp/eidolon-m4-orbstack-bundle \
  --edge-decisions /tmp/eidolon-m4-orbstack-edge-decisions.json \
  /tmp/eidolon-m4-orbstack \
  /tmp/eidolon-m4-orbstack-kali
```

## Operational Constraints

### SEO and verified crawlers

- Do not let generic bot score alone create high trust.
- Use verified or signed ingress identities to soften only configured discovery
  surfaces.
- When using local allowlists for verified crawlers or accessibility tooling,
  prefer per-entry soften scopes so one trusted actor can be limited to `/docs`
  without automatically softening `/openapi.json`.
- Keep `/docs` and `/openapi.json` softening scoped; do not globally exempt
  crawlers from containment.
- Preserve audit of every softened request.

### Accessibility tooling

- Accessibility probes and link checkers can resemble crawlers.
- Treat them like allowlisted or partner automation only when the operator can
  assert identity explicitly.
- Do not rely on `User-Agent` alone.

### Tor/VPN handling

- Tor/VPN status is risk context, not identity.
- Do not collapse Tor/VPN use directly into `signed_attested` or
  `edge_verified`.
- Prefer preserving the raw edge signal in export/webhook output and letting
  policy or SIEM correlation decide the next action.

### Analytics safety

- Do not emit raw request bodies, cookies, or query values into edge export.
- Do not feed bait markers into public analytics products.
- Use redacted bundle export for operator review and evidence packaging.

### WAF / CDN interference

- When Eidolon is already in controlled reality, the outbound recommendation
  should prefer `preserve_eidolon_routing`.
- Edge layers should avoid challenging or rewriting that session out from under
  Eidolon unless the operator explicitly wants the edge to take over.

## M4 Acceptance Criteria

M4 is complete when:

- Cloudflare Worker and Transform Rules examples exist and are tested.
- Trusted ingress contract is documented and matches runtime behavior.
- Eidolon edge decisions can be exported live from OrbStack state and sent to a
  webhook.
- OrbStack Kubernetes exposes both the shield edge and direct baseline path.
- Kali VM validation against OrbStack NodePorts is documented and scripted.
- SEO, accessibility, verified crawler, Tor/VPN, and analytics-safety
  constraints are documented in one operational note.
