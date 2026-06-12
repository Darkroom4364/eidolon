# Kali VM pwnkit Validation Against OrbStack Shield

This runbook is the M4 deployment validation path.

Use it when the target and shield are deployed on the macOS host's OrbStack
Kubernetes cluster and the scanner runs inside a Kali VM.

This is not the older M3 same-VM loopback path. The topology here is:

```text
Kali VM -> host.internal -> OrbStack NodePort -> Eidolon / direct target
```

## Contract

- run the scanner inside the Kali VM
- run the shield and demo target in OrbStack Kubernetes on the macOS host
- use the dedicated wrapper:
  [run-pwnkit-kali-vm.sh](/Users/darkroom/Projects/eidolon/examples/shield-lab/run-pwnkit-kali-vm.sh)
- keep artifacts outside the Eidolon repo
- export cluster evidence from the host after the run

Recorded evidence labels:

- `runner_environment = kali_vm`
- `network_topology = kali_vm_to_orbstack_nodeport`

## Host Preparation

On macOS:

```sh
cd ~/Projects/eidolon
examples/shield-lab/build-orbstack-images.sh
examples/shield-lab/deploy-orbstack.sh
examples/shield-lab/status-orbstack.sh
examples/shield-lab/smoke-trusted-ingress-scoped-softening-orbstack.sh
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
examples/shield-lab/smoke-rate-limited-decoy-write-recon-blocked-orbstack.sh
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
examples/shield-lab/smoke-rate-limited-recon-blocked-orbstack.sh
examples/shield-lab/smoke-rate-limited-blocked-orbstack.sh
examples/shield-lab/smoke-rate-limited-controlled-reality-orbstack.sh
examples/shield-lab/smoke-controlled-reality-blocked-orbstack.sh
examples/shield-lab/smoke-controlled-reality-depth-limit-blocked-orbstack.sh
```

The service-token smoke now also proves that replaying a minted `X-Api-Key`
from one session into another does not correlate and falls back to upstream
behavior, with edge export marking the replay as `session_value_mismatch`.
The OpenAPI smoke now proves the same replay-resistance for minted
`X-OpenAPI-Trace` values.
The legacy-import smoke now proves the same replay-resistance for minted
`X-Migration-Trace` values.

The expected host URLs are:

- shield edge: `http://127.0.0.1:31080`
- direct target: `http://127.0.0.1:31081`

## Kali VM Preparation

Inside the Kali VM:

```sh
cd ~/Projects/eidolon
cd ~/Projects/pwnkit && pnpm run build
```

The wrapper defaults to these VM-visible URLs:

- shield edge: `http://host.internal:31080`
- direct target: `http://host.internal:31081`

Override them only if your OrbStack host alias or ports differ.

## Dry Run

```sh
cd ~/Projects/eidolon
EIDOLON_SHIELD_KALI_VM_DRY_RUN=1 \
examples/shield-lab/run-pwnkit-kali-vm.sh 1 /tmp/eidolon-m4-orbstack
```

Inspect `/tmp/eidolon-m4-orbstack/sample-plan.txt`.

## Preflight

```sh
cd ~/Projects/eidolon
examples/shield-lab/run-pwnkit-kali-vm.sh --preflight 1 /tmp/eidolon-m4-orbstack
```

This checks:

- Kali runner contract
- direct and shield URLs are reachable from the VM
- pwnkit runner plumbing and freshness metadata

## Sample Run

```sh
cd ~/Projects/eidolon
examples/shield-lab/run-pwnkit-kali-vm.sh 1 /tmp/eidolon-m4-orbstack
```

This writes:

- `/tmp/eidolon-m4-orbstack/run-1/pwnkit-summary.json`
- `/tmp/eidolon-m4-orbstack/pwnkit-stability-sample.json`

To stress the same `pwnkit` runner against different Shield-side bait
semantics, redeploy the host-side shield with a different bait profile before
running the Kali sample:

```sh
EIDOLON_SHIELD_BAIT_PROFILE_PATH=examples/m3/bait-profiles/openapi-promotion-probe.json \
examples/shield-lab/deploy-orbstack.sh
```

That deploy step waits for the proxy rollout tied to the new profile digest.
Then rerun the same Kali wrapper and compare the host-side evidence bundle,
edge-decision export, and redacted `pwnkit` summaries across profiles.

## Host-Side Evidence Export

After the Kali run finishes, export host-side cluster evidence and then copy
the scanner-side sample onto the host with linked hashes:

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

Those artifacts stay linked through the collector manifest:

- `/tmp/eidolon-m4-orbstack-kali` is the scanner-side half
- `/tmp/eidolon-m4-orbstack-bundle` and
  `/tmp/eidolon-m4-orbstack-edge-decisions.json` are the deployment-side half
- `/tmp/eidolon-m4-orbstack-kali/README.md` records the scanner-side hashes and
  links them to the host bundle and edge decisions export by hash

The host bundle README now also carries the active polymorphic bait matrix from
the live `cluster-status.json`, so profile-level session-minted surfaces remain
visible after the cluster run is over.

Every host bundle now also includes `edge-session-index.md`, which gives a
compact redacted map of the exported sessions before you open a deeper
per-session summary, including a quick minted-coverage column for each
exported session.

If you want the host bundle itself to carry one ready-made redacted session
summary, add the session at export time:

```sh
examples/shield-lab/export-orbstack-evidence.sh \
  --session 11111111-1111-4111-8111-111111111111 \
  /tmp/eidolon-m4-orbstack-bundle
```

If you need one deployment-side session summary without cross-referencing the
bundle README and edge JSON separately, render the enriched edge export as
markdown for that session. The summary now includes observed-vs-active
session-minted bait coverage in addition to the raw mint audit list:

```sh
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format markdown \
  --session 11111111-1111-4111-8111-111111111111
```

For a quick ranked cut of the noisiest deployment-side sessions before you
build a bundle, use:

```sh
examples/shield-lab/export-edge-decisions-orbstack.sh \
  --format json \
  --min-polymorphic-coverage 2
examples/shield-lab/export-edge-decisions-orbstack.sh --format json --top 10
```

## Notes

- This wrapper does not start or stop cluster workloads.
- It does not pull raw proxy events into the VM artifacts.
- Use the host export scripts for redacted PVC-backed evidence and edge
  decisions.
