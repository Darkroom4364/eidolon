# M3 Kali VM pwnkit Runbook

This runbook is for an owned Lab-only pwnkit sample where the demo target,
Eidolon proxy, and pwnkit runner all execute inside one Kali Linux VM. An
OrbStack Kali machine is a suitable host, but the harness does not create or
manage the VM.

Use this path when the question is whether Eidolon still shapes current local
pwnkit behavior when pwnkit has access to a Linux/Kali tool environment. Use the
regular `run-pwnkit-sample.sh` path for host-mac diagnostics.

## Contract

- Run inside the Kali VM.
- Keep target and proxy on VM-local loopback.
- Use `EIDOLON_M3_RUNNER_ENVIRONMENT=kali_vm`.
- Use `EIDOLON_M3_NETWORK_TOPOLOGY=same_vm_loopback`.
- Keep sample artifacts outside the Eidolon checkout.
- Do not serve the sample artifact directory from the target.
- Do not pass Eidolon source paths, artifact paths, bait marker values, or prior
  M3 reports to pwnkit.
- Package and redact artifacts before moving them into the repo.

The wrapper enforces the environment labels, loopback URLs, positive run count,
and repo-external sample directory. It delegates execution to
`examples/m3/run-pwnkit-sample.sh`.

## VM Preparation

Inside the Kali VM:

```sh
cd ~/Projects/eidolon
cargo build -p eidolon-demo-target -p eidolon-proxy

cd ~/Projects/pwnkit
pnpm install
pnpm run build
```

Keep the pwnkit checkout local to the VM. If the public upstream is no longer
available, treat the local checkout as a pinned fixture and record the resulting
runner metadata instead of claiming moving-main behavior.

## Dry Run

```sh
cd ~/Projects/eidolon

EIDOLON_M3_KALI_VM_DRY_RUN=1 \
PWNKIT_NODE_ENTRY="$HOME/Projects/pwnkit/dist/pwnkit.js" \
  examples/m3/run-pwnkit-kali-vm.sh 3 /tmp/eidolon-m3-pwnkit-kali-vm
```

Inspect `/tmp/eidolon-m3-pwnkit-kali-vm/sample-plan.txt`. It should include:

```text
runner_environment=kali_vm
network_topology=same_vm_loopback
```

## Sample Run

```sh
cd ~/Projects/eidolon

PWNKIT_NODE_ENTRY="$HOME/Projects/pwnkit/dist/pwnkit.js" \
  examples/m3/run-pwnkit-kali-vm.sh 3 /tmp/eidolon-m3-pwnkit-kali-vm
```

The wrapper starts `eidolon-demo-target`, starts a fresh `eidolon-proxy` for
each run, runs direct and Eidolon pwnkit legs, collects per-run summaries, and
writes:

```text
/tmp/eidolon-m3-pwnkit-kali-vm/pwnkit-stability-sample.json
```

## Evidence Checks

Before packaging, verify the sample summary:

```sh
jq '.runner_environments,
    .runner_network_topologies,
    .tool_fingerprint_summary,
    .finding_reconciliation,
    .strict_stability' \
  /tmp/eidolon-m3-pwnkit-kali-vm/pwnkit-stability-sample.json
```

For VM-local evidence, expect:

- `runner_environments` includes only `kali_vm`
- `runner_network_topologies` includes only `same_vm_loopback`
- `tool_fingerprint_summary` records Kali tool availability without command
  paths
- `finding_reconciliation` distinguishes final JSON findings from DB-saved
  findings
- `strict_stability.ready_for_stability_claim` is interpreted only for repeated
  successful runs on the recorded pinned pwnkit fixture

## Packaging

Package inside the VM, then move only the packaged bundle back to the host or
commit workspace:

```sh
examples/m3/package-pwnkit-sample.sh \
  /tmp/eidolon-m3-pwnkit-kali-vm \
  /tmp/eidolon-m3-pwnkit-kali-vm-bundle
```

The bundle omits raw pwnkit DBs, auth files, stdout/stderr logs, full proxy
events, private debug logs, raw requested-path arrays, local command paths, and
scope-file paths.
