# M3 Kali VM pwnkit Runbook

This runbook is for an owned Lab-only pwnkit sample where the demo target,
Eidolon proxy, and pwnkit runner all execute inside one Kali Linux VM. An
OrbStack Kali machine is a suitable host, but the harness does not create or
manage the VM.

For the M4 deployment validation path where Kali scans an OrbStack Kubernetes
shield over NodePorts, use
[`../shield-lab/kali-vm-pwnkit.md`](../shield-lab/kali-vm-pwnkit.md) instead.

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
- Use the Kali wrapper defaults of three attempts per sample run and an 1800s
  pwnkit scan-leg timeout unless you are intentionally collecting shorter
  diagnostics.

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

Keep the pwnkit checkout local to the VM. The wrapper defaults to
`PWNKIT_SOURCE_DIR=~/Projects/pwnkit` and invokes
`$PWNKIT_SOURCE_DIR/dist/pwnkit.js`; it does not use globally installed pwnkit
packages. Set `PWNKIT_SOURCE_DIR` only if the checkout lives elsewhere.

If the public upstream is no longer available, treat the local checkout as a
pinned fixture instead of claiming moving-main behavior. Use a short non-secret
fixture label, for example:

```sh
export EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private
```

Pinned fixtures must still be clean git checkouts with a recorded git head.
When validating a local pwnkit patch rather than upstream current behavior, set
the evidence track explicitly:

```sh
export EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit
```

The Kali wrapper fails closed if `local_patched_pwnkit` is set without a
fixture id, or if `upstream_current` is set while a fixture id is also present.

For the validated June 2 canonical local patched fixture, use the dedicated
wrapper instead of setting those variables by hand:

```sh
cd ~/Projects/eidolon

examples/m3/run-pwnkit-local-patched-kali-vm.sh \
  --preflight 3 /tmp/eidolon-m3-pwnkit-local-patched

examples/m3/run-pwnkit-local-patched-kali-vm.sh \
  3 /tmp/eidolon-m3-pwnkit-local-patched
```

That wrapper pins:

- `EIDOLON_M3_PWNKIT_FIXTURE_ID=eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02`
- `EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit`
- `EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD=abd034b61042f14a0b9b3a2cf9b0dbfa5ef4f2b4`

and fails closed unless `PWNKIT_SOURCE_DIR` is a clean checkout at that exact
head. If `PWNKIT_SOURCE_DIR` is unset and `~/Projects/pwnkit` is on a different
head, the wrapper will auto-discover a clean sibling worktree at the validated
local-patched head.

For upstream-current runs, use the symmetric wrapper:

```sh
cd ~/Projects/eidolon

examples/m3/run-pwnkit-upstream-current-kali-vm.sh \
  --preflight 3 /tmp/eidolon-m3-pwnkit-upstream-current

examples/m3/run-pwnkit-upstream-current-kali-vm.sh \
  3 /tmp/eidolon-m3-pwnkit-upstream-current
```

That wrapper pins:

- `EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current`
- `EIDOLON_M3_UPSTREAM_CURRENT_REF=origin/main`

and fails closed unless `PWNKIT_SOURCE_DIR` is a clean checkout whose `HEAD`
matches local `origin/main`, with `EIDOLON_M3_PWNKIT_FIXTURE_ID` unset. If
`PWNKIT_SOURCE_DIR` is unset and `~/Projects/pwnkit` is on a different head,
the wrapper will auto-discover a clean sibling worktree whose `HEAD` matches
local `origin/main`.

For ongoing parity or drift checks, use the parity wrapper:

```sh
cd ~/Projects/eidolon

examples/m3/run-pwnkit-parity-kali-vm.sh \
  --preflight 3 /tmp/eidolon-m3-pwnkit-parity

examples/m3/run-pwnkit-parity-kali-vm.sh \
  3 /tmp/eidolon-m3-pwnkit-parity
```

That wrapper runs both dedicated track wrappers back to back and writes:

- `/tmp/eidolon-m3-pwnkit-parity/upstream-current/pwnkit-stability-sample.json`
- `/tmp/eidolon-m3-pwnkit-parity/local-patched/pwnkit-stability-sample.json`
- `/tmp/eidolon-m3-pwnkit-parity/pwnkit-parity-summary.json`

If the two tracks live in separate explicit worktrees, set:

```sh
export EIDOLON_M3_PARITY_UPSTREAM_PWNKIT_SOURCE_DIR=/path/to/pwnkit-upstream
export EIDOLON_M3_PARITY_LOCAL_PATCHED_PWNKIT_SOURCE_DIR=/path/to/pwnkit-patched
```

before invoking the parity wrapper.

## Dry Run

```sh
cd ~/Projects/eidolon

EIDOLON_M3_KALI_VM_DRY_RUN=1 \
  examples/m3/run-pwnkit-kali-vm.sh 3 /tmp/eidolon-m3-pwnkit-kali-vm
```

Inspect `/tmp/eidolon-m3-pwnkit-kali-vm/sample-plan.txt`. It should include:

```text
runner_environment=kali_vm
network_topology=same_vm_loopback
```

## Preflight

After the dry run looks correct, validate local VM plumbing before starting a
full sample:

```sh
cd ~/Projects/eidolon

EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private \
EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
  examples/m3/run-pwnkit-kali-vm.sh --preflight 3 /tmp/eidolon-m3-pwnkit-kali-vm
```

Preflight writes only generated scopes and runner metadata under:

```text
/tmp/eidolon-m3-pwnkit-kali-vm/private/kali-vm-preflight/
```

It checks the Kali wrapper contract, loopback URLs, required local tools, pwnkit
entrypoint availability, generated scope files, and pwnkit source-checkout
freshness metadata. For archived/private local pwnkit, the fixture id lets a
clean pinned checkout pass without origin/main freshness. It does not start the
demo target, proxy, or pwnkit scans.

## Sample Run

```sh
cd ~/Projects/eidolon

EIDOLON_M3_PWNKIT_FIXTURE_ID=pwnkit-v0.12.0-private \
EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
  examples/m3/run-pwnkit-kali-vm.sh 3 /tmp/eidolon-m3-pwnkit-kali-vm
```

The Kali wrapper defaults to `EIDOLON_M3_PWNKIT_MAX_ATTEMPTS=3` and
`EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS=1800`. Those defaults are longer than the
host diagnostics runner because current pwnkit Codex scans in a Kali tool
environment regularly outlive the host quick-run budget.
The delegated pwnkit runner emits sanitized heartbeat lines while each scan leg
runs. Override `EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS` only when intentionally
collecting more or less verbose operator progress.

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
- `runner_pwnkit_fixture_ids` records the pinned fixture id when upstream
  origin/main freshness is not the evidence contract
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
