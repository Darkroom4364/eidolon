# MicroVM Harness

This directory is the dry-run scaffold for a future microVM-backed pwnkit
validation path.

It exists to lock the host/guest contract, artifact layout, and evidence-linking
shape before we commit to a specific microVM runtime such as Firecracker.

The current scaffold is intentionally limited:

- dry-run planning is implemented
- sample collection from a host-side mirrored artifact tree is implemented
- live microVM boot, snapshotting, and guest execution are not implemented yet

Use this directory when you want the scanner to run in an ephemeral guest while
keeping Eidolon deployment evidence and redacted export logic on the host.

## Files

- `run-pwnkit-microvm.sh`
  Host-side planner for one or more disposable microVM sample runs.
- `fake-guest-runner.sh`
  Host-side simulation shim that consumes the sample plan and emits the guest
  artifact skeleton without booting a real microVM.
- `collect-microvm-sample.sh`
  Host-side collector for a mirrored microVM sample tree.
- `microvm-pwnkit.md`
  Runbook for the planned microVM topology and artifact flow.
- `configs/`
  Contract metadata for the default run-plan template and guest profiles.

## Contract

Recorded evidence labels:

- `runner_environment = microvm`
- `network_topology = microvm_to_orbstack_nodeport` or `microvm_isolated_local`

Planned hypervisor labels:

- `hypervisor = firecracker`
- `guest_profile = microvm_min` or `microvm_kali_compat`

## Dry Run

```sh
cd ~/Projects/eidolon
examples/microvm/run-pwnkit-microvm.sh 1 /tmp/eidolon-microvm-sample
examples/microvm/fake-guest-runner.sh /tmp/eidolon-microvm-sample/sample-plan.json
```

This writes:

- `/tmp/eidolon-microvm-sample/sample-plan.json`
- `/tmp/eidolon-microvm-sample/pwnkit-stability-sample.json`
- `/tmp/eidolon-microvm-sample/run-1/private/`

## Collector

When a future guest run has already mirrored artifacts onto the host, collect
and link them like this:

```sh
examples/microvm/collect-microvm-sample.sh \
  --host-bundle-dir /tmp/eidolon-microvm-bundle \
  --edge-decisions /tmp/eidolon-microvm-edge-decisions.json \
  /tmp/eidolon-microvm-sample \
  /tmp/eidolon-microvm-sample-collected
```

The collector writes a manifest that links scanner-side hashes to the host-side
bundle and edge export by path and hash.
