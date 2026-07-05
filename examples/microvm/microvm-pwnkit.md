# MicroVM pwnkit Validation

This runbook defines the planned microVM-backed pwnkit path for Eidolon.

It is the successor to the current Kali VM wrapper when you want:

- faster reset between runs
- cleaner isolation per attempt
- immutable base images with disposable writable state
- simpler snapshot and rollback semantics

This is not implemented as a live guest runner yet. The current repo ships the
planning and collection scaffold only.

## Intended topology

```text
microVM guest -> host alias / explicit host IP -> OrbStack NodePort -> Eidolon / direct target
```

Supported target topologies:

- `microvm_to_orbstack_nodeport`
- `microvm_isolated_local`

Recorded evidence labels:

- `runner_environment = microvm`
- `network_topology = microvm_to_orbstack_nodeport` or `microvm_isolated_local`
- `hypervisor = firecracker`
- `guest_profile = microvm_min` or `microvm_kali_compat`

## Host / guest split

Host responsibilities:

- render a run plan
- launch one guest per sample run
- attach output storage
- collect serial logs and artifact hashes
- export host-side cluster evidence
- export host-side edge decisions
- destroy the guest after the run

Guest responsibilities:

- read one run plan
- execute one scanner workflow
- emit structured artifacts
- exit cleanly with a final status record

## Planned artifact layout

Top-level sample directory:

```text
sample-plan.json
pwnkit-stability-sample.json
run-1/
  agent-summary.json
  hypotheses.jsonl
  actions.jsonl
  guest-trace.jsonl
  heartbeat.jsonl
  exit-status.json
  stdout.log
  stderr.log
  serial-console.log
  vm-metadata.json
  tool-results/
```

## Dry run

Use the current scaffold to render the expected host/guest contract:

```sh
cd ~/Projects/eidolon
examples/microvm/run-pwnkit-microvm.sh 1 /tmp/eidolon-microvm-sample
examples/microvm/fake-guest-runner.sh /tmp/eidolon-microvm-sample/sample-plan.json
```

Inspect:

- `/tmp/eidolon-microvm-sample/sample-plan.json`
- `/tmp/eidolon-microvm-sample/pwnkit-stability-sample.json`
- `/tmp/eidolon-microvm-sample/run-1/serial-console.log`

## Collection

After a future guest run mirrors artifacts onto the host, collect them with:

```sh
examples/microvm/collect-microvm-sample.sh \
  --host-bundle-dir /tmp/eidolon-microvm-bundle \
  --edge-decisions /tmp/eidolon-microvm-edge-decisions.json \
  /tmp/eidolon-microvm-sample \
  /tmp/eidolon-microvm-sample-collected
```

The collector keeps the same host-side evidence-linking pattern as the current
Kali VM flow.

## Implementation phases

1. dry-run planner and collection scaffold
2. guest image build scripts and static run-plan contract
3. one disposable guest boot path
4. host-side serial and artifact capture
5. OrbStack NodePort validation lane
6. snapshot optimization

## Notes

- Keep sample directories outside the Eidolon repo.
- Do not mount the repo writable into future guests.
- Do not pass host credentials through the guest boundary.
- Keep host-side evidence export on the host, not inside the guest.
