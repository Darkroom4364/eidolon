# M3 pwnkit Sample Evidence

Lab-only evidence bundle packaged on 2026-05-31.

## Scope

- Boundary: owned loopback lab.
- Source sample directory: omitted from the committed bundle.
- pwnkit runner head(s): `fa3a3c6c34e0e50ddb7f40b86e58fb50ed95833f`.
- pwnkit package version(s): `0.12.0`.
- pwnkit pinned fixture id(s): `eidolon-m3-local-patched-2026-05-29`.
- evidence track(s): `local_patched_pwnkit`.
- runner environment(s): `host_mac`.
- Session control: pinned Eidolon session cookie when enabled by the sample runner.

## Contents

- `pwnkit-stability-sample.json`: sample-level aggregate from `examples/m3/collect-pwnkit-sample.sh`.
- `run-*/pwnkit-summary.redacted.json`: claim-focused redaction of each run summary.
- `run-*/agent-replay-trace-summary.json`: sanitized proxy-trace summary for each run.
- `SHA256SUMS`: checksums for committed evidence files.

## Redaction

This bundle intentionally omits raw artifacts:

- pwnkit SQLite databases
- pwnkit auth JSON files
- raw stdout and stderr logs
- full proxy JSONL event logs
- private Eidolon debug logs
- raw pwnkit agent error text
- raw requested-path arrays and tool evidence labels from pwnkit summaries

Redacted summaries preserve runner freshness metadata, runner environment and tool fingerprints, final-vs-DB finding reconciliation, shape-only finding diagnostics, no-signal diagnostics, claim-level booleans, correlated evidence counts, bait matrix counts, pinned-session metrics, proxy count summaries, and M3 notes.

## Result

- valid summaries: `1`
- claim levels: `controlled_reality_entered`: `1`
- direct findings: `0`
- Eidolon findings: `2`
- DB-saved findings direct/Eidolon: `0/2`
- proxy trace controlled-reality runs: `1`
- strict pwnkit controlled-reality runs: `1`
- strict controlled-reality runs without Eidolon findings: `0`
- evidence gaps: `none`
- `strict_stability.ready_for_stability_claim`: `false`

This remains Lab-only evidence. It does not claim production readiness, autonomous-attacker identity, or stability beyond this sample on the recorded pwnkit head.
