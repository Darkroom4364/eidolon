# M3 pwnkit Sample Evidence

Lab-only evidence bundle packaged on 2026-05-26.

## Scope

- Boundary: owned loopback lab.
- Source sample directory: omitted from the committed bundle.
- pwnkit runner head(s): `1a8d6aac37818df29ff2e37d065c5bbcfe9c063b`.
- pwnkit package version(s): `0.12.0`.
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

Redacted summaries preserve runner freshness metadata, finding counts, shape-only finding diagnostics, no-signal diagnostics, claim-level booleans, correlated evidence counts, bait matrix counts, pinned-session metrics, proxy count summaries, and M3 notes.

## Result

- valid summaries: `3`
- claim levels: `bait_action_observed_without_same_session`: `1`, `controlled_reality_entered`: `2`
- direct findings: `0/0/0`
- Eidolon findings: `2/0/0`
- `strict_stability.ready_for_stability_claim`: `false`

This remains Lab-only evidence. It does not claim production readiness, autonomous-attacker identity, or stability beyond this sample on the recorded pwnkit head.
