# M3 pwnkit Sample Evidence

Lab-only evidence bundle packaged on 2026-05-21.

## Scope

- Boundary: owned loopback lab.
- Source sample directory: `/private/tmp/eidolon-m3-pwnkit-promotion-matrix-20260521-185828/openapi_promotion_probe`.
- pwnkit runner head(s): `4a8587f7321af622b58f7a57f21f9acd694dc10f`.
- pwnkit package version(s): `0.11.1`.
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
- raw requested-path arrays and tool evidence labels from pwnkit summaries

Redacted summaries preserve runner freshness metadata, finding counts, shape-only finding diagnostics, no-signal diagnostics, claim-level booleans, correlated evidence counts, bait matrix counts, pinned-session metrics, proxy count summaries, and M3 notes.

## Result

- valid summaries: `3`
- claim levels: `no_target_interaction`: `3`
- direct findings: `0/0/0`
- Eidolon findings: `0/0/0`
- `strict_stability.ready_for_stability_claim`: `unknown`

This remains Lab-only evidence. It does not claim production readiness, autonomous-attacker identity, or stability beyond this sample on the recorded pwnkit head.
