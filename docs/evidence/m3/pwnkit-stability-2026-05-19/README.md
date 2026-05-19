# M3 pwnkit Stability Evidence

Lab-only evidence bundle for the M3 current-pwnkit stability sample collected on
2026-05-19.

## Scope

- Boundary: owned loopback lab.
- Eidolon branch under test: post-merge `main` after PR #95.
- pwnkit upstream head: `5f5fdcf82fb4b352764f5d07ab7ababc5faf4b10`.
- Runtime: pwnkit `--runtime codex`.
- Auth path: current Codex access token supplied through the local environment.
- Session control: only the Eidolon scan leg received a generated
  `eidolon_session` cookie.

## Contents

- `pwnkit-stability-sample.json`: sample-level aggregate from
  `examples/m3/collect-pwnkit-sample.sh`.
- `run-*/pwnkit-summary.redacted.json`: claim-focused redaction of each
  `examples/m3/collect-pwnkit-codex.sh` summary.
- `run-*/agent-replay-trace-summary.json`: proxy-trace summary for each run.
- `SHA256SUMS`: checksums for the committed evidence files.

The source artifact directories were:

- `/private/tmp/eidolon-m3-stability-pwnkit-1.did5hJ`
- `/private/tmp/eidolon-m3-stability-pwnkit-2.cnWqi3`
- `/private/tmp/eidolon-m3-stability-pwnkit-3.Q0HFMX`

## Redaction

This bundle intentionally omits raw artifacts:

- pwnkit SQLite databases
- pwnkit auth JSON files
- raw stdout and stderr logs
- full proxy JSONL event logs
- raw requested-path arrays and tool evidence labels from pwnkit summaries

The redacted pwnkit summaries preserve runner metadata, finding counts,
claim-level booleans, correlated evidence counts, bait matrix counts, pinned
session metrics, proxy count summaries, and M3 notes. Raw path arrays were not
committed because they can contain synthetic secret-shaped query values from the
lab target.

## Result

The sample passed the minimum repeated-run stability gate:

- valid summaries: `3`
- `controlled_reality_entered`: `3/3`
- same-session confirmed bait action: `3/3`
- direct findings: `0/0/0`
- pinned cookie preserved: `3/3`
- `strict_stability.ready_for_stability_claim`: `true`

This remains lab-only evidence. It does not claim production readiness,
autonomous-attacker identity, or stability beyond this three-run sample on the
recorded pwnkit head.
