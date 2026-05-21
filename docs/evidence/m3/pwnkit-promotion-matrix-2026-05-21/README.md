# M3 pwnkit Promotion Matrix Evidence

Lab-only evidence bundle packaged on 2026-05-21.

## Scope

- Boundary: owned loopback lab.
- Source matrix directory: `/private/tmp/eidolon-m3-pwnkit-promotion-matrix-20260521-185828`.
- Matrix variants: `2` total, `2` observed.

## Contents

- `bait-promotion-variants.json`: matrix manifest used for the run.
- `pwnkit-promotion-matrix.json`: redacted matrix-level aggregate.
- `variants/<variant-id>/`: redacted sample evidence bundle for each observed variant.
- `SHA256SUMS`: checksums for committed evidence files.

## Redaction

This bundle intentionally omits raw artifacts from every variant:

- pwnkit SQLite databases
- pwnkit auth JSON files
- raw stdout and stderr logs
- full proxy JSONL event logs
- private Eidolon debug logs
- raw requested-path arrays and tool evidence labels from pwnkit summaries

The matrix summary omits source sample directory paths and points observed variants at their redacted bundle directories.

## Result

- observation classes: `no_signal`: `2`
- differential-finding-ready variants: none
- stability-claim-ready variants: none

This remains Lab-only evidence. It does not claim production readiness, autonomous-attacker identity, or stability beyond the recorded pwnkit head(s).
