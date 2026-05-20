# M3 pwnkit Differential Findings Investigation

This note defines the next M3 investigation after the archived current-pwnkit
stability sample. The open question is narrow:

```text
Why did current pwnkit reach bait, replay the open_api action, preserve the
Eidolon session, and enter controlled reality, while still reporting 0 Eidolon
findings versus 0 direct-target findings?
```

## Scope

Use this only for owned loopback Lab runs against the demo target and Eidolon
proxy. It is not a production-readiness, autonomous-attacker-attribution, or
offensive benchmark claim.

## Pre-Run Checklist

Before collecting a new sample:

1. Sync pwnkit to upstream main and rebuild its dist bundle.
2. Confirm `examples/m3/pwnkit-codex.sh` records the pwnkit git head in
   `pwnkit-runner-metadata.json`.
3. Run direct and Eidolon legs with generated pwnkit scope files.
4. Use `EIDOLON_M3_PIN_SESSION=1` for the Eidolon leg when testing same-session
   replay.
5. Keep the proxy event log, policy state, and intervention control files inside
   the same artifact directory.

## Collector Diagnostics

`examples/m3/collect-pwnkit-codex.sh` emits finding diagnostics under each run:

- `runs.<leg>.finding_count`
- `runs.<leg>.finding_diagnostics.severity_counts`
- `runs.<leg>.finding_diagnostics.category_counts`
- `runs.<leg>.finding_diagnostics.confidence_counts`
- `runs.<leg>.finding_diagnostics.field_presence`
- `runs.<leg>.finding_diagnostics.evidence_presence`
- `runs.<leg>.target_evidence_diagnostics`

These fields are intentionally shape-only. They preserve counts, coarse labels,
and field presence, but omit finding titles, descriptions, raw evidence, request
bodies, raw URLs, and analysis text.

The comparison-level field `comparison.finding_gap` is the main diagnostic:

- `positive_differential_findings`: Eidolon findings exceed direct findings.
- `eidolon_observed_target_evidence_without_findings`: pwnkit emitted target
  evidence but no Eidolon findings.
- `eidolon_bait_reached_without_findings`: pwnkit reached an owned bait surface
  but emitted no Eidolon findings.
- `eidolon_bait_action_without_findings`: pwnkit replayed a bait-shaped action
  but emitted no Eidolon findings.
- `eidolon_controlled_reality_without_findings`: pwnkit reached controlled
  reality but emitted no Eidolon findings.
- `next_question`: the next classification question for that run.

`examples/m3/collect-pwnkit-sample.sh` aggregates those signals under:

- `counts.positive_differential_findings`
- `counts.bait_reached_without_eidolon_findings`
- `counts.bait_action_without_eidolon_findings`
- `counts.controlled_reality_without_eidolon_findings`
- `differential_findings`

## Interpretation

Use the diagnostics to classify the gap before changing bait text or behavior:

- If `positive_differential_findings` is true, archive the sample and inspect
  which coarse finding categories changed.
- If `eidolon_controlled_reality_without_findings` is true, pwnkit consumed and
  acted on controlled evidence but did not promote that chain to a finding.
- If `eidolon_bait_action_without_findings` is true, focus on whether the action
  response looks too operationally benign for pwnkit to report.
- If `eidolon_bait_reached_without_findings` is true, focus on bait semantics:
  the surface was discoverable, but not finding-shaped enough.
- If only target interaction is observed, focus on route discovery and bait
  placement before tuning finding language.

Do not use raw pwnkit DBs, auth JSON, stdout/stderr logs, raw query values, or
request bodies in committed evidence bundles. Archive only redacted summaries
and checksums.
