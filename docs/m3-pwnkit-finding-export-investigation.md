# M3 pwnkit Finding Export Investigation

This note explains two historical M3 report-promotion gaps and two
local-patched validations:

1. the historical May 28 upstream-current Kali VM sample, which persisted
   Eidolon-side findings in pwnkit's SQLite DB but emitted zero final JSON
   findings, and
2. the refreshed May 31 upstream-current Kali VM sample, which emits
   Eidolon final JSON findings in `2/3` runs but still leaves one strict
   controlled-reality run at zero final JSON findings despite a saved active DB
   finding, and
3. the June 1 local-patched Kali rerun, which validates the report/export fix
   by promoting every strict controlled-reality run into final JSON while
   filtering only an inactive false-positive row, and
4. the June 2 canonical local-patched Kali sample, which keeps direct findings
   quiet in `3/3` runs and emits positive differential Eidolon findings in
   `3/3` runs with no saved-vs-final mismatch.

This is a Lab-only evidence note. It does not change the M3 containment claim
or make a production-readiness claim.

## Scope

- historical zero-export evidence bundle:
  `docs/evidence/m3/pwnkit-stability-2026-05-28/`
- refreshed upstream-current evidence bundle:
  `docs/evidence/m3/pwnkit-stability-2026-05-31/`
- canonical local-patched evidence bundle:
  `docs/evidence/m3/pwnkit-local-patched-canonical-2026-06-02/`
- historical pwnkit head:
  `1a8d6aac37818df29ff2e37d065c5bbcfe9c063b`
- refreshed pwnkit head:
  `c64410873b828f19f48ca4f8b12a3fc8dfe53c58`
- canonical local-patched pwnkit head:
  `abd034b61042f14a0b9b3a2cf9b0dbfa5ef4f2b4`
- historical pwnkit fixture id: `pwnkit-local-kali-2026-05-28`
- refreshed pwnkit fixture id: none
- canonical local-patched fixture id:
  `eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02`
- runner environment: `kali_vm`
- topology: `same_vm_loopback`
- raw pwnkit DBs, raw JSON, stdout/stderr logs, auth material, proxy JSONL, and
  private debug logs remain omitted from committed evidence.

## Observed Gap

The committed sample reports:

- final JSON direct findings: `0`
- final JSON Eidolon findings: `0`
- direct DB-saved findings: `0`
- Eidolon DB-saved findings: `6`
- Eidolon DB-active findings: `3`
- `strict_stability.ready_for_stability_claim`: `true`

Every Eidolon run had the same finding reconciliation shape:

- `final_json_finding_count`: `0`
- `db_saved_finding_count`: `2`
- `db_active_finding_count`: `1`
- one active information-disclosure finding
- one suppressed false-positive security-misconfiguration finding

The discrepancy is therefore not a collector arithmetic error. The final JSON
artifact had no top-level `findings`, while the pwnkit DB had saved findings.

## Refreshed Upstream-Current Follow-Up

The committed May 31 sample reports:

- final JSON direct findings: `0`
- final JSON Eidolon findings: `4` total across `3` runs
- Eidolon DB-saved findings: `7`
- Eidolon DB-active findings: `5`
- `strict_stability.ready_for_stability_claim`: `true`

Run shape in the refreshed sample:

- run 1: strict controlled reality, `2` Eidolon final JSON findings,
  `3` saved DB findings, `2` active DB findings
- run 2: strict controlled reality, `0` Eidolon final JSON findings,
  `1` saved DB finding, `1` active DB finding
- run 3: strict controlled reality, `2` Eidolon final JSON findings,
  `3` saved DB findings, `2` active DB findings

So the current upstream-current gap is narrower than the May 28 case. It is no
longer "final JSON always empty." It is now "one strict controlled-reality run
still fails to promote an active saved Eidolon finding into final JSON."

## Canonical Local-Patched Closeout

The committed June 2 canonical local-patched sample reports:

- final JSON direct findings: `0`
- final JSON Eidolon findings: `5` total across `3` runs
- Eidolon DB-saved findings: `5`
- Eidolon DB-active findings: `5`
- `strict_stability.ready_for_stability_claim`: `true`
- `differential_findings.ready_for_differential_finding_claim`: `true`

Run shape in the canonical sample:

- run 1: strict controlled reality, `3` Eidolon final JSON findings,
  `3` saved DB findings, `3` active DB findings
- run 2: strict controlled reality, `1` Eidolon final JSON finding,
  `1` saved DB finding, `1` active DB finding
- run 3: strict controlled reality, `1` Eidolon final JSON finding,
  `1` saved DB finding, `1` active DB finding

So the active export gap is closed on the current canonical patched track. The
saved-vs-final mismatch is now `0`.

## Collector Behavior

`examples/m3/collect-pwnkit-codex.sh` intentionally treats final JSON and DB
findings as separate signals:

- final JSON count comes from top-level `pwnkit-*.json.findings | length`
- DB saved count comes from rows in the pwnkit SQLite `findings` table
- DB active count excludes rows whose status/triage status is suppressed,
  rejected, closed, or false-positive

`examples/m3/collect-pwnkit-sample.sh` aggregates those per-run fields, and
`examples/m3/package-pwnkit-sample.sh` redacts/projects them into committed
evidence. Neither script promotes DB rows into final JSON findings.

That separation is intentional: pwnkit's public/reporting output is final JSON,
while DB findings are diagnostic evidence that pwnkit saw and persisted a
signal.

## Historical Root Cause

The local pwnkit pipeline drops discovery-stage findings from final JSON.

The relevant pwnkit flow is:

1. The discovery agent can call `save_finding`.
2. pwnkit persists that finding to SQLite immediately.
3. `runNativeDiscovery()` returns discovery-stage `state.findings`.
4. The main `agenticScan` flow starts the attack stage.
5. After attack completes, the main flow assigns final candidates from
   `attackState.findings`, not `discoveryState.findings`.
6. The final report filters out `status == "false-positive"` findings.

In the May 28 sample:

- the discovery stage saved one active information-disclosure finding per run
- the first attack attempt early-stopped with zero findings
- the retry attack saved one localhost/backend-service finding per run
- pwnkit's `holding-it-wrong` triage gate marked that retry finding
  `false-positive` / `suppressed`
- final JSON was built from attack-stage findings only, then filtered out the
  suppressed retry finding
- the active discovery-stage finding remained in SQLite but was absent from
  final JSON

The raw pwnkit JSON also had `summary.totalFindings: 1` while `findings` was
empty. That is internally confusing but consistent with the above path: the
summary counted the attack-stage finding before final false-positive filtering,
while the final `findings` array excluded it.

## Interpretation For M3

The May 28 evidence still supports the stronger M3 containment/stability claim:

- direct runs stayed quiet
- pwnkit through Eidolon interacted with target surfaces
- pwnkit followed bait into a same-session action
- controlled reality was entered in all three strict pwnkit-correlated runs
- the three-run strict stability gate passed

It does not support a final-output differential-finding claim against current
upstream pwnkit, because current pwnkit did not emit the active Eidolon-side DB
findings in final JSON.

The best wording for the May 28 sample is:

> current pwnkit persisted active Eidolon-side findings in SQLite, but the
> final JSON report dropped discovery-stage findings before emission.

The best wording for the refreshed May 31 sample is:

> upstream-current pwnkit now promotes some Eidolon-side findings into final
> JSON, but one strict controlled-reality run still left an active saved DB
> finding unreported in the final JSON output.

The best wording for the June 2 canonical sample is:

> on the canonical local-patched research fixture, pwnkit now preserves active
> Eidolon-side findings into final JSON in every strict controlled-reality run,
> while direct findings remain quiet.

## Follow-Up Tracks

Keep two evidence tracks separate:

1. Upstream-current pwnkit evidence:
   - May 28 historical zero-export sample:
     `pwnkit-local-kali-2026-05-28`
   - May 31 refreshed sample:
     `docs/evidence/m3/pwnkit-stability-2026-05-31/`
   - containment/stability: supported
   - final JSON differential findings: partial in the May 31 sample, not
     universal

2. Local patched pwnkit evidence:
   label future runs with a distinct fixture id such as
   `pwnkit-local-patched-discovery-findings-2026-05-28`
   - expected to preserve discovery-stage or persisted active findings into
     final JSON if the pwnkit patch is correct
   - must be documented as a patched local pwnkit fixture, not upstream-current
     pwnkit behavior

The local patched validation now uses a pwnkit build that reloads persisted
active findings before report construction, then continues to omit only
false-positive/suppressed findings from final JSON.

## Local Patched Follow-Up

A three-run local patched sample was collected on 2026-05-30 and archived under
`docs/evidence/m3/pwnkit-local-patched-2026-05-30/`.

- pwnkit head: `fa3a3c6c34e0e50ddb7f40b86e58fb50ed95833f`
- pwnkit fixture id: `pwnkit-local-patched-discovery-findings-2026-05-30`
- evidence track: `local_patched_pwnkit`
- strict same-session controlled reality: `3/3`
- direct final JSON findings: `0`
- Eidolon final JSON findings: `6` total across `2/3` runs
- Eidolon DB-saved findings: `8` total

This supports the patch direction: active Eidolon-side findings can now survive
into final JSON. It does not make an upstream-current pwnkit claim, and it does
not close the full stability question because one run still entered controlled
reality with zero Eidolon final JSON findings.

A refreshed three-run local patched rerun was then collected on 2026-06-01 and
archived under
`docs/evidence/m3/pwnkit-local-patched-report-fix-2026-06-01/`.

- pwnkit head: `18c7b3b46f77f9860ed603006a64aed7f8c9475e`
- pwnkit fixture id: `eidolon-m3-local-patched-report-fix-2026-06-01`
- evidence track: `local_patched_pwnkit`
- strict same-session controlled reality: `3/3`
- direct final JSON findings: `0`
- Eidolon final JSON findings: `5` total across `3/3` runs (`1/2/2`)
- Eidolon DB-saved findings: `6` total
- Eidolon DB-active findings: `5` total

This validates the active-finding export fix on the local patched track. The
only remaining saved-to-final mismatch in that rerun is one row already marked
inactive with `status:false-positive`; it is expected filtering rather than a
lost active finding before final JSON emission.

A further canonical local-patched sample was then collected on 2026-06-02 and
archived under
`docs/evidence/m3/pwnkit-local-patched-canonical-2026-06-02/`.

- pwnkit head: `abd034b61042f14a0b9b3a2cf9b0dbfa5ef4f2b4`
- pwnkit fixture id: `eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02`
- evidence track: `local_patched_pwnkit`
- strict same-session controlled reality: `3/3`
- direct final JSON findings: `0`
- Eidolon final JSON findings: `5` total across `3/3` runs (`3/1/1`)
- Eidolon DB-saved findings: `5` total
- Eidolon DB-active findings: `5` total
- any DB-saved findings omitted from final JSON: `false`

This is the current canonical patched-track closeout. It shows that the export
gap and the malformed-body control-leg noise are both gone on the pinned
research fixture.

Follow-up collector diagnostics now expose the remaining run's saved-to-inactive
or saved-but-unexported shape without committing raw pwnkit DB contents. The
useful fields are:

- `finding_reconciliation.db_rejection_diagnostics.inactive_reason_counts`
- `finding_reconciliation.db_rejection_diagnostics.lifecycle_counts`
- `finding_reconciliation.db_rejection_diagnostics.reject_layer_counts`
- `finding_reconciliation.db_rejection_diagnostics.reject_reason_class_counts`

Those fields are shape-only buckets. They are designed to correlate pwnkit
status, triage, workflow, and false-positive reduction-layer signals for saved
findings that did not remain active, while omitting raw titles, descriptions,
evidence, triage notes, layer-verdict reasons, and PoC step text.
