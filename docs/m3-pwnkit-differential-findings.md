# M3 pwnkit Differential Findings Investigation

This note defines the next M3 investigation after the archived current-pwnkit
stability sample. The open question is narrow:

```text
Why does upstream-current pwnkit now reach bait, replay the open_api action,
preserve the Eidolon session, and enter controlled reality in every strict run,
while still promoting Eidolon final JSON findings in only 2 of 3 runs?
```

## Scope

Use this only for owned loopback Lab runs against the demo target and Eidolon
proxy. It is not a production-readiness, autonomous-attacker-attribution, or
offensive benchmark claim.

## Current pwnkit Drift Note

The archived stability sample used pwnkit head
`5f5fdcf82fb4b352764f5d07ab7ababc5faf4b10`. A local review of pwnkit main on
2026-05-20 found head `4a8587f7321af622b58f7a57f21f9acd694dc10f` /
`v0.11.1`, with live-scan prompt changes that move web scans away from flag
extraction and toward real audit evidence. Treat that as a behavior-relevant
drift: rerun before tuning bait semantics or making new current-pwnkit
finding-gap claims.

A follow-up promotion matrix was collected on 2026-05-21 against pwnkit head
`4a8587f7321af622b58f7a57f21f9acd694dc10f` / `v0.11.1` and archived under
`docs/evidence/m3/pwnkit-promotion-matrix-2026-05-21`. Both matrix variants
classified as `no_signal`: direct and Eidolon legs were quiet, pwnkit emitted
zero request/tool artifacts, and Eidolon saw only uncorrelated proxy requests
for `/health`, `/readme.html`, `/wp-includes/version.php`, and
`/wp-login.php`. Treat the active open question as runner/current-pwnkit signal
loss before tuning bait semantics. A post-archive inspection of the pwnkit
SQLite events also found sanitized `agent_error` evidence consistent with a
Codex token-refresh failure, so a rerun must first clear pwnkit agent runtime
errors:

```text
Can current pwnkit produce an agent-error-free run with persisted request
artifacts, and only then does it still fail to correlate through Eidolon?
```

A post-auth rerun against synced pwnkit `v0.12.0` / head
`53f64d479d6c3b256a99f9adb2ae22896ea4c3cc` moved past the refresh-token
failure: the runner loaded a fresh Codex access token, pwnkit persisted request
artifacts, replayed the OpenAPI bait action in the same Eidolon session, and
entered controlled reality. The strict sample was still not archive-ready
because pwnkit emitted an `agent_error` consistent with a transient Codex
backend error, such as a timeout or transport/API failure.
Treat the active open question as:

```text
Can current pwnkit produce an agent-error-free v0.12.x run with the same
controlled-reality chain, and if so, why is that chain still not promoted to a
pwnkit finding?
```

A follow-up one-run diagnostic after adding browser hardening headers to the
benign demo target answered the first half for pwnkit `v0.12.0` /
`53f64d479d6c3b256a99f9adb2ae22896ea4c3cc`: the direct leg returned to
0 findings, both legs were agent-error-free, the Eidolon leg preserved the
pinned session, and the correlated chain still reached controlled reality with
0 Eidolon findings. Treat this as a local diagnostic, not archived evidence.

A fresh 3-run strict sample was archived on 2026-05-26 against synced pwnkit
`v0.12.0` / head `1a8d6aac37818df29ff2e37d065c5bbcfe9c063b` under
`docs/evidence/m3/pwnkit-stability-2026-05-26`. It was agent-error-free,
kept direct target findings quiet in all runs, reached bait and replayed a
bait-shaped action in all runs, preserved the pinned session in all runs, and
produced positive differential Eidolon findings in one run. The strict
same-session/controlled-reality chain held in two of three pwnkit-correlated
runs, while same-run proxy traces reached controlled reality in all three.
Treat the active open question as:

```text
Why does current pwnkit promote Eidolon evidence to findings in only one run,
and why does one run lose strict same-session confirmation despite proxy-trace
containment?
```

A local patched pwnkit fixture was collected on 2026-05-30 at head
`fa3a3c6c34e0e50ddb7f40b86e58fb50ed95833f` and archived under
`docs/evidence/m3/pwnkit-local-patched-2026-05-30`. The patch preserves
discovery-stage findings into final JSON. In that sample direct final JSON
findings stayed quiet in `3/3` runs, strict same-session controlled reality held
in `3/3` runs, and Eidolon final JSON findings appeared in `2/3` runs. Treat
that as `local_patched_pwnkit` evidence only; it confirms the export-gap patch
direction but does not make an upstream-current pwnkit claim.

A follow-up local patched promotion matrix was collected on 2026-05-31 at the
same head and archived under
`docs/evidence/m3/pwnkit-local-patched-promotion-matrix-2026-05-31`. The
matrix stayed agent-error-free, direct legs stayed quiet in both variants, both
variants preserved the pinned session and reached same-session controlled
reality, and both `default_m3_catalog` and `openapi_promotion_probe`
classified as `promoted_finding`. The matrix is interpretation-ready for the
`local_patched_pwnkit` track because every observed runner was clean, pinned to
fixture id `eidolon-m3-local-patched-2026-05-29`, and recorded
`source_checkout.runner_source_claim_safe: true` even though `origin/main`
remained intentionally out of sync. Treat this as a local-patched confirmation
that the export-gap patch is sufficient for both the baseline and the probe
catalog shapes; it is still not an upstream-current claim.

A refreshed 3-run upstream-current Kali sample was collected on 2026-05-31
against synced pwnkit `v0.12.0` / head
`c64410873b828f19f48ca4f8b12a3fc8dfe53c58` and archived under
`docs/evidence/m3/pwnkit-stability-2026-05-31`. It used `gpt-5.4`, stayed
agent-error-free, kept direct findings quiet in `3/3` runs, preserved the
pinned session in `3/3` runs, reached same-session confirmed bait action in
`3/3` runs, and entered strict pwnkit-correlated controlled reality in `3/3`
runs. Two runs emitted positive differential Eidolon final JSON findings, while
one strict controlled-reality run still emitted zero Eidolon final JSON
findings despite a saved active DB finding. One of the positive runs required a
later same-session request artifact to preserve the strict action attribution,
and the collector now records that as
`correlation_basis=request_after_action_same_session`. Treat the active open
question as:

```text
Why does upstream-current pwnkit still leave one strict controlled-reality run
at 0 final Eidolon findings after the containment-correlation gap is closed?
```

## Pre-Run Checklist

Before collecting a new sample:

1. Sync the local pwnkit source checkout and rebuild its dist bundle. The
   runners default to `PWNKIT_SOURCE_DIR=~/Projects/pwnkit` and execute
   `$PWNKIT_SOURCE_DIR/dist/pwnkit.js`, not a globally installed package.
2. Confirm `examples/m3/pwnkit-codex.sh` records the pwnkit git head in
   `pwnkit-runner-metadata.json`.
3. Keep `EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE=0` so
   `run-pwnkit-sample.sh` preflights pwnkit source-checkout freshness before
   starting the Lab target. Use `EIDOLON_M3_PWNKIT_FIXTURE_ID` only for a clean,
   archived/private pinned pwnkit fixture; use
   `EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE=1` only for diagnostic artifact
   preservation.
4. Confirm `runner.pwnkit.origin_main.in_sync` is `true` and
   `runner.pwnkit.git_dirty` is `false` in the collected summary before making
   current-pwnkit claims.
5. For VM-local Kali fixture runs, follow
   [`../examples/m3/kali-vm-pwnkit.md`](../examples/m3/kali-vm-pwnkit.md) and
   run `examples/m3/run-pwnkit-kali-vm.sh` from inside the VM so the evidence is
   labeled `kali_vm` / `same_vm_loopback`.
6. Run direct and Eidolon legs with generated pwnkit scope files.
7. Use `EIDOLON_M3_PIN_SESSION=1` for the Eidolon leg when testing same-session
   replay.
8. Keep `EIDOLON_M3_ALLOW_AGENT_ERRORS=0` for evidence collection so the sample
   runner fails after any pwnkit `agent_error` event in the promoted artifacts.
   The sample runner retries transient Codex backend-error attempts, including
   timeouts and transport/API failures, up to
   `EIDOLON_M3_PWNKIT_MAX_ATTEMPTS` with a fresh per-run proxy directory and
   archives failed attempts under `private/`. Do not retry the stateful Eidolon
   leg in-place because proxy policy state and event logs are part of the
   evidence. Use `EIDOLON_M3_ALLOW_AGENT_ERRORS=1` only for diagnostic
   no-signal preservation.
9. Keep the proxy event log, policy state, and intervention control files inside
   the same artifact directory.

For the standard repeated-run path, use:

```sh
examples/m3/run-pwnkit-sample.sh 3 /tmp/eidolon-m3-pwnkit-sample
```

The wrapper creates one artifact directory per run, keeps each proxy debug log
under `run-*/private/eidolon-debug.jsonl`, and writes the aggregate to
`pwnkit-stability-sample.json`.

When archiving a completed sample, use the evidence packager:

```sh
examples/m3/package-pwnkit-sample.sh \
  /tmp/eidolon-m3-pwnkit-sample \
  docs/evidence/m3/pwnkit-sample-YYYY-MM-DD
```

Review the generated README and redacted JSON before committing the bundle.
Committed bundles must not contain local source artifact directories, pwnkit
runner command paths, generated scope-file paths, raw pwnkit artifacts, or
private debug logs.

For the promotion investigation, run the seed bait-profile matrix after the
standard sample path is healthy:

```sh
EIDOLON_M3_PROMOTION_RUNS=3 \
  examples/m3/run-pwnkit-promotion-matrix.sh \
  examples/m3/bait-promotion-variants.json \
  /tmp/eidolon-m3-pwnkit-promotion-matrix
```

The matrix wrapper keeps the same direct/Eidolon runner shape and varies only
the optional lab-only bait profile declared by each manifest row. It writes
`pwnkit-promotion-matrix.json`, whose per-variant `observation_class` separates
actual `promoted_finding` runs from `behavior_only` controlled-reality runs and
lower-signal discovery/action outcomes.

When archiving a completed matrix, use the matrix evidence packager:

```sh
examples/m3/package-pwnkit-promotion-matrix.sh \
  /tmp/eidolon-m3-pwnkit-promotion-matrix \
  docs/evidence/m3/pwnkit-promotion-matrix-YYYY-MM-DD
```

Review the generated README, redacted matrix summary, per-variant redacted
sample bundles, and checksums before committing the bundle.

## Collector Diagnostics

`examples/m3/collect-pwnkit-codex.sh` emits finding diagnostics under each run:

- `runs.<leg>.finding_count`
- `runs.<leg>.finding_diagnostics.severity_counts`
- `runs.<leg>.finding_diagnostics.category_counts`
- `runs.<leg>.finding_diagnostics.confidence_counts`
- `runs.<leg>.finding_diagnostics.field_presence`
- `runs.<leg>.finding_diagnostics.evidence_presence`
- `runs.<leg>.target_evidence_diagnostics`
- `runs.<leg>.agent_error_diagnostics`
- `comparison.target_correlation_diagnostics`

These fields are intentionally shape-only. They preserve counts, coarse labels,
and field presence, but omit finding titles, descriptions, raw evidence, request
bodies, raw URLs, analysis text, and raw pwnkit agent error text.

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

`comparison.strict_correlation_gap` is the companion diagnostic for samples
where proxy trace containment is stronger than the strict pwnkit-correlated
claim. `matching_proxy_exposure_not_pwnkit_correlated` means the proxy saw a
matching prior exposure for the action, but pwnkit did not persist request
evidence that correlated to that exposure surface.

`examples/m3/collect-pwnkit-sample.sh` aggregates those signals under:

- `counts.positive_differential_findings`
- `counts.bait_reached_without_eidolon_findings`
- `counts.bait_action_without_eidolon_findings`
- `counts.controlled_reality_without_eidolon_findings`
- `no_signal_diagnostics`
- `differential_findings`
- `finding_reconciliation`
- `evidence_gap_diagnostics`
- `evidence_tracks` and `evidence_track_counts`
- per-run `artifacts[].trace_gap`
- per-run `artifacts[].strict_correlation_gap`

The sample health check fails closed if a sample mixes `upstream_current`,
`local_patched_pwnkit`, and `historical_stale` tracks, or if a positive
differential-finding claim is present without final JSON finding support.
DB-saved finding deltas remain diagnostics under `finding_reconciliation`; they
do not by themselves support a final-output pwnkit finding claim.
For `local_patched_pwnkit` samples, the collector treats a clean runner pinned
to an explicit fixture id as source-claim-safe even though `origin/main` is
expected to be out of sync.

`examples/m3/collect-pwnkit-promotion-matrix.sh` wraps those sample-level
signals per manifest variant and adds:

- `observation_class`
- `observation_class_counts`
- `no_signal_diagnostics`
- `ready_for_differential_finding_claim_variants`
- `ready_for_stability_claim_variants`

The matrix-level `ready_for_matrix_interpretation` gate follows the same
source-claim-safety rule: `upstream_current` matrices must stay clean and synced
to local `origin/main`, while `local_patched_pwnkit` matrices may still be
interpretation-ready when every observed sample is clean, pinned to an explicit
fixture id, and records `source_checkout.runner_source_claim_safe: true`.

## Interpretation

Use the diagnostics to classify the gap before changing bait text or behavior:

- If `positive_differential_findings` is true, archive the sample and inspect
  which coarse finding categories changed.
- If `evidence_gap_diagnostics.observed_gaps` includes
  `proxy_trace_controlled_reality_without_strict_pwnkit_correlation`, focus on
  whether pwnkit request artifacts preserved the exposure session, bait ID, and
  exposure ID required for the stricter comparison claim.
- If `strict_correlation_gap.likely_cause` is
  `matching_proxy_exposure_not_pwnkit_correlated`, inspect whether pwnkit reached
  the exposure surface through tooling whose output was not persisted as an HTTP
  request artifact.
- If `eidolon_controlled_reality_without_findings` is true, pwnkit consumed and
  acted on controlled evidence but did not promote that chain to a finding.
- If `eidolon_bait_action_without_findings` is true, focus on whether the action
  response looks too operationally benign for pwnkit to report.
- If `eidolon_bait_reached_without_findings` is true, focus on bait semantics:
  the surface was discoverable, but not finding-shaped enough.
- If only target interaction is observed, focus on route discovery and bait
  placement before tuning finding language.
- If `observation_class` is `no_signal`, inspect
  `no_signal_diagnostics.likely_cause` before changing bait content.
  `pwnkit_codex_token_refresh_failure_prevented_request_artifacts` means refresh
  pwnkit Codex auth and rerun before drawing current-pwnkit behavior
  conclusions. `pwnkit_codex_backend_timeout_prevented_request_artifacts` means
  rerun after the transient Codex backend condition clears, including timeouts
  and transport/API failures, before tuning bait semantics. A likely cause of
  `pwnkit_agent_errors_prevented_request_artifacts` means inspect the sanitized
  agent error classes and rerun after an agent-error-free scan. A
  likely cause of
  `eidolon_proxy_saw_uncorrelated_requests_but_pwnkit_emitted_no_request_artifacts`
  points at runner/current-pwnkit instrumentation or cookie reuse, not bait
  semantics.

Do not use raw pwnkit DBs, auth JSON, stdout/stderr logs, private debug logs,
raw query values, or request bodies in committed evidence bundles. Archive only
redacted summaries and checksums.
