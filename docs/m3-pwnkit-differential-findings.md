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
because pwnkit emitted an `agent_error` consistent with a Codex backend timeout.
Treat the active open question as:

```text
Can current pwnkit produce an agent-error-free v0.12.x run with the same
controlled-reality chain, and if so, why is that chain still not promoted to a
pwnkit finding?
```

## Pre-Run Checklist

Before collecting a new sample:

1. Sync pwnkit to upstream main and rebuild its dist bundle.
2. Confirm `examples/m3/pwnkit-codex.sh` records the pwnkit git head in
   `pwnkit-runner-metadata.json`.
3. Keep `EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE=0` so
   `run-pwnkit-sample.sh` preflights pwnkit source-checkout freshness before
   starting the Lab target. Use `EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE=1` only
   for diagnostic artifact preservation.
4. Confirm `runner.pwnkit.origin_main.in_sync` is `true` and
   `runner.pwnkit.git_dirty` is `false` in the collected summary before making
   current-pwnkit claims.
5. Run direct and Eidolon legs with generated pwnkit scope files.
6. Use `EIDOLON_M3_PIN_SESSION=1` for the Eidolon leg when testing same-session
   replay.
7. Keep `EIDOLON_M3_ALLOW_AGENT_ERRORS=0` for evidence collection so the sample
   runner fails after any pwnkit `agent_error` event. Use
   `EIDOLON_M3_ALLOW_AGENT_ERRORS=1` only for diagnostic no-signal preservation.
8. Keep the proxy event log, policy state, and intervention control files inside
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

`examples/m3/collect-pwnkit-sample.sh` aggregates those signals under:

- `counts.positive_differential_findings`
- `counts.bait_reached_without_eidolon_findings`
- `counts.bait_action_without_eidolon_findings`
- `counts.controlled_reality_without_eidolon_findings`
- `no_signal_diagnostics`
- `differential_findings`

`examples/m3/collect-pwnkit-promotion-matrix.sh` wraps those sample-level
signals per manifest variant and adds:

- `observation_class`
- `observation_class_counts`
- `no_signal_diagnostics`
- `ready_for_differential_finding_claim_variants`
- `ready_for_stability_claim_variants`

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
- If `observation_class` is `no_signal`, inspect
  `no_signal_diagnostics.likely_cause` before changing bait content.
  `pwnkit_codex_token_refresh_failure_prevented_request_artifacts` means refresh
  pwnkit Codex auth and rerun before drawing current-pwnkit behavior
  conclusions. `pwnkit_codex_backend_timeout_prevented_request_artifacts` means
  rerun after the backend timeout clears before tuning bait semantics. A likely
  cause of `pwnkit_agent_errors_prevented_request_artifacts` means inspect the
  sanitized agent error classes and rerun after an agent-error-free scan. A
  likely cause of
  `eidolon_proxy_saw_uncorrelated_requests_but_pwnkit_emitted_no_request_artifacts`
  points at runner/current-pwnkit instrumentation or cookie reuse, not bait
  semantics.

Do not use raw pwnkit DBs, auth JSON, stdout/stderr logs, private debug logs,
raw query values, or request bodies in committed evidence bundles. Archive only
redacted summaries and checksums.
