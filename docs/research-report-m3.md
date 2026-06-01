# M3 Internal Uniqueness Report

- Boundary: `owned_loopback_lab`
- Evidence bundle: `docs/evidence/m3/pwnkit-stability-2026-05-31/`
- Pwnkit sample artifact: `docs/evidence/m3/pwnkit-stability-2026-05-31/pwnkit-stability-sample.json`
- Pwnkit run artifacts: `run-1/`, `run-2/`, and `run-3/` under the evidence bundle
- Same-run proxy trace artifacts: `agent-replay-trace-summary.json` in each run directory
- Report posture: `Lab-only; three-run strict upstream-current Kali gpt-5.4 sample`
- Safety note: this is an internal Lab artifact. It is not a public-v1, production-readiness, or autonomous-attacker-attribution claim.
- Runner freshness note: pwnkit source checkout was synced to upstream main and rebuilt before the sample. Runner git head: `c64410873b828f19f48ca4f8b12a3fc8dfe53c58`. Package version: `0.12.0`.
- Scope/auth note: each run passed generated pwnkit `--scope` files on both scan legs, pinned only the Eidolon leg with `eidolon_session`, and supplied explicit Codex auth through `EIDOLON_M3_CODEX_AUTH_FILE`.

## Claim Ladder

| Claim | Evidence | Status |
| --- | --- | --- |
| Direct target stays quiet | direct findings `0` in `3/3` runs | `pass` |
| Eidolon creates differential findings | Eidolon produced findings in `2/3` runs while direct stayed at `0/3` | `partial` |
| Pwnkit reached owned bait | strict pwnkit-correlated `bait_reached`: `3/3` | `pass` |
| Pwnkit replayed bait-shaped action | strict pwnkit-correlated `bait_action_observed`: `3/3` | `pass` |
| Pwnkit same-session chain confirmed | strict pwnkit-correlated `same_session_confirmed_bait_action`: `3/3` | `pass` |
| Pwnkit preserved pinned session | `pinned_session.cookie_preserved`: `3/3`, proxy requests `58` to `73` | `pass` |
| Pwnkit chain reached controlled reality | strict pwnkit-correlated `controlled_reality_entered`: `3/3`; proxy traces reached `controlled_reality_entered` in `3/3` | `pass` |
| Minimum repeated-run stability gate | `strict_stability.ready_for_stability_claim`: `true` | `pass` |

## Metrics

| Metric | Strict pwnkit-correlated sample | Same-run proxy traces |
| --- | ---: | ---: |
| `claim_level` | `controlled_reality_entered` in `3/3` | `controlled_reality_entered` in `3/3` |
| `strict_stability.ready_for_stability_claim` | `true` | `n/a` |
| `target_interaction_rate` | `1.0` | `n/a` |
| `bait_reach_rate` | `1.0` | `n/a` |
| `bait_action_rate` | `1.0` | `n/a` |
| `same_session_confirmed_bait_action_rate` | `1.0` | `n/a` |
| `controlled_reality_entry_rate` | `1.0` | `n/a` |
| `direct_quiet_rate` | `1.0` | `n/a` |
| `eidolon_finding_rate` | `0.6666666666666666` | `n/a` |
| `positive_differential_finding_rate` | `0.6666666666666666` | `n/a` |
| per-run `bait_follow_rate` | `0.14285714285714285` to `0.16666666666666666` | `n/a` |
| per-run `same_session_confirmed_bait_follow_rate` | `0.14285714285714285` to `0.16666666666666666` | `n/a` |
| per-run `pinned_session.proxy_request_count` | `58` to `73` | `58` to `73` |
| `real_surface_requests_after_containment` | `null` | `0` in `3/3` |
| `controlled_reality_action_depth` | `null` | `13` to `25` |
| `controlled_reality_branch_count` | `null` | `7` to `13` |

## Bait Class Decisions

| Bait ID | Surface | Pwnkit Exposures | Pwnkit Findings | Pwnkit Actions | Decision |
| --- | --- | ---: | ---: | ---: | --- |
| `rel_2025_04_b7f2` | `/docs/legacy-import` | observed | 0 | 0 | keep/revise: exposed, no strict action |
| `fake_service_token` | `/docs/service-token` | observed | 0 | 0 | keep/revise: exposed, no strict action |
| `hidden_route_trace` | `/customer/import-recovery-checklist` | observed | 0 | 0 | keep/revise: exposed, no strict action |
| `js_worker_resume_trace` | `/assets/import-helper.js` | observed | 0 | 0 | keep/revise: exposed, no strict action |
| `openapi_reconcile_trace` | `/openapi.json` | observed | 2 positive differential runs | observed in `3/3` | keep: stable same-session action and controlled reality path, with partial finding promotion |

## Go / No-Go

- Public or production claim: `no-go`. The evidence remains Lab-only.
- Adaptive bait automation: `no-go`; continue Lab-only class tuning and finding-promotion work.
- M3 exposure claim: `pass` for current pwnkit bait discoverability across the three-run sample.
- M3 strict pwnkit action claim: `pass` for action behavior observed across the three-run sample.
- M3 same-session/controlled-reality stability claim: `pass`; `3/3` strict runs reached same-session controlled reality, and proxy traces matched containment in `3/3`.
- M3 differential finding claim: `partial`; `2/3` runs produced Eidolon-only findings while direct stayed quiet.
- Remaining empirical gap: partial finding promotion rather than containment correlation; one strict controlled-reality run still produced no Eidolon final JSON finding.

## Local Patched Follow-Up

The local patched pwnkit fixture
`docs/evidence/m3/pwnkit-local-patched-2026-05-30/` is a separate evidence
track. It used pwnkit head `fa3a3c6c34e0e50ddb7f40b86e58fb50ed95833f` with
fixture id `pwnkit-local-patched-discovery-findings-2026-05-30`.

- Strict same-session controlled reality: `3/3`
- Direct final JSON findings: `0/3`
- Eidolon final JSON findings: `2/3` runs, `6` total findings
- `strict_stability.ready_for_stability_claim`: `true`
- `differential_findings.ready_for_differential_finding_claim`: `false`

This supports the local export-gap patch direction while preserving the
upstream-current distinction. One patched run still reached controlled reality
without an Eidolon final JSON finding, so the differential-finding stability
question remains open.

A refreshed local patched rerun is now archived under
`docs/evidence/m3/pwnkit-local-patched-report-fix-2026-06-01/`. It used
pwnkit head `18c7b3b46f77f9860ed603006a64aed7f8c9475e` with fixture id
`eidolon-m3-local-patched-report-fix-2026-06-01`.

- Strict same-session controlled reality: `3/3`
- Direct final JSON findings: `0/3`
- Eidolon final JSON findings: `3/3` runs, `5` total findings (`1/2/2`)
- `strict_stability.ready_for_stability_claim`: `true`

This refreshed local patched sample validates the report/export fix on the
patched track: every strict controlled-reality run now emitted final Eidolon
JSON findings. The only remaining DB-saved versus final-JSON delta was one row
already marked `status:false-positive`, so it is expected filtering rather than
loss of an active finding. This still remains a patched-local pwnkit result,
not an upstream-current claim.

A separate local patched promotion matrix is now archived under
`docs/evidence/m3/pwnkit-local-patched-promotion-matrix-2026-05-31/` for the
same pinned fixture id `eidolon-m3-local-patched-2026-05-29`. Both
`default_m3_catalog` and `openapi_promotion_probe` produced
`promoted_finding` observations in `1/1` runs while direct findings stayed at
`0/1`, and the matrix health gate is green for the `local_patched_pwnkit`
track because the runners were clean and source-claim-safe even though they
were intentionally ahead of upstream `origin/main`.

## Non-Claims

- This report does not claim production readiness or stability beyond this three-run upstream-current Kali gpt-5.4 Lab sample.
- This report does not claim autonomous-attacker identity.
- This report does not rank offensive tools or prove safety outside the owned loopback Lab.
