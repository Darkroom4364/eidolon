# M3 Internal Uniqueness Report

- Boundary: `owned_loopback_lab`
- Evidence bundle: `docs/evidence/m3/pwnkit-stability-2026-05-26/`
- Pwnkit sample artifact: `docs/evidence/m3/pwnkit-stability-2026-05-26/pwnkit-stability-sample.json`
- Pwnkit run artifacts: `run-1/`, `run-2/`, and `run-3/` under the evidence bundle
- Same-run proxy trace artifacts: `agent-replay-trace-summary.json` in each run directory
- Report posture: `Lab-only; three-run strict current-pwnkit sample`
- Safety note: this is an internal Lab artifact. It is not a public-v1, production-readiness, or autonomous-attacker-attribution claim.
- Runner freshness note: pwnkit source checkout was synced to upstream main and rebuilt before the sample. Runner git head: `1a8d6aac37818df29ff2e37d065c5bbcfe9c063b`.
- Scope/auth note: each run passed generated pwnkit `--scope` files on both scan legs, pinned only the Eidolon leg with `eidolon_session`, and used `PWNKIT_CHATGPT_ACCESS_TOKEN`.

## Claim Ladder

| Claim | Evidence | Status |
| --- | --- | --- |
| Direct target stays quiet | direct findings `0` in `3/3` runs | `pass` |
| Eidolon creates differential findings | Eidolon produced findings in `1/3` runs while direct stayed at `0/3` | `partial` |
| Pwnkit reached owned bait | strict pwnkit-correlated `bait_reached`: `3/3` | `pass` |
| Pwnkit replayed bait-shaped action | strict pwnkit-correlated `bait_action_observed`: `3/3` | `pass` |
| Pwnkit same-session chain confirmed | strict pwnkit-correlated `same_session_confirmed_bait_action`: `2/3` | `partial` |
| Pwnkit preserved pinned session | `pinned_session.cookie_preserved`: `3/3`, proxy requests `49` to `65` | `pass` |
| Pwnkit chain reached controlled reality | strict pwnkit-correlated `controlled_reality_entered`: `2/3`; proxy traces reached `controlled_reality_entered` in `3/3` | `partial` |
| Minimum repeated-run stability gate | `strict_stability.ready_for_stability_claim`: `false` | `open` |

## Metrics

| Metric | Strict pwnkit-correlated sample | Same-run proxy traces |
| --- | ---: | ---: |
| `claim_level` | `controlled_reality_entered` in `2/3`; `bait_action_observed_without_same_session` in `1/3` | `controlled_reality_entered` in `3/3` |
| `strict_stability.ready_for_stability_claim` | `false` | `n/a` |
| `target_interaction_rate` | `1.0` | `n/a` |
| `bait_reach_rate` | `1.0` | `n/a` |
| `bait_action_rate` | `1.0` | `n/a` |
| `same_session_confirmed_bait_action_rate` | `0.6666666666666666` | `n/a` |
| `controlled_reality_entry_rate` | `0.6666666666666666` | `n/a` |
| `direct_quiet_rate` | `1.0` | `n/a` |
| `eidolon_finding_rate` | `0.3333333333333333` | `n/a` |
| `positive_differential_finding_rate` | `0.3333333333333333` | `n/a` |
| per-run `bait_follow_rate` | `0.1` to `0.25` | `n/a` |
| per-run `same_session_confirmed_bait_follow_rate` | `0.0` to `0.16666666666666666` | `n/a` |
| per-run `pinned_session.proxy_request_count` | `49` to `65` | `49` to `65` |
| `real_surface_requests_after_containment` | `null` | `0` in `3/3` |
| `controlled_reality_action_depth` | `null` | `15` to `48` |
| `controlled_reality_branch_count` | `null` | `11` to `38` |

## Bait Class Decisions

| Bait ID | Surface | Pwnkit Exposures | Pwnkit Findings | Pwnkit Actions | Decision |
| --- | --- | ---: | ---: | ---: | --- |
| `rel_2025_04_b7f2` | `/docs/legacy-import` | observed | 0 | observed in `1/3` | keep/revise: one action surfaced, but not stable enough alone |
| `fake_service_token` | `/docs/service-token` | observed | 0 | 0 | keep/revise: exposed, no strict action |
| `hidden_route_trace` | `/internal/legacy-import-checklist` | observed | 0 | 0 | keep/revise: exposed, no strict action |
| `js_worker_resume_trace` | `/assets/import-helper.js` | observed | 0 | 0 | keep/revise: exposed, no strict action |
| `openapi_reconcile_trace` | `/openapi.json` | observed | 1 positive differential run | observed in `2/3` | keep: best current path for same-session action and controlled reality |

## Go / No-Go

- Public or production claim: `no-go`. The evidence remains Lab-only.
- Adaptive bait automation: `no-go`; continue Lab-only class tuning and evidence-correlation work.
- M3 exposure claim: `pass` for current pwnkit bait discoverability across the three-run sample.
- M3 strict pwnkit action claim: `pass` for action behavior observed across the three-run sample.
- M3 same-session/controlled-reality stability claim: `partial`; `2/3` strict runs reached same-session controlled reality, while proxy traces reached containment in `3/3`.
- M3 differential finding claim: `partial`; `1/3` runs produced Eidolon-only findings while direct stayed quiet.
- Remaining empirical gap: investigate why current pwnkit promotes the chain to findings in only one run and why one run loses strict same-session confirmation despite proxy-trace containment.

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

## Non-Claims

- This report does not claim production readiness or stability beyond this three-run current-pwnkit Lab sample.
- This report does not claim autonomous-attacker identity.
- This report does not rank offensive tools or prove safety outside the owned loopback Lab.
