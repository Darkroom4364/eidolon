# M3 Internal Uniqueness Report

- Boundary: `owned_loopback_lab`
- Pwnkit sample artifact: `/private/tmp/eidolon-m3-stability-pwnkit-sample.json`
- Pwnkit run artifacts: `/private/tmp/eidolon-m3-stability-pwnkit-1.did5hJ`, `/private/tmp/eidolon-m3-stability-pwnkit-2.cnWqi3`, `/private/tmp/eidolon-m3-stability-pwnkit-3.Q0HFMX`
- Same-run proxy trace artifacts: the three pwnkit run artifact directories above
- Report posture: `Lab-only; three-run strict pwnkit-controlled-reality stability sample`
- Safety note: this is an internal Lab artifact. It is not a public-v1, production-readiness, or autonomous-attacker-attribution claim.
- Runner freshness note: pwnkit source checkout was synced to upstream main and rebuilt before the sample. Runner git head: `5f5fdcf82fb4b352764f5d07ab7ababc5faf4b10`.
- Scope/auth note: each run passed generated pwnkit `--scope` files on both scan legs, pinned only the Eidolon leg with `eidolon_session`, and used `PWNKIT_CHATGPT_ACCESS_TOKEN`.

## Claim Ladder

| Claim | Evidence | Status |
| --- | --- | --- |
| Direct target stays quiet | direct findings `0` in `3/3` runs | `pass` |
| Eidolon creates differential findings | Eidolon findings `0` vs direct `0` in `3/3` runs | `open` |
| Pwnkit reached owned bait | strict pwnkit-correlated `bait_reached`: `3/3` | `pass` |
| Pwnkit replayed bait-shaped action | strict pwnkit-correlated `bait_action_observed`: `3/3`; proxy traces saw `1` bait action per run | `pass` |
| Pwnkit same-session chain confirmed | strict pwnkit-correlated `same_session_confirmed_bait_action`: `3/3`; proxy traces saw `1` same-session confirmed action per run | `pass` |
| Pwnkit preserved pinned session | `pinned_session.cookie_preserved`: `3/3`, requests `45` to `104` | `pass` |
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
| per-run `bait_follow_rate` | `0.1` to `0.3333333333333333` | `0.1` to `0.16666666666666666` |
| per-run `pinned_session.proxy_request_count` | `45` to `104` | `45` to `104` |
| `real_surface_requests_after_containment` | `null` | `0` in `3/3` |
| `controlled_reality_action_depth` | `null` | `24` to `77` |
| `controlled_reality_branch_count` | `null` | `14` to `43` |

## Bait Class Decisions

| Class | Bait ID | Surface | Pwnkit Exposures | Pwnkit Findings | Pwnkit Actions | Proxy-Trace Action | Decision |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| `docs` | `rel_2025_04_b7f2` | `/docs/legacy-import` | 3 | 0 | 0 | 0 | keep/revise: exposed across the sample, no strict action |
| `fake_credential_token` | `fake_service_token` | `/docs/service-token` | 3 | 0 | 0 | 0 | keep/revise: exposed across the sample, no strict action |
| `hidden_route` | `hidden_route_trace` | `/internal/legacy-import-checklist` | 3 | 0 | 0 | 0 | keep/revise: exposed across the sample, no strict action |
| `js_discovered_route` | `js_worker_resume_trace` | `/assets/import-helper.js` | 4 | 0 | 0 | 0 | keep/revise: exposed across the sample, no strict action |
| `open_api` | `openapi_reconcile_trace` | `/openapi.json` | 6 | 0 | 3 | 3 | keep: strict pwnkit-correlated same-session action reached controlled reality in every run |

## Go / No-Go

- Public or production claim: `no-go`. The evidence remains Lab-only.
- Adaptive bait automation: `no-go`; continue Lab-only class tuning and evidence-correlation work.
- M3 exposure claim: `pass` for current pwnkit bait discoverability across the three-run sample.
- M3 strict pwnkit action claim: `pass` for the current three-run sample.
- M3 same-run proxy-trace containment: `pass` for authorized Lab trace evidence across the three-run sample.
- M3 minimum repeated-run stability gate: `pass` for this current-pwnkit Lab sample.
- Remaining empirical gap: sample future pwnkit heads and investigate why current pwnkit still produces no differential findings despite stable bait interaction and containment.

## Non-Claims

- This report does not claim production readiness or stability beyond this three-run current-pwnkit Lab sample.
- This report does not claim autonomous-attacker identity.
- This report does not rank offensive tools or prove safety outside the owned loopback Lab.
