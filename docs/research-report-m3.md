# M3 Internal Uniqueness Report

- Boundary: `owned_loopback_lab`
- Pwnkit artifact: `/private/tmp/eidolon-m3-fresh-pwnkit-fixed.jEZIeM`
- Same-run proxy trace artifact: `/private/tmp/eidolon-m3-fresh-pwnkit-fixed.jEZIeM`
- Report posture: `Lab-only; pwnkit exposure pass, strict pwnkit action correlation open`
- Safety note: this is an internal Lab artifact. It is not a public-v1, production-readiness, or autonomous-attacker-attribution claim.
- Runner freshness note: pwnkit source checkout was rebuilt before the run. Runner git head: `5861f0c0c1dd141f0d61d2defd7de4d092324306`.
- Scope note: the runner passed generated pwnkit `--scope` files on both scan legs and pinned only the Eidolon leg with `eidolon_session`.

## Claim Ladder

| Claim | Evidence | Status |
| --- | --- | --- |
| Direct target stays quiet | direct findings `0` | `pass` |
| Eidolon creates differential findings | Eidolon findings `0` vs direct `0` | `open` |
| Pwnkit reached owned bait | strict pwnkit-correlated `bait_reached`: `yes` | `pass` |
| Pwnkit replayed bait-shaped action | strict pwnkit-correlated `bait_action_observed`: `no`; proxy trace saw `2` bait actions | `split` |
| Pwnkit same-session chain confirmed | strict pwnkit-correlated `same_session_confirmed_bait_action`: `no`; proxy trace saw `1` same-session confirmed action | `split` |
| Pwnkit preserved pinned session | `pinned_session.cookie_preserved`: `yes`, requests `75` | `pass` |
| Pwnkit chain reached controlled reality | strict pwnkit-correlated `controlled_reality_entered`: `no`; proxy trace reached `controlled_reality_entered` | `split` |

## Metrics

| Metric | Strict pwnkit-correlated | Same-run proxy trace |
| --- | ---: | ---: |
| `claim_level` | `bait_exposed_without_action` | `controlled_reality_entered` |
| `bait_follow_rate` | `0` | `0.14285714285714285` |
| `same_session_confirmed_bait_follow_rate` | `0` | `0.07142857142857142` |
| `pinned_session.proxy_request_count` | `75` | `75` |
| `real_surface_requests_after_containment` | `null` | `0` |
| `controlled_reality_action_depth` | `null` | `26` |
| `controlled_reality_branch_count` | `null` | `15` |

## Bait Class Decisions

| Class | Bait ID | Surface | Pwnkit Exposures | Pwnkit Findings | Pwnkit Actions | Proxy-Trace Action | Decision |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| `docs` | `rel_2025_04_b7f2` | `/docs/legacy-import` | 1 | 0 | 0 | 0 | keep/revise: exposed by current pwnkit, no strict action |
| `fake_credential_token` | `fake_service_token` | `/docs/service-token` | 1 | 0 | 0 | 0 | keep/revise: exposed by current pwnkit, no strict action |
| `hidden_route` | `hidden_route_trace` | `/internal/legacy-import-checklist` | 1 | 0 | 0 | 0 | keep/revise: exposed by current pwnkit, no strict action |
| `js_discovered_route` | `js_worker_resume_trace` | `/assets/import-helper.js` | 1 | 0 | 0 | 0 | keep/revise: exposed by current pwnkit, no strict action |
| `open_api` | `openapi_reconcile_trace` | `/openapi.json` | 2 | 0 | 0 | 1 | keep: proxy trace reached same-session controlled reality, strict pwnkit correlation still open |

## Go / No-Go

- Public or production claim: `no-go`. The evidence remains Lab-only.
- Adaptive bait automation: `no-go`; continue Lab-only class tuning and evidence-correlation work.
- M3 exposure claim: `pass` for current pwnkit bait discoverability.
- M3 strict pwnkit action claim: `open`.
- M3 same-run proxy-trace containment: `pass` for authorized Lab trace evidence.
- Remaining empirical gap: make pwnkit shell-mode action evidence correlate with proxy trace, then rerun or recollect to see whether the strict pwnkit claim reaches `controlled_reality_entered`.

## Non-Claims

- This report does not claim strict pwnkit-correlated controlled reality.
- This report does not claim autonomous-attacker identity.
- This report does not rank offensive tools or prove safety outside the owned loopback Lab.
