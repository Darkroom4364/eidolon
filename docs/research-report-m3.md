# M3 Internal Uniqueness Report

- Boundary: `owned_loopback_lab`
- Pwnkit artifact: `/private/tmp/eidolon-m3-post-merge-pwnkit-access.LOIXvq`
- Same-run proxy trace artifact: `/private/tmp/eidolon-m3-post-merge-pwnkit-access.LOIXvq`
- Report posture: `Lab-only; strict pwnkit-controlled-reality trace pass`
- Safety note: this is an internal Lab artifact. It is not a public-v1, production-readiness, or autonomous-attacker-attribution claim.
- Runner freshness note: pwnkit source checkout was rebuilt before the run. Runner git head: `5861f0c0c1dd141f0d61d2defd7de4d092324306`.
- Scope/auth note: the runner passed generated pwnkit `--scope` files on both scan legs, pinned only the Eidolon leg with `eidolon_session`, and used `PWNKIT_CHATGPT_ACCESS_TOKEN` for the post-merge rerun.

## Claim Ladder

| Claim | Evidence | Status |
| --- | --- | --- |
| Direct target stays quiet | direct findings `0` | `pass` |
| Eidolon creates differential findings | Eidolon findings `0` vs direct `0` | `open` |
| Pwnkit reached owned bait | strict pwnkit-correlated `bait_reached`: `yes` | `pass` |
| Pwnkit replayed bait-shaped action | strict pwnkit-correlated `bait_action_observed`: `yes`; proxy trace saw `1` bait action | `pass` |
| Pwnkit same-session chain confirmed | strict pwnkit-correlated `same_session_confirmed_bait_action`: `yes`; proxy trace saw `1` same-session confirmed action | `pass` |
| Pwnkit preserved pinned session | `pinned_session.cookie_preserved`: `yes`, requests `72` | `pass` |
| Pwnkit chain reached controlled reality | strict pwnkit-correlated `controlled_reality_entered`: `yes`; proxy trace reached `controlled_reality_entered` | `pass` |

## Metrics

| Metric | Strict pwnkit-correlated | Same-run proxy trace |
| --- | ---: | ---: |
| `claim_level` | `controlled_reality_entered` | `controlled_reality_entered` |
| `bait_follow_rate` | `0.14285714285714285` | `0.14285714285714285` |
| `same_session_confirmed_bait_follow_rate` | `0.14285714285714285` | `0.14285714285714285` |
| `pinned_session.proxy_request_count` | `72` | `72` |
| `real_surface_requests_after_containment` | `null` | `0` |
| `controlled_reality_action_depth` | `null` | `20` |
| `controlled_reality_branch_count` | `null` | `15` |

## Bait Class Decisions

| Class | Bait ID | Surface | Pwnkit Exposures | Pwnkit Findings | Pwnkit Actions | Proxy-Trace Action | Decision |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| `docs` | `rel_2025_04_b7f2` | `/docs/legacy-import` | 1 | 0 | 0 | 0 | keep/revise: exposed by current pwnkit, no strict action |
| `fake_credential_token` | `fake_service_token` | `/docs/service-token` | 1 | 0 | 0 | 0 | keep/revise: exposed by current pwnkit, no strict action |
| `hidden_route` | `hidden_route_trace` | `/internal/legacy-import-checklist` | 1 | 0 | 0 | 0 | keep/revise: exposed by current pwnkit, no strict action |
| `js_discovered_route` | `js_worker_resume_trace` | `/assets/import-helper.js` | 1 | 0 | 0 | 0 | keep/revise: exposed by current pwnkit, no strict action |
| `open_api` | `openapi_reconcile_trace` | `/openapi.json` | 3 | 0 | 1 | 1 | keep: strict pwnkit-correlated same-session action reached controlled reality |

## Go / No-Go

- Public or production claim: `no-go`. The evidence remains Lab-only.
- Adaptive bait automation: `no-go`; continue Lab-only class tuning and evidence-correlation work.
- M3 exposure claim: `pass` for current pwnkit bait discoverability.
- M3 strict pwnkit action claim: `pass` for the post-merge current artifact.
- M3 same-run proxy-trace containment: `pass` for authorized Lab trace evidence.
- Remaining empirical gap: sample more current pwnkit runs before claiming stability beyond this Lab trace.

## Non-Claims

- This report does not claim production readiness or stability across repeated current-pwnkit runs.
- This report does not claim autonomous-attacker identity.
- This report does not rank offensive tools or prove safety outside the owned loopback Lab.
