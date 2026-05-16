# M3 Internal Uniqueness Report

- Boundary: `owned_loopback_lab`
- Pwnkit artifact: `/tmp/eidolon-m3-pinned-metrics-EPFsYY`
- Scripted action artifact: `/tmp/eidolon-m3-scripted-action-VGXkkh`
- Report posture: `no-go for adaptive automation; continue Lab-only class tuning and agent replay work`
- Safety note: this is an internal Lab artifact. It is not a public-v1, production-readiness, or autonomous-attacker-attribution claim.

## Claim Ladder

| Claim | Evidence | Status |
| --- | --- | --- |
| Direct target stays quiet | direct findings `0` | `pass` |
| Eidolon creates differential findings | Eidolon findings `4` vs direct `0` | `pass` |
| Pwnkit reached owned bait | `bait_reached`: `yes` | `pass` |
| Pwnkit replayed bait-shaped action | `bait_action_observed`: `yes` | `pass` |
| Pwnkit same-session chain confirmed | `same_session_confirmed_bait_action`: `no` | `open` |
| Pwnkit preserved pinned session | `pinned_session.cookie_preserved`: `no`, requests `0` | `open` |
| Pwnkit chain reached controlled reality | `controlled_reality_entered`: `no` | `open` |
| Scripted trace proves containment mechanics | action trace `controlled_reality_entered`, confirmed actions `5` | `scripted-pass` |

## Metrics

| Metric | Pwnkit | Scripted action trace |
| --- | --- | --- |
| `claim_level` | `bait_action_observed_without_same_session` | `controlled_reality_entered` |
| `bait_follow_rate` | `0.3333333333333333` | `1` |
| `same_session_confirmed_bait_follow_rate` | `0` | `1` |
| `pinned_session.proxy_request_count` | `0` | `null` |
| `real_surface_requests_after_containment` | `null` | `0` |
| `controlled_reality_action_depth` | `null` | `10` |
| `controlled_reality_branch_count` | `null` | `1` |

## Bait Class Decisions

| Class | Bait ID | Surface | Pwnkit Exposures | Pwnkit Findings | Pwnkit Actions | Scripted Confirmed Actions | Decision |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| `docs` | `rel_2025_04_b7f2` | `/docs/legacy-import` | 0 | 0 | 0 | 1 | revise: mechanics work, no agent signal |
| `fake_credential_token` | `fake_service_token` | `/docs/service-token` | 1 | 2 | 0 | 1 | keep/revise: reported by pwnkit, no replay yet |
| `hidden_route` | `hidden_route_trace` | `/internal/legacy-import-checklist` | 1 | 2 | 1 | 1 | keep: agent replay observed |
| `js_discovered_route` | `js_worker_resume_trace` | `/assets/import-helper.js` | 1 | 2 | 0 | 1 | keep/revise: reported by pwnkit, no replay yet |
| `open_api` | `openapi_reconcile_trace` | `/openapi.json` | 0 | 0 | 0 | 1 | revise: mechanics work, no agent signal |

## Go / No-Go

- Public or production claim: `no-go`. The evidence remains Lab-only.
- Adaptive bait automation: `no-go for adaptive automation; continue Lab-only class tuning and agent replay work`.
- M3 exposure claim: `pass` for pwnkit discoverability.
- M3 containment mechanics: `pass-scripted` for proxy trace enforcement.
- Remaining empirical gap: same-session marker replay from the agent-derived bait-shaped action, preferably with controlled-reality entry.

## Non-Claims

- This report does not claim pwnkit reached controlled reality.
- This report does not claim autonomous-attacker identity.
- This report does not rank offensive tools or prove safety outside the owned loopback Lab.
