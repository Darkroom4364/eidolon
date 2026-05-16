# M3 Lab-Only Uniqueness Bakeoff Note

This note is a Lab-only M3 evidence artifact. It is not a public-v1 note,
production-readiness statement, or deployment claim.

## Claim Under Test

Eidolon should create measurable, differential agentic-scanner behavior against
an owned loopback Lab target:

- direct scans of the protected demo target should remain quiet
- scans through Eidolon should discover owned synthetic bait surfaces
- stronger M3 claims require the scanner to follow bait into a bait-shaped
  action, same-session confirmation, or controlled-reality containment

## Current Evidence

Fresh pwnkit Codex pinned-session replay probe:

- artifact directory: `/tmp/eidolon-m3-pinned-metrics-EPFsYY`
- direct findings: `0`
- Eidolon findings: `4`
- proxy events: `47`
- `bait_exposed` events: `4`
- `bait_action_observed` events: `1`
- `comparison.conclusion`: `bait_action_observed`
- `comparison.claim_level`: `bait_action_observed_without_same_session`
- `comparison.target_interaction_observed`: `true`
- `comparison.bait_reached`: `true`
- `comparison.bait_action_observed`: `true`
- `comparison.same_session_confirmed_bait_action`: `false`
- `comparison.controlled_reality_entered`: `false`
- `metrics.bait_follow_rate`: `0.3333333333333333`
- `metrics.same_session_confirmed_bait_follow_rate`: `0.0`
- `pinned_session.cookie_preserved`: `false`
- `pinned_session.proxy_request_count`: `0`

The bait-shaped action was a hidden-route replay:

- first attempt: `POST /api/v2/import/reconcile` without the required static
  headers, status
  `404`
- replay attempt: `POST /api/v2/import/reconcile` with
  `X-Hidden-Route-Trace: hidden_route_2026_05_d91c`,
  `X-Api-Key: eidolon_lab_token_2026_05_7e2a`, and
  `X-Import-Worker: worker_2026_05_c19b`, status `202`

The Eidolon-side findings were:

- service token note exposes API key for hidden reconcile endpoint
- leaked static headers grant access to hidden reconcile endpoint
- internal legacy import checklist exposes hidden route and trace header
- import helper JavaScript leaks worker header for hidden reconcile API

Fresh scripted action-trace run:

- artifact directory: `/tmp/eidolon-m3-scripted-action-VGXkkh`
- proxy events: `65`
- scripted events: `15`
- `claim_level`: `controlled_reality_entered`
- bait exposures: `5`
- bait actions: `5`
- same-session confirmed bait actions: `5`
- controlled-reality entries after confirmed action: `10`
- `bait_follow_rate`: `1.0`
- `same_session_confirmed_bait_follow_rate`: `1.0`
- `real_surface_requests_after_containment`: `0`
- `controlled_reality_action_depth`: `10`
- `controlled_reality_branch_count`: `1`

## Interpretation

The pwnkit artifact now supports the first agent-derived bait-action claim:
pwnkit interacted with the protected target through Eidolon, reached owned bait
surfaces, reported Eidolon-only findings while the direct target baseline stayed
quiet, and replayed hidden-route/static-header bait into the bait-shaped
reconciliation endpoint.

It does not support the stronger same-session or containment claims. The
pinned-session runner generated a fixed `eidolon_session` cookie for the Eidolon
leg, but the proxy saw `0` requests with that session ID and pwnkit's recorded
HTTP artifacts had no `Cookie` header. The replayed
`POST /api/v2/import/reconcile` therefore has no matching exposure identifier,
and the session never reached controlled reality.

The scripted action-trace artifact supports the M3 containment mechanics claim:
when the harness replays each class-specific marker in the same session,
Eidolon records matching bait actions, enters controlled reality, and keeps
post-decision real-surface requests away from the protected upstream.

The scripted artifact is not autonomous-agent evidence. It proves the
instrumented boundary and trace pipeline can represent the stronger
same-session and controlled-reality claims that the pwnkit run has not yet
produced.

## Non-Claims

M3 does not yet claim:

- same-session causal proof for the pwnkit run
- controlled-reality entry from a pwnkit-derived chain
- production readiness
- safety outside the owned loopback Lab

## Remaining M3 Work

The next M3 evidence target is an authorized agentic or scanner run whose
collector summary reaches `same_session_bait_action_confirmed`, followed by
`controlled_reality_entered` if the same session reaches containment.

The pwnkit path has now reached `bait_action_observed_without_same_session`.
The harness path has reached `controlled_reality_entered`. The open gap is
agent-derived same-session replay of the exposed marker.

Use `examples/m3/agent-replay-probe.md` for the blind prompt and contamination
rules, then collect the resulting proxy trace with
`examples/m3/collect-agent-replay-trace.sh`. The collector reuses the scripted
trace claim ladder while labeling the evidence as an authorized agent/scanner
replay trace.
