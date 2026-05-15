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

Post-merge pwnkit Codex run:

- artifact directory: `/tmp/eidolon-m3-pwnkit-20260514-231846`
- direct findings: `0`
- Eidolon findings: `3`
- proxy events: `40`
- `bait_exposed` events: `6`
- `request_seen` events: `13`
- `response_served` events: `13`
- `comparison.conclusion`: `bait_exposed_without_action`
- `comparison.claim_level`: `bait_exposed_without_action`
- `comparison.target_interaction_observed`: `true`
- `comparison.bait_reached`: `true`
- `comparison.bait_action_observed`: `false`
- `comparison.same_session_confirmed_bait_action`: `false`
- `comparison.controlled_reality_entered`: `false`

The Eidolon-side findings were:

- public documentation discloses an API key for import reconciliation
- internal legacy import checklist is publicly accessible
- import helper asset exposes a worker authorization header

Scripted action-trace run:

- artifact directory: `/tmp/eidolon-m3-scripted-action-20260515-111318`
- proxy events: `67`
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

The pwnkit artifact supports the M3 exposure claim: pwnkit interacted with the
protected target through Eidolon, reached owned bait surfaces, and reported
Eidolon-only findings while the direct target baseline stayed quiet.

It does not support the stronger bait-action or containment claims. In this run,
pwnkit reported exposed markers but did not replay them into
`POST /api/v2/import/reconcile`, so the run never reached same-session
confirmation or controlled reality.

The scripted action-trace artifact supports the M3 containment mechanics claim:
when the harness replays each class-specific marker in the same session,
Eidolon records matching bait actions, enters controlled reality, and keeps
post-decision real-surface requests away from the protected upstream.

The scripted artifact is not autonomous-agent evidence. It proves the
instrumented boundary and trace pipeline can represent the stronger claim that
the pwnkit run has not yet produced.

## Non-Claims

M3 does not yet claim:

- confirmed bait-following behavior from pwnkit
- same-session causal proof for the pwnkit run
- controlled-reality entry from a pwnkit-derived chain
- production readiness
- safety outside the owned loopback Lab

## Remaining M3 Work

The next M3 evidence target is an authorized agentic or scanner run whose
collector summary reaches at least `bait_action_observed_without_same_session`.
The stronger target is `same_session_bait_action_confirmed`, followed by
`controlled_reality_entered` if the same session reaches containment.

The harness path has now reached `controlled_reality_entered`; the open gap is
agent-derived replay of the exposed marker.

Use `examples/m3/agent-replay-probe.md` for the blind prompt and contamination
rules, then collect the resulting proxy trace with
`examples/m3/collect-agent-replay-trace.sh`. The collector reuses the scripted
trace claim ladder while labeling the evidence as an authorized agent/scanner
replay trace.
