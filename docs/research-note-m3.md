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

Fresh current-pwnkit scoped pinned-session run:

- artifact directory: `/private/tmp/eidolon-m3-fresh-pwnkit-fixed.jEZIeM`
- pwnkit git head: `5861f0c0c1dd141f0d61d2defd7de4d092324306`
- pwnkit runner: `node /Users/darkroom/Projects/pwnkit/dist/pwnkit.js`
- runtime: `codex`
- direct findings: `0`
- Eidolon findings: `0`
- generated pwnkit scope files: `pwnkit-eidolon-scope.json`,
  `pwnkit-direct-scope.json`
- `pinned_session.cookie_preserved`: `true`
- `pinned_session.proxy_request_count`: `75`
- strict pwnkit-correlated `comparison.claim_level`:
  `bait_exposed_without_action`
- strict pwnkit-correlated bait exposures: `6`
- strict pwnkit-correlated bait actions: `0`
- same-run proxy-trace `claim_level`: `controlled_reality_entered`
- same-run proxy-trace bait exposures: `14`
- same-run proxy-trace bait actions: `2`
- same-run proxy-trace same-session confirmed bait actions: `1`
- same-run proxy-trace controlled-reality entries after confirmed action: `4`
- same-run proxy-trace `controlled_reality_action_depth`: `26`
- same-run proxy-trace `controlled_reality_branch_count`: `15`

Historical pwnkit Codex pinned-session replay probe:

- artifact directory: `/tmp/eidolon-m3-pinned-metrics-EPFsYY`
- validity: `stale-runner artifact; current pwnkit rerun required`
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

After syncing pwnkit main, this artifact was traced to an ignored stale
source-checkout `dist/pwnkit.js` bundle that still contained pwnkit's removed
Codex MCP live runner. Keep the artifact as a historical Lab record only. Do not
use it to claim current pwnkit behavior, current pinned-session handling, or a
current same-session failure.

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

The fresh current-pwnkit artifact supersedes the stale-runner interpretation for
current pwnkit behavior. With a fresh source checkout build, direct ChatGPT Codex
runtime, generated pwnkit scope files, and pinned-session auth, pwnkit interacted
with the protected target through Eidolon and reached owned bait surfaces while
the direct target stayed quiet. The strict pwnkit-correlated collector supports
only `bait_exposed_without_action`: it can correlate pwnkit target-tool artifacts
to bait exposures, but not to the later bait-shaped action.

The same artifact's proxy trace is stronger. It records a same-session
`bait_action_observed` for `openapi_reconcile_trace`, a policy transition into
controlled reality, and subsequent controlled-reality entries for the pinned
session. That is valid authorized proxy-trace evidence, but it is not yet a
strict pwnkit-correlated action claim because the pwnkit DB evidence does not map
the shell-mode action cleanly back to the proxy request.

The stale artifact did not support the stronger same-session or containment
claims. Because the pwnkit bundle was stale, the recorded
`pinned_session.proxy_request_count: 0` result must not be interpreted as current
pwnkit's cookie behavior.

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

- pwnkit-correlated same-session action proof from the fresh run
- pwnkit-correlated controlled-reality entry from the fresh run
- production readiness
- safety outside the owned loopback Lab

## Remaining M3 Work

The next evidence target is closing the correlation gap between pwnkit's
shell-mode action evidence and the proxy trace. The fresh run shows the stronger
same-session controlled-reality path in proxy events, but the pwnkit-specific
collector remains at `bait_exposed_without_action`.

Use `examples/m3/agent-replay-probe.md` for the blind prompt and contamination
rules, then collect the resulting proxy trace with
`examples/m3/collect-agent-replay-trace.sh`. The collector reuses the scripted
trace claim ladder while labeling the evidence as an authorized agent/scanner
replay trace.
