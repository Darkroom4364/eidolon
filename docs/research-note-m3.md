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

Three-run canonical local-patched pwnkit scoped pinned-session Kali VM
stability sample:

- committed evidence bundle:
  `docs/evidence/m3/pwnkit-local-patched-canonical-2026-06-02/`
- sample artifact:
  `docs/evidence/m3/pwnkit-local-patched-canonical-2026-06-02/pwnkit-stability-sample.json`
- run artifacts: `run-1/`, `run-2/`, and `run-3/` under the committed
  evidence bundle
- pwnkit git head: `abd034b61042f14a0b9b3a2cf9b0dbfa5ef4f2b4`
- pwnkit package version: `0.12.0`
- pwnkit runner: source-checkout `dist/pwnkit.js`; local checkout path omitted
- pwnkit pinned fixture id:
  `eidolon-m3-canonical-pwnkit-demo-target-fix-2026-06-02`
- evidence track: `local_patched_pwnkit`
- runner environment: `kali_vm`
- network topology: `same_vm_loopback`
- runtime: `codex`, model `gpt-5.4`
- auth path: explicit `EIDOLON_M3_CODEX_AUTH_FILE`; local temp paths omitted
  from this note; committed evidence lives under `docs/evidence/m3/`
- valid summaries: `3`
- `strict_stability.ready_for_stability_claim`: `true`
- direct findings: `0` in all three runs
- Eidolon final JSON findings: `3`, `1`, `1`
- Eidolon final JSON findings total: `5`
- Eidolon DB-saved findings: `5` total, all still active, with no saved-vs-final
  mismatch
- generated pwnkit scope files: `pwnkit-eidolon-scope.json`,
  `pwnkit-direct-scope.json` per run
- `pinned_session.cookie_preserved`: `true` in all three runs
- `pinned_session.proxy_request_count`: `45` to `61`
- strict pwnkit-correlated `comparison.claim_level`:
  `controlled_reality_entered` in all three runs
- pwnkit request artifacts for the Eidolon leg: `37` to `50`
- strict pwnkit-correlated target requests: `41` to `68`
- strict pwnkit-correlated bait exposures: `10`, `6`, `10`
- strict pwnkit-correlated bait actions: `1` in each run
- strict pwnkit-correlated same-session confirmed bait actions: `1` in each run
- strict pwnkit-correlated controlled-reality entries: `4` in each run
- sample-level rates: target interaction `1.0`, bait reach `1.0`, bait action
  `1.0`, same-session confirmed bait action `1.0`, controlled-reality entry
  `1.0`, direct quiet `1.0`, final JSON Eidolon finding `1.0`, final JSON
  positive differential finding `1.0`, pinned-cookie preservation `1.0`
- same-run proxy traces reached `controlled_reality_entered` in all three runs
- same-run proxy-trace `real_surface_requests_after_containment`: `0` in all
  three runs
- observed evidence gaps: `none`

Historical upstream-current Kali VM reference:

- committed evidence bundle:
  `docs/evidence/m3/pwnkit-stability-2026-05-31/`
- validity: retained as the best unpatched upstream-current reference, but
  superseded as the current canonical M3 sample
- pwnkit git head: `c64410873b828f19f48ca4f8b12a3fc8dfe53c58`
- `strict_stability.ready_for_stability_claim`: `true`
- direct findings: `0` in all three runs
- Eidolon final JSON findings: `2`, `0`, `2`
- observed evidence gaps:
  `strict_controlled_reality_without_eidolon_findings`,
  `partial_positive_differential_findings`

Prior three-run upstream-current Kali VM sample:

- committed evidence bundle:
  `docs/evidence/m3/pwnkit-stability-2026-05-28/`
- validity: superseded by the May 31 Kali VM sample for current M3 status
- pwnkit git head: `1a8d6aac37818df29ff2e37d065c5bbcfe9c063b`
- pwnkit pinned fixture id: `pwnkit-local-kali-2026-05-28`
- `strict_stability.ready_for_stability_claim`: `true`
- direct findings: `0` in all three runs
- Eidolon final JSON findings: `0` in all three runs
- observed evidence gap: `strict_controlled_reality_without_eidolon_findings`

Prior three-run current-pwnkit scoped pinned-session sample:

- committed evidence bundle:
  `docs/evidence/m3/pwnkit-stability-2026-05-26/`
- validity: superseded by the May 28 Kali VM sample for current M3 status
- `strict_stability.ready_for_stability_claim`: `false`
- strict pwnkit-correlated `comparison.claim_level`:
  `controlled_reality_entered` in two runs and
  `bait_action_observed_without_same_session` in one run

Prior single current-pwnkit scoped pinned-session run:

- local artifact path: omitted from this note
- pwnkit git head: `5861f0c0c1dd141f0d61d2defd7de4d092324306`
- `comparison.claim_level`: `controlled_reality_entered`
- direct findings: `0`
- Eidolon findings: `0`
- `pinned_session.cookie_preserved`: `true`

Historical pwnkit Codex pinned-session replay probe:

- local artifact path: omitted from this note
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

- local artifact path: omitted from this note
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

The current canonical sample is now the June 2 local-patched Kali VM run on
pwnkit `abd034b61042f14a0b9b3a2cf9b0dbfa5ef4f2b4`, collected after the
demo-target import-validation fix merged into Eidolon. With a fresh source
checkout build, generated pwnkit scope files, pinned-session auth, and same-VM
loopback topology, pwnkit interacted with the protected target through
Eidolon, reached owned bait surfaces, replayed one bait-shaped
`POST /api/v2/import/reconcile` action per run, preserved the pinned session in
all three runs, confirmed each bait action in the same session, entered
controlled reality in all three strict pwnkit-correlated runs, and emitted
positive differential final JSON findings in all three runs while the direct
target stayed quiet.

That canonical result is intentionally labeled `local_patched_pwnkit`. It is
the best current proof that Eidolon's M3 containment path, the stricter
collector, the pwnkit report/export fixes, and the demo-target validation fix
now line up cleanly enough to produce stable final-output differential findings
on the pinned research fixture. It is not an upstream-current claim.

The May 31 upstream-current sample remains useful as the last unpatched
baseline. It already supported the stronger same-session containment claim on
`gpt-5.4`, but it still showed partial final-output finding promotion. That is
now best interpreted as historical pre-fix behavior rather than an active
Eidolon-side blocker.

The strict pwnkit-correlated collector changes remain important. The current
contract requires an unambiguous pwnkit-to-proxy request match, exact proxy
`request_id` linkage for action and containment events, and an accepted proof.
One-to-one queryless crawl-start matches may still support exposure evidence,
but ambiguous crawl matches cannot, and a later request in the same session
cannot repair missing action linkage.
Proxy-only or rejected actions do not upgrade the strict claim. Historical
samples that depended on the older fallback must be reproduced before their
strict attribution is reused.

The stale artifact did not support the stronger same-session or containment
claims. Because the pwnkit bundle was stale, the recorded
`pinned_session.proxy_request_count: 0` result must not be interpreted as
current pwnkit's cookie behavior.

The scripted action-trace artifact supports the M3 containment mechanics claim:
when the harness replays each class-specific marker in the same session,
Eidolon records matching bait actions, enters controlled reality, and keeps
post-decision real-surface requests away from the protected upstream.

The scripted artifact is not autonomous-agent evidence. It proves the
instrumented boundary and trace pipeline can represent the stronger
same-session and controlled-reality claims, and it still provides class-by-class
coverage beyond the single `open_api` action that current pwnkit replayed.

## Non-Claims

M3 does not yet claim:

- production readiness
- safety outside the owned loopback Lab
- that the June 2 canonical local-patched result automatically generalizes to
  unpatched upstream-current pwnkit without rerun

## Remaining M3 Work

The immediate containment-correlation gap is closed, the canonical local-patched
stability gate now passes cleanly, and the canonical sample now supports a
stable final-output differential-finding claim on that pinned research
fixture. The remaining work is no longer Eidolon-side containment tuning.
Instead:

- keep upstream-current reruns explicitly separated from the canonical patched
  track
- decide whether upstream-current parity is still worth chasing or whether M3
  should now freeze on the canonical local-patched evidence track
- continue to treat pwnkit-side drift, not Eidolon containment, as the main
  reason to rerun this experiment

A separate operational note from these reruns: local refresh-token auth can
fail after rotation, while forwarding the current Codex access token through
`EIDOLON_M3_CODEX_AUTH_FILE` allowed the Kali runs to complete. Current pwnkit
also honors `429 Retry-After` with a conservative floor, so post-containment
runs can take substantially longer as the seeded worklist grows.

Use `examples/m3/run-pwnkit-sample.sh` for future repeated current-pwnkit
samples from a synced source checkout. It writes one collected artifact
directory per run and aggregates them with `collect-pwnkit-sample.sh`. The
resulting `strict_stability.ready_for_stability_claim` gate requires at least
three valid current-run summaries from one pwnkit git head with preserved pinned
cookies, quiet direct-target legs, same-session confirmed bait action, and
controlled-reality entry in every run.

Use `examples/m3/package-pwnkit-sample.sh` before committing future sample
evidence. It emits a README, checksums, the sample aggregate, redacted pwnkit
summaries, and sanitized trace summaries while omitting raw pwnkit artifacts,
full proxy logs, auth files, stdout/stderr logs, and private debug logs.

Use `examples/m3/agent-replay-probe.md` for the blind prompt and contamination
rules, then collect the resulting proxy trace with
`examples/m3/collect-agent-replay-trace.sh`. The collector reuses the scripted
trace claim ladder while labeling the evidence as an authorized agent/scanner
replay trace.
