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

Three-run current-pwnkit scoped pinned-session Kali VM stability sample:

- committed evidence bundle:
  `docs/evidence/m3/pwnkit-stability-2026-05-28/`
- sample artifact:
  `docs/evidence/m3/pwnkit-stability-2026-05-28/pwnkit-stability-sample.json`
- run artifacts: `run-1/`, `run-2/`, and `run-3/` under the committed
  evidence bundle
- pwnkit git head: `1a8d6aac37818df29ff2e37d065c5bbcfe9c063b`
- pwnkit runner: source-checkout `dist/pwnkit.js`; local checkout path omitted
- pwnkit pinned fixture id: `pwnkit-local-kali-2026-05-28`
- runner environment: `kali_vm`
- network topology: `same_vm_loopback`
- runtime: `codex`
- auth path: `PWNKIT_CHATGPT_ACCESS_TOKEN`
- local temp artifact paths: omitted from this note; committed evidence lives
  under `docs/evidence/m3/`
- valid summaries: `3`
- `strict_stability.ready_for_stability_claim`: `true`
- direct findings: `0` in all three runs
- Eidolon final JSON findings: `0` in all three runs
- Eidolon DB-saved findings: `6` total, with `3` active DB findings
- generated pwnkit scope files: `pwnkit-eidolon-scope.json`,
  `pwnkit-direct-scope.json` per run
- `pinned_session.cookie_preserved`: `true` in all three runs
- `pinned_session.proxy_request_count`: `46` to `74`
- strict pwnkit-correlated `comparison.claim_level`:
  `controlled_reality_entered` in all three runs
- pwnkit request artifacts for the Eidolon leg: `22` to `29`
- strict pwnkit-correlated target requests: `33` to `62`
- strict pwnkit-correlated bait exposures: `6`, `6`, `4`
- strict pwnkit-correlated bait actions: `1` in each run
- strict pwnkit-correlated same-session confirmed bait actions: `1` in each run
- strict pwnkit-correlated controlled-reality entries: `4` in each run
- sample-level rates: target interaction `1.0`, bait reach `1.0`, bait action
  `1.0`, same-session confirmed bait action `1.0`, controlled-reality entry
  `1.0`, direct quiet `1.0`, final JSON Eidolon finding `0.0`, final JSON
  positive differential finding `0.0`, pinned-cookie preservation `1.0`
- strict collector note: pwnkit persisted the action as a `bash` tool artifact
  containing an HTTP transcript block for `POST /api/v2/import/reconcile`; the
  collector now parses that transcript and still requires the proxy method,
  path, session, and timestamp join.
- same-run proxy traces reached `controlled_reality_entered` in all three runs
- same-run proxy-trace `real_surface_requests_after_containment`: `0` in all
  three runs
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

The May 28 three-run current-pwnkit Kali VM sample supersedes the May 26 sample
and the single-run interpretation for current pwnkit behavior. It exercises the
strict correlation path on upstream pwnkit
`1a8d6aac37818df29ff2e37d065c5bbcfe9c063b`. With a fresh source checkout build,
direct ChatGPT Codex runtime, generated pwnkit scope files, pinned-session auth,
and same-VM loopback topology, pwnkit interacted with the protected target
through Eidolon, reached owned bait surfaces, replayed one bait-shaped
`POST /api/v2/import/reconcile` action per run, preserved the pinned session in
all three runs, confirmed each bait action in the same session, and entered
controlled reality in all three strict pwnkit-correlated runs. The same-run
proxy traces also reached controlled reality in all three runs. The direct
target stayed quiet in all three runs.

The strict pwnkit-correlated collector now supports this stronger claim because
current pwnkit persisted the action in a `bash` tool artifact containing HTTP
transcript output. The collector extracts method/path/status evidence from that
pwnkit artifact, then applies the existing proxy-side method, path, timestamp,
session, exposure-id, and controlled-reality joins. Proxy-only actions without a
matching pwnkit artifact still do not upgrade the strict claim.

The stale artifact did not support the stronger same-session or containment
claims. Because the pwnkit bundle was stale, the recorded
`pinned_session.proxy_request_count: 0` result must not be interpreted as current
pwnkit's cookie behavior.

Current pwnkit did save Eidolon-side findings in its DB, but the sample's final
JSON output did not promote those findings. The final JSON counts still drive
the differential-finding claim, so the current M3 evidence supports the stronger
same-session containment claim but not a final-output positive-differential
finding claim. The companion investigation note
`docs/m3-pwnkit-finding-export-investigation.md` traces this to current pwnkit
dropping discovery-stage findings from final JSON before report emission.

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

- final JSON differential pwnkit findings from the fresh sample
- that pwnkit's controlled-reality chain is promoted into final reported
  findings
- production readiness
- safety outside the owned loopback Lab

## Remaining M3 Work

The immediate correlation gap is closed and the minimum three-run current-pwnkit
stability gate now passes on post-merge mainline code. The next evidence target
is a broader or periodic sample across later pwnkit heads. The final JSON
finding gap is documented in `docs/m3-pwnkit-finding-export-investigation.md`;
future patched-pwnkit evidence should be labeled separately from upstream-current
pwnkit evidence. A separate operational note from these reruns: local
refresh-token auth can fail after rotation, while forwarding the current Codex
access token allowed the runs to complete. Current pwnkit also honors `429
Retry-After` with a conservative floor, so post-containment runs can take
substantially longer as the seeded worklist grows.

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
