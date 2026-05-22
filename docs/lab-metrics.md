# Lab Metrics

Eidolon Lab metrics benchmark the defensive boundary, not offensive agents.

The first metrics are intentionally small. They should answer whether Eidolon controls perception, proves bait-derived behavior, and contains suspicious sessions better than static baselines.

## V0 Metrics

Required v0 metric names:

- `time_to_first_bait_action_seconds`
- `bait_follow_rate`
- `false_positive_rate`
- `trace_confidence_score`
- `real_surface_requests_after_containment`
- `controlled_reality_dwell_seconds`
- `controlled_reality_action_depth`
- `controlled_reality_branch_count`

### `time_to_first_bait_action_seconds`

Elapsed time between a recorded bait exposure and the first matching bait-derived action in the same session.

For benign baselines, this should be `null` because no bait action should occur.

### `bait_follow_rate`

Fraction of sessions or runs that perform a bait-derived follow-up action after exposure.

For benign baselines, this should be `0.0`.

### `false_positive_rate`

Fraction of benign runs that produce a confirmed bait-derived chain.

For benign baselines, this should be `0.0`.

### `trace_confidence_score`

Rule-based confidence score produced by Eidolon's trace layer.

For direct benign baseline traffic before the proxy/trace pipeline exists, this is represented as `0`.

### `real_surface_requests_after_containment`

Number of requests to protected target routes after a session enters controlled reality.

In trace/report summaries, this is `null` until a containment marker exists in the session. Once containment exists, it is the count of later `request_seen` events routed to `protected_upstream` or `rewritten_upstream`.

The temporary v0 shell collectors may still emit `null` until they consume proxy/trace events.

### `controlled_reality_dwell_seconds`

Elapsed time between the first and last controlled-reality containment marker in a session.

This is `null` until the session enters controlled reality or rate-limited containment.

### `controlled_reality_action_depth`

Number of actions observed while the session is inside controlled reality or rate-limited containment. The transition response that first moves a bait-derived request into controlled reality counts as the first action even though its request was initially audited as `eidolon_owned`.

This is `0` until the session enters controlled reality or rate-limited containment.

### `controlled_reality_branch_count`

Number of distinct controlled-reality paths touched by the session. This includes the transition request path when its response is served by controlled reality.

This is `0` until the session enters controlled reality or rate-limited containment.

## V0 Summary Schema

The first summary artifact is JSON:

```json
{
  "schema_version": 0,
  "run_kind": "benign_baseline",
  "boundary": "owned_loopback_lab",
  "request_count": 14,
  "mode_counts": {
    "curl_like": 4,
    "browser_like": 5,
    "crawler_like": 5
  },
  "status_counts": {
    "successful": 14,
    "failed": 0
  },
  "metrics": {
    "time_to_first_bait_action_seconds": null,
    "bait_follow_rate": 0.0,
    "false_positive_rate": 0.0,
    "trace_confidence_score": 0,
    "real_surface_requests_after_containment": null,
    "controlled_reality_dwell_seconds": null,
    "controlled_reality_action_depth": 0,
    "controlled_reality_branch_count": 0
  }
}
```

## M2.5 Trace/Report Derivation

The trace/report summary derives controlled-reality metrics only from the existing core event vocabulary:

- `controlled_reality_entered`
- `request_seen` and `response_served` with routing decision `controlled_reality` or `rate_limited`
- policy state values `controlled_reality` or `rate_limited`
- `policy_changed` events whose `from` or `to` state is `controlled_reality` or `rate_limited`

`controlled_reality_dwell_seconds` uses the first and last containment markers in trace order and computes elapsed event time. If there is only one marker, dwell is `0.0`.

`controlled_reality_action_depth` counts `request_seen` events whose routing decision or policy state places the request inside controlled reality or rate-limited containment, plus transition responses routed to controlled reality when the preceding request was not already counted.

`controlled_reality_branch_count` counts distinct request paths in those controlled actions, including the transition request path when the response is controlled.

`real_surface_requests_after_containment` counts later `request_seen` events routed to `protected_upstream` or `rewritten_upstream`. These are the trace/report signal for protected-surface access after containment has started.

## Collecting Benign Metrics

Start the demo target:

```sh
cargo run -p eidolon-demo-target
```

In another shell, collect benign baseline traffic and summarize it:

```sh
examples/baselines/benign.sh all > /tmp/eidolon-benign.jsonl
examples/metrics/collect-benign.sh /tmp/eidolon-benign.jsonl
```

Expected result:

```text
bait_follow_rate: 0.0
false_positive_rate: 0.0
trace_confidence_score: 0
```

The collector is a temporary v0 tool. Later M1/M2 work should produce richer metrics from proxy events, bait exposure events, trace scores, and policy transition events.

## Collecting Defense Baseline Metrics

Run the baseline comparison modes against the same owned demo target:

```sh
examples/baselines/defense-modes.sh all > /tmp/eidolon-baselines.jsonl
examples/metrics/collect-baselines.sh /tmp/eidolon-baselines.jsonl
```

The mode collector emits the same v0 metric keys for each comparison mode:

```json
{
  "schema_version": 0,
  "run_kind": "defense_baseline_comparison",
  "boundary": "owned_loopback_lab",
  "baseline_modes": {
    "static_token": {
      "source_mode": "static-token",
      "metrics": {
        "time_to_first_bait_action_seconds": 0.0,
        "bait_follow_rate": 1.0,
        "false_positive_rate": 0.0,
        "trace_confidence_score": 50,
        "real_surface_requests_after_containment": null,
        "controlled_reality_dwell_seconds": null,
        "controlled_reality_action_depth": 0,
        "controlled_reality_branch_count": 0
      }
    }
  }
}
```

The v0 static baseline trace score is capped. Static clues can show that a trap was followed, but they do not prove per-session causal control the way Eidolon is meant to prove it.

## Collecting M3 Scripted Bakeoff Metrics

The M3 scripted runner compares the deterministic bait catalog against the same owned Lab target and emits one JSONL stream for all comparison modes:

```sh
examples/m3/bakeoff.sh all > /tmp/eidolon-m3-bakeoff.jsonl
examples/m3/collect-bakeoff.sh /tmp/eidolon-m3-bakeoff.jsonl
```

The summary uses the same v0 metric keys per defense mode and per bait class. It adds `bait_classes` under each mode so the M3 report can later classify each bait class as keep, revise, or kill.

This scripted summary is not sufficient for the final M3 uniqueness claim. It validates the matrix and artifact format before authorized agentic/scanner runs and proxy trace-derived reports.

For the scripted containment mechanics claim, collect the proxy trace from the
same run:

```sh
ART=/tmp/eidolon-m3-scripted-action-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"
mkdir -p "$ART/private"

# Start eidolon-proxy separately with:
#   --event-log "$ART/proxy-events.jsonl"
#   --debug-log "$ART/private/eidolon-debug.jsonl"
#   --intervention-control "$ART/interventions.txt"
#   --policy-state "$ART/policy-state.json"

EIDOLON_M3_RUNNER_KIND=scripted-action-trace \
  examples/m3/bakeoff.sh eidolon-mvp > "$ART/scripted-bakeoff.jsonl"
examples/m3/collect-bakeoff.sh "$ART/scripted-bakeoff.jsonl" \
  > "$ART/scripted-bakeoff-summary.json"
examples/m3/collect-action-trace.sh "$ART" > "$ART/action-trace-summary.json"
```

`collect-action-trace.sh` reads the proxy JSONL directly. It can support
`controlled_reality_entered` for the scripted harness, but it is not autonomous
agent evidence.

## Collecting M3 pwnkit Codex Metrics

The pwnkit Codex runner records an authorized local agentic scan against the
Eidolon proxy and the direct demo target. Start the demo target and proxy first,
using one artifact directory for the proxy event log:

```sh
ART=/tmp/eidolon-m3-pwnkit-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"
mkdir -p "$ART/private"
```

Start `eidolon-proxy` with:

```sh
--event-log "$ART/proxy-events.jsonl"
--debug-log "$ART/private/eidolon-debug.jsonl"
--intervention-control "$ART/interventions.txt"
--policy-state "$ART/policy-state.json"
```

The debug log is a server-side JSONL stream for operator inspection only. It
records sanitized proxy internals such as request lifecycle, policy state,
surface decisions, bait exposure/action handling, rewrite outcomes, upstream
forwarding, and response status. It intentionally omits request/response bodies,
header values, and query strings, and the proxy never reflects it into HTTP
responses, pwnkit scope files, pwnkit auth files, or normalized pwnkit reports.
Keep it outside any served target directory and do not pass its path to pwnkit.

Then run the pwnkit scans and collector:

```sh
examples/m3/pwnkit-codex.sh all "$ART"
examples/m3/collect-pwnkit-codex.sh "$ART" > "$ART/pwnkit-summary.json"
```

Current pwnkit main routes `--runtime codex` through the direct ChatGPT Codex
provider. The runner no longer sets the removed legacy Codex-live feature flag by
default. When running from a pwnkit source checkout, rebuild after pulling
upstream changes:

```sh
(cd ~/Projects/pwnkit && pnpm run build)
```

`examples/m3/pwnkit-codex.sh` refuses obviously stale source-checkout
`dist/pwnkit.js` bundles, including bundles that still contain the removed Codex
MCP live runner. `EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST=1` exists only for debugging
old artifacts. Each run writes `$ART/pwnkit-runner-metadata.json` with the
resolved command, runtime settings, source-checkout package version, git head,
dirty-worktree state, local `origin/main` ahead/behind counts, dist mtime, and
generated pwnkit scope files; the collector copies this into
`pwnkit-summary.json` under `runner`. For current-behavior claims against a
moving pwnkit mainline, prefer artifacts where
`runner.pwnkit.origin_main.in_sync` is `true` and
`runner.pwnkit.git_dirty` is `false`.

The repeated sample runner executes `examples/m3/pwnkit-codex.sh preflight`
before starting the Lab target. Preflight writes only pwnkit scopes and
`pwnkit-runner-metadata.json`, then `check-pwnkit-runner-freshness.sh` fails
dirty or unsynced source-checkout runs before any scan. Set
`EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE=1` only for diagnostic preservation.

The runner captures pwnkit stdout as `$ART/pwnkit-<leg>.stdout.log` and writes a
normalized JSON-only report to `$ART/pwnkit-<leg>.json`. This preserves current
pwnkit cost footers for audit while keeping collector input strict JSON.

The collector emits shape-only finding diagnostics for differential-finding
work. These diagnostics count finding severities, categories, confidence labels,
field presence, and evidence presence, but intentionally omit finding titles,
descriptions, raw evidence, request bodies, raw URLs, and analysis text. Use
`comparison.finding_gap` to distinguish:

- pwnkit reported more Eidolon findings than direct-target findings
- pwnkit observed target evidence but reported no Eidolon findings
- pwnkit reached bait, replayed a bait-shaped action, or entered controlled
  reality without reporting an Eidolon finding

The corresponding sample-level fields live under `differential_findings`. See
[`m3-pwnkit-differential-findings.md`](m3-pwnkit-differential-findings.md) for
the investigation checklist and interpretation rules.

The runner now writes `$ART/pwnkit-eidolon-scope.json` and
`$ART/pwnkit-direct-scope.json`, then passes the matching file with `--scope` on
each scan leg. Current pwnkit shell-mode auth injection is intentionally scoped:
without a scope file, curl/wget commands cannot be safely rewritten with
operator-provided credentials. Treat unscoped authenticated pwnkit artifacts as
invalid for M3 pinned-session conclusions.

For a session-control replay probe, set `EIDOLON_M3_PIN_SESSION=1` on the
pwnkit command. The runner gives only the Eidolon leg one generated
`eidolon_session` cookie and records the UUID in
`$ART/pinned-eidolon-session-id.txt`. This is useful when testing whether an
observed marker replay can become same-session evidence without seeding the
marker itself.

When that file is present, the pwnkit and agent-trace collectors emit a
`pinned_session` object. `proxy_request_count` answers whether the proxy saw
the pinned cookie at all, while the correlated pwnkit counts answer whether the
cookie was part of the agent evidence stream. A run with
`proxy_request_count: 0` means the auth file was generated but the scanner did
not preserve the session cookie on observed proxy requests.

The collector consumes pwnkit SQLite `tool_artifact` events and Eidolon proxy
JSONL events. It treats target interaction as observed only when pwnkit evidence
matches an Eidolon proxy request by method, path, and timestamp window. The
pwnkit evidence can be a structured `http_request` artifact or a `bash` artifact
whose HTTP transcript exposes method/path/status. A `bait_not_reached`
conclusion therefore means pwnkit had correlated interaction with the protected
target through Eidolon, but did not request any owned M3 bait surface. If that
correlation is absent, the conclusion is `no_target_interaction` and the run is
not evidence for bait discoverability.

The collector also emits `runs.<leg>.agent_error_diagnostics` from pwnkit
`agent_error` events. This is sanitized runtime telemetry: counts,
stage/agent-role counts, coarse error classes, and booleans for Codex auth or
token-refresh failures. It does not include raw pwnkit error strings. In
`no_signal` runs, a `pwnkit_codex_token_refresh_failure_prevented_request_artifacts`
or `pwnkit_agent_errors_prevented_request_artifacts` likely cause must be
cleared with an agent-error-free rerun before interpreting bait behavior. The
sample runner enforces this by default after each collected run. Set
`EIDOLON_M3_ALLOW_AGENT_ERRORS=1` only when intentionally preserving diagnostic
no-signal artifacts.

The summary separates the strength of the pwnkit-correlated bait evidence.
`comparison.conclusion` keeps the broad runner outcome, while
`comparison.claim_level` states the strongest supported claim:

- `bait_exposed_without_action`: the agent reached a bait surface only.
- `bait_action_observed_without_same_session`: the agent made a bait-shaped
  follow-up action, but did not preserve the original Eidolon session.
- `same_session_bait_action_confirmed`: the follow-up action carried an
  exposure ID from a prior pwnkit-correlated bait exposure in the same session.
- `controlled_reality_entered`: the pwnkit-correlated confirmed chain reached
  containment.

Use `metrics.bait_follow_rate` for action-shaped follow-up rate and
`metrics.same_session_confirmed_bait_follow_rate` for the stricter confirmed
same-session rate. These rates are computed from `comparison.correlated_bait_events`,
not from unrelated proxy traffic that may share the artifact directory.

The current post-merge M3 note is recorded in
[`docs/research-note-m3.md`](research-note-m3.md). It records a fresh current
pwnkit run plus a strict collector pass that extracts the pwnkit shell-mode HTTP
transcript and correlates one same-session bait action into
`controlled_reality_entered`. Older stale-runner artifacts remain historical
only and must not be used to claim current pwnkit behavior.

To collect a repeated current-pwnkit sample from a synced source checkout, use
the sample wrapper. It starts the local demo target once, starts a fresh proxy
for each run with per-run `proxy-events.jsonl` and
`private/eidolon-debug.jsonl`, runs pinned direct and Eidolon pwnkit legs,
collects each run, then aggregates the sample:

```sh
examples/m3/run-pwnkit-sample.sh 3 /tmp/eidolon-m3-pwnkit-sample
```

The wrapper writes the aggregate to
`/tmp/eidolon-m3-pwnkit-sample/pwnkit-stability-sample.json`. To aggregate
already-collected runs manually, pass their artifact directories to
`examples/m3/collect-pwnkit-sample.sh`.

To prepare a commit-safe evidence bundle from a completed sample, package it
through the redaction helper:

```sh
examples/m3/package-pwnkit-sample.sh \
  /tmp/eidolon-m3-pwnkit-sample \
  docs/evidence/m3/pwnkit-sample-YYYY-MM-DD
```

The packager writes redacted per-run summaries, sanitized trace summaries, a
sample aggregate, a README, and `SHA256SUMS`. It intentionally omits raw pwnkit
databases, auth files, stdout/stderr logs, full proxy event logs, and private
Eidolon debug logs.

For the finding-promotion investigation, keep the runner shape identical and
vary only owned bait surfaces with a lab-only profile:

```sh
EIDOLON_M3_BAIT_PROFILE=examples/m3/bait-profiles/openapi-promotion-probe.json \
  examples/m3/run-pwnkit-sample.sh 3 /tmp/eidolon-m3-pwnkit-promotion-openapi
```

To run the full seed matrix, use the promotion matrix wrapper:

```sh
examples/m3/run-pwnkit-promotion-matrix.sh \
  examples/m3/bait-promotion-variants.json \
  /tmp/eidolon-m3-pwnkit-promotion-matrix
```

The wrapper runs `examples/m3/run-pwnkit-sample.sh` once per manifest variant,
varying only `EIDOLON_M3_BAIT_PROFILE`, then writes
`pwnkit-promotion-matrix.json`. The summary classifies each variant as
`promoted_finding`, `behavior_only`, `bait_reached_only`, or another observation
class from the same shape-only sample counters. Use
`EIDOLON_M3_PROMOTION_RUNS=3` when collecting evidence for a stability claim;
the default is `1` so exploratory profile tuning does not accidentally launch a
long matrix.

To aggregate already-collected variant samples manually:

```sh
examples/m3/collect-pwnkit-promotion-matrix.sh \
  examples/m3/bait-promotion-variants.json \
  /tmp/eidolon-m3-pwnkit-promotion-matrix \
  > /tmp/eidolon-m3-pwnkit-promotion-matrix/pwnkit-promotion-matrix.json
```

`examples/m3/bait-promotion-variants.json` is the seed matrix manifest. Each row
names a profile, hypothesis, changed knobs, and expected observation class
without changing the direct-target leg.

To prepare a commit-safe evidence bundle from a completed promotion matrix,
package it through the matrix redaction helper:

```sh
examples/m3/package-pwnkit-promotion-matrix.sh \
  /tmp/eidolon-m3-pwnkit-promotion-matrix \
  docs/evidence/m3/pwnkit-promotion-matrix-YYYY-MM-DD
```

The packager reuses the sample packager for each observed variant, writes a
redacted matrix aggregate, copies the manifest, and emits `SHA256SUMS`. It
omits raw pwnkit databases, auth files, stdout/stderr logs, full proxy events,
and private Eidolon debug logs from every variant.

The sample summary reports per-run claim levels, runner git heads, pwnkit
package versions, source-checkout freshness, pinned-cookie preservation,
direct-target quietness, and strict pass rates. Treat
`strict_stability.ready_for_stability_claim: true` as the minimum gate before
describing current-pwnkit behavior as stable across repeated Lab scans; it
requires at least three valid summaries from one runner git head, all with clean
source-checkout metadata synced with local `origin/main`, target interaction,
same-session confirmed bait action, controlled-reality entry, preserved pinned
cookies, and quiet direct-target runs.

To generate the internal M3 uniqueness report from the pwnkit and scripted
action-trace artifacts:

```sh
examples/m3/report.sh \
  --pwnkit-artifact /tmp/eidolon-m3-pinned-metrics-EPFsYY \
  --action-artifact /tmp/eidolon-m3-scripted-action-VGXkkh \
  > docs/research-report-m3.md
```

The report combines the pwnkit comparison, proxy trace containment metrics, and
class-level keep/revise/kill guidance. It also surfaces
`comparison.finding_gap` so the report distinguishes bait interaction and
controlled-reality entry from actual differential pwnkit findings. It preserves
the distinction between pwnkit exposure evidence and scripted-only containment
mechanics.

## Interpretation Guardrail

Metrics must describe Eidolon boundary behavior:

- how often controlled evidence causes follow-up action
- how often benign traffic is falsely classified
- how much protected-surface access drops after containment
- how clear the evidence trace is

Metrics must not rank agents, measure offensive solve rate, or become a leaderboard.
