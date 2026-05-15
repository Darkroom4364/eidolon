# Examples

Examples are for local, owned-target Eidolon Lab use only.

Do not point example runners or future agent integrations at public third-party targets.

## Demo Target

Run the local synthetic target:

```sh
cargo run -p eidolon-demo-target
```

Then open:

```text
http://127.0.0.1:9001
```

The target binds to `127.0.0.1:9001` by default. To change the port, keep the bind address on loopback:

```sh
EIDOLON_LAB_TARGET_ADDR=127.0.0.1:9101 cargo run -p eidolon-demo-target
```

See [../docs/lab.md](../docs/lab.md) for Lab guardrails and target routes. See [../docs/lab-runbook.md](../docs/lab-runbook.md) for the current local runbook.

## Benign Baselines

With the demo target running, replay benign baseline traffic:

```sh
examples/baselines/benign.sh all
```

The runner supports:

```text
curl-like
browser-like
crawler-like
```

Use `EIDOLON_LAB_BASE_URL` to point the same traffic at a loopback proxy later:

```sh
EIDOLON_LAB_BASE_URL=http://127.0.0.1:8080 examples/baselines/benign.sh all
```

Collect a v0 metrics summary:

```sh
examples/baselines/benign.sh all > /tmp/eidolon-benign.jsonl
examples/metrics/collect-benign.sh /tmp/eidolon-benign.jsonl
```

## Defense Baseline Modes

Run comparison modes against the same local target:

```sh
examples/baselines/defense-modes.sh all > /tmp/eidolon-baselines.jsonl
examples/metrics/collect-baselines.sh /tmp/eidolon-baselines.jsonl
```

The runner supports:

```text
no-defense
static-token
static-honeypot
waf-style-block
```

These modes are local comparison controls for Eidolon's boundary metrics. They are not agent rankings.

## M3 Scripted Bakeoff

With the demo target and proxy running, emit the M3 comparison matrix:

```sh
examples/m3/bakeoff.sh all > /tmp/eidolon-m3-bakeoff.jsonl
examples/m3/collect-bakeoff.sh /tmp/eidolon-m3-bakeoff.jsonl
```

The runner compares `no-defense`, `static-token`, `static-honeypot`, `waf-style-block`, and `eidolon-mvp` against the five deterministic M3 bait classes. It validates the local artifact shape; final M3 still requires authorized agentic/scanner runs and trace evidence.

To collect proxy-trace-backed scripted action evidence, run the Eidolon mode
with the proxy log in the same artifact directory:

```sh
ART=/tmp/eidolon-m3-scripted-action-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"

# Start eidolon-proxy separately with:
#   --event-log "$ART/proxy-events.jsonl"
#   --intervention-control "$ART/interventions.txt"
#   --policy-state "$ART/policy-state.json"

EIDOLON_M3_RUNNER_KIND=scripted-action-trace \
  examples/m3/bakeoff.sh eidolon-mvp > "$ART/scripted-bakeoff.jsonl"
examples/m3/collect-bakeoff.sh "$ART/scripted-bakeoff.jsonl" \
  > "$ART/scripted-bakeoff-summary.json"
examples/m3/collect-action-trace.sh "$ART" > "$ART/action-trace-summary.json"
```

The action-trace collector reads `proxy-events.jsonl` and can prove scripted
same-session bait action and controlled-reality entry. It does not claim
autonomous agent behavior.

## M3 pwnkit Codex Bakeoff

With the demo target and Eidolon proxy running, collect a pwnkit Codex run
against both the defended proxy and direct target:

```sh
ART=/tmp/eidolon-m3-pwnkit-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"

# Start eidolon-proxy separately with:
#   --event-log "$ART/proxy-events.jsonl"
#   --intervention-control "$ART/interventions.txt"
#   --policy-state "$ART/policy-state.json"

examples/m3/pwnkit-codex.sh all "$ART"
examples/m3/collect-pwnkit-codex.sh "$ART" > "$ART/pwnkit-summary.json"
```

For source checkouts of pwnkit, set `PWNKIT_NODE_ENTRY` if the built CLI is not
at `~/Projects/pwnkit/dist/pwnkit.js`:

```sh
PWNKIT_NODE_ENTRY=/path/to/pwnkit/dist/pwnkit.js examples/m3/pwnkit-codex.sh all "$ART"
```

Some pwnkit builds exit nonzero when findings are present even after writing a
valid JSON report. The runner keeps those reports and continues the comparison;
missing or invalid reports still fail the run.

The collector reports whether pwnkit HTTP artifacts correlate with Eidolon proxy
requests by method, path, and timestamp window, and whether any M3 bait surface
or bait action was reached. It is evidence for the M3 bakeoff, not an agent
leaderboard.

For report language, prefer `comparison.claim_level` over the broad
`comparison.conclusion`; it distinguishes exposed-only bait, action-shaped
follow-up, same-session confirmation, and controlled-reality entry for
pwnkit-correlated proxy events.

To render the internal M3 uniqueness report from a pwnkit artifact and a
scripted action-trace artifact:

```sh
examples/m3/report.sh \
  --pwnkit-artifact /tmp/eidolon-m3-pwnkit-20260514-231846 \
  --action-artifact /tmp/eidolon-m3-scripted-action-20260515-111318 \
  > docs/research-report-m3.md
```

The report is Lab-only. It can summarize differential bait discovery and
scripted containment mechanics, but it must not be used to claim pwnkit reached
controlled reality until the pwnkit-correlated trace supports that claim.
