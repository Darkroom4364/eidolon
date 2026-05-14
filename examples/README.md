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
