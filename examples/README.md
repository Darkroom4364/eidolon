# Examples

Examples are for local, owned-target Eidolon Lab use only.

Do not point example runners or future agent integrations at public third-party targets.

## Edge Adapters

Trusted ingress adapters belong at the edge, not inside the proxy runtime.

The first concrete adapter is the Cloudflare Worker example in
[edge/cloudflare](edge/cloudflare/README.md). It strips forged
`X-Eidolon-*` headers, maps official Cloudflare bot signals into the normalized
Eidolon ingress contract, and forwards to the protected origin. The same
directory also includes a Cloudflare request-header Transform Rules payload for
zones that want a Workerless transport path.

Run its local mapping test with:

```sh
examples/edge/test-cloudflare-worker.sh
```

Run the Transform Rules payload test with:

```sh
examples/edge/test-cloudflare-transform-rules.sh
```

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

## Scanner Qualification

To separate scanner-quality claims from Eidolon's M3 uniqueness closeout, use
the dedicated pwnkit qualification matrix:

```sh
examples/qualification/run-pwnkit-qualification-matrix.sh
```

The seed manifest lives at
[`qualification/pwnkit-qualification-variants.json`](qualification/pwnkit-qualification-variants.json).
It records positive-control, transfer-control, direct-only negative-control,
and stock-vs-patched comparison slots separately from M3. The negative-control
path uses the dedicated simple owned target profile through
`examples/qualification/run-pwnkit-direct-qualification-sample.sh`, the
stock-vs-patched path compares one `upstream_current` local sample against the
canonical `local_patched_pwnkit` sample through
`examples/qualification/run-pwnkit-stock-vs-patched-qualification-sample.sh`,
and the VM-backed Kali variants still flow through the existing wrappers. In
dry-run mode the matrix also writes `vm-spool-plan.json` so those VM
requirements stay explicit without pretending the repo already owns a real VM
provisioner:

```sh
EIDOLON_PWNKIT_QUAL_DRY_RUN=1 \
  examples/qualification/run-pwnkit-qualification-matrix.sh
```

To turn a completed matrix into a review bundle plus Markdown summary:

```sh
examples/qualification/report-pwnkit-qualification-matrix.sh /tmp/eidolon-pwnkit-qualification
examples/qualification/package-pwnkit-qualification-matrix.sh \
  /tmp/eidolon-pwnkit-qualification \
  /tmp/eidolon-pwnkit-qualification-bundle
```

To exercise the direct-only negative-control sample by itself:

```sh
examples/qualification/run-pwnkit-direct-qualification-sample.sh \
  3 \
  /tmp/eidolon-pwnkit-direct-qualification
examples/qualification/package-pwnkit-direct-qualification-sample.sh \
  /tmp/eidolon-pwnkit-direct-qualification \
  /tmp/eidolon-pwnkit-direct-qualification-bundle
```

To exercise the stock-vs-patched comparison sample by itself:

```sh
examples/qualification/run-pwnkit-stock-vs-patched-qualification-sample.sh \
  3 \
  /tmp/eidolon-pwnkit-stock-compare
examples/qualification/package-pwnkit-stock-vs-patched-qualification-sample.sh \
  /tmp/eidolon-pwnkit-stock-compare \
  /tmp/eidolon-pwnkit-stock-compare-bundle
```

The initial matrix reuses existing runners:

- `examples/m3/run-pwnkit-sample.sh`
- `examples/m3/run-pwnkit-kali-vm.sh`
- `examples/shield-lab/run-pwnkit-kali-vm.sh`

To turn the matrix `vm-spool-plan.json` into real OrbStack Kali machines plus
host-side helper scripts for the mapped VM wrappers:

```sh
examples/qualification/spool-pwnkit-qualification-orbstack-vms.sh \
  /tmp/eidolon-pwnkit-qualification/vm-spool-plan.json \
  /tmp/eidolon-pwnkit-vm-spool
```

## M3 pwnkit Codex Bakeoff

With the demo target and Eidolon proxy running, collect a pwnkit Codex run
against both the defended proxy and direct target:

```sh
ART=/tmp/eidolon-m3-pwnkit-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"
mkdir -p "$ART/private"

# Start eidolon-proxy separately with:
#   --event-log "$ART/proxy-events.jsonl"
#   --debug-log "$ART/private/eidolon-debug.jsonl"
#   --intervention-control "$ART/interventions.txt"
#   --policy-state "$ART/policy-state.json"

examples/m3/pwnkit-codex.sh all "$ART"
examples/m3/collect-pwnkit-codex.sh "$ART" > "$ART/pwnkit-summary.json"
```

The runner defaults to a local pwnkit source checkout at `~/Projects/pwnkit` and
invokes `dist/pwnkit.js` from that checkout. It intentionally does not fall back
to globally installed or package-manager pwnkit binaries. Rebuild after every
pwnkit checkout change:

```sh
(cd ~/Projects/pwnkit && pnpm run build)
examples/m3/pwnkit-codex.sh all "$ART"
```

Set `PWNKIT_SOURCE_DIR` when the local checkout lives elsewhere, or
`PWNKIT_NODE_ENTRY` for an explicit built entrypoint:

```sh
PWNKIT_SOURCE_DIR=/path/to/pwnkit examples/m3/pwnkit-codex.sh all "$ART"
```

The runner generates one pwnkit `--scope` file per scan leg:
`$ART/pwnkit-eidolon-scope.json` for the proxy target and
`$ART/pwnkit-direct-scope.json` for the direct target. This is part of the
evidence contract for current pwnkit because shell-mode credential injection is
scope-aware.

Raw pwnkit stdout is kept as `$ART/pwnkit-<leg>.stdout.log`; the collector reads
the normalized JSON-only `$ART/pwnkit-<leg>.json` files.
`$ART/private/eidolon-debug.jsonl`, when enabled, is a server-side operator log
only. It records sanitized Eidolon decisions and never appears in HTTP responses,
pwnkit scope files, auth files, or normalized pwnkit reports.
When the runner uses a pwnkit source checkout, `$ART/pwnkit-runner-metadata.json`
also records the pwnkit package version, git head, dirty-worktree state, and the
local `origin/main` ahead/behind relation. It also records
`runner.environment.runner_environment`, `network_topology`, and a sanitized tool
fingerprint so archived or private local pwnkit fixtures can be interpreted
later. Set `EIDOLON_M3_PWNKIT_FIXTURE_ID` for a clean pinned fixture; leave it
unset and require `origin_main.in_sync == true` plus `git_dirty == false` for
current-main claims.

To test whether an observed replay can preserve one Eidolon Lab session without
seeding any bait markers, pin the Eidolon leg to a generated session cookie:

```sh
EIDOLON_M3_PIN_SESSION=1 examples/m3/pwnkit-codex.sh all "$ART"
```

The runner writes the generated UUID to
`$ART/pinned-eidolon-session-id.txt` and passes it only as the
`eidolon_session` cookie for the Eidolon scan leg. This is a session-control
experiment, not a marker-seeding experiment.

Some pwnkit builds exit nonzero when findings are present even after writing a
valid JSON report. The runner keeps those reports and continues the comparison;
missing or invalid reports still fail the run.

The collector reports whether pwnkit target-tool artifacts correlate with
Eidolon proxy requests by method, path, and timestamp window, and whether any M3
bait surface or bait action was reached. It reads structured pwnkit
`http_request` artifacts and shell-mode `bash` artifacts whose HTTP transcript
contains method/path/status evidence. It keeps final JSON findings separate from
DB-saved finding rows with `finding_reconciliation` and `finding_export_gap`. It
is evidence for the M3 bakeoff, not an agent leaderboard.

For report language, prefer `comparison.claim_level` over the broad
`comparison.conclusion`; it distinguishes exposed-only bait, action-shaped
follow-up, same-session confirmation, and controlled-reality entry for
pwnkit-correlated proxy events.

To summarize repeated current-pwnkit runs from a synced source checkout, use the
sample wrapper:

```sh
examples/m3/run-pwnkit-sample.sh 3 /tmp/eidolon-m3-pwnkit-sample
```

It starts the owned demo target, starts a fresh proxy per run with private debug
logs, runs pinned direct and Eidolon pwnkit legs, collects each run, and writes
`/tmp/eidolon-m3-pwnkit-sample/pwnkit-stability-sample.json`. The sample report
keeps one row per artifact and emits strict stability gates.
Use `strict_stability.ready_for_stability_claim` only for repeated-run Lab
stability language; single successful traces remain single-trace evidence.

For VM-local Kali evidence, use
[`m3/kali-vm-pwnkit.md`](m3/kali-vm-pwnkit.md) and run
`examples/m3/run-pwnkit-kali-vm.sh` from inside the Kali VM. The wrapper does
not create or manage the VM; it enforces `runner_environment=kali_vm`,
`network_topology=same_vm_loopback`, loopback target/proxy URLs, and an artifact
directory outside the Eidolon checkout.

For finding-promotion experiments, pass a lab-only bait profile through the
sample runner:

```sh
EIDOLON_M3_BAIT_PROFILE=examples/m3/bait-profiles/openapi-promotion-probe.json \
  examples/m3/run-pwnkit-sample.sh 3 /tmp/eidolon-m3-pwnkit-promotion-openapi
```

The seed promotion manifest is
[`m3/bait-promotion-variants.json`](m3/bait-promotion-variants.json). Profiles
change only owned bait surfaces and OpenAPI insertions; ordinary traffic still
uses the protected upstream path.

To prepare a sample for committing under `docs/evidence/m3/`, package only the
redacted evidence:

```sh
examples/m3/package-pwnkit-sample.sh \
  /tmp/eidolon-m3-pwnkit-sample \
  docs/evidence/m3/pwnkit-sample-YYYY-MM-DD
```

The package helper omits raw pwnkit DBs, auth files, stdout/stderr logs, full
proxy event logs, and private debug logs.

To render the internal M3 uniqueness report from a pwnkit artifact and a
scripted action-trace artifact:

```sh
examples/m3/report.sh \
  --pwnkit-artifact /tmp/eidolon-m3-agent-replay-iZLjjN \
  --action-artifact /tmp/eidolon-m3-scripted-action-VGXkkh \
  > docs/research-report-m3.md
```

The report is Lab-only. It can summarize differential bait discovery and
containment mechanics when the pwnkit-correlated trace supports those claims,
but it must not be used as a production-readiness or autonomous-attacker
attribution claim.

## M3 Agent Replay Probe

Strict current-pwnkit same-session replay and controlled-reality entry are
covered by the archived three-run Lab sample. Use
[m3/agent-replay-probe.md](m3/agent-replay-probe.md) for later pwnkit heads,
broader authorized local subjects, and drift checks that need the blind prompt
and contamination rules.

After an authorized loopback subject finishes, collect its proxy trace:

```sh
examples/m3/collect-agent-replay-trace.sh "$ART" \
  > "$ART/agent-replay-trace-summary.json"
```

This wrapper uses the same trace claim ladder as the scripted action collector,
but labels the artifact as an authorized agent/scanner replay trace. It still
does not prove autonomous behavior unless the companion agent/tool artifact shows
the subject was not seeded with the bait catalog.
