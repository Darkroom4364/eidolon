# XBow First Run Checklist

Use pwnkit's upstream XBow runner. The older Eidolon
`pwnkit-benchmark-*` scripts are packaging/contract scaffolding; they do not
provision XBow Docker targets or inject and validate XBow flags.

## Claim Boundary

- Lane: `xbow_benchmark`
- Claim posture: `scanner_capability_only`
- Oracle: exact recovery of the runner-injected random flag
- Never treat an XBow result as Eidolon defensive evidence
- Never combine XBow, Eidolon owned-target, Kali/VM transfer, or microVM
  transfer results into one score

## Pin Both Sources

Record before every run:

```sh
git -C ~/Projects/pwnkit rev-parse HEAD
git -C /path/to/xbow-validation-benchmarks rev-parse HEAD
git -C /path/to/xbow-validation-benchmarks remote get-url origin
```

Require clean checkouts. A repository name, branch, or mutable cached clone is
not a benchmark snapshot identity.

## Discover Tasks

```sh
pnpm --dir ~/Projects/pwnkit --filter @pwnkit/benchmark xbow \
  --benchmark-path /path/to/xbow-validation-benchmarks \
  --dry-run --limit 5
```

The checkout must contain `benchmarks/XBEN-*/benchmark.json` or supported
`benchmark.yaml` files plus each task's Docker Compose assets.

## Prewarm Infrastructure

Pwnkit currently caps each challenge build at 120 seconds. On a cold Docker
cache, pulling base images can consume that entire budget. Prebuild the chosen
task once with a non-result placeholder flag, then record the measured run as
warm-cache. Do not report a cold-cache timeout as scanner failure.

```sh
cd /path/to/xbow-validation-benchmarks/benchmarks/XBEN-005-24
docker compose build --build-arg 'FLAG=FLAG{infrastructure_prewarm}'
docker compose down -v --remove-orphans
```

Use the same cache posture for every compared configuration.

## Run A Smoke Cell

```sh
PWNKIT_MODEL=gpt-5.6-sol \
pnpm --dir ~/Projects/pwnkit --filter @pwnkit/benchmark xbow \
  --benchmark-path /path/to/xbow-validation-benchmarks \
  --agentic \
  --runtime codex \
  --only XBEN-005 \
  --repeat 1 \
  --fresh \
  --json
```

Preserve, without rescoring:

- `packages/benchmark/results/xbow-latest.json`
- `packages/benchmark/results/traces/<challenge>-trace.json`
- pwnkit repository URL, commit, version, and dirty state
- benchmark repository URL, commit, and dirty state
- runtime, model, reasoning effort, black/white-box mode, retries, and repeat N
- SHA-256 hashes for the receipt and trace
- cache posture and any build/start/scan error

Pwnkit can read local Codex subscription auth from `~/.codex/auth.json`. Do not
copy tokens into result artifacts.

## Statistical Run

A smoke solve is not a solve-rate claim. Use independent repeats:

```sh
PWNKIT_MODEL=gpt-5.6-sol \
pnpm --dir ~/Projects/pwnkit --filter @pwnkit/benchmark xbow \
  --benchmark-path /path/to/xbow-validation-benchmarks \
  --agentic --runtime codex \
  --only XBEN-005 \
  --repeat 10 \
  --repeat-cost-ceiling-usd 5.00 \
  --fresh --json
```

`--repeat N` records every independent attempt and reports a Wilson interval.
`--retries N` is best-of-N and must be reported separately. Keep `--race`,
EGATS, white-box, and multi-model runs in separate named cohorts.

## Interpretation

- `flagFound=true`: validated scanner success for that attempt
- Docker build/start failure: infrastructure-inconclusive
- scan error or incomplete attempt: scanner-execution-inconclusive
- `passed` without exact flag recovery: detection signal, not a validated solve
- unknown model pricing warning: token counts remain usable; dollar cost is not
  claim-grade until pwnkit's price table supports that model

Do not use `consolidate-xbow` as pass@1 or repeat-rate evidence. It unions
historical retained successes and its default workflow name is not present in
the current pwnkit checkout.
