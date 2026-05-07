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

See [../docs/lab.md](../docs/lab.md) for Lab guardrails and target routes.

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
