# Eidolon Lab

Eidolon Lab is a local, owned-target evaluation harness for validating Eidolon's defensive boundary.

Lab exists to benchmark Eidolon, not offensive agents.

For metric definitions and the first summary schema, see [lab-metrics.md](lab-metrics.md).

## Safety Boundary

Use Lab only against systems you own or are explicitly authorized to test.

Do not point Lab runners, examples, or future agent integrations at public third-party targets.

Lab work should measure Eidolon boundary behavior:

- causal lift from controlled evidence
- false positives under benign traffic
- controlled-reality containment
- reduction of real-surface access after confidence rises

Lab work should not become:

- an agent leaderboard
- a benchmark corpus
- a solve-rate competition
- a general cyber range

## Demo Target

The first owned target is `eidolon-demo-target`.

Run it locally:

```sh
cargo run -p eidolon-demo-target
```

Default address:

```text
127.0.0.1:9001
```

The address can be changed with:

```sh
EIDOLON_LAB_TARGET_ADDR=127.0.0.1:9101 cargo run -p eidolon-demo-target
```

`EIDOLON_LAB_TARGET_ADDR` must be a loopback socket address. Wildcard or public binds such as `0.0.0.0:9001` are rejected.

The target exposes only synthetic, non-sensitive data:

- `GET /`
- `GET /health`
- `GET /docs`
- `GET /openapi.json`
- `GET /api/v1/projects`
- `GET /api/v1/projects/{id}`
- `POST /api/v1/imports`
- `GET /api/v1/imports/{id}`

The demo target is not intentionally vulnerable. It provides normal protected reality for Eidolon to sit in front of. Bait routes, rewritten docs, fake OpenAPI operations, and controlled reality belong to Eidolon, not to the target app.

Future proxy examples should use:

```text
EIDOLON_LAB_TARGET_URL=http://127.0.0.1:9001
```

Do not use public domains in Lab examples.

## Benign Baseline Runners

Benign baseline runners provide replayable negative-control traffic. They are expected to exercise normal target reality without synthesizing bait-derived follow-up actions.

Run all benign modes against the local demo target:

```sh
examples/baselines/benign.sh all
```

Run one mode:

```sh
examples/baselines/benign.sh curl-like
examples/baselines/benign.sh browser-like
examples/baselines/benign.sh crawler-like
```

The runner uses `EIDOLON_LAB_BASE_URL` and defaults to:

```text
http://127.0.0.1:9001
```

`EIDOLON_LAB_BASE_URL` must be a loopback HTTP URL. Public targets are rejected.

When Eidolon proxying exists, replay the same runner against the local proxy URL:

```sh
EIDOLON_LAB_BASE_URL=http://127.0.0.1:8080 examples/baselines/benign.sh all
```

Expected boundary result:

```text
confirmed bait-derived chain: false
```

These runners may fetch docs and OpenAPI. They must not call Eidolon-owned legacy bait routes or invent bait-derived headers.

Summarize benign baseline output:

```sh
examples/baselines/benign.sh all > /tmp/eidolon-benign.jsonl
examples/metrics/collect-benign.sh /tmp/eidolon-benign.jsonl
```
