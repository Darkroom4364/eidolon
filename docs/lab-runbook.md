# Eidolon Lab Runbook v0

This runbook validates the M0.5 local Lab harness.

It does not prove the full Eidolon Blackwall loop yet. M0.5 does not have the real proxy path, runtime bait exposure events, session correlation, trace reports, or controlled-reality routing. Those begin in M1 and M2.

Use this runbook to verify:

- the owned demo target runs locally
- benign traffic produces no bait-follow chain
- static comparison modes produce comparable metrics
- the future agentic scan shape stays local, defensive, and non-destructive

Do not use this runbook to rank agents, demonstrate exploitation, or claim Eidolon has detected an autonomous attacker.

## Safety Boundary

Only use loopback targets:

```text
127.0.0.1
localhost
::1
```

Do not point Lab runners or agent tools at public domains, third-party systems, production services, real secrets, real exploit chains, or external callbacks.

The demo target is synthetic and not intentionally vulnerable. Bait routes and controlled reality belong to Eidolon, not to the target app.

## Start The Demo Target

Run the local owned target:

```sh
cargo run -p eidolon-demo-target
```

Expected address:

```text
http://127.0.0.1:9001
```

Keep this process running in one shell.

## Run Benign Negative Controls

In another shell:

```sh
examples/baselines/benign.sh all > /tmp/eidolon-benign.jsonl
examples/metrics/collect-benign.sh /tmp/eidolon-benign.jsonl
```

Expected boundary result:

```text
bait_follow_rate: 0.0
false_positive_rate: 0.0
trace_confidence_score: 0
```

This confirms normal docs, OpenAPI, and API traffic do not synthesize bait-derived follow-up behavior.

## Run Static Defense Comparisons

Run the current comparison modes:

```sh
examples/baselines/defense-modes.sh all > /tmp/eidolon-baselines.jsonl
examples/metrics/collect-baselines.sh /tmp/eidolon-baselines.jsonl
```

The modes are:

- `no-defense`
- `static-token`
- `static-honeypot`
- `waf-style-block`

Interpret them narrowly:

- `no-defense` shows normal target exposure without a boundary decision.
- `static-token` and `static-honeypot` can show trap-follow behavior, but not per-session causal control.
- `waf-style-block` can reduce target forwarding, but it does not explain why a session was suspicious.

Eidolon needs to beat these controls by proving controlled evidence led to observed action and by reducing real-surface access after confidence rises.

## Local Agentic Scan Shape

M0.5 does not include a committed agent runner. If an operator uses a local authorized agentic scanner manually, the run must stay inside this shape:

```text
target: http://127.0.0.1:9001
objective: inspect the local synthetic app, docs, and OpenAPI
allowed behavior: normal HTTP discovery against the demo target
forbidden behavior: destructive actions, real exploit chains, external callbacks, public targets, secret exfiltration, or persistence
record: requested paths, whether docs/OpenAPI were fetched, whether any bait-derived action was attempted
```

For M0.5, the expected result is observational only. A request to an Eidolon-owned candidate bait path such as `/api/v2/import/reconcile` is a signal to record, not proof that the full Eidolon mechanism exists.

When the M1 proxy exists, the same local scan shape should point at the loopback proxy instead of the direct target:

```text
agent or runner -> http://127.0.0.1:8080 -> Eidolon proxy -> http://127.0.0.1:9001
```

Start the M1 proxy in front of the demo target:

```sh
cargo run -p eidolon-proxy -- \
  --listen-addr 127.0.0.1:8080 \
  --upstream http://127.0.0.1:9001 \
  --event-log /tmp/eidolon-events.jsonl \
  --intervention-control /tmp/eidolon-interventions.txt
```

Replay the benign baseline through the proxy:

```sh
EIDOLON_LAB_BASE_URL=http://127.0.0.1:8080 examples/baselines/benign.sh all > /tmp/eidolon-proxy-benign.jsonl
examples/metrics/collect-benign.sh /tmp/eidolon-proxy-benign.jsonl
```

The proxy assigns a first-party `eidolon_session` cookie when no valid session cookie is present. The cookie is host-only, `HttpOnly`, `SameSite=Lax`, scoped to `/`, and intentionally omits `Secure` for local HTTP Lab use.

The event log is JSONL. Request events record method, path, policy state, routing decision, session ID, and selected safe header presence. They do not log request bodies or header values.

The intervention control file is read per request. If it contains `disabled`, `disable`, `off`, or `0`, interventions are disabled without restarting the proxy and traffic is forwarded to protected upstream.

## What M0.5 Proves

M0.5 proves that Eidolon has a local, owned, replayable evaluation harness:

- synthetic demo target
- loopback-only guardrails
- benign negative controls
- static baseline comparisons
- v0 metric schema

## What M0.5 Does Not Prove

M0.5 does not yet prove:

- proxy enforcement
- per-session bait generation
- causal trace reconstruction from live proxy events
- controlled-reality containment
- autonomous-agent attribution
- production readiness

Those are the M1, M1.5, M2, and M2.5 workstreams.
