# Architecture

## Mental Model

The full Eidolon project has five major parts:

```text
1. Edge Boundary
2. Surface Controller
3. Bait/Canary Engine
4. Trace Intelligence
5. Policy Router
```

Runtime view:

```text
external actor / scanner / autonomous agent
                  |
                  v
          +------------------+
          | Eidolon Edge   |
          +------------------+
             |            |
             |            |
      low-risk path   suspicious path
             |            |
             v            v
      protected app   controlled reality
                    decoys / tarpits / fake docs

                  |
                  v
          events -> traces -> score -> policy -> report
```

## Component Boundaries

The proxy is the runtime entrypoint, not the architecture boundary.

The durable boundary between components is the event and policy contract:

```text
proxy / surface controller / bait engine
  -> append structured events
  -> trace intelligence reads events
  -> policy router updates session state
  -> proxy enforces current policy on later requests
```

Ownership:

- Edge Boundary owns HTTP I/O, forwarding, session attachment, and enforcement of the current policy state.
- Surface Controller owns the decision of whether a request sees protected reality, controlled surfaces, or rewritten content.
- Bait/Canary Engine owns bait definitions, expected actions, matching rules, and safe generated values.
- Trace Intelligence owns event reading, session timelines, scoring inputs, and evidence reports.
- Policy Router owns state transitions and reasons; it should not directly rewrite HTTP responses.

This keeps the proxy boring and makes causal trace reconstruction the central product surface.

## Event Contract

Event schema version 2 defines a small structured event vocabulary for the current M2.5 runtime:

```text
request_seen
response_served
bait_exposed
bait_action_observed
policy_decision
policy_changed
controlled_reality_entered
rate_limit_applied
reality_escape_attempt
```

Every event should include:

- schema version
- event id
- session id
- timestamp
- source component
- current policy state
- reason or correlation fields when applicable

Request events should log method, path, selected safe header metadata, and routing decision. They should not log request bodies or secrets by default.

`policy_decision` records an audited routing decision without claiming the policy state changed. `policy_changed` is reserved for actual state transitions where `from` and `to` differ.
`controlled_reality_entered` and `rate_limit_applied` are per-request enforcement markers, not policy-state transition events. `reality_escape_attempt` records a contained session requesting outside the configured controlled branch without logging request bodies or secret values.

## 1. Edge Boundary

The edge boundary is where traffic enters.

For the first implementation this is a reverse proxy.

Responsibilities:

- listen on a local/public port
- identify or assign a session
- forward normal traffic to the protected target
- call the surface controller for Eidolon-owned routes and rewrites
- emit structured events
- enforce current policy state

The v1 proxy should be boring:

```text
Rust
Tokio
Axum/Hyper/Tower
JSONL or SQLite event log
```

The hard part is not high-performance proxying. The hard part is causal trace reconstruction.

## 2. Surface Controller

The surface controller decides what the actor sees.

The surface controller should expose a narrow interface:

```text
session + normalized request + policy state
  -> protected upstream
  -> Eidolon-owned response
  -> rewritten upstream response
  -> controlled-reality response
  -> rate-limit or delay action
```

It may consult the bait engine, but it should not own trace scoring.

For benign sessions it may expose protected reality:

- real app
- real API
- real docs
- real OpenAPI

For suspicious sessions it may expose controlled reality:

- fake docs
- fake OpenAPI operations
- fake legacy endpoints
- fake debug paths
- fake credentials
- fake internal hostnames
- decoy state machines

Eidolon does not need to pollute the real app. The proxy can serve controlled surfaces itself.

## 3. Bait/Canary Engine

The bait engine creates traceable false evidence.

It should produce two things:

- the controlled surface shown to the actor
- the expected follow-up action used for later correlation

It should not depend on HTTP proxy internals.

Bad bait:

```text
static /debug endpoint
static aw-* token
same OpenAPI operation in every deployment
obvious fake admin panel
```

Good bait:

```text
context-aware naming
per-session values
target-style paths and headers
safe expected follow-up action
cheap defender-side verification
```

Example bait object:

```text
bait_id: rel_2025_04_b7f2
surface: /docs/legacy-import
expected_action:
  method: POST
  path: /api/v2/import/reconcile
  header: X-Migration-Trace
  value: rel_2025_04_b7f2
```

## 4. Trace Intelligence

Trace intelligence turns raw events into behavior.

Trace intelligence should be able to run offline against an event log. That keeps Lab evaluation, reports, and future SIEM export from depending on a live proxy process.

Raw logs:

```text
GET /openapi.json
GET /docs/legacy-import
POST /api/v2/import/reconcile
```

Trace:

```text
Session 42:
  fetched OpenAPI
  fetched fake legacy docs
  used bait header
  hit bait-derived endpoint
  retried endpoint variants
  entered controlled reality
```

The trace layer should start rule-based and graph-like.

Do not add ML first.

Initial scoring can be simple:

```text
+15 controlled bait exposed
+70 exact bait-derived action observed
+20 fake credential used
+15 impossible endpoint retried
-20 browser-like navigation
```

Output should avoid overclaiming.

Weak:

```text
AI attacker detected
```

Strong:

```text
High-confidence bait-derived autonomous recon/action chain observed
```

## 5. Policy Router

The policy router decides what happens next.

The policy router consumes trace/scoring output and emits explicit state transitions with reasons. The proxy should treat policy state as input, not as hidden scoring logic.

Policy state values serialize in snake_case:

```text
normal
observe
suspicious
controlled_reality
rate_limited
blocked
```

Routing decision values serialize separately:

```text
protected_upstream
eidolon_owned
rewritten_upstream
controlled_reality
rate_limited
```

M1/M1.5 may use the `blocked` policy state in local validation, but production-grade
blocking policy comes later because it can teach the attacker too much.

## Request Lifecycle

```text
request arrives
  -> normalize request
  -> assign/update session
  -> load policy state
  -> choose protected or controlled reality
  -> forward, serve bait, serve decoy, delay, or rate-limit
  -> emit event
  -> update trace
  -> update score
  -> maybe update policy
```

## V0 Architecture

The first useful version is much smaller than the full project:

```text
scanner
  |
  v
eidolon-proxy
  |
  +--> real target
  |
  +--> Eidolon-owned bait routes
```

V0 components:

- proxy
- surface controller boundary
- bait registry
- event log
- policy state model
- trace report

The loop:

```text
serve clue -> observe action -> correlate -> report
```
