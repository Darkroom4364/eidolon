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

## 1. Edge Boundary

The edge boundary is where traffic enters.

For the first implementation this is a reverse proxy.

Responsibilities:

- listen on a local/public port
- identify or assign a session
- forward normal traffic to the protected target
- serve Eidolon-owned routes
- optionally inject controlled surfaces
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

Possible states:

```text
normal
observe
suspicious
controlled-reality
rate-limited
blocked
reported
```

V1 should implement only:

```text
normal
observe
controlled-reality
rate-limited
```

Blocking comes later because it teaches the attacker too much.

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
- bait registry
- event log
- trace report

The loop:

```text
serve clue -> observe action -> correlate -> report
```

