# Eidolon Repo Lesson (About 60 Minutes)

This lesson is the fastest route to real working mastery of this repository.
In one hour, you will not memorize every line, but you can get to the point
where every top-level directory, every implemented runtime path, and every
major design document makes sense.

The key framing to keep in your head the whole time:

- the repo has a bigger vision than the current implementation
- the current implementation is still substantial
- the truth is split across `docs/`, `crates/`, and `examples/`

If you lose that distinction, the repo feels inconsistent. If you keep it in
mind, it becomes coherent.

## What You Should Be Able To Explain At The End

By the end of this lesson, you should be able to explain:

- what Eidolon is, and what it is explicitly not
- the difference between Lab and Shield
- how a request moves through the proxy today
- how bait is defined, exposed, matched, and logged
- how trusted ingress identity differs from runtime suspicious evidence
- how policy state differs from routing decision
- how controlled reality works in the current code
- how the trace engine reconstructs evidence from JSONL
- what each `examples/` area is for
- which docs are product vision, which are runbooks, and which are evidence

## Setup

Open these files before you start:

- [`README.md`](../README.md)
- [`docs/architecture.md`](architecture.md)
- [`crates/eidolon-core/src/lib.rs`](../crates/eidolon-core/src/lib.rs)
- [`crates/eidolon-bait/src/lib.rs`](../crates/eidolon-bait/src/lib.rs)
- [`crates/eidolon-proxy/src/main.rs`](../crates/eidolon-proxy/src/main.rs)
- [`crates/eidolon-trace/src/evidence.rs`](../crates/eidolon-trace/src/evidence.rs)

If you want the lesson to be hands-on, keep two terminals ready.

## 60-Minute Agenda

| Time | Focus | Primary files |
| --- | --- | --- |
| 0-5 min | Product and repo mental model | `README.md`, `docs/architecture.md`, `docs/completed-project.md` |
| 5-10 min | Repo map | root, `crates/`, `examples/`, `docs/`, `scripts/` |
| 10-20 min | Core contracts | `crates/eidolon-core/src/lib.rs` |
| 20-28 min | Bait model | `crates/eidolon-bait/src/lib.rs` |
| 28-43 min | Proxy runtime | `crates/eidolon-proxy/src/main.rs` and sibling modules |
| 43-50 min | Surface rewriting, policy, session, controlled reality | `surface.rs`, `policy.rs`, `session.rs`, `controlled_reality.rs`, `policy_store.rs` |
| 50-56 min | Trace and reporting | `crates/eidolon-trace/src/*` |
| 56-60 min | Examples, evidence, CI, remaining corners | `examples/`, `docs/`, `scripts/ci/` |

## 1. Product Mental Model

Start with [`README.md`](../README.md), then skim
[`docs/architecture.md`](architecture.md), then
[`docs/completed-project.md`](completed-project.md).

The main idea:

- Eidolon is target-side active defense for autonomous cyber agents.
- The core primitive is causal bait.
- The goal is not "someone touched a fake thing".
- The goal is "this session consumed controlled evidence and then acted on it".

Three distinctions matter immediately:

1. `Lab` is the evaluation harness.
2. `Shield` is the deployable defensive boundary.
3. The current codebase implements a narrow but real slice of that vision.

Important reality check:

- the docs often describe the full intended architecture
- the current code now includes a merged first-defensible M5 runtime plane on
  top of the earlier M3/M4 proxy and trace pipeline
- some docs still speak in future-tense even when code already exists

That is normal for this repo.

## 2. Repo Map

Treat the repository as five layers.

### Layer 1: Root

- `Cargo.toml`: workspace definition
- `README.md`: project framing
- `SECURITY.md`: defensive-use boundary
- `Cargo.lock`: dependency lockfile

### Layer 2: Rust crates

- `crates/eidolon-core`: shared schema and types
- `crates/eidolon-bait`: bait templates, registry, matching
- `crates/eidolon-trace`: offline log reading, evidence, scoring, reports
- `crates/eidolon-proxy`: the runtime entrypoint and most of the implementation

### Layer 3: Examples and operators

- `examples/demo-target`: synthetic protected upstream
- `examples/baselines`: negative controls and simple defensive comparisons
- `examples/metrics`: summary collectors for those runs
- `examples/m3`: scripted bakeoff, pwnkit-oriented artifact collection, packaging
- `examples/shield-lab`: the active private-cluster Shield operator lab
- `examples/lib`: shell safety helpers

### Layer 4: Docs

Docs are not one thing. Split them mentally into four groups:

- positioning and architecture: `proposal`, `architecture`, `name`, `roadmap`
- safety and threat model: `safety`, `threat-model`, `lab`
- operational runbooks: `lab-runbook`, `ci`, `release-checklist-m2.5`
- research and evidence: `research-*`, `m3-*`, `evidence/`

### Layer 5: CI and glue

- `scripts/ci/wait-for-github-app-check.sh`: waits for external Foxguard review signal

## 3. Core Contracts

Read [`crates/eidolon-core/src/lib.rs`](../crates/eidolon-core/src/lib.rs).
This is the contract crate. Everything else depends on it.

Focus on these types:

- `SessionId`: the unit of correlation
- `BaitId` and `ExposureId`: distinguish the clue from one observation of it
- `BaitClass`: current M3 bait family taxonomy
- `ExpectedAction`: what follow-up action counts as bait-derived
- `EventKind`: the event vocabulary
- `PolicyState`: the session's current defensive state
- `RoutingDecision`: what happened for one request
- `Score` and `ConfidenceBand`: trace output

Two concepts are easy to mix up:

### Policy state

This is durable session state:

- `observe`
- `suspicious`
- `controlled_reality`
- `rate_limited`
- `blocked`

### Routing decision

This is what happened for one request:

- `protected_upstream`
- `eidolon_owned`
- `rewritten_upstream`
- `controlled_reality`
- `rate_limited`

That separation is one of the cleanest design choices in the repo.

Also notice what is intentionally absent from events:

- request bodies
- raw secret values
- arbitrary full-header capture

The event contract is designed for behavioral evidence, not packet capture.

## 4. Bait Model

Read [`crates/eidolon-bait/src/lib.rs`](../crates/eidolon-bait/src/lib.rs).

This crate does three jobs:

1. defines reusable bait templates
2. collects them in a registry
3. matches later requests against expected actions

The current built-in catalog has five bait families:

- docs
- OpenAPI
- hidden route
- fake credential/token
- JavaScript-discovered route

The important state update here is that the bait model is no longer purely
static. The default Shield lab now enables per-session HMAC-minted values on
several bait surfaces, while the hidden-route and JS-helper classes remain
static on purpose as negative controls.

Pay attention to `BaitRegistry::match_action(...)`.
Matching is currently:

- method
- normalized path
- optional header name
- optional header value

It is not currently:

- query-based
- body-based
- graph-based

That simplicity is deliberate.

Also notice `docs_for_bait(...)`: the repo encodes bait as plausible product
content, not as exploit payloads.

## 5. Proxy Runtime: The Most Important 15 Minutes

The current runtime lives mostly in
[`crates/eidolon-proxy/src/main.rs`](../crates/eidolon-proxy/src/main.rs).

This is the single biggest file in the repo, and it is where you should spend
the most attention.

### First big insight

The docs mention future `Axum/Hyper/Tower` style architecture.
The current implementation is not that.

Today it is:

- a custom TCP listener
- a small hand-rolled HTTP parser/forwarder
- thread-per-connection
- JSONL files for events and debug data
- file-backed policy state

That mismatch is not a bug in your understanding. It is the repo's current
state.

### What `main.rs` does

Mentally split the file into seven zones:

1. CLI and config parsing
2. safety validation for listen/upstream addresses
3. runtime construction
4. request lifecycle in `handle_connection(...)`
5. helper logic for policy, bait exposure, direct responses
6. debug and redaction helpers
7. low-level HTTP parsing and forwarding

### Runtime state

`ProxyRuntime` bundles:

- upstream target config
- event log writer
- optional debug log writer
- intervention control path
- policy store
- controlled reality config
- controlled reality responder
- surface controller
- bait registry
- bait exposure store

This tells you the architecture is still file-centric and single-process.

### The actual request lifecycle

Here is the code path to memorize:

1. `read_http_request(...)`
2. `derive_session_from_headers(...)`
3. `intervention_mode_from_control_file(...)`
4. `policy_state_for_session(...)`
5. `surface_controller.decide(...)` or `controlled_reality_action(...)`
6. optional bait-action interception before upstream forwarding
7. either direct Eidolon response or upstream forwarding
8. optional response rewrite
9. event logging, debug logging, response header normalization

That is the runtime.

### Session handling

`session.rs` is small but important:

- session cookie name: `eidolon_session`
- host-only cookie
- `HttpOnly`
- `SameSite=Lax`
- no `Secure` because current lab is local HTTP

This is careful local-lab engineering, not production web auth.

### Intervention control

The proxy can be turned off per request by editing a file.

If the intervention control file contains:

- `disabled`
- `disable`
- `off`
- `0`

then interventions stop and traffic forwards normally.

That is an operator escape hatch, not a dynamic policy engine.

### Direct surfaces vs upstream traffic

The surface controller can return:

- `ProtectedUpstream`
- `RewrittenUpstream`
- `EidolonOwned`
- `ControlledReality`
- `RateLimited`

That is the runtime seam between "show the real app" and "show Eidolon-managed content".

### Bait exposure path

For a direct Eidolon-owned bait surface:

- request is logged
- bait surface is served
- `bait_exposed` is emitted
- an `ExposureId` is stored by `(session_id, bait_id)`

That last part is crucial.
The proxy does not just know that bait exists.
It knows which session saw which bait.

### Bait action interception path

Before a request reaches the upstream, the proxy tries
`bait_registry.match_action(...)`.

If it matches:

- the request is not forwarded
- `bait_action_observed` is emitted
- the proxy looks for a prior exposure in the same session
- a correlated action can transition the session into `controlled_reality`

This is the central demo of the whole repo.

### Controlled reality path

If correlation is good enough:

- policy changes to `controlled_reality`
- later requests get synthetic responses
- action depth increments in the policy store
- after the configured max depth, the proxy returns `429` with tarpit behavior

This is containment, but only for a narrow branch today.

### Upstream rewrite path

Some requests still go upstream first, then get rewritten on the way back.
Current examples:

- `/docs`: HTML insertion
- `/openapi.json`: OpenAPI path insertion

This is how the proxy exposes clues without modifying the demo target itself.

### Low-level HTTP behavior

The proxy:

- accepts origin-form and absolute `http://` request targets
- rewrites `Host`
- strips hop-by-hop headers
- supports chunked upstream responses
- does not support chunked request bodies
- bounds header and body sizes

That tells you the current server is intentionally narrow and auditable.

## 6. Proxy Submodules You Must Understand

### `policy.rs`

This file encodes the policy-state-to-routing-decision mapping.

Important points:

- initial state is `observe`
- the merged M5 plane now has a real graduated ladder:
  `observe -> suspicious -> rate_limited -> controlled_reality -> blocked`
- correlated bait action is still the strongest direct path into
  `controlled_reality`
- trusted ingress can soften selected low-confidence bait surfaces, but must
  not bypass later containment once runtime evidence gets stronger
- interventions disabled forces `protected_upstream`
- `policy_changed` and `policy_decision` are different events

### `policy_store.rs`

This is durable session state.

It stores:

- `policy_state`
- `controlled_reality_depth`
- small per-session recon and persistence state used by the current M5 ladder

Important operational truth:

- state is persisted as JSON
- writes are single-writer style
- files are owner-only on Unix
- this is why the shield-lab template stays single replica today

### `controlled_reality.rs`

This is the synthetic branch implementation.

Current branch:

- `/api/v2/import/reconcile`

Important behaviors:

- known decoy write path returns synthetic non-write data
- over-depth containment becomes rate limiting
- synthetic responses carry `X-Eidolon-Synthetic: true`

### `surface.rs`

This file is the rewrite engine abstraction.

It is cleaner than it first looks.
It defines:

- request/response metadata structs
- the `SurfaceController` trait
- `SurfaceAction`
- `RewritePlan`
- body rewrite operations and refusal reasons

The important teaching point:

- the proxy does not embed rewrite logic everywhere
- rewrite logic is isolated behind explicit operations

### `event_log.rs` and `debug_log.rs`

Both are newline-delimited JSON writers.

Difference:

- event log: product evidence
- debug log: operator-only internals

That distinction matters throughout the repo.

## 7. Trace Engine

Now read `crates/eidolon-trace/src/`.

The trace crate is offline analysis over proxy output.
That is a strong design choice because it decouples:

- live request handling
- later evidence generation

### `reader.rs`

Reads JSONL, validates `schema_version`, and converts each line into a
`TimelineEvent`.

### `timeline.rs`

Groups events by `SessionId` and sorts them by:

1. `observed_at`
2. file order as tie-breaker

That gives stable replay semantics.

### `evidence.rs`

This is the heart of the analysis layer.

It extracts:

- observed surfaces
- bait exposures
- matched actions
- unmatched actions
- policy events
- containment metrics

Read this file with one question in mind:

"What claims is the repo willing to make from target-side evidence alone?"

Answer:

- confirmed same-session bait chains
- unconfirmed bait-shaped follow-up
- containment entry and dwell
- real-surface access after containment

Not:

- AI identity
- chain of thought
- exploit success

### `scoring.rs`

The scoring model is intentionally simple.

Current major weights:

- `+15` bait exposed
- `+70` confirmed bait-derived action
- `+50` same-bait action after exposure but missing matching exposure id
- `+40` bait-shaped action without matching exposure

That simplicity is a feature. The repo is not hiding the scoring.

### `report.rs`

This renders:

- markdown trace report
- evidence markdown
- replay table

It also preserves the repo's safety posture by redacting query values and
avoiding overclaiming.

## 8. Demo Target

Read [`examples/demo-target/src/main.rs`](../examples/demo-target/src/main.rs).

This is the protected upstream that the proxy sits in front of.

Important things to notice:

- it is synthetic and non-vulnerable by design
- it binds to loopback by default
- it rejects non-loopback unless explicit cluster-lab mode is enabled
- it exposes real-looking but safe docs and API routes

The most important conceptual point:

- the demo target is not where the bait lives
- the proxy owns the bait

That separation is central to the whole system.

## 9. Examples: How The Repo Is Operated

You do not understand this repo if you only read Rust.
The shell harnesses matter.

### `examples/lib/local-lab.sh`

This is the safety gate for the shell workflows.
It rejects non-loopback URLs and malformed local lab inputs.

### `examples/baselines/`

These are negative controls and comparison baselines.

- `benign.sh`: normal curl/browser/crawler traffic
- `defense-modes.sh`: compare no-defense, static-token, static-honeypot, waf-style-block

These scripts are not general scanners.
They are controlled workload generators.

### `examples/metrics/`

These are lightweight collectors over JSONL emitted by the baseline scripts.

They are intentionally simple:

- mostly `awk`
- explicit schema fields
- narrow claims

### `examples/m3/`

This directory is the heaviest operational area outside the proxy itself.

Think of it as four groups:

1. runners: `bakeoff.sh`, `pwnkit-codex.sh`, `run-pwnkit-*.sh`
2. collectors: `collect-*.sh`
3. validators: `test-*.sh`, `check-*.sh`
4. packagers/reporting: `package-*.sh`, `report.sh`

This is where the repo turns runtime behavior into research artifacts.

### `examples/shield-lab/`

This is still not production Shield.
It is now the main private owned-target operator lab for the repo, with live
OrbStack deployment, export, and smoke coverage for trusted-ingress and
polymorphic-bait work.

What it teaches you:

- current proxy state is single-writer and PVC-backed
- Shield hardening work now lands here first before any broader deployment story
- the public repo deliberately stops short of carrying private operator material

## 10. Docs: Read Them By Role

If you read the docs randomly, they feel repetitive.
Read them by role instead.

### Product and differentiation

- [`docs/proposal.md`](proposal.md)
- [`docs/name.md`](name.md)
- [`docs/ai-labyrinth-vs-eidolon.md`](ai-labyrinth-vs-eidolon.md)
- [`docs/learning-hardness.md`](learning-hardness.md)

### Architecture and roadmap

- [`docs/architecture.md`](architecture.md)
- [`docs/mvp-plan.md`](mvp-plan.md)
- [`docs/roadmap.md`](roadmap.md)
- [`docs/completed-project.md`](completed-project.md)

### Safety and operation

- [`docs/safety.md`](safety.md)
- [`docs/threat-model.md`](threat-model.md)
- [`docs/lab.md`](lab.md)
- [`docs/lab-runbook.md`](lab-runbook.md)
- [`docs/ci.md`](ci.md)

### Research and evidence

- `docs/research-*`
- `docs/m3-*`
- `docs/evidence/`

`docs/evidence/` is not architecture. It is archived proof material.

## 11. One Interactive Walkthrough

If you want to make this lesson stick, run this sequence.

Start the demo target:

```sh
cargo run -p eidolon-demo-target
```

Start the proxy in another terminal:

```sh
cargo run -p eidolon-proxy -- \
  --listen-addr 127.0.0.1:8080 \
  --upstream http://127.0.0.1:9001 \
  --event-log /tmp/eidolon-events.jsonl \
  --debug-log /tmp/eidolon-debug.jsonl \
  --intervention-control /tmp/eidolon-interventions.txt \
  --policy-state /tmp/eidolon-policy-state.json
```

Trigger one bait chain:

```sh
rm -f /tmp/eidolon-cookies.txt
curl -i -c /tmp/eidolon-cookies.txt http://127.0.0.1:8080/docs/legacy-import
curl -i -b /tmp/eidolon-cookies.txt \
  -H 'X-Migration-Trace: rel_2025_04_b7f2' \
  -X POST http://127.0.0.1:8080/api/v2/import/reconcile
```

Then inspect:

- `/tmp/eidolon-events.jsonl`
- `/tmp/eidolon-debug.jsonl`
- `/tmp/eidolon-policy-state.json`

If you can explain those three files after the curl sequence, you understand
the implemented core of the repo.

## 12. The "Every Corner" Cheat Sheet

When you finish the hour, make sure you can say one sentence about each area:

- `crates/eidolon-core`: shared data model and event contract
- `crates/eidolon-bait`: bait catalog, matcher, and session-minted bait helpers
- `crates/eidolon-proxy`: live boundary, sessioning, rewriting, containment
- `crates/eidolon-trace`: offline evidence and reporting
- `examples/demo-target`: safe upstream app
- `examples/baselines`: replayable control traffic
- `examples/metrics`: baseline summarizers
- `examples/m3`: research harness and artifact pipeline
- `examples/shield-lab`: active private-cluster operator lab, not prod runtime
- `docs/`: framing, runbooks, research, evidence
- `scripts/ci/`: GitHub/Foxguard integration glue

## 13. Final Comprehension Check

If you can answer these from memory, the lesson worked:

1. What is the difference between `PolicyState::ControlledReality` and `RoutingDecision::ControlledReality`?
2. Why does the proxy need both `BaitId` and `ExposureId`?
3. Why does the trace engine work from JSONL instead of directly from the live process?
4. Which part of the system owns bait surfaces: the demo target or the proxy?
5. What happens when interventions are disabled and a request hits a known decoy write path?
6. What is the current persistence model for policy state?
7. What makes an action "confirmed" instead of merely "bait-shaped"?
8. Why is `examples/shield-lab/` intentionally single-replica?

## 14. If You Want A Deeper Second Hour

Do this next:

1. Read `crates/eidolon-proxy/src/main.rs` end to end once.
2. Read every test in `crates/eidolon-trace/src/scoring.rs`.
3. Walk through one `examples/m3/` collection flow from runner to packaged evidence.
4. Compare `docs/completed-project.md` against the current implementation and make a list of still-missing capabilities.
   Include the remaining M5 generalization and trusted-ingress hardening work,
   not the already-merged `#175` baseline.

That second hour is where you move from "I understand the repo" to "I can change it safely."
