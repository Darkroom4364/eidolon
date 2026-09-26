# Changelog

All notable changes to Eidolon are documented here.

## [0.1.0] - 2026-09-26

Initial research-alpha source release.

### Included

- Rust reverse proxy, causal-bait primitives, policy state, trace
  reconstruction, reports, and edge-decision export
- owned demo target and repeatable M3 fixture/evidence workflows
- OrbStack behavioral Lab harness and Kali VM validation path
- pinned kind/Calico Lab profile with an authenticated standalone
  controlled-reality renderer
- fail-closed unsafe-action routing, request-linked causality,
  integrity-protected session identity, and bounded recoverable state
- continuity sidecar schema v2 with schema-v1 migration and a bounded,
  fail-closed active/previous continuity-key rotation path; production now
  validates and prepares continuity state read-only before the durable writer
  lease, repeats the authoritative prepare under the lease, and commits only
  the prepared canonical state before serving traffic
- policy-state schema 1--3 loading with a 32 MiB startup/write bound,
  order-independent duplicate-session rejection, and pre-migration pending
  workflow/response/event-contract validation; production preflights invalid
  state and its reserved temp type before touching lease metadata and
  revalidates under the lease and immediately before persistence
- schema-v1 bait-exposure and consumed-proof sidecars with independent 4 MiB
  startup/write bounds, strict duplicate-key and lifetime validation, and
  owner-only atomic replacement through a bounded reserved temp; production
  preflights existing sidecars and their canonical rewrite before lease or
  durable-log effects
- bounded schema-v2 event-log recovery across one active 32 MiB segment and
  three canonical numeric archives (128 MiB total), with a 1 MiB record cap,
  a 215-byte active-file-name limit, reserved event/debug archive namespaces
  and hard-link isolation (including active-to-archive aliases), streaming
  validation, global duplicate-event rejection,
  active-only tail repair, immutable full-family verification, missing-only
  full-family sidecar reconstruction, pre-mutation workflow-contract
  validation, evidence-safe deferred rotation, preflight sizing for missing
  recovery appends and final quarantine-bearing proof state, and one selected
  pending-workflow index built during the authoritative under-lease scan

### Limitations

- research Lab software, not a production security boundary
- no managed-cluster, high-availability, or multi-replica renderer claim
- source-only release; no published crates, container images, or hosted service
- semantic-canary scoring is an offline synthetic benchmark only, not runtime
  routing, containment, actor attribution, or accepted bait proof

[0.1.0]: https://github.com/Darkroom4364/eidolon/releases/tag/v0.1.0
