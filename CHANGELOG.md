# Changelog

All notable changes to Eidolon are documented here.

## [0.1.0] - Unreleased

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
  fail-closed active/previous continuity-key rotation path
- policy-state schema 1--3 loading with a 32 MiB startup/write bound,
  order-independent duplicate-session rejection, and pre-migration pending
  workflow/response/event-contract validation; production preflights invalid
  state before touching lease metadata and revalidates under the lease
- schema-v1 bait-exposure and consumed-proof sidecars with independent 4 MiB
  startup/write bounds, strict duplicate-key and lifetime validation, and
  owner-only atomic replacement through a bounded reserved temp; production
  preflights existing sidecars and their canonical rewrite before lease or
  durable-log effects
- bounded schema-v2 event-log recovery across one active 32 MiB segment and
  three canonical numeric archives (128 MiB total), with a 1 MiB record cap,
  streaming validation, global duplicate-event rejection, active-only tail
  repair, full-family sidecar reconstruction, and one pending-workflow index
  built during the authoritative under-lease scan

### Limitations

- research Lab software, not a production security boundary
- no managed-cluster, high-availability, or multi-replica renderer claim
- no published crates, container images, or hosted service

[0.1.0]: https://github.com/Darkroom4364/eidolon/releases/tag/v0.1.0
