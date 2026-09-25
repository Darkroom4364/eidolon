# Semantic-Canary Fixtures

The canonical checked-in corpus is embedded by `eidolon-semantic-canary` at
`crates/eidolon-semantic-canary/fixtures/semantic-canary-v1.json`. It is
synthetic, inert, offline-only test data. The scorer accepts bytes supplied by
the caller; it performs no filesystem, network, DNS, callback, browser, tool,
credential, subprocess, or runtime-control operation.

See `docs/semantic-canary-benchmark.md` for the normative contract.

## Qualification artifacts

`qualify_held_out()` scores a distinct embedded held-out corpus three times with
documented fixed-seed metadata. `export_qualification_summary_json()` emits only
qualification metadata plus version, hash, aggregate confusion, abstention, and
limitations metadata. It never emits fixture text, candidate text, or case
identifiers.

Run the qualification CLI from the repository root:

```sh
cargo run -p eidolon-semantic-canary --bin eidolon-semantic-canary-qualify --locked
```

The command accepts no input paths or positional arguments. Its stdout is the
summary-only `QualificationReport`; operational errors go to stderr.
