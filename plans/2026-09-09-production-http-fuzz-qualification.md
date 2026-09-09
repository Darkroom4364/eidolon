# Production HTTP fuzz qualification — #292 / #251 C4

Status: **C4a and C4b are locally implemented and all applicable native gates
pass; independent review, publication, Linux/image CI, and the final C4c
candidate campaign remain open**.

Starting head: `264cea2bab8b275eb78709eb3e43a9f7fc855ab9`, the reviewed
C3 documentation head. The dedicated
`/Users/darkroom/Projects/.worktrees/eidolon-release-http-fuzz-c4-20260909`
worktree was clean at that exact head before C4 editing.

This document records bounded parser, policy, and canonicalization fuzz
evidence. It is not production-listener, admission, deadline, processor,
upstream, audit, Linux/image CI, four-hour soak, publication, merge, or release
qualification. In particular, the successful 30-second local mutation smoke is
not the final C4c campaign.

## Invariant and ordered contract

For every raw byte input within the target's explicit cap, the production HTTP/1
parser, body collector, strict request policy, and shared target canonicalizer
must produce the same bounded observation when the bytes arrive in one read or
under the target's deterministic fragmented-read schedule. Any accepted request
must remain HTTP/1.1, non-CONNECT, strict origin form or `OPTIONS *`, canonical
and idempotent, within production header/body limits, exactly single-Host, free
of unsupported protocol headers, and consistent with its one optional
Content-Length field. A timeout, response-capture overflow, second request, or
driver invariant error is a failing fuzz input rather than an ignored result.

The slices are deliberately ordered:

| Slice | Contract | Current status |
| --- | --- | --- |
| C4a | Add a socket-free, feature-gated driver around the exact vendored Hyper HTTP/1 builder, production body collector and transport classifier, public strict policy adapter, and shared canonicalizer. Compare whole and deterministic fragmented delivery exactly. | Locally implemented and focused tests pass. |
| C4b | Add the pinned `cargo-fuzz` package, strict named corpus/manifest, dictionary, ASan replay, finite mutation smoke, lock parity check, and private-only failure artifacts in CI. | Locally implemented; corpus replay and 30-second mutation smoke pass after the fail-first repair below. Full gates and review remain. |
| C4c | Run and preserve the separately authorized final candidate campaign for at least 3,600 seconds with exact commit, toolchain, sanitizer, corpus, command, statistics, and failure disposition. | Not run. A short smoke cannot satisfy this slice. |

## Exact layer inventory and non-claims

| Layer | Reached by C4 driver | Exact implementation or retained evidence |
| --- | --- | --- |
| TCP listener, peer address, accept loop | No | C1/C3 listener suites remain authoritative. The driver creates no socket. |
| Connection admission, task limits, reaping, shutdown | No | C3 lifecycle matrix remains authoritative. |
| Hyper HTTP/1 request-head parser | Yes | `hyper::server::conn::http1::Builder` from the exact `vendor/hyper` source selected by both root and fuzz workspaces. |
| Raw head count/byte configuration | Yes | Exact production `max_headers(100)` and `max_buf_size(65,536)` values. |
| Production header-read timer | No | The driver uses one 250 ms harness deadline. C1/C3 retain real staged deadline evidence. |
| Hyper body decoder and production body collector | Yes | Exact private `collect_inbound_body`; body frames, disconnect classification, trailer and decoded-body policy are retained. |
| Pre-service transport classification | Yes | Exact private `pre_service_transport_rejection`; stable typed outcome only, with no Hyper error strings retained. |
| Strict request policy | Yes | Public `ProductionHttpPolicy::adapt`. |
| Shared request-target canonicalizer | Yes | Accepted output is rechecked through `canonical_request_target` in `OriginOnly` mode. |
| Processor permits, lifecycle processor, upstream and retry rules | No | C1/C2/C3 retain those boundaries. The service returns a deterministic empty 204. |
| Durable/debug audit and disclosure projection | No | Existing full-profile tests remain authoritative. No fuzz input or artifact is uploaded for a public repository. |

The fuzzing feature adds an inspection surface only when explicitly enabled. It
does not change the default production feature set or route production traffic
through the driver.

## Driver bounds and stable observation

| Bound | Value and failure behavior |
| --- | --- |
| Input bytes | At most 65,537 (`MAX_PRODUCTION_HEADER_BYTES + 1`); direct driver calls above this return `InputTooLarge`. The fuzz target skips values above the declared libFuzzer cap. |
| Whole schedule | Zero or one input chunk. |
| Fragmented schedule | Repeating widths `1,3,7,2,11,5,17,13`, capped at 64 non-empty chunks; the last chunk contains all remaining bytes. Concatenation must equal the input. |
| Requests | Hyper keep-alive is disabled for this one-input driver; observing more than one service request fails. |
| Response capture | 4 KiB maximum; overflow fails. Automatic Date is disabled so exact response bytes are deterministic. |
| Per-input deadline | 250 ms around one connection evaluation; expiry fails. This is a harness bound, not the production request-timeout contract. |
| Runtime and external work | One reused current-thread Tokio runtime per fuzz thread; no socket, DNS, external network, detached task, processor, upstream, audit, or credential access. |
| Comparison | Exact equality of request outcome, connection class, and captured response bytes across both schedules. |

The stable request outcome is no complete request, client disconnect, a typed
policy rejection, or bounded accepted fields. The connection outcome is clean,
a typed pre-service rejection, incomplete, or another transport failure. Error
payloads and reason strings are not corpus contracts.

## Checked-in corpus and lock contract

The strict JSON manifest names every seed, requires a lowercase SHA-256 digest,
requires the manifest and corpus directory to contain exactly the same regular
files, replays both delivery schedules, and matches the complete stable
observation. It fails closed on unknown manifest fields, path escape, duplicate
names/files, unmanifested or missing files, invalid expected shapes, digest
drift, oversized bytes, differential results, or outcome drift.

| Seed | Bytes | Expected boundary |
| --- | ---: | --- |
| `positive_origin_canonical` | 138 | Accepted POST; canonical `/qualification/reconcile/~?slash=%2F`; exact headers and `seed\r\n` body. |
| `positive_options_asterisk` | 78 | Accepted `OPTIONS *`. |
| `reject_absolute_target` | 76 | Policy `invalid_target_form`. |
| `reject_invalid_percent` | 58 | Policy `invalid_target_form`. |
| `reject_missing_host` | 73 | Policy `missing_host`. |
| `reject_duplicate_host` | 92 | Policy `multiple_host_headers`. |
| `reject_duplicate_content_length` | 110 | Policy `multiple_content_lengths`; retained vendored duplicate preservation. |
| `reject_conflicting_content_length` | 112 | Pre-service `malformed_transport`; no complete request. |
| `reject_cl_te` | 113 | Policy `unsupported_transfer_encoding`. |
| `reject_upgrade` | 103 | Policy `unsupported_upgrade`. |
| `reject_http10` | 61 | Policy `unsupported_http_version`. |
| `incomplete_head` | 63 | Incomplete connection; no request or response. |

Manifest total: **12 seeds / 1,077 bytes**. The manifest test also proves that
the fuzz lock contains every exact registry package version from the candidate
root lock and adds only `arbitrary 1.4.2`, `jobserver 0.1.35`, and
`libfuzzer-sys 0.4.13`. Root attributes mark `*.raw` corpus inputs as binary so
Git never normalizes their byte-exact CRLF framing.

Pinned fuzz identity:

- Rust `nightly-2026-04-22`, rustc commit
  `9ec5d5f32e19d250c7fbeaa90978c79105b39dee`;
- `cargo-fuzz 0.13.2`, installed with its lock;
- `libfuzzer-sys = 0.4.13` exactly;
- exact candidate path dependencies and the same vendored Hyper patch;
- ASan build/replay and deterministic seed `292` finite mutation smoke in CI.

CI failure artifacts are uploaded only while the repository is private, are
retained for seven days, and are ignored when absent. This avoids automatically
publishing attacker-controlled request bytes after open-source visibility.

## Fail-first finding and disposition

The first 30-second ASan mutation smoke failed on its first generated mutation.
The 76-byte input (SHA-256
`eaba0c4dbafb860cfad425abe35408af9865a1e65f246fe158fb4218c904d3c1`)
minimized to the two bytes `".\n"` (SHA-256
`eb4bd64f7014f7d42e9d358035802242741b974e8dfcd37c59f9c21ce29d781e`).
Whole delivery produced Hyper's 400 and typed `MalformedTransport`; fragmented
delivery closed as incomplete. Both paths produced zero complete request,
policy, processor, or upstream work, so this was not an unsafe-request bypass.
It was an inconsistent malformed-transport attribution and response at EOF.

Cause: after one partial read, vendored Hyper's terminator fast path can defer a
full parse. At EOF the old path returned `IncompleteMessage` without rechecking
the already-buffered bytes, so classification depended on read segmentation.

Repair: when EOF follows that fast-path deferral, `vendor/hyper` clears the
partial marker and performs exactly one full bounded parse before incomplete
classification. Malformed buffered input now rejects consistently; a
syntactically valid incomplete head remains `IncompleteMessage`. The repair
does not add a read, loop without a bound, service call, request acceptance, or
upstream work.

Retained regressions:

- production driver: `malformed_partial_head_is_segmentation_invariant_at_eof`;
- vendored connection: `conn_reparses_fragmented_malformed_partial_head_at_eof`;
- vendored control: `conn_rejects_eof_during_partial_head`.

The minimized bytes are safe to retain only as normal source-code regression
data. Raw fuzzer failure artifacts remain ignored and are not part of the
candidate tree.

## Local behavior evidence to date

Focused driver, manifest, vendor repair, ASan build, checked-in corpus replay,
and minimized-artifact replay pass locally. After the repair, the same seed-292
finite mutation command completed **341,858 runs in 31 seconds** with no
failure, final `cov: 4070` / `ft: 8803`, reported corpus `1254/112Kb`, input
limit progress to 273 bytes, and peak RSS 457 MiB. The temporary working corpus
contained 1,255 files / 115,805 bytes, minimum 1 and maximum 264 bytes. It is
outside the repository and is not release evidence or a substitute for C4c.

## Exact validation contract

Run from the repository root unless a manifest path says otherwise:

```text
cargo +1.95.0 fmt --all -- --check
cargo +nightly-2026-04-22 fmt --manifest-path fuzz/Cargo.toml -- --check
cargo +1.95.0 build --workspace --all-targets --locked
cargo +1.95.0 clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.95.0 test --workspace --all-targets --locked
cargo +1.95.0 test -p eidolon-proxy --features fuzzing --lib fuzzing::tests --locked
cargo +1.95.0 test --manifest-path vendor/hyper/Cargo.toml --features client,http1,http2,server --locked --target-dir target --lib read_buffer_regression
cargo +1.95.0 test --manifest-path vendor/hyper/Cargo.toml --features client,http1,http2,server --locked --target-dir target --lib proto::h1::conn::tests::conn_reparses_fragmented_malformed_partial_head_at_eof -- --exact
cargo +1.95.0 test --manifest-path vendor/hyper/Cargo.toml --features client,http1,http2,server --locked --target-dir target --lib proto::h1::conn::tests::conn_rejects_eof_during_partial_head -- --exact
cargo +1.95.0 test --manifest-path fuzz/Cargo.toml --locked
cargo +nightly-2026-04-22 fuzz build production_http1_request --sanitizer address
cargo +nightly-2026-04-22 fuzz run production_http1_request fuzz/corpus/production_http1_request --sanitizer address -- -runs=12 -max_len=65537 -timeout=2 -dict=fuzz/dictionaries/production_http1_request.dict
cargo audit --file Cargo.lock --deny warnings
cargo audit --file vendor/hyper/Cargo.lock --deny warnings
cargo audit --file fuzz/Cargo.lock --deny warnings
git diff --exit-code -- fuzz/Cargo.lock
```

The existing M3/Shield fixture gates, tracked shell syntax, JSON fixture checks,
Linux workflow, and image builds remain applicable release gates. Successful
native fuzzing does not infer those results.

Final pre-review native results on the formatted working tree:

| Check | Result |
| --- | --- |
| Root, fuzz-workspace, and vendored-Hyper rustfmt checks; `git diff --check`; workflow YAML parse; corpus JSON parse | Passed. |
| Workspace build, `--workspace --all-targets` | Passed. |
| Workspace Clippy, `--workspace --all-targets --all-features -- -D warnings` | Passed, including the feature-gated driver. |
| Workspace tests, `--workspace --all-targets` | **820 passed**, no failures or ignores. The first restricted run passed every socket-free path and reported 47 owned-loopback bind `EPERM` failures; the authorized owned-loopback rerun passed all 820. |
| Focused driver tests | **5 passed**, including the two-byte malformed EOF regression and driver-bound controls. |
| Fuzz manifest/lock tests | **5 passed**, including expected-outcome, seed-byte, and unmanifested-file fail-closed controls. |
| Full vendored Hyper library suite | **121 passed / 6 upstream ignores**, including both EOF outcomes, both read-buffer repairs, all three Content-Length regressions, and the upstream request-decoder control. |
| Pinned-nightly ASan build and checked-in corpus replay | Passed; 12 files / 1,077 bytes loaded, no failure. |
| Root, vendor, and fuzz lock audits | Passed against a refreshed **1,243-advisory** RustSec database; 110 / 73 / 112 dependencies scanned. |
| M3 JSON, every tracked shell syntax check, all M3 and Shield Lab `test-*.sh`, and archived M3 SHA-256 inventories | Passed. These are stubbed/rendered fixture checks, not live cluster qualification. |
| Candidate and vendor lock immutability | Passed; only the new checked-in `fuzz/Cargo.lock` differs by design and its parity test passes. |
| Linux workflow and image builds | Not run locally; require the published exact head and CI. |

## Completion checklist

- [x] C4a exact bounded driver implemented with focused normal tests.
- [x] Strict 12-seed corpus, manifest negative controls, dictionary, and lock
      parity check implemented.
- [x] Fail-first EOF inconsistency minimized, explained, narrowly repaired, and
      retained as normal regressions.
- [x] Checked-in ASan replay and repaired 30-second deterministic mutation smoke
      pass locally.
- [x] Formatting, full workspace, full vendor, audit, and retained fixture gates
      pass on the pre-review tree.
- [ ] Independent cross-runtime review passes against an exact implementation
      commit, with every finding disposed.
- [ ] #292 issue state and roadmap comments match the reviewed local evidence.
- [ ] Branch is published and exact-head Linux/image CI passes.
- [ ] C4c final campaign runs for at least 3,600 seconds against the exact
      candidate and records its complete reproducibility and failure disposition.
- [ ] PR review, merge, and release qualification complete under #251.
