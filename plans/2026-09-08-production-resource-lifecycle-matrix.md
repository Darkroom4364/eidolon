# Production resource lifecycle matrix — #291 / #251 C3

Status: **C3a and C3b locally complete and independently reviewed; C3c
implemented and locally behavior-verified, with independent review pending**.
C3a starting head: `742b29e8b0e3b815e51c5ce017b166e10dcc1fb7`, the reviewed local
C2-on-C1 stack. The worktree was clean at that exact head before this slice.
Final reviewed C3a implementation head:
`9cabb4d48aafd2bda7065ee7a9166145a05c7324`, tree
`df793fdd647395b1887900087c38d83ae0e3767b`.

C3b starting head: `a4dd236cdf92c81b4457190f3910c4e26a54ad0a`, tree
`d673137e628d27bcba9c6679637b9e18060a9e94`. The dedicated worktree was clean
at those exact values before editing. Independently reviewed C3b implementation
head: `a6c1227952127dc15063f2d9820cba614e51d609`, tree
`7609e2ff7c61863eb796bc4ce22c245cb94213a1`.

C3c starting HEAD: `d8b5cfdbbdef538146142d653151a73b22d0765d`, tree
`c597e1977d1c3f63354256312aa607bfd2785f91`, branch
`test/production-resource-lifecycle-c3c`. The dedicated
`/Users/darkroom/Projects/.worktrees/eidolon-release-lifecycle-c3c-20260908`
worktree was clean at those exact values before editing. Those values identify
the base. Initial implementation head
`0cdfc70bb57f18f72d5bcacfe0aa91b6285c358e`, tree
`e2d27361d8cadeb9e3df23352f02bb70a31c2bdf`, was independently reviewed and
blocked on the portability of one pipeline wire assertion. The phase-aware
correction and fresh exact-tree review are pending; their identities and result
will be recorded only after root freezes and reviews that corrected tree.

This is finite production-listener regression evidence. It is not Linux/image
CI, Gate 2 completion, Gate 9 load/latency/RSS/soak evidence, publication,
merge, release qualification, or full C3 completion.

## Invariant, scope, and observed production result

The actual production accept loop must bound accepted connection work at its
configured capacity, discard cap+1 without starting request, rejection,
processor, or upstream work, and recover first one released slot and then all
capacity. Header and body stage deadlines, and a client EOF before its declared
body is complete, must release the connection task without poisoning the still
running listener. Only a fully validated recovery request may reach the real
`dispatch_production_upstream` path.

C3a adds test-only evidence, a test-module declaration, and an atomic
test-only connection-task peak hook beside the existing current-task watch.
The C1 harness passes `None` for that new observation hook; its assertions and
matrix are unchanged. Production branches, `main.rs`, vendor code, manifests,
locks, and workflows are unchanged. All agreed C3a cases passed against the
unchanged production behavior. **No production defect was demonstrated.** In
particular:

- cap+1 remains the existing terminal close/reset with zero response, not a
  synthetic HTTP overload response; both successful-write and terminal
  write-error paths perform the same bounded receive-side observation;
- a body-stage timeout remains exact `RequestTimedOut` with the fixture's safe
  empty 408 response;
- advertised-body EOF remains the existing empty HTTP 200 / `Content-Length:
  0` / connection-close wire outcome, but is explicitly neither a timeout nor
  successful processing;
- head parsing and body collection retain separate stage timers. C3a asserts a
  generous composed upper bound, not one accept-to-body absolute deadline.

C3b extends the test-only listener harness with a separate `c3b` submodule.
Its invariant is serial, exactly-once processing and complete upstream work
across three requests on one connection, followed by terminal close, task reap,
and fresh-connection recovery. Unsupported raw versions must release the task
through the exact typed request or pre-service rejection hook, produce no
normal/upstream work, and leave the same listener usable. The four new tests
compile. Their first restricted-sandbox run stopped at the recorder bind before
reaching production code; the subsequent owned-loopback run passed all four
cases and observed the exact version hooks, response ordering, counters, task
reaping, and recovery described below. **No production defect was
demonstrated.** Production behavior and all C3a/C1/C2 assertions remain
unchanged.

## Evidence layers

- **Listener:** the public production TCP accept loop and Hyper HTTP/1 server.
- **Full profile:** listener plus `ProductionLifecycleProcessor`, durable
  fixtures, renderer, and production upstream.
- **Direct/typed:** a helper or typed client/policy path without the accept loop.
- **Synthetic:** a fixture processor, TCP marker, parser diagnostic, Lab
  transport, or fixture renderer rather than complete production lifecycle.

The new C3a harness is Listener evidence with a synthetic counting/forwarding
processor and the real production upstream dispatcher. It does not replace the
full-profile durable-audit oracle.

## Existing exact-test inventory retained

All tests listed here remain unchanged.

| Exact test or group | Layer and retained evidence | Limit relevant to C3 |
| --- | --- | --- |
| `production_runtime::boundary_tests::raw_hyper_ingress_enforces_raw_head_cap_complete_write` | Listener; raw 65,536-byte head accepted and 65,537 rejected. | No simultaneous capacity or recovery. |
| `production_runtime::boundary_tests::raw_hyper_ingress_enforces_raw_head_cap_fragmented_writes` | Listener; the same head edge across two client writes. | Client writes are not TCP/Hyper read segmentation; not byte drip. |
| `production_runtime::boundary_tests::raw_hyper_ingress_rejects_unsafe_requests_before_the_protected_upstream_probe` | Listener; malformed transport, header count, HTTP/2 preface, target, CONNECT, upgrade, expectation, TE, and trailers stay before its TCP marker. | The marker is not an HTTP recorder; no post-rejection recovery. |
| `production_runtime::boundary_tests::raw_hyper_ingress_times_out_held_open_header_and_body_before_the_protected_upstream_probe` | Listener; held head -> `HeaderReadTimedOut`, held body -> `RequestTimedOut`, zero marker work. | No paced progress, terminal-wire, task-reap, or same-listener recovery oracle. |
| `production_runtime::boundary_tests::raw_hyper_ingress_rejects_an_oversized_collected_body_before_the_protected_upstream_probe` | Listener; collected body cap and zero marker work. | Not slow/partial-client lifecycle evidence. |
| C1 `production_runtime::ingress_tests::raw_host_authority_matrix` | Listener + real production client/owned HTTP recorder. | Fresh listener per matrix exchange; authority scope is not duplicated. |
| C1 `production_runtime::ingress_tests::raw_target_forms_and_canonical_forwarding_matrix` | Listener + real client/recorder. | Target scope is not duplicated. |
| C1 `production_runtime::ingress_tests::raw_duplicate_content_length_is_rejected_before_dispatch` | Listener + real client/recorder; parser-preservation boundary. | Framing scope is not duplicated. |
| C1 `production_runtime::ingress_tests::raw_invalid_and_conflicting_content_length_transport_matrix` | Listener + real client/recorder. | Framing scope is not duplicated. |
| C1 `production_runtime::ingress_tests::raw_content_length_transfer_encoding_both_orders_are_rejected` | Listener + real client/recorder. | Framing scope is not duplicated. |
| C1 `production_runtime::ingress_tests::raw_truncated_body_disconnect_has_no_validated_or_upstream_work` | Listener + real client/recorder; zero/two of four bytes, body-start synchronization, empty 200/close, zero hook/work. | Fresh listener; no task-release plus same-listener recovery. |
| C1 `production_runtime::ingress_tests::raw_forwarding_preserves_fields_and_strips_protected_headers` | Listener + real client/recorder; canonical forwarding. | Forwarding matrix is not duplicated. |
| C2 `production_runtime::upstream_tests::upstream_malformed_and_truncated_responses_do_not_replay` | Direct and Listener production client; exact typed errors and no post-send replay. | Upstream response boundary, not inbound resource cleanup. |
| C2 `production_runtime::upstream_tests::upstream_framing_acceptance_is_distinct_from_strict_ingress` | Direct and Listener production client. | Upstream framing only. |
| C2 `production_runtime::upstream_tests::upstream_decoded_body_cap_and_empty_controls` | Direct and Listener production client. | Upstream body only. |
| C2 `production_runtime::upstream_tests::upstream_informational_and_hop_header_controls` | Direct and Listener production client. | Upstream response only. |
| C2 `production_runtime::upstream_tests::upstream_protocol_switch_is_rejected_without_replay` | Direct and Listener production client. | Upstream protocol switch only. |
| C2 `production_runtime::upstream_tests::upstream_proxy_connection_is_not_forwarded` | Direct and Listener production client. | Response sanitization only. |
| C2 `production_runtime::upstream_tests::upstream_stage_and_absolute_deadlines_do_not_replay` | Direct and Listener production client; response-stage and dispatch deadlines. | Outbound deadlines, distinct from inbound head/body stages. |
| C2 `production_runtime::upstream_tests::upstream_recorders_and_connect_failure_fallback_are_live` | Positive controls for both owned recorders and pre-send fallback. | Not connection-admission evidence. |
| `production_runtime::tests::completed_connection_tasks_are_reaped_while_listener_is_running` | Listener; 128 sequential close/reap cycles with the test task watch. | Sequential cap one; no simultaneous exact-cap proof or RSS claim. |
| `production_runtime::tests::handler_waits_for_delayed_processor_before_responding_and_releasing_permit` | Listener; cap-one delayed synthetic processor owns work until release. | No cap greater than one, real upstream capture, or later recovery. |
| `production_runtime::tests::graceful_shutdown_drains_accepted_response_before_returning` | Listener; one accepted synchronous response drains within grace. | Injected shutdown; C3c phase isolation remains. |
| `production_runtime::tests::graceful_shutdown_closes_idle_keep_alive_connection` | Listener; post-response idle connection closes at shutdown. | No ordinary reuse or ordinary idle-timeout recovery. |
| `production_runtime::tests::closed_admission_denies_pipelined_service_without_processor_work` | Direct connection helper; closed gate yields first 200 then fixed 503, one processor call. | Bypasses the public accept-loop shutdown path; C3b/C3c remain. |
| `production_runtime::tests::pre_service_rejection_skips_processor_after_admission_closes` | Direct hook; post-close pre-service work is suppressed. | No listener socket. |
| `production_runtime::tests::shutdown_deadline_aborts_observed_cancellable_body_collection_then_waits_for_side_effect_quiescence` | Listener; grace aborts body collection, then waits for accepted non-cancellable synchronous work before exact `DrainDeadlineExceeded`. | Couples two phases; body-only C3c isolation remains. |
| `production_runtime::tests::committed_post_response_drop_never_retries_next_address` and `production_runtime::tests::total_dispatch_deadline_stops_fallback_and_releases_processor_permit` | Direct real client; retained no-retry/deadline behavior. | Not listener admission/cleanup. |
| `production_runtime::tests::handler_does_not_connect_upstream_after_pre_dispatch_budget_expires` and `production_runtime::tests::failed_processor_returns_empty_500_once_without_retry` | Listener controls for expired dispatch budget and processor failure. | Synthetic processors; not C3 resource matrix. |
| `production_runtime::tests::serve_production_http1_rejects_current_thread_runtime`, `production_runtime::tests::closed_processor_permit_semaphore_maps_to_unavailable_without_panic`, and `production_runtime::tests::empty_upstream_address_set_returns_typed_connect_failure_without_panic` | Runtime/typed defensive controls. | No lifecycle socket matrix. |
| `production_http::tests::supports_only_http11` | Typed policy rejects HTTP/1.0, HTTP/2, and HTTP/3. | Only HTTP/2 currently has raw-listener coverage; C3b remains. |
| `tests::production_hyper_loopback_forwards_normal_traffic_and_never_forwards_unsafe_proofs` | Listener + real lifecycle processor; unsafe proof shapes never forward. | Short-lived servers; not capacity/cleanup evidence. |
| `tests::production_profile_loopback_preserves_lifecycle_and_audits_pre_service_rejections` | Full profile; one continuing listener, durable/debug audits and finalization. | No concurrent capacity, active deadline recovery, or C3c phase isolation. |
| `tests::production_partial_body_disconnect_has_no_boundary_audit_event_or_upstream` | Full profile; durable no-normal-event/no-boundary-audit/no-upstream EOF oracle. | No body-start/task-count/same-listener recovery; deliberately retained as the durable companion to C3a. |
| `tests::production_malformed_body_remains_audited_boundary_rejection` | Full profile; malformed chunking is audited `BodyReadFailed`, unlike EOF. | Not partial-EOF recovery. |
| `tests::production_finalization_invokes_optional_debug_sync` and `tests::production_finalization_syncs_results_before_propagating_debug_sync_failure` | Direct finalizer ordering. | Not active public-listener shutdown. |
| `tests::connection_limiter_allows_exact_capacity_and_releases_on_drop` and `tests::connection_limiter_releases_when_worker_panics` | **Lab-only** atomic `ConnectionLimiter`. | Not the production semaphore, Hyper listener, processor, or upstream. |
| `tests::byte_drip_client_hits_total_deadline_and_releases_connection_capacity` | **Lab-only** blocking `DeadlineTcpReader` plus Lab limiter. | Its result cannot qualify production Hyper; C3a adds that missing listener evidence. |
| Vendored `proto::h1::io::tests::read_buffer_regression_exact_zero_still_reads_available_data`, `...read_buffer_regression_positive_next_limits_read_capacity`, and three `proto::h1::role::tests::content_length_regression_*` tests | Deterministic parser/buffer regressions retained from #287/C1. | No listener, lifecycle, allocator, or RSS claim. |
| `test-smoke-controlled-reality-capacity-kind.sh` | Fixture-renderer capacity classification and restoration. | Does not start the production listener. |
| Gate 9 | No checked-in load/soak result. | Its 25 connections, 100 rps, four-hour latency/error/RSS criteria are outside C3. |

C1's checked-in accounting remains 7 functions / 148 bounded exchanges. C2's
accounting remains 8 functions / 43 cases at both layers / 92 HTTP exchanges
plus one no-request port-zero control. C3a neither re-counts nor duplicates
those exchanges.

## Gap and duplicate analysis

| Area | Evidence before C3a | C3 disposition |
| --- | --- | --- |
| Exact capacity and recovery | Lab exact-cap, production cap-one block, and 128 sequential reaps. | **C3a implemented locally:** simultaneous cap two, terminal cap+1, zero excess work, one-slot/full recovery, peak and task quiescence through real dispatch. |
| Slow head/body | #287 held-open listener cases and Lab-only header drip. | **C3a implemented locally:** idle, paced incomplete head, paced incomplete body, exact hook/status/task/upstream outcomes, same-listener recovery. |
| Partial-body EOF | C1 wire/no-work and full-profile durable no-audit tests. | **C3a implemented locally:** extends only task release and same-listener real-upstream recovery; retains both earlier oracles unchanged. |
| Keep-alive/pipeline | Shutdown of one idle keep-alive and direct closed-gate pipeline denial. | **C3b locally complete and independently reviewed:** sequential reuse and successful bounded ordinary pipeline, with fresh recovery; no C1 framing or direct closed-gate denial duplication. |
| Unsupported versions | Typed HTTP/1.0/2/3 policy and raw HTTP/2 rejection. | **C3b locally complete and independently reviewed:** raw HTTP/1.0 and raw HTTP/2 rejection, task reap, and same-listener recovery; no HTTP/2 support. |
| Shutdown phases | Accepted drain, idle drain, direct admission closure, and coupled expiry/quiescence. | **C3c implemented and locally passed:** public-listener accepted/idle/late, queued pipeline, body-within-grace, and body-only expiry isolation; independent review remains. |

## Ordered C3 contract and case accounting

| Slice | Contract | Test functions / cases | Exchange accounting | Status |
| --- | --- | ---: | --- | --- |
| C3a | Exact capacity and one-slot/full recovery; idle/header/body deadline cleanup and recovery; zero/two-byte partial EOF cleanup and recovery. | **4 / 6**, plus one fixture-oracle negative check inside the capacity function. | **14 production-listener downstream TCP exchanges/peers; 8 complete upstream HTTP requests; one isolated fixture-only TCP exchange.** | **Implemented and locally passed.** |
| C3b | Three sequential requests on one keep-alive connection plus fresh recovery; three-request ordinary pipeline plus fresh recovery; raw HTTP/1.0 and existing raw HTTP/2 rejection recovery. | **4 / 4 implemented and passed** | Observed **8 downstream TCP peers / 12 request attempts / 10 complete upstream HTTP requests** after the earlier sandbox-denied run created zero exchanges. | **Locally complete; independent exact-tree review passed with no findings.** |
| C3c | Public-listener accepted/idle/late shutdown, queued pipeline isolation, body completion within grace, and body-only grace expiry. | **4 / 4 implemented and passed** | Observed per complete invocation: **6 downstream connection attempts, 5 successful TCP connects/accepted production tasks, 5 accepted-peer request attempts (one incomplete), 3 complete upstream requests**. The sixth, post-drop late TCP attempt was refused and wrote no request. | **Locally behavior-verified; independent review pending.** |

Full planned C3 is 12 test functions / 14 cases. C3a retains its independently
reviewed 4 functions / 6 cases and observed exchange accounting. C3b adds only
the next 4 functions / 4 cases, now locally behavior-verified and independently
reviewed; C3c is locally behavior-verified with independent review pending. C3b and C3c do not
retroactively expand C3a claims.

## New C3a fixtures, synchronization, and exact oracles

Source: `crates/eidolon-proxy/src/production_runtime_lifecycle_tests.rs`.
Prefix: `production_runtime::lifecycle_tests::`.

| Exact test | Cases and exchanges | Synchronization and exact oracle |
| --- | ---: | --- |
| `exact_capacity_overload_has_zero_excess_work_and_recovers` | 1 production case; 4 downstream peers, 3 upstream requests; plus one isolated fixture-only TCP exchange. | The fixture-only negative check injects a terminal write result after an owned peer queues a distinguishable 503 and proves that the common receive-side oracle preserves those bytes rather than fabricating an empty result. The production case uses capacity two. Each fixture processor calls the real dispatcher and stays held until the recorder has captured its complete method/target/headers/body. Snapshot at full: current tasks/current processors/peak tasks/peak processors/normal-process/upstream = `2/2/2/2/2/2`, request and pre-service rejections zero. Cap+1 must connect and attempt its bounded write; whether the write completes or observes a terminal reset, the client must then read through bounded EOF/reset, observe zero response bytes, and leave every work counter unchanged. Releasing only `/capacity/one` yields its exact target-body 200 and tasks/current one. `/capacity/recovered` restores tasks/current two and totals three. Releasing the remaining captures yields all three distinguishable exact responses, tasks/current zero, both peaks exactly two, then clean listener and recorder joins. No internal semaphore count is inspected. |
| `idle_and_header_byte_drip_deadlines_release_capacity_and_recover` | 2 cases; 4 downstream peers, 2 upstream requests. | Capacity one and one-second head deadline. Idle sends zero bytes. Drip attempts 12 one-byte client writes at fixed 100 ms intervals (well below the 32-write cap), requires at least eight successes, and invalidates itself if adjacent attempts are more than 250 ms apart. It never completes a head. Each peer must terminate within 1.7 seconds with zero bytes, task count zero, exactly one `HeaderReadTimedOut`, and zero request-rejection/normal/upstream work. A timer incorrectly restarted by the final write would expire at about 2.1 seconds and fail this bound; a scheduler pause long enough to turn the case into idle expiry fails the pacing oracle first. A same-listener GET then yields one complete recorder capture and exact target-body 200. |
| `head_then_body_byte_drip_has_composed_stage_bound_and_recovers` | 1 case; 2 downstream peers, 1 upstream request. | Capacity one. After 400 ms within the independent head stage, send a complete `Content-Length: 16` head, wait for the actual body-collection signal, then attempt at most 12 one-byte writes at fixed 100 ms intervals without completing the body. Require at least eight successes and no adjacent attempt gap above 250 ms. Require exact `RequestTimedOut`, empty 408 with one `Content-Length: 0` and connection close, zero pre-service/normal/upstream work, task zero, and body-stage terminal outcome within 1.7 seconds; a timer restarted by the last byte would expire at about 2.1 seconds. Admission-to-terminal is also bounded by a generous 3 seconds: two one-second stage budgets plus one second scheduler/socket margin, explicitly not one absolute deadline. Same-listener recovery traverses the recorder and returns exact 200. |
| `partial_body_disconnect_releases_capacity_and_same_listener_recovers` | 2 cases; 4 downstream peers, 2 upstream requests. | Capacity one; advertise four bytes, wait for actual body collection, send zero or two bytes, then half-close the client write side. Each partial request retains the empty HTTP 200 / one `Content-Length: 0` / connection-close outcome, with zero request/pre-service/normal/upstream work and task zero. A distinct same-listener recovery GET then creates exactly one normal processor and complete upstream request and returns its exact target-body 200. The full-profile test above remains the durable no-audit oracle. |

The shared counting processor records exact normal, request-rejection,
pre-service, current processor, and peak processor values. Its normal path calls
`dispatch_production_upstream` with the production request deadline. The raw
recorder independently parses one canonical fixed-length request, caps the full
wire at 16 KiB, signals only after complete capture, withholds a distinguishable
response until release, records through client EOF/reset, drains the concrete
accept queue after listener quiescence, and joins every accepted worker. Its
atomic complete-request count is the mid-test zero/exact-work oracle; no negative
accept timeout is used.

The listener records every post-spawn `JoinSet` length into an atomic maximum,
so an intermediate task-count transition cannot be lost through the coalescing
current-count watch. Current task values still provide the synchronized
`2 -> 1 -> 2 -> 0` checkpoints.

Every target is owned `127.0.0.1:0`. The capacity test also owns one isolated
fixture-only loopback pair for its write-reset receive-oracle negative check;
it is not counted as a production-listener exchange. Each operation, response
read, and join is bounded to five seconds; each test function has a 20-second
outer bound. There are at most four downstream and four upstream peers per
case/test and no more
than two production connection tasks. Every capture is at most 16 KiB. Expected
Darwin/Linux-style clean EOF and connection reset/abort/broken-pipe terminal
variants are normalized; a timeout never satisfies cap+1 termination. Assertion
unwind aborts the owned listener and recorder task trees. An abort-on-drop join
guard retains each handle across its bounded await, including cancellation by
the 20-second outer timeout. Drip writes are client application writes, not
claims about TCP packets or Hyper read boundaries.

## Retained C3a first-run observations

1. Before editing, `git rev-parse HEAD` returned
   `742b29e8b0e3b815e51c5ce017b166e10dcc1fb7` and `git status --short` was
   empty.
2. The first requested new-filter invocation, before any production-behavior
   edit, compiled only as far as the new harness and exited 101 with four
   fixture compile diagnostics: one borrowed-head lifetime error, one missing
   `JoinSet` unwrap that produced two type errors, and one watch-borrow error in
   timeout diagnostics. No test or production behavior ran. Only those test
   fixture errors were corrected.
3. The next unchanged filter execution started all four tests inside the
   restricted sandbox; each stopped at the first owned recorder bind with
   `PermissionDenied` / `Operation not permitted`. Result: 0 passed, 4 failed,
   349 filtered. This was an environment restriction, not protocol evidence.
4. The first loopback-permitted behavior run passed all four functions in 1.08
   seconds, 349 filtered. It observed the exact counter/task/response sequences
   in the table above. No production source behavior was changed before or
   after that run, and no source defect was demonstrated.
5. Root review found that the initial 500 ms / 50 ms drip schedule and
   five-second read bound could still pass if each byte incorrectly restarted a
   stage timer. The final oracle uses a one-second deadline, 12 writes at 100 ms,
   and a 1.7-second terminal bound; a restart on the last write would expire at
   about 2.1 seconds. This is a test-only oracle correction, not a runtime
   behavior change.
6. Independent review of checkpoint
   `90a5b653057ee8c988f4a4643f94e42aa6b913c4` blocked three test-evidence
   weaknesses and identified one portability risk: a coalescing watch could
   miss an intermediate task peak; an interrupted drip schedule could turn into
   idle expiry; finish-time or outer cancellation could detach moved join
   handles; and cap+1 could reset during the write. The follow-up adds a
   sender-side atomic task maximum, measured pacing gaps/minimum progress, an
   abort-on-drop join owner, and write-side terminal normalization. None changes
   production behavior.
7. Exact-head re-review of `1498966f89fa85f95c690d991a874de3ab60cb52`
   confirmed the three P2 corrections but blocked the terminal-write branch's
   fabricated empty response: a peer could queue bytes before the write reset,
   while direct overload-path output would leave all work counters unchanged.
   The final helper now always performs the bounded receive-side read, and the
   capacity test contains a deterministic buffered-503 negative check for that
   branch. This remains test-only oracle repair, not a production behavior
   change.
8. Final exact-head review of
   `9cabb4d48aafd2bda7065ee7a9166145a05c7324` / tree
   `df793fdd647395b1887900087c38d83ae0e3767b` passed with no findings. It
   independently confirmed both review rounds resolved, the negative check is
   executed/owned/bounded and separately accounted, all source and test counts
   reconcile, and production behavior remains unchanged. Report:
   `/tmp/codex-tasks/eidolon-lifecycle-c3a-finalreview-20260908.last.md`.

## Retained C3a local verification

These are the previously recorded C3a results, not new C3b executions.

Platform: Darwin 25.6.0 arm64. Toolchain: `rustc 1.95.0
(59807616e 2026-04-14)`. All Cargo commands used `--offline --locked` and the
worktree-local `$PWD/target/c3a`.

| Command/check | Result |
| --- | --- |
| `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime::lifecycle_tests:: -- --nocapture` | Initial socket-enabled behavior run: **4 passed** in 1.08 seconds. After root strengthened the non-reset timing oracle and corrected both review rounds: **4 passed** in 2.14 seconds, 0 failed, 349 filtered; six production cases, 14 production-listener downstream exchanges, eight complete upstream requests, plus the fixture-only buffered-response negative check. |
| `cargo +1.95.0 fmt --all -- --check` | Passed after mechanical formatting. |
| `git diff --check` | Passed. |
| `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime:: -- --nocapture` | Final write-reset-corrected tree: **38 passed**, 0 failed, 315 filtered in 30.29 seconds: four new and all 34 retained runtime/#287/C1/C2 tests. |
| `cargo +1.95.0 build --offline --locked --workspace --all-targets` | Passed again after the second review correction. |
| `cargo +1.95.0 clippy --offline --locked --workspace --all-targets --all-features -- -D warnings` | Passed again after the second review correction. |
| `cargo +1.95.0 test --offline --locked --workspace --all-targets` | Final write-reset-corrected tree passed all targets; **812 tests**, four more than the retained 808-test C2 tree. Includes the unchanged full-profile partial-body no-audit test. |
| Vendored Hyper `regression` filter with `client,http1,http2,server` | **5 passed**: both #287 read-buffer and all three C1 content-length regressions. |
| Vendored Hyper exact `proto::h1::role::tests::test_decoder_request` | **1 passed**. |

Verification used only owned loopback sockets and offline local artifacts. It
did not access external network services, GitHub, Docker/Kubernetes/OrbStack,
credentials, sensitive files, external targets, or online audits.

## C3b implementation, synchronization, and expected accounting

Source: `crates/eidolon-proxy/src/production_runtime_lifecycle_tests.rs`.
Exact prefix: `production_runtime::lifecycle_tests::c3b::`.
The following counts describe one complete matrix invocation of the implemented
and subsequently observed cases; the earlier blocked run created zero
exchanges. Each function contains exactly one production-listener case.

| Exact test | Cases / downstream TCP peers / request attempts / complete upstream requests | Synchronization and required oracle |
| --- | ---: | --- |
| `three_sequential_keep_alive_requests_and_fresh_connection_recover` | **1 / 2 / 4 / 4** | One capacity-one listener and one reused downstream connection send `/sequential/one`, `/sequential/two`, and `/sequential/three`. Only request three asks to close. Each complete upstream capture is checked and released; its exact `HTTP/1.1 200 OK` and target body are fully parsed before the next write. Held-capture snapshots require normal/upstream counts `1`, `2`, `3`, current processor one, both retained peaks one, and no rejection hooks. After each response current processors must be zero; after the first two, the connection-task watch remains one. After response three, no extra bytes may precede terminal EOF/reset, and the task must reap before a fresh `/recovery/sequential` close exchange. Final exact normal/upstream totals are four, current processors/tasks zero, both peaks one, and the joined recorder set contains exactly all four targets once. |
| `three_pipelined_requests_are_ordered_once_and_fresh_connection_recovers` | **1 / 2 / 4 / 4** | One bounded application write contains three complete requests for `/pipeline/one`, `/pipeline/two`, and `/pipeline/three`, with only the last asking to close. Complete upstream captures are observed and released in target order, with the same exact held-capture snapshots as the sequential case. Downstream reads begin after all three releases, using one retained per-peer buffer. Exactly three `HTTP/1.1 200 OK` frames must contain the corresponding target bodies in wire order. Both buffered trailing bytes and bytes arriving after frame three fail, including a partial fourth response; EOF/reset must be terminal and a timeout fails. Task reap precedes fresh `/recovery/pipeline`; final exact totals, peaks, and joined target set match the sequential case. The existing direct closed-admission pipeline denial test is unchanged. |
| `raw_http10_rejection_releases_task_and_listener_recovers` | **1 / 2 / 2 / 1** | A complete raw `GET /version/http10 HTTP/1.0` includes Host and `Connection: close` and reaches the actual listener. Require exactly `[UnsupportedHttpVersion]`, no pre-service hook, zero normal/current/peak processor and upstream counts, task peak one, an empty fixed-length 400, terminal peer, and task zero. Only fresh `/recovery/http10` may enter normal processing and the final joined recorder set; final normal/upstream/processor peak/task peak are each one, current processors/tasks zero, and the rejection vectors remain exact. |
| `raw_http2_preface_rejection_releases_task_and_listener_recovers` | **1 / 2 / 2 / 1** | A fixed `[u8; 24]` contains the retained `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` shape. Require exactly `[ProductionPreServiceRejection::Http2Preface]`, zero request rejection/normal/current/peak processor/upstream work, task peak one, zero response bytes, terminal EOF/reset, and task zero. Only fresh `/recovery/http2-preface` may enter normal processing and the final joined recorder set; final exact counters and retained hook vector prove same-listener recovery without HTTP/2 support. |
| **C3b total** | **4 / 8 / 12 / 10** | Exactly four new behavior functions and four cases; the preface counts as one downstream request attempt, not a policy-adapted HTTP request. |

`ResponseFrames` is an incremental fixed-length response reader. It finds one
complete CRLF-delimited head, requires exactly one nonempty decimal
`Content-Length` that fits `usize` and the remaining capture budget, rejects
transfer encoding, and waits for exactly that body length before returning a
borrowed frame. Every caller checks the exact status line and body. A cursor
advances through one retained wire buffer, preserving any following response
bytes; consumed bytes still count toward the aggregate 16 KiB peer limit.
It never uses `read_to_end`. Final termination first rejects buffered bytes,
then performs a bounded read that must yield EOF/reset with no bytes. Terminal
state prevents later reads or frames; timeout never satisfies termination.

All C3b sockets use the existing owned `127.0.0.1:0` fixtures. Each case opens
exactly two downstream peers, sequentially, and permits at most four upstream
peers and one production connection task at a time. The request writes are
finite literal-sized messages; the pipeline also explicitly caps its single
application write at 16 KiB. Downstream and upstream captures are at most
16 KiB per peer. Reads, writes, connects, capture releases/waits, and joins
retain five-second operation bounds, and every test has a 20-second outer
timeout. Release sends are synchronous one-shot operations. The existing
`serve_production_http1_inner`, counting/forwarding processor, real
`dispatch_production_upstream`, complete-capture counter, task watch, atomic
retained peak, recorder accept-queue drain, and joined final record set are
reused unchanged. No negative accept timeout is a zero-work oracle.

There are no new spawned tasks or detached handles. Successful finish joins
the production listener and recorder; existing abort-on-drop owners cover
assertion unwind and outer-timeout cancellation, including bounded join
futures, and the recorder's `JoinSet` owns accepted workers. These are source
ownership/boundedness checks exercised through each passing completion path,
not hard-kill fault injection. Client writes and response buffering make no TCP
segmentation claim. C1/C2 matrices, C3a assertions and accounting, runtime
behavior, `main.rs`, manifests, locks, workflows, and vendor code remain
unchanged.

## C3b first run, version semantics, and local verification

Platform: Darwin 25.6.0 arm64. Toolchain: `rustc 1.95.0
(59807616e 2026-04-14)`. Commands ran in the supplied dedicated worktree with
`CARGO_TARGET_DIR="$PWD/target/c3b"`. Every Cargo compilation/lint/test command
used `--offline --locked`; formatting used `CARGO_NET_OFFLINE=true`.

The first no-run compile passed without fixture diagnostics. The first focused
behavior invocation then exited 101: **0 passed, 4 failed, 353 filtered out,
0.00 seconds**. All four failed at the same initial recorder bind, before the
production listener existed:

```text
crates/eidolon-proxy/src/production_runtime_lifecycle_tests.rs:290:14
owned recorder should bind: Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }
```

The complete original output is retained at
`target/c3b/c3b-first-behavior.log` in this worktree. It was captured with
`set -o pipefail` and `2>&1 | tee target/c3b/c3b-first-behavior.log`, preserving
the failing Cargo exit status. This is exact sandbox failure evidence, not
fail-first evidence of a production defect. No production repair or access
escalation followed it, and no helper-only passing test replaced the cases.

Root then ran the same focused command with owned loopback permitted. It passed
all four functions in 0.01 seconds, 353 filtered. This confirmed that HTTP/1.0
reaches `ProductionHttpPolicy::adapt` and exact `UnsupportedHttpVersion`; the
fixture supplies an empty `HTTP/1.0 400 Bad Request` with one
`Content-Length: 0`, no connection header, and terminal close by HTTP/1.0
semantics. The retained 24-byte HTTP/2 preface maps to exact
`ProductionPreServiceRejection::Http2Preface` before request policy, with no
response channel or wire bytes. Both version cases reap their task and recover
on the same listener. Sequential and pipelined cases observed exact ordered
target bodies, serial processor peak one, no extra response, task reap, and
fresh-connection recovery. The observed totals were the planned eight
downstream peers, 12 request attempts, and ten complete upstream requests. No
production defect was demonstrated.

| Command/check (with the environment above) | Exact local outcome |
| --- | --- |
| `cargo +1.95.0 fmt --all -- --check` | Exit 0 after formatting only the changed test file with the pinned rustfmt. |
| `git diff --check` | Exit 0. |
| `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime::lifecycle_tests::c3b:: --no-run` | Exit 0; compiled the library test executable in 11.27 seconds, including all four C3b tests. |
| `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime::lifecycle_tests::c3b:: -- --nocapture` | Exit 101; all four initial owned recorder binds denied as quoted above; 0 passed, 4 failed, 353 filtered, no production exchanges. |
| `cargo +1.95.0 clippy --offline --locked -p eidolon-proxy --lib --tests -- -D warnings` | Exit 0 in 5.74 seconds; no warnings. |
| `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime:: -- --list` | Exit 0; inventory only: 42 tests, 0 benchmarks, comprising the 38 retained runtime tests and four C3b additions. No behavior ran. |
| Root rerun: `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime::lifecycle_tests::c3b:: -- --nocapture` | **4 passed**, 0 failed, 353 filtered in 0.01 seconds; four cases, eight downstream peers, 12 attempts, ten complete upstream requests. |
| Root rerun: `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime:: -- --nocapture` | **42 passed**, 0 failed, 315 filtered in 30.30 seconds: eight C3a/C3b lifecycle tests and all 34 retained runtime/#287/C1/C2 tests. |
| `cargo +1.95.0 build --offline --locked --workspace --all-targets` | Passed on the C3b tree. |
| `cargo +1.95.0 clippy --offline --locked --workspace --all-targets --all-features -- -D warnings` | Passed on the C3b tree. |
| `cargo +1.95.0 test --offline --locked --workspace --all-targets` | Passed all targets; **816 tests**, four more than the reviewed C3a tree. |
| Vendored Hyper `regression` filter with `client,http1,http2,server` | **5 passed**. |
| Vendored Hyper exact `proto::h1::role::tests::test_decoder_request` | **1 passed**. |
| Direct compiled C3b test-binary filter repeated ten times | **10/10 suite repetitions passed** (40 test executions). This is a stability diagnostic; the matrix table records one invocation's case/exchange counts. |

No unrelated shell fixture/live suites were run for C3b. There was no external
network, credential/secret access, container or cluster operation, or
other-worktree mutation. The C3a verification and independent-review results
above remain separate historical evidence, not substitutes for the C3b passes.

Root froze the inspected implementation in local commit
`a6c1227952127dc15063f2d9820cba614e51d609`, tree
`7609e2ff7c61863eb796bc4ce22c245cb94213a1`. An independent read-only review
of that exact clean detached target passed with no findings. It independently
checked the response parser and no-fourth-response oracle, all four behavior
oracles, exchange accounting, finite bounds, task/recorder ownership, retained
C3a content, diff scope, pinned formatting, and final Git cleanliness. The
fresh review worktree intentionally had no build artifacts, so compilation and
behavior results above remain root-run evidence rather than reviewer reruns.

## C3c implementation and exact local oracles

Source: `crates/eidolon-proxy/src/production_runtime_lifecycle_tests.rs`.
Exact prefix: `production_runtime::lifecycle_tests::c3c::`.
Each of the following four functions contains exactly one production-listener
case through `serve_production_http1_inner` and the owned HTTP recorder. The
invariant is phase isolation: shutdown closes admission and drops the listener,
accepted work can finish within grace, queued/late work never reaches request
or pre-service rejection hooks, normal processing, or upstream, and isolated
body collection is aborted and joined on grace expiry. The retained coupled
expiry/non-cancellable-quiescence test and direct closed-gate test are unchanged.

These exact oracles passed on owned Darwin loopback. Linux/image and independent
review remain open.

| Exact test | Connection attempts / accepted production tasks / accepted-peer request attempts / complete upstream requests | Exact wire and work oracle |
| --- | ---: | --- |
| `accepted_idle_and_late_shutdown_drains_only_accepted_work` | **3 / 2 / 1 / 1** | Capacity two. Hold `/shutdown/accepted` only after its complete GET upstream capture, then positively observe two tasks including a second idle peer. After shutdown acknowledgment, the idle peer must reach EOF/reset with zero bytes and reap, leaving one task/current processor. A distinct late connection attempt must resolve within five seconds; refusal/reset is accepted, or a successful TCP connect must attempt one finite request write and then read bounded EOF/reset with zero bytes even if the write reset. The total-spawn counter must remain two, both rejection vectors empty, and normal/upstream/processor peak exactly one. At that fence the server remains pending on the held processor. Release within three-second grace; require exactly one complete target-body `HTTP/1.1 200 OK`, close, no extra bytes, processor/task zero, the one exact joined recorder entry, and `Ok(())`. |
| `queued_pipeline_shutdown_never_dispatches_second_request` | **1 / 1 / 2 / 1** | One capacity-one peer makes one finite application write of two complete HTTP/1.1 GETs, first keep-alive and second close. Hold the complete capture for `/shutdown/pipeline/first`, acknowledge real shutdown, then release within grace. Require the first complete exact target-body `HTTP/1.1 200 OK`. A test-only service-call counter then phase-correlates the only two source-permitted terminal outcomes: zero closed-admission calls requires immediate EOF/reset with no second frame; exactly one call requires one complete empty `HTTP/1.1 503 Service Unavailable` with `Content-Length: 0`/`Connection: close`, then EOF/reset. Any partial, extra, mismatched, or multiple response/call fails. Normal/upstream/processor peak/task peak/total spawned tasks each equal one, both rejection vectors remain empty, current processors/tasks zero, only the first record joins, and the server returns `Ok(())`. Darwin observed the one-call 503 branch. |
| `body_completed_after_shutdown_within_grace_is_processed_once` | **1 / 1 / 1 / 1** | Capacity one. Write the complete POST `/shutdown/body` head with `Content-Length: 1` and close. Wait for the actual body-collection signal with zero work, acknowledge shutdown, then write exactly `x` within grace. Require exactly one complete upstream POST with that target/body, hold and release it within grace, one complete exact target-body 200 and terminal close, zero rejection hooks, exact normal/upstream/processor peak/task peak/total spawned tasks one, current processor/task zero, one byte-exact joined recorder entry, and `Ok(())`. |
| `body_only_grace_expiry_aborts_without_processor_or_upstream_work` | **1 / 1 / 1 incomplete / 0** | Same POST head and actual body signal, capacity one, 200 ms shutdown grace versus independent five-second request/body timeout. Acknowledge shutdown and withhold the byte without half-closing early. Require terminal EOF/reset with zero response bytes, zero normal/current/peak processor and upstream work, empty request/pre-service rejection vectors, task peak/total one then joined task zero, an empty joined recorder, and exact `Err(DrainDeadlineExceeded)`. No synchronous processor is added to this isolated case. |

One successful invocation observed four cases, six downstream connection
attempts, five successful TCP connects/accepted production peers/tasks, five
accepted-peer request attempts (four complete requests and one incomplete POST),
and three complete upstream requests. The sixth connection attempt occurred
after the listener-drop acknowledgment and was refused, so it wrote no request
and created no task. A connected late-peer terminal path remains an explicitly
bounded portable oracle, but it was not the observed Darwin outcome. Each
passing case emits its accounting. The earlier sandbox-denied run remains
separate and observed no production exchanges.

`ShutdownObservation` and its new inner-function argument are `cfg(test)` only.
The one-shot is sent after admission closes, drain is sent, the listener is
dropped, and the existing grace deadline is established. It does not wait on or
steer the runtime. A cumulative atomic post-spawn counter supplements the
retained peak: a late task cannot hide below the earlier peak of two. The
existing task-count watch now publishes the actual `JoinSet` length after clean
drain joins and publishes zero on deadline failure only after abort and all
joins complete. A separate test-only counter records each service invocation
that observes closed admission; the pipeline wire must match that positive phase
observation after the connection task joins. No sleep, quiet accept, or
negative-timeout-only assertion establishes admission closure, zero work, or
task quiescence.

The first independent review blocked the initial unconditional 503 oracle.
Although every Darwin execution produced 200 then empty 503, Hyper may yield on
read/flush after the first response and let the ready drain branch close the
connection before dispatching the buffered second head. The corrected oracle is
phase-aware rather than an unconditional fallback: a complete second 503 is
accepted only with exactly one observed closed-admission service call; terminal
close after the first complete 200 is accepted only with zero such calls. Strict
framing, no-extra-data, exact one-work counters, joined-task state, and the sole
upstream record remain common. No unsafe behavior or production defect was
demonstrated.

The shared harness retains the sole shutdown sender and consumes it exactly
once, waits for the positive acknowledgment, and owns the server through the
bounded join using `AbortOnDropTask`. Clean and deadline results are compared
exactly. The recorder is stopped, its concrete accept queue drained, and every
worker joined only after production listener quiescence and server join.
Assertion unwind and outer cancellation abort the owned server/recorder task
trees; no new spawned task is detached. The recorder's existing four-peer bound
is configurable test-only and is reduced to one for C3c; C3a/C3b retain four.

Each C3c case has a 20-second outer timeout. All connects, writes, reads,
signal/capture waits, and joins have at most five-second operation bounds;
releases are synchronous one-shot sends. Clean grace is three seconds and
release-time checks conservatively measure from the shutdown request, before
the runtime establishes its grace deadline. Every downstream peer and upstream
capture retains the 16 KiB aggregate cap, including consumed response frames.
The C3b framed reader is reused with only visibility changes, preserving exact
fixed-length framing and extra-data rejection. There are at most three
downstream TCP attempts, two accepted production tasks, and one complete
upstream request per case. Timeout never counts as peer termination. All
sockets are owned `127.0.0.1:0`; there is no external target or TCP segmentation
claim.

Changed runtime code is limited to `cfg(test)` signals/counts and a test-only
Clippy argument-count allowance; the non-test/public signature and behavior
are unchanged. Direct test call sites pass `None` when not observing shutdown.
C1/C2/C3a/C3b behavioral assertions, production contracts, `main.rs`, manifests,
lockfiles, workflows, and vendor sources are unchanged. Compilation, formatting,
lint, sandbox, and behavior outcomes are recorded separately below when run.

## C3c local verification

Platform: Darwin 25.6.0 arm64, `rustc 1.95.0 (59807616e 2026-04-14)`.
All commands ran only in the dedicated C3c worktree. Cargo compile/lint/test
commands used `CARGO_TARGET_DIR="$PWD/target/c3c"` and `--offline --locked`;
formatting also used `CARGO_NET_OFFLINE=true`. Source edits, including the
mechanical formatting correction, used `apply_patch`.

The first focused no-run compilation passed without compiler/fixture errors.
The single focused behavior invocation exited 101: **0 passed, 4 failed,
357 filtered out, 0.00 seconds**. All four functions stopped at their initial
owned recorder bind, before a production listener or recorder task existed:

```text
crates/eidolon-proxy/src/production_runtime_lifecycle_tests.rs:292:14
owned recorder should bind: Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }
```

The exact output is retained at `target/c3c/c3c-first-behavior.log`. Capture
used `set -o pipefail` and `2>&1 | tee target/c3c/c3c-first-behavior.log`,
preserving Cargo's exit 101. Actual execution accounting is **four denied
recorder bind attempts, zero production listeners, zero downstream connection
attempts/accepted tasks/request attempts, and zero upstream exchanges**. No
pipeline or late-peer wire outcome was observed. This is sandbox environment
evidence, not a production behavior failure or pass. No repair followed the
bind denial.

Root then ran the initial exact dirty tree with owned loopback permitted. The
first real behavior invocation passed all four functions in 0.21 seconds, 357
filtered.
The late post-drop connection was refused, so the complete invocation observed
six connection attempts, five successful connects/accepted tasks, five
accepted-peer request attempts, no late request write, and three complete
upstream requests. The pipeline emitted exactly the first target-body 200,
fixed empty 503, then EOF/reset. The body-within-grace case completed its exact
POST once and returned `Ok(())`; the isolated withheld-body case emitted zero
bytes/work and returned exact `DrainDeadlineExceeded`. No production defect was
demonstrated and production behavior was not changed.

Root froze that initial implementation as
`0cdfc70bb57f18f72d5bcacfe0aa91b6285c358e`, tree
`e2d27361d8cadeb9e3df23352f02bb70a31c2bdf`. Independent read-only review
returned **BLOCK** with one P2 finding: Hyper is allowed to yield while
flushing the first response, select the ready drain signal, and close before a
buffered second request reaches the service. The unconditional 503 assertion
therefore encoded one Darwin schedule rather than the complete source-permitted
contract. The reviewer found no other lifecycle, boundedness, accounting, or
instrumentation issue.

The corrected tree adds a test-only closed-admission service-call counter and a
bounded optional-frame reader. After the connection task joins, the pipeline
case now requires exact correlation: zero calls with immediate terminal close,
or one call with one complete empty 503 and then terminal close. Partial frames,
extra data, call/frame mismatches, and multiple calls fail. The corrected
focused invocation passed all four functions in 0.21 seconds and observed one
closed-admission call with the complete 503 branch. Ten additional corrected
suite repetitions passed all 40 executions. The corrected runtime, workspace,
build, lint, and vendored-Hyper gates also passed as recorded below.

| Command/check (with the environment above) | Exact outcome |
| --- | --- |
| `pwd`; `git rev-parse HEAD HEAD^{tree}`; `git branch --show-current`; `git status --short` | Exit 0 each; exact starting worktree/HEAD/tree/branch quoted above and empty status before edits. |
| `rustc +1.95.0 --version`; `uname -srm` | Exit 0 each; exact toolchain/platform quoted above. |
| `cargo +1.95.0 fmt --all -- --check` | Initial exit 1: line wrapping in the new test helper/import only. Corrected with `apply_patch`; both the initial committed implementation and final phase-aware correction then passed. |
| `git diff --check` | Exit 0 on the initial implementation and corrected tree. |
| `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime::lifecycle_tests::c3c:: --no-run` | Exit 0 initially in 12.50 seconds and again after the phase-aware correction; all four C3c functions compile. Compilation evidence only. |
| `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime::lifecycle_tests::c3c:: -- --nocapture` | Exit 101; 0 passed, 4 failed, 357 filtered, 0.00 seconds; all recorder binds denied as above. Executed exactly once; no behavior evidence. |
| `cargo +1.95.0 clippy --offline --locked -p eidolon-proxy --lib --tests -- -D warnings` | Exit 0 in 6.06 seconds; no warnings. |
| `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime:: -- --list` | Exit 0; 46 tests, 0 benchmarks: all 42 retained runtime tests plus exactly four C3c additions. Listing only; no unrelated test executed. |
| Read-only Python comparison against `git show HEAD:crates/eidolon-proxy/src/production_runtime_lifecycle_tests.rs` | Exit 0; C3a case/helper bodies byte-identical, C3b module identical except helper visibility, exactly four C3c test functions and four outer timeouts. |
| Initial root loopback run of the focused C3c filter with `--nocapture` | **4 passed**, 0 failed, 357 filtered in 0.21 seconds; exact initial accounting and observed 503 wire are recorded above. |
| Initial focused C3c filter repeated ten additional times | **10/10 suite repetitions passed** (40 test executions, 0 failures; 0.20–0.24 seconds per suite). This preceded the independent review block. |
| Corrected root loopback run of the focused C3c filter with `--nocapture` | **4 passed**, 0 failed, 357 filtered in 0.21 seconds; exact phase correlation was one closed-admission call and one complete empty 503. |
| Corrected focused C3c filter repeated ten additional times | **10/10 suite repetitions passed** (40 test executions, 0 failures). Repetition is a stability diagnostic; accounting above records one corrected invocation only. |
| Corrected root loopback rerun: `cargo +1.95.0 test --offline --locked -p eidolon-proxy --lib production_runtime:: -- --nocapture` | **46 passed**, 0 failed, 315 filtered in 30.35 seconds: all 12 C3 functions plus 34 retained runtime/#287/C1/C2 tests. |
| Corrected `cargo +1.95.0 build --offline --locked --workspace --all-targets` | Passed in 2.62 seconds. |
| Corrected `cargo +1.95.0 clippy --offline --locked --workspace --all-targets --all-features -- -D warnings` | Passed in 2.29 seconds with no warnings. |
| Corrected `cargo +1.95.0 test --offline --locked --workspace --all-targets` | Passed all targets; **820 tests** (30 + 22 + 17 + 361 + 14 + 260 + 1 + 110 + 5), four more than C3b. A restricted-sandbox rerun separately failed only because 47 loopback-binding tests received `PermissionDenied`; the permitted exact rerun passed. |
| Corrected vendored Hyper `regression` filter with `client,http1,http2,server` | **5 passed**, 121 filtered. |
| Corrected vendored Hyper exact `proto::h1::role::tests::test_decoder_request` | **1 passed**, 125 filtered. |

The only tracked edits are the lifecycle test file, runtime test-only
instrumentation, one `None` at the direct C1 test call site, and this plan. No
unrelated fixture/live suite, network service, credential/secret,
container/OrbStack/cluster, or other worktree was used. Root alone owns the
pending local commit. The retained C3a/C3b results remain separate historical
evidence; the 46-test runtime and 820-test workspace passes explicitly reran
their code on the C3c tree.

Next root actions are to freeze this inspected tree in a local commit and obtain
independent exact-tree review. Linux/image CI, publication/integration/merge,
Gate 2/Gate 9, and release qualification remain open.

## Remaining gates and limits

- [x] C3a exact capacity, cap+1 zero excess work, one-slot/full recovery, exact
  counters, task reaping, joined recorder, and clean listener shutdown.
- [x] C3a idle/header drip and body drip stage cleanup/recovery with exact hook,
  response, process, task, and upstream outcomes.
- [x] C3a zero/two-byte partial-body EOF cleanup/recovery while retaining C1 and
  the full-profile durable no-audit test unchanged.
- [x] C3b four-case test implementation, pinned formatting, offline no-run
  compile, and scoped Clippy with warnings denied.
- [x] C3b keep-alive, ordinary pipeline, HTTP/1.0, and post-HTTP/2 local
  behavior verification and actual exchange accounting.
- [x] Independent exact-tree C3b review passed with no findings.
- [x] C3c four-case test-only implementation, pinned formatting, offline
  no-run compilation, scoped Clippy, and static inventory.
- [x] C3c public-listener shutdown phase isolation locally passed with exact
  accepted/idle/late, queued-pipeline, within-grace, and expiry outcomes.
- [x] Exact implementation-head independent re-review of the corrected C3a
  harness passed with no findings.
- [ ] Linux/image exact-head CI and full C3 cross-runtime review.
- [ ] Authorized publication, C1/C2 integration order, PR/merge checks, and
  merged-commit verification.

Darwin loopback results do not substitute for Linux/image CI. This finite matrix
does not measure allocator/RSS behavior, throughput, burst handling, latency or
SLOs; does not test external services, HTTP/2 support, OS signal/process
orchestration, HA, or hard interruption of synchronous processor work; and does
not complete Gate 2, Gate 9, #251, #253, #254, C4, release, or v1 promotion.
