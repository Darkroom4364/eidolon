# Production upstream-response boundary — #251 C2

Status: local C2 implementation and macOS verification complete for #290 on
reviewed C1 `4f8b3eb98afee972d00da18100cbd10426f7ff05` (#289). Root independently
reproduced both response-boundary defects on the unchanged C1 runtime, applied
the two narrow repairs below, and passed the complete local gate. Independent
cross-runtime review of `f0e55a60689571a0b358a589b5682ee25d240893`
returned `PASS` with no findings; Linux CI remains. Neither C1 nor C2 is merged
or published; C1 publication still needs GitHub workflow permission. This plan
does not supersede or edit C1's source/inventory.

## Contract

Exercise the actual production Hyper client against owned raw HTTP responders.
Record response status/body/header sanitization or the exact typed failure and
downstream behavior. Once a request has been sent, an upstream response failure
must never replay it to another resolved address. Observe one complete request
at the first responder and zero fallback requests/connections. Positive controls
must demonstrate that both recording endpoints can receive real requests.

## Implementation and evidence boundary

New module: `crates/eidolon-proxy/src/production_runtime_upstream_tests.rs`.
`production_runtime.rs` wires that test module, rejects a surfaced `101
Switching Protocols` response with the existing `ResponseFailed` error, and
removes `Proxy-Connection` in the existing response sanitizer. Existing test
bodies, `main.rs`, vendor source, manifests, locks, workflows, other worktrees,
credentials and clusters are unchanged.

Every matrix case has two distinct executions:

- **Direct**: `ProductionHttpPolicy.adapt` -> actual
  `dispatch_production_upstream` -> two owned raw TCP recorders.
- **Listener**: raw downstream HTTP -> public `serve_production_http1` ->
  forwarding processor -> actual `dispatch_production_upstream` -> the same
  two-recorder arrangement -> real Hyper downstream serialization. The
  processor records the exact `Result<ProductionResponse,
  ProductionUpstreamError>` before mapping an error to
  `ProductionProcessorError::Failed`.

The executed listener harness proves this public runtime composition; it
does not instantiate the complete `ProductionLifecycleProcessor` or production
profile. Its error mapping follows the real application source:
`main.rs::process_request`, `UpstreamTransport::Production`, maps the dispatch
error to `io::Error`; `ProductionLifecycleProcessor::process` calls
`production_request_processing_failed`, returning `Failed`;
`production_runtime.rs::finish_processor_result` creates the empty 500;
`response_to_hyper` lets Hyper serialize it. There is no application 502 or
504 claim. The existing deadline-handler test's 504 is its fixture processor's
choice, not this application mapping. No extra `main.rs` regression was needed
to express the public listener contract; full profile verification remains a
separate root gate.

The invariant is one complete `POST /c2/commit?case=owned HTTP/1.1` with the
exact eight-byte binary body `commit\x00\xff` at address one, followed by client
EOF/reset, and **zero address-two connections/requests** after a post-send
failure. Each recorder retains all request bytes through connection closure,
so another request on the same connection fails the body equality assertion.
After direct dispatch returns (including dropping its in-task Hyper driver),
or after listener shutdown/drain joins, each recorder drains its nonblocking
accept queue and joins every accepted connection before assertions. No
negative accept timeout is used as the no-replay oracle.

All listeners use owned `127.0.0.1:0`. Capture is capped at 4,096 bytes, each
endpoint at four accepted connections, and socket work/joins at 15 seconds.
`JoinSet` owns every spawned fixture/connection/listener task and aborts its
members on failed-test cleanup; the production driver is never replaced or
spawned separately. Request completion precedes responder writes. Held/staged
cases record response-write progress before cancellation. These are application
write/progress observations, not claims about TCP segments or server reads.
The fallback control uses loopback port zero, which cannot denote a connectable
TCP service, verifies `ConnectFailed` directly, then exercises successful
fallback to a recording endpoint; there is no released-port race.

## Existing exact-test inventory

Names below identify unchanged baseline tests, not additional C2 passes.
The `production_runtime.rs` names use the prefix
`production_runtime::tests::`; `main.rs` names use `tests::` in the
`eidolon-proxy` binary test target. Counts in this section are Rust test
functions unless an exchange count is explicitly stated.

| Exact test name | Layer and existing evidence/limit |
| --- | --- |
| `committed_post_response_drop_never_retries_next_address` | Real production client, one POST/drop case, `ResponseFailed`; first request contains method/body, second has a 250 ms negative accept. Retained intact; new matrices add complete framing and quiescence evidence. |
| `total_dispatch_deadline_stops_fallback_and_releases_processor_permit` | Real production client, one stalled case, `DispatchTimedOut`, first peer sees close, processor permit releases; fallback negative accept is 300 ms. |
| `handler_does_not_connect_upstream_after_pre_dispatch_budget_expires` | Real listener and dispatch called after budget expiry, zero observed upstream accepts; fixture maps `DispatchTimedOut` to empty 504. Does not establish application timeout status. |
| `failed_processor_returns_empty_500_once_without_retry` | Real public listener, synthetic failing processor; empty 500 and one processor invocation. No actual upstream dispatch. |
| `empty_upstream_address_set_returns_typed_connect_failure_without_panic` | Typed-only impossible empty-address helper fallback -> `ConnectFailed`; no socket. |
| `closed_processor_permit_semaphore_maps_to_unavailable_without_panic` | Typed-only closed semaphore -> `Unavailable`; no socket. |
| `production_hyper_loopback_forwards_normal_traffic_and_never_forwards_unsafe_proofs` | `main.rs`, production listener/lifecycle and real client: six listener exchanges, only normal GET reaches raw recorder; missing/replayed/expired/malformed unsafe proofs stay contained. |
| `production_profile_loopback_preserves_lifecycle_and_audits_pre_service_rejections` | Full production profile, nine listener exchanges including six lifecycle and three ingress rejection cases; one normal upstream request. Tests lifecycle/audits, not malformed upstream responses. |
| `production_partial_body_disconnect_has_no_boundary_audit_event_or_upstream` | Full production profile, partial inbound body EOF; no lifecycle/boundary audit or upstream request. |
| `production_malformed_body_remains_audited_boundary_rejection` | Full production profile, malformed inbound chunked body -> audited 400, zero upstream. |
| `production_boundary_rejections_are_redacted_audited_and_fail_closed_without_debug_log` | Production listener/lifecycle, three ingress/audit-availability cases; 417/503/503 and zero upstream. |
| `production_policy_transition_omits_sentinel_path_from_event_and_debug_jsonl` | Production listener/lifecycle, two contained requests, redacted audits and zero protected-upstream requests. |
| `production_surface_action_audit_projects_trusted_bait_soften_prefixes` | Production listener/lifecycle and normal real upstream response, production audit projection. |
| `production_upstream_resolution_is_startup_owned_and_reuses_resolved_target` | Injected resolver/typed target only; no real connection despite loopback addresses in values. |
| `production_upstream_resolution_rejects_unbounded_address_sets` | Injected resolver/typed address-cap rejection only. |
| `production_processing_failure_stderr_code_omits_error_display` | Typed mapping to `Failed` and fixed redacted stderr bytes; no listener/upstream. |

Existing lifecycle guards also remain unchanged:
`completed_connection_tasks_are_reaped_while_listener_is_running`,
`handler_waits_for_delayed_processor_before_responding_and_releasing_permit`,
`graceful_shutdown_drains_accepted_response_before_returning`,
`graceful_shutdown_closes_idle_keep_alive_connection`,
`closed_admission_denies_pipelined_service_without_processor_work`,
`pre_service_rejection_skips_processor_after_admission_closes`, and
`shutdown_deadline_aborts_observed_cancellable_body_collection_then_waits_for_side_effect_quiescence`.
These seven runtime tests are not C2 response matrices. Grace expiry remains
nonzero only after accepted non-cancellable work quiesces, not a hard exit
deadline. C1's seven ingress matrices and #287's raw-head boundary matrices are
inventoried in `plans/2026-09-07-production-ingress-equivalence.md`; that
inventory/source and its duplicate-ingress repair are untouched.

### Lab-only and response-only tests

These exact `main.rs` tests use the Lab parser/serializer. Their assertions do
not define what the production Hyper upstream client accepts:

| Exact test name | Existing scope |
| --- | --- |
| `parses_http_response_with_body` | In-memory fixed-body Lab decode. |
| `decodes_chunked_upstream_responses` | In-memory chunked Lab decode. |
| `rejects_chunked_response_size_overflow_after_prior_chunk` | Lab size-overflow path. |
| `rejects_unsupported_upstream_transfer_encodings` | Lab rejects gzip TE; this is not automatically production policy. |
| `skips_bounded_informational_responses_before_the_final_response` | Lab 100 + 103 + final. |
| `rejects_upstream_protocol_switching` | Lab rejects 101. Does not prove a production rejection. |
| `head_and_no_content_statuses_never_read_or_emit_a_message_body` | Lab HEAD/204/304 decode/serialize controls. |
| `no_body_responses_still_validate_framing_headers` | Five Lab invalid no-body framing cases and one Lab CL+TE rejection. |
| `serializes_http_response_after_header_update` | Constructed `HttpResponse`, Lab serializer, no production listener. |
| `runtime_decodes_chunked_upstream_response_before_downstream_send` | Real loopback **Lab** runtime/client -> Lab decode -> downstream serialization. |
| `production_projection_redacts_authenticated_ingress_values_from_durable_audits` | Despite its name, `run_runtime_request` uses Lab transport with production audit projection. |

## New exact-test inventory and observed results

All eight new test names have prefix `production_runtime::upstream_tests::`
in the `eidolon-proxy` library target. Root executed all of them against owned
loopback responders. The eight functions contain 43 matrix cases x two layers
= 86 HTTP exchanges, plus six positive HTTP exchanges (92 total: 46 direct and
46 listener), and one additional direct
pre-send `ConnectFailed` control with no received HTTP request.

| Exact test name | Cases | HTTP exchanges | Observed final result |
| --- | ---: | ---: | --- |
| `upstream_malformed_and_truncated_responses_do_not_replay` | 14 | 28 | Ten `ResponseFailed`, four `ResponseBodyFailed` shapes, each in both layers. |
| `upstream_framing_acceptance_is_distinct_from_strict_ingress` | 8 | 16 | Accepted upstream framing controls; body `ok` or opaque close-delimited bytes; canonical downstream CL. |
| `upstream_decoded_body_cap_and_empty_controls` | 9 | 18 | Three framings x empty/exact-eight/nine bytes; three over-cap shapes -> `ResponseBodyTooLarge`. |
| `upstream_informational_and_hop_header_controls` | 2 | 4 | 100 + 103 followed by 203 final; separate 202 response with mixed-case/duplicate Connection nominations and end-to-end values. |
| `upstream_protocol_switch_is_rejected_without_replay` | 1 | 2 | 101 -> `ResponseFailed`, empty downstream 500, one complete first request and zero second-address access. |
| `upstream_proxy_connection_is_not_forwarded` | 1 | 2 | Duplicate/mixed-case Proxy-Connection removed; status/body/end-to-end field preserved. |
| `upstream_stage_and_absolute_deadlines_do_not_replay` | 8 | 16 | Three held shapes x stage/absolute budgets, plus two staged-progress total-budget cases. |
| `upstream_recorders_and_connect_failure_fallback_are_live` | 3 x two layers, plus port-zero control | 6 | A returns 201/`a1`/`X-C2-Recorder: first`; B returns 202/`b2`/`X-C2-Recorder: second`; the expected signature is asserted for A-first, B-first and port-zero-then-B in both layers. Endpoint counts are A=2 and B=4; standalone port zero -> exact `ConnectFailed`. |

There are 26 post-send failure shapes x two layers = 52 exact typed-error
assertions and 26 corresponding empty-500 listener assertions. No expected
error can be satisfied by a generic `is_err()` or an arbitrary HTTP status.

### Framing case details

- `ResponseFailed`: `malformed_status`, `invalid_status_code`,
  `malformed_header_name`, `malformed_header_value` (NUL), `invalid_cl`,
  `negative_cl`, `overflow_cl`, `conflicting_cl`, `conflicting_list_cl`,
  `http10_te`.
- `ResponseBodyFailed`: `truncated_fixed`, `truncated_chunk_data`,
  `missing_final_chunk`, `invalid_chunk_size`.
- Accepted controls: `equal_duplicate_cl` (2/2),
  `numerically_equal_duplicate_cl` (02/2), `equal_list_cl` (2, 02),
  `cl_then_te` and `te_then_cl` (CL0 plus chunked `ok`, both field orders),
  `nonchunked_te_close_delimited` (gzip TE/opaque bytes),
  `final_chunked_te` (gzip, chunked/dechunked `ok`),
  `nonfinal_chunked_te` (chunked, gzip/opaque bytes).

The observed acceptances follow the pinned Hyper client source:
`Client::decoder` chooses TE before CL; a final chunked coding selects chunk
decoding, other HTTP/1.1 TE selects EOF framing, and
`content_length_parse_all_values` accepts equal numeric duplicates/list values.
Owned-wire execution confirmed those selections. No gzip decompression or correctness of
arbitrary transfer-coding semantics is claimed; the small opaque controls
record the selected framing/body/header behavior only. Strict ingress still
rejects ambiguous/multiple framing under C1. No upstream policy is tightened
to copy ingress policy, and no acceptance is described as a smuggling exploit.

Body controls use config cap **8**, bodies of 0/8/9 bytes, and fixed, chunked,
and EOF framing. Nonempty bytes include NUL and 0xff. Chunked bodies use up to
three application chunks; no read/frame boundary is assumed. Accepted typed
responses have upstream CL/TE removed, and downstream has one CL equal to the
collected body length, with no TE or extra trailing bytes.

Header controls remove all Connection-nominated values across two Connection
fields, mixed-case names, and duplicate nominated fields; also Keep-Alive,
Proxy-Authenticate, Proxy-Authorization, TE, Trailer and Upgrade. Separate
Proxy-Connection regression covers two differently cased fields without a
Connection nomination. Exact repeated `X-End-To-End: one` / `two` and ETag
values are asserted in both typed and downstream results. These duplicate
end-to-end assertions apply to the public forwarding harness, not the
`main.rs` lifecycle header conversion. That conversion/full-profile response
equivalence has not been exercised by C2 here.

### Deadline case details

- `held_head`: partial response header; `held_fixed_body`: CL4 with one byte;
  `held_chunked_body`: chunk size 4 with one byte. Each uses either a one-second
  per-stage response budget (8-second dispatch / 10-second incoming budget,
  expecting `ResponseTimedOut`) or a two-second total dispatch budget
  (6-second stage / 10-second incoming budget, expecting `DispatchTimedOut`).
- `dispatch_deadline_across_progress`: full chunked head after one second,
  a complete one-byte chunk after another second, then held open; total
  dispatch budget 3 seconds, stage 6 seconds, incoming 10 seconds.
- `incoming_deadline_across_progress`: the same progress, incoming request
  budget 3 seconds, dispatch 8 seconds, stage 6 seconds. Listener mode uses
  the actual context deadline from `processor_timeout`, not a replacement
  deadline invented inside the processor.

Response scripts wait for the complete first request, joins are bounded, and
the staged controls require both writes to have completed before cancellation.
Their separated budgets avoid races between stage and absolute timeouts; no
millisecond-scale elapsed-time upper bound or hard processor-exit deadline is
asserted. They require a functioning local scheduler within the documented
seconds-scale margins; all eight deadline cases passed in both layers.

## Before/after confirmed defects

Before C2 there were isolated production drop/deadline controls plus Lab
response tests. Root's independent raw-responder probe and fail-first focused
tests confirmed two production response-boundary defects. The focused tests
stop at the first direct assertion, so the fail-first observation is a direct
production-dispatch result; the repaired tests then pass both direct dispatch
and public-listener executions.

| Defect | Unchanged C1 observation | Narrow repair and final observation |
| --- | --- | --- |
| Unsupported 101 | Raw `101 Switching Protocols` produced `Ok(ProductionResponse { status: 101, headers: {}, body: b"" })`; the focused fail-first test expected `Err(ResponseFailed)` and failed. | Reject status 101 immediately after `send_request`. Final direct result is exact `ResponseFailed`; listener emits one empty 500; first POST is complete and address two remains untouched. |
| Proxy-Connection response leak | Mixed-case/duplicate `Proxy-Connection` remained in the typed production response; the focused fail-first test reported `proxy_connection: leaked proxy-connection`. | Remove `Proxy-Connection` beside `Keep-Alive` in the existing sanitizer. Both layers remove it while preserving 200/body/end-to-end fields. |

Neither repair changes retry selection. Both occur after the request has been
sent, and every error execution retains exactly one complete first request and
zero connections or requests at address two. Positive controls separately
prove both recorder addresses and pre-send fallback are live.

## Verification checkpoint (2026-09-08)

The final Rust gate uses the CI-pinned Rust **1.95.0**, `--offline --locked`,
and target directory `$PWD/target/c2` inside this dedicated worktree. Root also
ran the full suite once under local stable 1.97.1 as secondary evidence. No
dependency was installed or upgraded.

- Passed: final formatting check, `git diff --check`, workspace all-target
  build, and workspace all-target/all-feature Clippy with `-D warnings`.
- Passed execution: **808 workspace tests** (800 retained + eight new), zero
  failed or ignored. This includes the full production listener/lifecycle,
  retained C1/#287 ingress, admission, no-retry, reaping and drain regressions.
- Passed C2 boundary execution: all eight test functions, 43 cases across both
  layers, 92 live HTTP exchanges plus the no-request port-zero control. The
  complete C2 filter took about 30 seconds because deadline cases use deliberate
  seconds-scale budgets.
- Passed execution: six pinned Hyper regressions: two
  `read_buffer_regression` tests (positive budget and exact-zero progress),
  three `content_length_regression` tests (duplicate preservation,
  invalid/conflicting rejection, TE precedence), and exact
  `proto::h1::role::tests::test_decoder_request`. Full vendor suite not run.
- Passed refreshed RustSec audits for the workspace lock (110 dependencies) and
  vendored Hyper lock (73 dependencies) against 1,242 loaded advisories, with
  warnings denied.
- Passed `jq empty` for M3 promotion/profile JSON, Bash syntax for all 193
  tracked shell files, all 22 M3 fixture scripts, all 60 Shield Lab fixture
  scripts, Kubernetes manifest validation, and every archived M3 SHA256SUMS set.
- Harness correction: the first root matrix run passed seven functions but a
  bound/unlistening macOS socket timed out instead of returning `ConnectFailed`.
  Replacing that nonportable fixture with loopback port zero made the standalone
  pre-send failure and successful fallback control deterministic; the full
  matrix and full workspace then passed. This did not change runtime behavior.
- Initial independent review of `a94fff68fc0ba399acc569626bce82af3d57c5ca`
  returned `BLOCK`: identical A/B positive responses plus aggregate-only counts
  could false-pass reversed address iteration (medium), and the plan said 201
  where the Proxy-Connection case preserves 200 (low). The corrected harness
  now gives A and B distinct status/body/header signatures and asserts the
  expected responder per dispatch; the plan typo is fixed. Pinned fmt, build,
  Clippy, the focused fallback test, all eight C2 tests and all 808 workspace
  tests passed again. Follow-up review of
  `f0e55a60689571a0b358a589b5682ee25d240893` returned `PASS` with no blocking
  or non-blocking findings. Dynamic gates remain root evidence; Linux
  exact-head CI and full-profile response equivalence remain residual limits.

## Remaining gates and root handoff

- [x] Inventory current production-client, public-listener, typed-only and Lab-only tests.
- [x] Implement bounded response/framing/body/header/deadline matrices and live-positive controls.
- [x] Execute all C2 wire cases and record exact actual behavior, especially equal CL/list CL and CL+TE.
- [x] Confirm 101/Proxy-Connection defects on C1; make only evidenced minimal fixes and verify both layers.
- [x] Obtain actual no-replay, safe downstream and connection-quiescence evidence for all error shapes.
- [x] Execute retained C1/#287 ingress, admission, no-retry, reaping and drain socket regressions.
- [x] Pass final pinned fmt/build/Clippy/full workspace/vendor tests and applicable fixtures/audits on the final tree.
- [x] Follow-up independent review passes after the corrected fallback oracle.
- [ ] Authorized publication, exact-head Linux/image CI, C1 integration and merge.

No Linux CI, PR, merge, release or v1 Gate completion is claimed while
publication remains authentication-blocked and C1 is not integrated. C2 is a
stacked local slice and must not bypass C1's review/merge order.

## Limits

Finite loopback coverage, not C3 load/lifecycle, C4 fuzz, Gate 9 soak, production
durability, deployment qualification, release promotion or public publication.
Do not conflate Lab serialization tests with real production-client observations,
or claim zero initial upstream access after a request was already sent.
