# Production ingress equivalence — #289 / #251 C1

Status: implemented and native-validated; final independent review, exact-head CI
and merge evidence are tracked in #289.
Baseline: `87b291b6cca29eb88be3cf6a7b77a497fae7a214` (#288).

This is an exact-test inventory and bounded slice evidence, not full
release qualification. Names below are Rust test-harness names; source references
are relative to the repository root.

## Invariant, change and contract

Raw production ingress, the strict typed policy, and the production upstream
client must agree on authority, framing, and canonical target. Rejected ingress
causes zero validated processor calls and zero upstream HTTP requests. Accepted
method, body and canonical target arrive unchanged at the configured owned HTTP
upstream; Host and Content-Length are replaced, and prohibited headers removed.

One parser defect was demonstrated with both raw wire and deterministic tests:
Hyper 1.11.1's server parser
discarded identical duplicate Content-Length fields before
`ProductionHttpPolicy::adapt` / `validate_content_length` in
`crates/eidolon-proxy/src/production_http.rs` could reject multiplicity.
`vendor/hyper/src/proto/h1/role.rs` now appends equal fields after checking numeric
agreement. Decoder selection remains based on the first field. Conflicting and
invalid lengths still fail at Hyper. CL+TE retains chunked decoding, removes CL,
disables connection reuse, and is rejected by the existing application TE policy.

The strict policy, status/rejection vocabulary, event/privacy contracts, body and
header limits, admission/reaping/drain and client no-retry behavior are unchanged.
Identical duplicate CL can now reach the existing `MultipleContentLengths`
rejection instead of becoming upstream-eligible. This is the intended operator
behavior correction; there is no new event schema.

An independent probe exercised the public production listener and actual
`dispatch_production_upstream` against an owned raw HTTP recorder. On the baseline,
`CL: 4` plus `CL: 4`, and `CL: 04` plus `CL: 4`, each produced HTTP 200, one
validated processor call and one upstream request. With only the Hyper path
changed to this repair, both produced HTTP 400 / `MultipleContentLengths` and
zero processor/upstream requests. Results agree for complete and fragmented
writes. Single-length and canonical-forwarding controls still reach the recorder;
the six other rejection/disconnect controls retain their outcomes. This proves a
raw-to-typed multiplicity-contract violation, not a request-smuggling exploit.

Production remains Hyper **1.11.1**, features `client,http1,server`. The #287
positive-read and exact-zero repair in `vendor/hyper/src/proto/h1/io.rs` is
untouched. Both manifests, both lockfiles, and the upstream license are unchanged.
The source/provenance/CI delta is limited to:

- `crates/eidolon-proxy/src/production_runtime_ingress_tests.rs`: new raw listener
  and HTTP forwarding tests.
- `crates/eidolon-proxy/src/production_runtime.rs`: four lines of `cfg(test)` module
  wiring; existing body-collection and connection-count synchronization is reused.
- `vendor/hyper/src/proto/h1/role.rs`: preservation seam and three regressions.
- `vendor/hyper/EIDOLON_PROVENANCE`: scope, invariants, checks and retirement criteria.
- `.github/workflows/ci.yml`: scoped CL regressions and retained upstream request
  decoder test, alongside the unchanged #287 buffer regression step.
- This inventory.

## New actual-listener tests

Source: `crates/eidolon-proxy/src/production_runtime_ingress_tests.rs`.
Every name below has prefix **`production_runtime::ingress_tests::`**.
Each case uses both complete and fragmented client writes. These are client
write patterns, not a claim that TCP or Hyper performs corresponding reads.

| Exact test suffix | Matrix and intended outcome | Cases across both write patterns |
| --- | --- | --- |
| `raw_host_authority_matrix` | DNS, IPv4 and bracketed IPv6 Host, each with/without valid port: accepted. Missing Host: `MissingHost`; same/conflicting mixed-case duplicates: `MultipleHostHeaders`; empty/OWS-only, non-ASCII and malformed authority: `InvalidHost`. NUL in Host: transport `MalformedTransport`. | 12 accepted; 34 policy; 2 transport |
| `raw_target_forms_and_canonical_forwarding_matrix` | Canonical origin path/query, encoded unreserved path/query with reserved-query escape case normalization, and `OPTIONS *`: accepted and recorded. Matching/conflicting HTTP absolute targets, HTTPS absolute target, GET authority, `GET *`, network-path spelling, empty/dot segments, path parameters, encoded dots/slash/backslash/percent/NUL/non-ASCII, and invalid/truncated escapes: `InvalidTargetForm`. CONNECT authority: `UnsupportedConnect`. | 6 accepted; 40 policy |
| `raw_duplicate_content_length_is_rejected_before_dispatch` | Single-length POST control. Same duplicates at zero and positive length, and three numerically equal differently padded fields: `MultipleContentLengths`, no transport hook. Actual-listener regression for the parser repair. | 2 accepted; 6 policy |
| `raw_invalid_and_conflicting_content_length_transport_matrix` | Single-length POST control. Conflicts in both orders, equal fields followed by conflict, invalid/empty/signed/overflow lengths, same/conflicting comma lists, and valid followed by invalid length: transport `MalformedTransport`, no policy hook. | 2 accepted; 22 transport |
| `raw_content_length_transfer_encoding_both_orders_are_rejected` | Single-length POST control. CL+TE and TE+CL, each with one or duplicate CL, with complete chunked body: policy `UnsupportedTransferEncoding`, no transport hook. | 2 accepted; 8 policy |
| `raw_truncated_body_disconnect_has_no_validated_or_upstream_work` | Complete POST control. Declared length four with zero/two body bytes; wait for production body-collection signal before write-side EOF. Assert existing empty HTTP 200 / Connection close / CL 0, no policy/transport hook, no validated/upstream work. The status is neither an upstream response nor successful processing. | 2 accepted; 4 disconnects |
| `raw_forwarding_preserves_fields_and_strips_protected_headers` | GET/POST/PATCH including binary body. Record canonical target, method/body, one configured Host and decimal CL replacing padded input; strip multiple mixed-case Connection nominations, duplicate nominated fields, hop headers and mixed-case `x-eidolon-*`. Preserve content type, duplicate end-to-end values and ordinary `X-Eidolon` without the protected trailing hyphen. | 6 accepted |

Total: **7 test functions, 148 exchanges: 32 accepted controls, 88 policy
rejections, 24 transport rejections, 4 disconnects**. All passed in root's
socket-enabled native workspace run.

Malformed Host values are exactly `user@proxy.owned.test`, `proxy.owned.test:0`,
`proxy.owned.test:`, `proxy.owned.test:65536`, `proxy.owned.test:invalid`, `[::1`,
`::1`, `[not-ipv6]`, `proxy.owned.test/path`, `proxy%2eowned.test`, and `bad host`.
The raw arrays in the source are the authoritative byte inventory.

The forwarding matrix sends `Connection`, `Proxy-Connection`, `Keep-Alive`, `TE`,
`Proxy-Authenticate`, and `Proxy-Authorization` with synthetic fixture values.
`Trailer`, `Transfer-Encoding`, and `Upgrade` cannot pass strict ingress: their
pre-forwarding rejection coverage is retained below; their absence from accepted
output is also checked. No credentials are needed.

### Observation model and bounds

`ForwardingProcessor::process` records validated fields and directly calls
`dispatch_production_upstream` with the production request deadline. It does not
implement or directly test `prepare_upstream_request`. The actual Hyper client
connects to the recorder's pre-resolved loopback address; its configured HTTP Host
is a distinct synthetic authority. No DNS or external targets are used.

`record_http_request` captures actual request bytes and independently reads the
request line, headers and fixed-length body. A bounded `201` / `recorded` response
must traverse the real client and listener back to every accepted caller. Each
rejection family has a positive listener/client/recorder control with the same
harness. Extra bytes before/after the response and unexpected incomplete/malformed
upstream connections fail the test instead of being counted as zero work.

Each case has fresh listeners. The existing connection-count watch must observe
admission before client writes and reaping before shutdown, while admission is
still open. Thus shutdown cannot suppress a late rejection hook, including in the
no-hook disconnect control. Rejection assertions run after production joins all
work. The recorder then drains already queued accepts before its own join; the
final empty-accept window is not the sole quiescence evidence. Assertion unwinding
aborts both owned tasks. No detached client driver is introduced.

Bind/connect, each raw exchange (admission/writes/body signal/response/reaping), each recorder
request/response/close, and each task join have five-second bounds. Recorder
accepts have a five-second case budget and 25 ms empty-queue check after production
quiescence. Captures are capped at 16 KiB and four upstream connections per case.
Production fixtures retain bounded admission, request, processor, dispatch and
shutdown budgets. No peer-controlled unbounded `read_to_end` is used. Fixture
bounds are not production capacity or hard-shutdown qualification.

## New deterministic parser regressions

Source: `vendor/hyper/src/proto/h1/role.rs`.
Prefix: **`proto::h1::role::tests::`**.

| Exact test suffix | Evidence |
| --- | --- |
| `content_length_regression_preserves_duplicate_fields` | One CL control, same zero/positive duplicates, three numerically equal differently padded fields; exact HeaderMap multiplicity/values, unchanged decoded length, unconsumed body bytes. Failed before repair: `["0"]` instead of `["0", "0"]`. Passes after repair. |
| `content_length_regression_rejects_invalid_or_conflicting_fields` | Eleven conflict/list/invalid-length rows still fail in Hyper. Passed before and after repair. |
| `content_length_regression_keeps_transfer_encoding_precedence` | CL/CL/TE, TE/CL/CL, CL/TE/CL retain chunked decoding, remove CL and disable reuse. Passed before and after repair. |

These prove parser behavior, not TCP behavior. Before repair, the scoped run was
**2 passed / 1 failed**. After repair, the full vendor library suite was
**120 passed / 6 upstream ignores**, including all three new tests, both buffer
regressions and `proto::h1::role::tests::test_decoder_request`. CI enables
`client,http1,http2,server` solely for the upstream shared test harness.

## Existing coverage mapped and retained

All existing test bodies are untouched. The inventory distinguishes typed policy,
transport, lifecycle and Lab coverage rather than treating them as interchangeable.

### Typed policy and shared target rules

Source `crates/eidolon-proxy/src/production_http.rs`, prefix
`production_http::tests::` — all **12 passed locally**:

- `adapts_valid_http11_request_without_losing_typed_fields`
- `supports_only_http11`
- `rejects_connect_upgrades_expectations_and_unsupported_framing`
- `rejects_unsupported_or_ambiguous_target_forms`
- `returns_the_shared_canonical_target`
- `rejects_missing_duplicate_empty_and_non_ascii_host`
- `accepts_valid_dns_ip_and_port_host_authorities`
- `rejects_non_ascii_end_to_end_header_values`
- `enforces_header_count_and_encoded_size_limits`
- `enforces_unambiguous_bounded_content_length`
- `rejects_actual_body_above_limit_before_dispatch`
- `rejection_statuses_are_explicit_and_safe_to_expose`

Source `crates/eidolon-proxy/src/http_request.rs`, prefix `http_request::tests::`:

- `both_modes_share_canonical_origin_form_validation`
- `absolute_form_is_an_explicit_lab_compatibility_difference`
- `rejects_host_confusion_and_ambiguous_targets`
- `canonicalization_is_idempotent_for_every_accepted_ascii_percent_byte`

These construct typed requests or exercise shared canonicalization; they do not
establish that a raw parser preserves original fields.

### #287 raw-head/body controls

Source `crates/eidolon-proxy/src/production_runtime_boundary_tests.rs`, prefix
`production_runtime::boundary_tests::`:

- `raw_hyper_ingress_enforces_raw_head_cap_complete_write`
- `raw_hyper_ingress_enforces_raw_head_cap_fragmented_writes`
- `raw_hyper_ingress_rejects_unsafe_requests_before_the_protected_upstream_probe`
- `raw_hyper_ingress_times_out_held_open_header_and_body_before_the_protected_upstream_probe`
- `raw_hyper_ingress_rejects_an_oversized_collected_body_before_the_protected_upstream_probe`

These retain raw 65,536-byte acceptance / 65,537-byte rejection, leading CRLF/OWS,
header count, malformed/version/protocol cases, held-open head/body deadlines,
and collected-body limits. Their upstream probe is a TCP marker, not HTTP
forwarding equivalence. The delegated sandbox attempt stopped at loopback bind
(`EPERM`), before any request behavior was exercised. All five later passed in
root's socket-enabled native workspace run.

Source `vendor/hyper/src/proto/h1/io.rs`, prefix `proto::h1::io::tests::`:

- `read_buffer_regression_exact_zero_still_reads_available_data`
- `read_buffer_regression_positive_next_limits_read_capacity`

Both passed in the full vendor suite; their code is unchanged.

### Production admission, no-retry, reaping and drain

Source `crates/eidolon-proxy/src/production_runtime.rs`, prefix
`production_runtime::tests::`:

- `serve_production_http1_rejects_current_thread_runtime`
- `committed_post_response_drop_never_retries_next_address`
- `total_dispatch_deadline_stops_fallback_and_releases_processor_permit`
- `completed_connection_tasks_are_reaped_while_listener_is_running`
- `handler_waits_for_delayed_processor_before_responding_and_releasing_permit`
- `graceful_shutdown_drains_accepted_response_before_returning`
- `graceful_shutdown_closes_idle_keep_alive_connection`
- `closed_admission_denies_pipelined_service_without_processor_work`
- `pre_service_rejection_skips_processor_after_admission_closes`
- `shutdown_deadline_aborts_observed_cancellable_body_collection_then_waits_for_side_effect_quiescence`
- `handler_does_not_connect_upstream_after_pre_dispatch_budget_expires`
- `failed_processor_returns_empty_500_once_without_retry`
- `closed_processor_permit_semaphore_maps_to_unavailable_without_panic`
- `empty_upstream_address_set_returns_typed_connect_failure_without_panic`

### Production lifecycle/privacy and Lab distinction

Source `crates/eidolon-proxy/src/main.rs`, binary test prefix `tests::`:

- `production_hyper_loopback_forwards_normal_traffic_and_never_forwards_unsafe_proofs`
- `production_profile_loopback_preserves_lifecycle_and_audits_pre_service_rejections`
- `production_partial_body_disconnect_has_no_boundary_audit_event_or_upstream`
- `production_malformed_body_remains_audited_boundary_rejection`
- `production_boundary_rejections_are_redacted_audited_and_fail_closed_without_debug_log`
- `production_policy_transition_omits_sentinel_path_from_event_and_debug_jsonl`
- `production_surface_action_audit_projects_trusted_bait_soften_prefixes`
- `production_projection_redacts_authenticated_ingress_values_from_durable_audits`
- `production_audit_projection_redacts_paths_and_reason_paths`
- `production_processing_failure_stderr_code_omits_error_display`

These retain lifecycle/audit coverage the new forwarding processor does not
claim to reproduce. Existing truncated-body handling suppresses disconnect
audits; C1 does not relabel that behavior as a policy hook.

The same source's `rewrites_request_for_upstream`,
`upstream_forwarding_uses_the_canonical_request_target`,
`upstream_request_strips_hop_by_hop_and_connection_nominated_headers`,
`upstream_request_emits_one_canonical_content_length`, and
`proxy_never_forwards_reserved_eidolon_headers_upstream` are Lab serializer tests.
They remain intact; Lab acceptance/normalization of duplicate CL or absolute form
is not the strict production contract or C1 forwarding evidence.

## Local validation and remaining gates

Rust **1.95.0**, offline locked builds/tests. The implementation worker used
`CARGO_INCREMENTAL=0`; root independently ran the full workspace with loopback
permission. Network-enabled root audits refreshed RustSec. No dependency upgrades
or cluster/container/VM mutations were needed; CI retains the Linux image gates.

| Check | Local result |
| --- | --- |
| `cargo +1.95.0 fmt --all -- --check` | Passed. Only added vendor test code was formatted; upstream formatting preserved. |
| Workspace build, `--workspace --all-targets` | Passed. |
| Workspace Clippy, `--workspace --all-targets --all-features -- -D warnings` | Passed, including root's disconnect assertion correction. |
| Workspace tests, `--workspace --all-targets` | **800 passed**, no ignored or filtered tests: 793 retained, seven new. Includes all 148 raw ingress/forwarding exchanges and retained admission/no-retry/reaping/drain/audit controls. |
| Vendor `--manifest-path vendor/hyper/Cargo.toml --features client,http1,http2,server --lib` | **120 passed, six upstream ignores**, independently rerun by root; includes both buffer, three CL and upstream request-decoder regressions. |
| Fail-first evidence | Deterministic duplicate-preservation regression: two controls passed, preservation failed before repair. Independent actual-wire baseline/patched probe: equal duplicate CL changes from one validated/upstream request to zero in both write modes; accepted controls still forward. |
| Initial new raw suite | Six passed; the disconnect test incorrectly expected no response bytes. Root observed existing empty HTTP 200, corrected only the test assertion, and the full suite passed. No runtime disconnect behavior changed. |
| Root and vendor lockfile audits, `cargo audit --deny warnings` | Both passed against refreshed RustSec advisories (1,240 advisories; 110 root / 73 vendor dependencies). |
| M3 and Shield Lab `test-*.sh`, tracked shell syntax, M3 JSON fixtures | Passed. These are fixture checks with stubs, not live Kubernetes deployment qualification. |
| Final cross-runtime review, exact-head Linux CI and image builds | Tracked with issue -> PR -> commit -> checks in #289; not inferred from native success. |

Unique workspace tests executed successfully: **800**; earlier subset or repeated
runs are not added again. Vendor tests are a separate workspace. The delegated
sandbox's `EPERM` result was an environmental restriction, not protocol evidence;
the native socket-enabled run supersedes that validation gap.

Preservation checks (SHA-256 before/after match):

| File | SHA-256 |
| --- | --- |
| `Cargo.lock` | `89f50448d6f23d44295bfaf22e52da08dde46210c717b232011508db129dff71` |
| `vendor/hyper/Cargo.lock` | `ce0c4521c833d3f57ac27a27c99f5bd6791d0d00e34773bb6417f609494a3b13` |
| `vendor/hyper/LICENSE` | `2d01890414494742ba4a509fcec8efa40f6d8be22cbd72be7cff08d6fda4ec89` |

The retained production wire gate is
`cargo +1.95.0 test --offline --locked --target-dir target -p eidolon-proxy --lib production_runtime::`,
alongside normal full workspace gates. Baseline/patched probe builds used the
same locked versions and baseline production library, selecting the baseline or
candidate vendored Hyper via a command-local Cargo patch path. Thus the observed
wire correction did not depend on replacing production code with the test harness.

## Evidence limits

The parser defect and repair have deterministic and actual-wire before/after
evidence. Other new rows are finite coverage additions with observed native
passes, not newly discovered exploits or exhaustive protocol qualification.

This does not complete upstream-response/no-replay C2, resource/lifecycle C3,
fuzz/differential C4, #254 durability, #252 full operator/privacy qualification,
supported deployment, Gate 9 soak, or full-v1/publication qualification. The matrix
is finite; IPv6 Host syntax runs over IPv4 loopback transport. No TCP fragmentation,
exhaustive parser equivalence, load, HA or hard-exit deadline claim follows. There
is no full-release qualification implied by this slice. Exact-head CI, final
review and the eventual merged commit must be verified through #289.
