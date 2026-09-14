# Eidolon compatibility policy

Status: governing contract-policy statement for the supported v1 envelope.
This document satisfies the Gate 1 requirement for versioned contracts with a
written compatibility policy (`docs/v1-release-definition.md`). It names every
versioned artifact Eidolon produces or consumes, the current version, the
stability promise for v1, and the fail-closed rule for unknown or future
versions. Field-level contract documents live in `docs/contracts/`; this file
only fixes versions and policy.

## Version policy

Eidolon releases use semantic versioning. Within a major release line:

- **Minor and patch releases never remove or change the meaning of an existing
  artifact version.** They may add a new artifact version while keeping the
  previous one readable.
- **Every reader must fail closed on an unknown or newer artifact version**
  with an actionable error naming the artifact, the version found, and the
  versions supported. Readers never guess, partially apply, or silently skip
  unrecognized versions.
- **Writers always emit the newest supported version** unless an operator
  explicitly selects an older one for rollback compatibility.
- An artifact version bump is a breaking change and is called out in the
  changelog with the migration path.

## Artifact versions

| Artifact | Version field | Current | Reader fail-closed rule |
| --- | --- | --- | --- |
| Event log (`events.jsonl`) | `schema_version` per record | `2` (one 33,554,432-byte active segment, three 33,554,432-byte archives, 134,217,728-byte family, 1,048,576-byte record excluding newline) | Production recovery accepts only schema-v2 events in the bounded family. Canonical archives are `<event-log>.<39 ASCII digits>`; all-digit noncanonical names, a fourth archive, symlinks, non-regular members, over-limit segments/records, invalid complete records, duplicate event IDs, and conflicting selected workflow evidence fail closed. |
| Debug log (`debug.jsonl`) | `schema_version` + `run_kind` envelope | `1` (`eidolon_proxy_debug`) | Server-side diagnostic only; no supported reader today. A validating reader is tracked by issue #252. |
| Policy state (`policy-state.json`) | `schema_version` | `3` (reads `1..=3`; maximum 33,554,432 bytes and 8,192 retained records) | Missing state initializes empty. Existing empty, malformed, truncated, oversized, unsupported-version, duplicate-session, or internally inconsistent pending-workflow state fails startup before migration or listener bind. A staged controlled-reality-to-blocked event accepts its legacy omitted persistence metadata or coherent post-containment metadata; rate-limit and pre-containment retry metadata is rejected for that transition. Writers reject an oversized current-schema snapshot before opening the temp file (`policy_store.rs`). |
| Session continuity sidecar (`<policy-state>.continuity.json`) | `schema_version` | `2` (reads `1..=2`) | Unsupported versions, an unverifiable signer, or a live record whose continuity key is unavailable prevent startup (`session_continuity_store.rs`). |
| Bait exposure sidecar (`<event-log>.exposures.json`) | `schema_version` | `1` (maximum 4,194,304 bytes, 4,096 records, 24-hour TTL) | Missing state rebuilds in canonical archive order followed by the active event-log segment, including the archive-only post-rename crash window. Existing empty, malformed, oversized, unsupported-version, over-capacity, unknown-field, empty-identifier, future-timestamp, duplicate-key, or canonical-rewrite-over-limit state fails production preflight before the writer lease or durable-file mutation. Writers enforce the same byte ceiling before creating the reserved temp file. |
| Consumed proof sidecar (`<event-log>.consumed-proofs.json`) | `schema_version` | `1` (maximum 4,194,304 bytes, 4,096 records, 24-hour maximum proof/quarantine lifetime) | Missing state rebuilds from the complete ordered event-log family, including archive-only history, and prior history activates the bounded migration quarantine. Existing empty, malformed, oversized, unsupported-version, over-capacity, unknown-field, invalid-digest/identifier/lifetime, duplicate-key, or canonical-rewrite-over-limit state fails production preflight. Writers enforce the same byte ceiling before creating the reserved temp file. |
| Bait profile config | `schema_version` | `1` | Any other version rejected at load (`main.rs`). |
| Ingress trust config | `schema_version` | `1` | Any other version rejected at load (`ingress_identity.rs`). |
| Session signing key ring (`key-ring.json`) | key `version` integers + `active_key_version` | shape v1 (unversioned shape) | The JSON shape is validated strictly (unique u32 versions, active present, 64-hex keys); unknown key *versions* in cookies fail closed to a fresh mint. A shape version field may be added in a future minor release and will follow this policy. |
| Controlled-reality backend protocol | `CONTROLLED_REALITY_BACKEND_SCHEMA_VERSION` | `1` | Mismatch rejected in both directions (`controlled_reality_backend.rs`). |
| Edge decision export | `contract_version` | `2026-06-05.v1` | Producer-stamped today; consumer-side validation is tracked by issue #252. |
| Smoke evidence JSON (kind/orbstack smokes) | `schema_version` | `1` | Fixture validators (`--validate-fixture`) reject missing/extra files and violated invariants; m3 packaging enforces via `pe_expect`. |
| Metrics summary (lab) | `schema_version` | `0` | Lab artifact, not part of the supported envelope. |
| Proxy effective configuration (`--print-effective-config`) | `schema_version` | `1` | Redacted output projection only; it never starts the runtime. Unknown CLI flags and invalid profile inputs are rejected before startup (`main.rs`). |

The policy-state reader accepts an otherwise valid current-schema snapshot at
exactly 33,554,432 bytes, including one padded with trailing JSON whitespace,
and reads at most one byte beyond that limit to distinguish an oversized file.
File metadata is only an early rejection; the bounded read remains authoritative
if the file changes. Read acceptance does not bypass the same write bound: if a
schema migration or startup compaction would expand the current-schema snapshot
beyond the limit, startup fails before opening the temp file and leaves the
source snapshot unchanged. A duplicate `session_id` is invalid regardless of
record contents, schema 1--3, or input order, so ordering can never select an
enforcement state. Snapshot-local pending depth/workflow/origin, transition,
event-association, and response-state invariants are also validated for schema
1--3 before map construction, eviction, or migration persistence. A staged
blocked response must retain status 403, `eidolon_owned` routing, no controlled
interaction, and the canonical absent-interaction digest, with a response event
ID distinct from its staged policy event. Ready workflow state has no origin;
queued state requires an origin and depth of at least one; completed state
requires an origin and depth of at least two. Non-blocked pending responses must
match either the deterministic controlled-reality action/progress semantics or
the config-independent 429 rate-limit form, so a later depth-configuration
change does not invalidate a legitimate crash snapshot. Production
performs this bounded validation without mutation before acquiring the writer
lease, including a dry-run serialization for any startup migration or
eviction, then re-reads and revalidates under the lease before persistence.
Invalid state therefore neither creates nor rewrites lease metadata, while a
path change in the preflight-to-lock window is still rejected by the
authoritative read.

### Lab and production audit projections

Route-bearing event fields, debug diagnostics, and policy transition reasons
are projected per runtime profile. The Lab profile preserves the schema-v2
values exactly: raw request paths with query and fragment values redacted,
full ingress identity and advisory detail, and raw `path=` segments in
transition reasons. The production profile emits bounded route classes (for
example `route:docs`), redacted ingress values, and route-class reason paths
so production durable sinks never carry raw path data. This is a projection
of identical field semantics, not a schema change: `events.jsonl` remains
version 2 and the debug envelope remains version 1.

### Production diagnostic and configuration projections

Production requires the server-side debug JSONL v1 envelope. Rejections that
never enter the normal lifecycle use fixed, redacted diagnostic records with a
fresh request ID and `session_id: null`: `production_pre_service_rejected`
records terminal Hyper boundary classifications before the request service
(`request_id`, `rejection`), while `production_request_rejected` records
post-service adapter rejections (`request_id`, `rejection`,
`response_status`). These records contain no request payload, error text,
normal Event, trace, or export data; their rejection codes are fixed v1
values. They are diagnostic audit records, not additions to the Event schema.

The effective-config v1 projection contains only the selected profile,
session-signing/cookie mode, ingress dependency booleans, trusted-ingress
source-network count/IP-family presence, required-sink configuration state,
and renderer mode. It omits supplied CIDR values, secrets, peer addresses, and
filesystem paths and exits without starting the runtime.

Production resolves its upstream once through Tokio before binding the
listener, retains the complete ordered address set for typed dispatch, and
fails startup on its explicit resolution timeout or lookup error. Failure uses
the runtime's bounded shutdown path; it does not claim to cancel a system
resolver operation that has already outlived the lookup future.

Continuity sidecar schema v2 adds a domain-separated continuity-key identifier
to each minimized record. Schema-v1 records omit that field and inherit the
identifier of the exactly matched state signer. A successful v1 or v2 startup
always rewrites the complete validated snapshot as v2 under the active key.
During the bounded `--previous-ingress-continuity-key-file` overlap, live
previous-key records remain explicitly identified until an authenticated
return durably re-keys them; removing the previous key while any such record is
live fails startup. Expired records may be discarded before that check.
Unknown signers are never tried speculatively, and unverified timestamps never
authorize retirement. A v1-era binary presented with v2 state fails closed as
required by the downgrade rule below.

The schema-v1 bait-exposure and consumed-proof sidecars have independent fixed
4 MiB read/write ceilings. A reader retains at most the limit plus one sentinel
byte; file metadata is only an early check, so growth after metadata cannot
bypass the bound. The 4,096-record and byte ceilings apply jointly. All rows
validate before TTL pruning or map construction, and duplicate logical keys
fail even when identical or expired, so file order never chooses correlation or
replay state. Production validates existing sidecars without mutation before
the writer lease, including a dry run of the canonical pretty-printed rewrite,
then repeats the bounded validation during authoritative open. Successful
rewrites use the fixed reserved `<sidecar>.tmp` path with owner-only
`create_new` creation in the same directory, file sync, atomic rename, and
parent-directory sync. After validating the committed file, authoritative open
under the single-writer lease removes one regular crash-left temp; a symlink or
non-regular object at the reserved path fails closed. The fixed name bounds
crash residue and is part of the deployment recovery-file allowlist.
Missing-sidecar reconstruction consumes the same already-validated event
stream used for pending-workflow recovery; it does not reopen or buffer the
family. Production performs a read-only event-family and repair-plan preflight
before taking the durable-state lease, then performs the authoritative scan
under that lease before policy migration/eviction, event/debug writer open,
sidecar replacement, or listener startup. Only the active segment may repair
one unterminated valid record by appending a newline or discard one invalid
final fragment. Archives must end on a delimiter and are never repaired.

The authoritative scanner reads through fixed-size chunks, admits no more
than the segment limit plus one sentinel and no more than the record limit plus
one sentinel, and treats metadata only as an early rejection. It orders the
three fixed-width archive suffixes numerically/lexicographically before the
active segment, validates every complete record, and rejects duplicate event
IDs across segments. It simultaneously reconstructs bounded sidecar state and
indexes only the response/policy evidence needed by at most 8,192 pending
policy workflows. Durable appends update that in-memory index; lookup no
longer rescans the family once per pending session.

## Compatibility rules

1. **Durable state first.** `events.jsonl`, `policy-state.json`, and the
   sidecars are the release-critical state. Their readers accept every version
   in their documented window and fail closed outside it; writers bump the
   version only with a reader window that includes the previous version.
2. **No partial application.** A config, profile, or state document that fails
   validation is never partially applied; startup or load fails closed.
3. **Unknown future versions are operator-visible.** Every rejection names the
   artifact, found version, and supported versions and is auditable in the
   debug log where a debug log exists, except policy-state rejection. Its
   fixed-output contract names the artifact and supported range but
   deliberately does not echo the untrusted found version, keeping its
   diagnostic independent of snapshot contents.
4. **Export and evidence contracts are redaction-preserving.** A version bump
   may add fields but must not weaken the default omission of secrets, bodies,
   cookies, query values, sensitive path segments, or incidental personal data
   (Gate 7).
5. **Downgrades are explicit.** Running an older binary against newer state is
   supported only when the state's version is inside the older binary's reader
   window; otherwise the older binary fails closed, and the documented
   rollback path is the tested backup/restore or upgrade/rollback procedure.
6. **Lab-only artifacts are excluded.** Lab metrics, lab fixtures, and
   OrbStack harness outputs follow this policy on a best-effort basis but are
   not part of the supported envelope.

## Change management

- Any change to an artifact version, the reader window, or this policy requires
  a contract-doc update, regression coverage for both acceptance and rejection,
  and a changelog entry.
- Deprecating a version requires one full minor release of overlap in which the
  version is still readable before it is removed from the reader window.
