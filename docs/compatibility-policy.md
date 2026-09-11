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
| Event log (`events.jsonl`) | `schema_version` per record | `2` | Readers reject any other version with an actionable error (`eidolon-trace` reader enforces; tested). |
| Debug log (`debug.jsonl`) | `schema_version` + `run_kind` envelope | `1` (`eidolon_proxy_debug`) | Server-side diagnostic only; no supported reader today. A validating reader is tracked by issue #252. |
| Policy state (`policy-state.json`) | `schema_version` | `3` (reads `1..=3`) | Unsupported versions fail startup; no downgrade guessing (`policy_store.rs`). |
| Session continuity sidecar (`<policy-state>.continuity.json`) | `schema_version` | `2` (reads `1..=2`) | Unsupported versions, an unverifiable signer, or a live record whose continuity key is unavailable prevent startup (`session_continuity_store.rs`). |
| Bait exposure sidecar (`<event-log>.exposures.json`) | `schema_version` | `1` | Unsupported versions fail closed; missing sidecar with prior history enters the documented migration quarantine. |
| Consumed proof sidecar (`<event-log>.consumed-proofs.json`) | `schema_version` | `1` | Same rule as the exposure sidecar. |
| Bait profile config | `schema_version` | `1` | Any other version rejected at load (`main.rs`). |
| Ingress trust config | `schema_version` | `1` | Any other version rejected at load (`ingress_identity.rs`). |
| Session signing key ring (`key-ring.json`) | key `version` integers + `active_key_version` | shape v1 (unversioned shape) | The JSON shape is validated strictly (unique u32 versions, active present, 64-hex keys); unknown key *versions* in cookies fail closed to a fresh mint. A shape version field may be added in a future minor release and will follow this policy. |
| Controlled-reality backend protocol | `CONTROLLED_REALITY_BACKEND_SCHEMA_VERSION` | `1` | Mismatch rejected in both directions (`controlled_reality_backend.rs`). |
| Edge decision export | `contract_version` | `2026-06-05.v1` | Producer-stamped today; consumer-side validation is tracked by issue #252. |
| Smoke evidence JSON (kind/orbstack smokes) | `schema_version` | `1` | Fixture validators (`--validate-fixture`) reject missing/extra files and violated invariants; m3 packaging enforces via `pe_expect`. |
| Metrics summary (lab) | `schema_version` | `0` | Lab artifact, not part of the supported envelope. |
| Proxy effective configuration (`--print-effective-config`) | `schema_version` | `1` | Redacted output projection only; it never starts the runtime. Unknown CLI flags and invalid profile inputs are rejected before startup (`main.rs`). |


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
session-signing/cookie mode, ingress dependency booleans, required-sink
configuration state, and renderer mode. It omits supplied secrets and
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

## Compatibility rules

1. **Durable state first.** `events.jsonl`, `policy-state.json`, and the
   sidecars are the release-critical state. Their readers accept every version
   in their documented window and fail closed outside it; writers bump the
   version only with a reader window that includes the previous version.
2. **No partial application.** A config, profile, or state document that fails
   validation is never partially applied; startup or load fails closed.
3. **Unknown future versions are operator-visible.** Every rejection names the
   artifact, the found version, and the supported versions, and is auditable
   in the debug log where a debug log exists.
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
