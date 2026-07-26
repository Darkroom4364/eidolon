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
| Session continuity sidecar (`<policy-state>.continuity.json`) | `schema_version` | `1` | Unsupported versions or a continuity-key mismatch prevent startup (`session_continuity_store.rs`). |
| Bait exposure sidecar (`<event-log>.exposures.json`) | `schema_version` | `1` | Unsupported versions fail closed; missing sidecar with prior history enters the documented migration quarantine. |
| Consumed proof sidecar (`<event-log>.consumed-proofs.json`) | `schema_version` | `1` | Same rule as the exposure sidecar. |
| Bait profile config | `schema_version` | `1` | Any other version rejected at load (`main.rs`). |
| Ingress trust config | `schema_version` | `1` | Any other version rejected at load (`ingress_identity.rs`). |
| Session signing key ring (`key-ring.json`) | key `version` integers + `active_key_version` | shape v1 (unversioned shape) | The JSON shape is validated strictly (unique u32 versions, active present, 64-hex keys); unknown key *versions* in cookies fail closed to a fresh mint. A shape version field may be added in a future minor release and will follow this policy. |
| Controlled-reality backend protocol | `CONTROLLED_REALITY_BACKEND_SCHEMA_VERSION` | `1` | Mismatch rejected in both directions (`controlled_reality_backend.rs`). |
| Edge decision export | `contract_version` | `2026-06-05.v1` | Producer-stamped today; consumer-side validation is tracked by issue #252. |
| Smoke evidence JSON (kind/orbstack smokes) | `schema_version` | `1` | Fixture validators (`--validate-fixture`) reject missing/extra files and violated invariants; m3 packaging enforces via `pe_expect`. |
| Metrics summary (lab) | `schema_version` | `0` | Lab artifact, not part of the supported envelope. |
| Proxy CLI/config | — | none yet | Unknown flags are rejected; a `--version` flag and a config-contract doc are tracked by issue #252. |

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
