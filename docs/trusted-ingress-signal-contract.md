# Trusted Ingress Signal Contract

## Purpose

This document defines the vendor-neutral contract between an edge security
system and Eidolon.

The problem is not "ingest one bot score." Eidolon needs a stable way to carry:

- identity signals
- verification strength
- signed or attested agent claims
- raw vendor scores and detections
- edge policy hints
- Eidolon policy and evidence back out to the edge

Without that contract, the proxy will drift into per-vendor header parsing and
inconsistent policy behavior.

## Scope

This contract covers:

1. inbound request-scoped trust and risk signals
2. normalization and precedence
3. outbound Eidolon decision export
4. adapter examples

This contract does not require Eidolon to implement every field immediately.
The current runtime enforces only the normalized ingress identity subset plus
local trust config, and it accepts explicit edge-provided identity only when a
trusted adapter supplies the configured transport-auth secret **and** the
request's direct TCP peer is inside a configured trusted-ingress source CIDR.
It now also captures authenticated advisory ingress signal fields into request
audit events, includes them in outbound edge-decision export when present, but
those fields remain advisory rather than direct enforcement inputs. Richer
score and attestation fields are specified here so future adapters do not fork
the schema.

## Design Principles

- Vendor-neutral core: Cloudflare, DataDome, Akamai, and custom adapters should
  map into the same Eidolon contract.
- Fail closed: missing, stale, malformed, or contradictory edge signals must
  degrade to weaker trust, never stronger trust.
- Identity is separate from risk: "this is a known signed agent" is different
  from "this request looks abusive."
- Runtime evidence outranks ingress trust: once Eidolon has bait-derived runtime
  evidence, ingress trust cannot exempt the session from containment.
- Edge transport must be scrubbed: adapters must strip inbound client-supplied
  `X-Eidolon-*` headers before adding trusted headers of their own.
- Opaque attestation references: Eidolon can store a verifier reference or key
  identifier without embedding whole signatures or secrets into the event log.

## Contract Layers

There are three distinct layers:

1. Raw vendor signal
   Example: `cf.bot_management.score`, DataDome identification strength

2. Normalized ingress contract
   Vendor-neutral fields carried into Eidolon

3. Runtime decision and evidence export
   Eidolon's output back to a SIEM, webhook, or edge policy system

The normalized contract is the durable interface. Raw vendor fields are adapter
inputs, not the product surface.

## Inbound Normalized Schema

Conceptual JSON shape:

```json
{
  "contract_version": "2026-06-05.v1",
  "producer": {
    "system": "cloudflare",
    "instance": "zone:example.com",
    "generated_at": "2026-06-05T12:00:00Z"
  },
  "request_scope": {
    "host": "app.example.com",
    "method": "GET",
    "path_prefixes": ["/docs", "/openapi.json"]
  },
  "identity": {
    "source": "signed_agent",
    "trust_tier": "signed_attested",
    "verification_strength": "cryptographic",
    "label": "operator.openai.com",
    "actor_kind": "agentic_browser",
    "verified_category": "AI Assistant",
    "expires_at": "2026-06-05T12:05:00Z",
    "attestation_ref": "jkt:sha256:ba3e64"
  },
  "risk": {
    "vendor_score": 12,
    "vendor_score_kind": "automation_likelihood_inverse",
    "vendor_score_scale": "1-99",
    "raw_detection_ids": ["3355446"],
    "reason_codes": ["heuristics", "ml"]
  },
  "edge_policy_hint": {
    "suggested_action": "allow",
    "reason": "known signed agent"
  }
}
```

### Identity Fields

- `source`
  - `none`
  - `internal_scanner`
  - `local_allowlist`
  - `verified_bot`
  - `signed_agent`
  - `partner_automation`
  - `operator_override`

- `trust_tier`
  - `none`
  - `weakly_asserted`
  - `allowlisted`
  - `edge_verified`
  - `signed_attested`

- `verification_strength`
  - `none`
  - `low`
  - `medium`
  - `high`
  - `cryptographic`

- `actor_kind`
  - `unknown`
  - `crawler`
  - `assistant`
  - `autonomous_agent`
  - `agentic_browser`
  - `partner_automation`
  - `internal_scanner`

### Risk Fields

Risk is advisory. Eidolon should preserve vendor scores and detections even if
the current runtime does not enforce on them yet.

- `vendor_score`: raw numeric value from the edge platform
- `vendor_score_kind`: explains score polarity and semantics
- `vendor_score_scale`: raw score scale such as `1-99`
- `raw_detection_ids`: vendor-provided detection IDs or categories
- `reason_codes`: adapter-specific non-secret reasons

## Current HTTP Transport

The current proxy already consumes this subset through reserved headers:

- `X-Eidolon-Ingress-Identity-Source`
- `X-Eidolon-Ingress-Trust-Tier`
- `X-Eidolon-Ingress-Identity-Label`
- `X-Eidolon-Ingress-Identity-Expires-At`
- `X-Eidolon-Ingress-Transport-Auth`
- `X-Eidolon-Ingress-Continuity`

The first four fields map directly to the runtime `IngressIdentity`. The
transport-auth header is not part of the identity model; it is a transport-only
attestation check that must match the proxy's configured shared secret before
the explicit identity is trusted. In production that check is necessary but
not sufficient: the direct TCP peer must also match one of the explicit
`--trusted-ingress-source-cidr` networks. The continuity header is an opaque,
adapter-minted identity used only for session continuity. Eidolon immediately
reduces it to an HMAC-SHA256 key under the configured continuity key; when no
separate continuity key is configured, the transport secret is used as a
legacy fallback. The raw value is not stored, logged, exported, or forwarded
upstream. Keeping an explicit continuity key stable allows the transport
credential to change without changing the recovered session or enforcement
floor.

Reserved and now captured in authenticated request audit events:

- `X-Eidolon-Ingress-Verification-Strength`
- `X-Eidolon-Ingress-Actor-Kind`
- `X-Eidolon-Ingress-Verified-Category`
- `X-Eidolon-Ingress-Attestation-Ref`
- `X-Eidolon-Ingress-Vendor-Score`
- `X-Eidolon-Ingress-Vendor-Score-Kind`
- `X-Eidolon-Ingress-Vendor-Score-Scale`
- `X-Eidolon-Ingress-Detection-Ids`
- `X-Eidolon-Ingress-Edge-Action`

### Transport Rules

- Adapters must remove any client-supplied `X-Eidolon-*` headers first.
- Adapters must attach `X-Eidolon-Ingress-Transport-Auth` with the shared
  secret expected by the proxy before emitting explicit identity headers.
  Each request must carry exactly one transport-auth header. When
  `--previous-ingress-transport-auth-secret-file` is configured, either the
  active credential or that one previous credential authenticates the same
  identity, advisory signals, and stable continuity mapping; multiple header
  values are rejected even when every value is valid.
- Production requires 1-32 repeatable `--trusted-ingress-source-cidr <CIDR>`
  entries. Entries are normalized, duplicate normalized networks and universal
  IPv4/IPv6 `/0` networks are rejected, and matching uses only the direct TCP
  peer. An IPv4-mapped IPv6 peer is normalized to IPv4 before matching; supply
  the corresponding IPv4 CIDR rather than a mapped IPv6 CIDR. Forwarded,
  `X-Forwarded-For`, `X-Real-IP`, identity, and advisory header values never
  influence this decision.
- A missing or nonmatching direct peer in production receives the same fixed
  no-store `400` as other invalid ingress-continuity input before session
  adoption or minting, continuity lookup/re-key, policy/evidence/state mutation,
  renderer dispatch, or protected-upstream access. Production diagnostics emit
  only `untrusted_ingress_source` and configured count/family metadata, never
  the peer address or configured CIDR values.
- Adapters must attach exactly one `X-Eidolon-Ingress-Continuity` value of
  16-256 ASCII alphanumeric, `-`, or `_` characters. It must distinguish
  clients sharing one ingress peer and must not contain an email, account ID,
  IP address, or other direct identifier.
- `--require-authenticated-ingress-continuity` makes the pair mandatory on
  every request; a missing/disallowed peer or missing, duplicate, malformed,
  or unauthenticated continuity then returns `400` before protected-upstream
  access. Merely configuring the transport secret keeps existing Lab peer
  continuity compatible. If source CIDRs are explicitly configured in Lab,
  they gate trusted-ingress input there too.
- Authenticated continuity remains bound to one stable session through cookie
  loss, malformed cookies, and conflicting valid cookies. One valid cookie
  cannot bind multiple authenticated continuity identities.
- Continuity storage is TTL- and capacity-bounded. Suspicious-or-higher records
  are not evicted; if they saturate capacity, an unknown identity receives a
  `503` Eidolon-owned response even when interventions are disabled.
- Authenticated continuity mappings are HMAC-minimized and persisted beside
  policy state at `<policy-state-path>.continuity.json`. Raw continuity
  identities and process-local Lab peer keys are excluded. The sidecar is
  HMAC-authenticated, and new durable mappings are limited to 64 per rolling
  60-second window so a trusted ingress cannot trigger unbounded synchronous
  state rewrites.
- If the sidecar is missing while prior state exists, unknown authenticated
  identities fail closed for a bounded migration quarantine. Corrupt state or
  state bound to a different continuity key prevents startup.
- The active transport credential, optional previous transport credential,
  active continuity key, and optional previous continuity key have separate
  roles. Transport credentials authenticate the adapter request. Continuity
  keys minimize its opaque identity and authenticate durable continuity state.
  Do not change the continuity key as part of a transport-credential rollout.
- Use this order for a planned source-runtime rotation: start with the old
  credential active; restart with the new credential active and the old one
  configured as previous; move every adapter to the new credential while each
  request continues to send exactly one header; then remove the previous flag
  and restart again. Active, previous, and continuity-key files must be
  distinct production startup inputs; the previous-key path also cannot alias
  any other configured startup input. Active/previous contents must be
  non-empty and different.
- Removing the previous credential before every adapter has moved causes old
  adapter requests to fail before session adoption, cookie minting, policy
  mutation, or protected-upstream access. It does not erase or weaken the
  contained session or replay state; presenting the new credential with the
  unchanged continuity key recovers that state.
- A continuity-key rotation uses
  `--previous-ingress-continuity-key-file <PATH>`, with the new key active and
  exactly one old key previous. After transport authentication succeeds,
  Eidolon derives both minimized candidates. An existing previous-key binding
  is atomically persisted under the active key before its session, enforcement
  floor, or recovery metadata can affect the request. New identities use only
  the active key. If both candidates exist, or migration persistence fails,
  the request receives a `503` Eidolon-owned response with no cookie or
  protected-upstream access.
- Continuity sidecar schema v2 records each binding's domain-separated key
  provenance. Schema-v1 snapshots remain readable under their exactly matched
  signer and are rewritten as v2 under the active key before traffic. Startup
  exposes only redacted active/previous record counts. After migration traffic,
  restart with the overlap and require a zero previous count before removing
  the old key; otherwise new-only startup fails closed. A dormant binding that
  exceeds the continuity TTL is deliberately expired and returns as a new
  active-key session. If reissue or migration is interrupted, retain both
  candidates, repair storage, and retry the overlap because the last durable
  snapshot may be signed by either configured key. A bounded rollback swaps
  active and previous roles and follows the same migration rule. Active and
  previous contents must be non-empty and different, and all transport and
  continuity key files must be distinct production startup inputs.
- These source-runtime overlaps do not add Kubernetes Secret wiring or prove a
  live deployment rotation. Deployment automation and live
  upgrade/rollback/retirement evidence remain part of issues `#253` and
  `#254`; old-key state is accepted only after the snapshot authenticates
  under the exact configured candidate, never based on unverified timestamps.
- This source-runtime overlap slice does not complete issue `#254` or establish
  production readiness.
- Adapters must only emit normalized values, never secrets or raw signatures.
- Headers are request-scoped, not session-scoped storage.
- Large raw payloads belong in sidecar logs or webhooks, not inline request
  headers.
- Bare NodePort, port-forward, or direct-origin traffic is not a trusted edge
  adapter boundary. Outside strict production, explicit
  `X-Eidolon-Ingress-*` claims from a nonmatching peer, including a presented
  transport/continuity pair, are ignored and existing cookie/Lab direct-peer
  continuity remains in effect. Strict production rejects the nonmatching peer
  because every request requires the authenticated pair. Possession of a
  transport credential never overrides the direct-peer network boundary.

Issue `#253` must populate the CIDRs from the named ingress-to-proxy hop and
also enforce the corresponding NetworkPolicy/topology. Source CIDRs are an
application boundary, not a replacement for cluster isolation; the live
deployment proof must demonstrate both and record the exact configured
networks without placing them in production request diagnostics.

## Local Trust Config

Local trust config is part of the same contract, not a separate exception.

The current local config supports:

- label
- source
- trust tier
- optional expiry
- method scope
- exact host scope, matched against the normalized request host without the port
- path-prefix scope
- optional source CIDR scope, matched against the proxy's direct TCP peer
- required header matchers

That config is an operator-controlled trust source and participates in the same
precedence rules as edge-provided claims.

## Precedence And Normalization

The current precedence model is:

1. `operator_override`
2. `signed_attested`
3. `edge_verified`
4. `allowlisted`
5. `weakly_asserted`
6. `none`

Tie-break rules:

- Local config wins over an equal-strength explicit edge claim.
- A malformed or incomplete explicit claim degrades to `none`.
- An explicit claim without a valid transport-auth header degrades to `none`.
- A stale explicit claim is now degraded to at most `weakly_asserted` in
  runtime code, so it remains auditable but no longer softens bait exposure as
  a strong trusted identity.
- A stale local ingress-trust config entry no longer matches at all.

### Important Runtime Rule

Ingress trust can soften bait exposure while a session is still in
`normal`/`observe`, but it does not override runtime evidence.

Current runtime behavior:

- stronger trusted identities may skip configured bait exposure surfaces
- confirmed bait-derived actions can still move the session into controlled
  reality
- contained sessions do not escape because of ingress trust

This keeps trust as a front-door input, not a permanent immunity token.

## Bait Softening Scope

Trusted identities should not suppress every controlled surface.

Current runtime policy:

- softening is limited to configured path prefixes
- default scope:
  - `/docs`
  - `/openapi.json`
- local allowlist entries may now carry optional
  `bait_soften_path_prefixes` that narrow this scope for that specific trusted
  actor
- local allowlist entries may also carry optional `source_cidrs` so verified
  crawler or partner automation matches can be bound to expected source
  networks instead of header/path shape alone
- local allowlist entries may also carry optional `hosts` so verified crawler
  or partner automation matches can be bound to expected first-party hostnames
  instead of header/path shape alone
- local allowlist entries may also carry optional `user_agent_substrings` so
  verified crawler or partner automation matches can be narrowed to expected
  agent families without treating `User-Agent` itself as a trust source
- local allowlist entries may also carry optional `required_headers` so
  deployment-safe trust can still demand exact edge-provided headers without
  treating those header names or values as permanent runtime evidence
- local allowlist entries may also carry optional `not_before` and `expires_at`
  windows so deployment-safe trust can be staged and retired without changing
  any other match scopes
- authenticated explicit trust rules may now be configured separately from
  local allowlist entries, so transport-authenticated strong explicit claims
  such as `signed_agent` can be narrowed by their own method/path soften scope
  and optional `verified_category` requirements
- when multiple authenticated explicit trust rules could match the same strong
  explicit claim, Eidolon now chooses the most specific matching rule instead
  of relying on config order alone
- when authenticated explicit trust rules are configured, a strong explicit
  claim that does not match one of them is degraded to `weakly_asserted`
  before bait softening is considered
- when a request nearly matches a local allowlist entry but misses the allowed
  HTTP method or request path scope, Eidolon records that explicitly as
  `method_mismatch` or `path_mismatch` instead of silently collapsing back to
  `none`
- when a request nearly matches a local allowlist entry but misses one required
  header name or value, Eidolon records that explicitly as
  `required_header_missing` or `required_header_value_mismatch` instead of
  silently collapsing back to `none`
- local allowlist scopes do not widen the global soften list; they only
  intersect with it
- strong trusted identities do not suppress unrelated bait surfaces outside that
  scope

This keeps verified crawlers and signed agents away from obvious discovery bait
without letting them bypass all Eidolon surfaces.

## Outbound Eidolon Decision Schema

Conceptual JSON shape:

```json
{
  "contract_version": "2026-06-05.v1",
  "observed_at": "2026-06-05T12:00:02Z",
  "session_id": "6f2c3c4a-6b6a-4f50-81b8-96a3953d4f6c",
  "request": {
    "method": "GET",
    "path": "/docs/legacy-import"
  },
  "ingress_identity": {
    "source": "signed_agent",
    "trust_tier": "signed_attested",
    "label": "operator.openai.com"
  },
  "ingress_signals": {
    "verification_strength": "cryptographic",
    "actor_kind": "agentic_browser",
    "verified_category": "AI Assistant",
    "attestation_ref": "jkt:sha256:ba3e64",
    "vendor_score": 12,
    "vendor_score_kind": "automation_likelihood_inverse",
    "vendor_score_scale": "1-99",
    "detection_ids": ["3355446"],
    "edge_action": "allow"
  },
  "policy": {
    "state": "observe",
    "routing_decision": "protected_upstream",
    "reason": "trusted ingress identity suppressed bait surface intervention before runtime suspicion was established"
  },
  "evidence": {
    "event_schema_version": 2,
    "event_ids": [],
    "bundle_ref": "events.jsonl#session=6f2c3c4a-6b6a-4f50-81b8-96a3953d4f6c"
  },
  "edge_recommendation": {
    "action": "allow",
    "ttl_seconds": 300,
    "reason_codes": ["trusted_identity", "bait_softened"]
  }
}
```

Minimum outbound fields:

- `session_id`
- request method/path
- normalized ingress identity
- latest authenticated advisory ingress signals when present
- Eidolon policy state
- routing decision
- human-readable reason
- evidence reference
- recommended edge action

Recommended edge actions:

- `allow`
- `observe`
- `rate_limit`
- `challenge`
- `block`
- `preserve_eidolon_routing`

`preserve_eidolon_routing` means the edge should avoid interfering because
Eidolon is already performing the relevant containment or deception step.

## Safety Rules

- Missing signal -> degrade to `none`
- Malformed signal -> degrade to `none`
- Expired signal -> degrade to weaker trust or `none`
- Contradictory identity/risk -> preserve both in audit, prefer weaker trust for
  enforcement
- Bot score alone must not create a `signed_attested` or `edge_verified`
  identity
- `User-Agent` alone must never create trust

## Adapter Example: Cloudflare

Cloudflare exposes:

- `cf.bot_management.score`
- `cf.bot_management.verified_bot`
- `cf.bot_management.signed_agent`
- `cf.verified_bot_category`
- `cf.bot_management.detection_ids`

Recommended mapping:

- `cf.bot_management.signed_agent = true`
  - `source = signed_agent`
  - `trust_tier = signed_attested`
  - `verification_strength = cryptographic`

- `cf.bot_management.verified_bot = true`
  - `source = verified_bot`
  - `trust_tier = edge_verified`
  - `verification_strength = high`

- `cf.verified_bot_category`
  - `verified_category = <raw string>`

- `cf.bot_management.score`
  - `vendor_score = <raw score>`
  - `vendor_score_kind = automation_likelihood_inverse`
  - `vendor_score_scale = 1-99`

- `cf.bot_management.detection_ids`
  - `raw_detection_ids = [...]`

The edge adapter should normalize these fields into reserved
`X-Eidolon-Ingress-*` headers before forwarding to Eidolon.

A concrete Worker example lives at
`examples/edge/cloudflare/eidolon-ingress-worker.mjs`.

A Workerless request-header Transform Rules example lives at
`examples/edge/cloudflare/eidolon-request-header-transform-rules.json`.

The current live OrbStack export wrapper for the outbound side of this contract
lives at `examples/shield-lab/export-edge-decisions-orbstack.sh`.

## Adapter Example: DataDome

DataDome exposes:

- agent identity
- identification strength
- agent category
- trust score / recommended policy context

Recommended mapping:

- high-strength Web Bot Auth or cryptographic token verification
  - `trust_tier = signed_attested`
  - `verification_strength = cryptographic`

- high-strength trusted IP / reverse-DNS verification
  - `trust_tier = edge_verified`
  - `verification_strength = high`

- medium-strength attribution or fingerprinting
  - `trust_tier = weakly_asserted`
  - `verification_strength = medium`

- category mapping
  - `AI Crawler -> crawler`
  - `AI Assistant -> assistant`
  - `Autonomous Agent -> autonomous_agent`
  - `Agentic Browser -> agentic_browser`

Raw vendor trust scores should be preserved as advisory risk signals, not
collapsed directly into Eidolon trust tiers without adapter-specific policy.

## What The Runtime Already Supports

Today the proxy supports:

- normalized ingress identity headers
- authenticated request-audit capture of advisory ingress signals such as
  verification strength, actor kind, vendor score, detection IDs, and edge
  action hints
- outbound edge-decision export that preserves normalized ingress identity plus
  the latest authenticated advisory ingress signals when present
- local trust config
- precedence merging between explicit and local trust
- trusted bait-softening on configured path prefixes
- one conservative `observe -> suspicious` promotion for authenticated
  discovery-surface requests that combine a low inverse vendor score with an
  explicitly agentic actor kind
- runtime containment overriding ingress trust

It does not yet support:

- automatic push delivery of webhook/SIEM export directly from the proxy runtime
- automatic enforcement that interprets attestation references
- automatic containment or high-friction enforcement on vendor score,
  detection IDs, or edge action hints alone
- automatic vendor adapters

Those should land after this document, not before it.

## Implementation Guidance

Immediate implementation order:

1. keep the current normalized identity transport stable
2. add richer reserved fields without changing trust semantics
3. implement outbound export using the same contract version
4. add one real adapter at a time behind explicit config

Do not add vendor-specific runtime branches before step 1 is stable.

## References

- Cloudflare Bots overview:
  https://developers.cloudflare.com/bots/concepts/bot/
- Cloudflare Bot Management variables:
  https://developers.cloudflare.com/bots/reference/bot-management-variables/
- Cloudflare signed-agent field:
  https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.signed_agent/
- Cloudflare verified-bot field:
  https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.bot_management.verified_bot/
- Cloudflare Web Bot Auth background:
  https://blog.cloudflare.com/en-us/web-bot-auth/
- DataDome AI Agent Identification:
  https://docs.datadome.co/docs/ai-agent-identification
- DataDome Agentic Trust getting started:
  https://docs.datadome.co/docs/agentic-trust-getting-started
