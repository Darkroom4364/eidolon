# Threat Model

## In Scope

Eidolon is designed for:

- autonomous pentesting frameworks
- LLM-driven web/API scanners
- agentic bug bounty systems
- semi-automated offensive workflows
- malicious or unauthorized recon against public targets
- authorized defensive evaluation in a lab

The first target class is web/API/developer-surface reconnaissance:

- web apps
- REST APIs
- OpenAPI specs
- documentation
- repos or repo mirrors
- CI/CD logs
- fake credentials
- fake internal hostnames
- cloud/identity canaries

## Out Of Scope For The Historical Lab Candidate

- nation-state operators with strong OPSEC
- malware delivery
- hack-back
- endpoint compromise
- stealing attacker secrets
- corrupting attacker infrastructure
- production deception involving real secrets
- internal enterprise agent governance
- generic MCP gateway enforcement
- public-v1 or production-ready claims

Those limits apply to the historical Lab milestone and its archived evidence.
The supported Shield target and its additional production requirements are
defined separately in
[v1-release-definition.md](v1-release-definition.md).

The v1 Shield release remains limited to owned or authorized HTTP web/API
surfaces, one declared self-hosted deployment profile, synthetic bait, and one
isolated controlled-reality workflow. It does not expand the allowed defensive
boundary below.

## v1 Production Trust Boundary

The supported v1 deployment assumes:

- the named ingress terminates TLS and is the only trusted source of forwarded
  or trusted-ingress headers; the production proxy enforces both the shared
  transport credential and an explicit bounded direct-peer CIDR list, while
  the deployment independently constrains the hop with NetworkPolicy
- clients control all request data, can forge cookies, and can replay observed
  requests
- storage can become unavailable, stale, or corrupt; Eidolon must fail closed
  rather than reset enforcement
- the renderer can fail or be compromised; its identity, input, output,
  resources, and network reach are constrained by the proxy and cluster policy
- direct access to the protected target is a deployment defect, not a supported
  topology
- volumetric traffic can exhaust declared capacity; queues and state remain
  bounded and overload fails closed
- root compromise of a cluster node or control plane is outside the v1
  guarantee and requires ordinary platform incident response

Release qualification must test the in-scope failures above and document the
remaining node, cluster, ingress, and storage assumptions.

The source runtime bounds `policy-state.json` at 33,554,432 bytes and 8,192
retained sessions, reads only one byte past the byte limit, and rejects empty,
malformed, truncated, unsupported-schema, duplicate-session, or internally
inconsistent pending-workflow state before migration or serving traffic. The
production path preflights that validation without touching lease metadata and
revalidates under the lease, closing the intervening path race. The same byte
limit is checked before replacement writes, so an oversized mutation cannot
replace the last good snapshot. These controls bound source startup and fail
closed on files presented at startup. Pending recovery additionally rejects
impossible workflow/origin/depth combinations, non-deterministic response
contracts, and colliding policy/response event IDs before durable side effects.
It also byte-counts every ordered canonical policy snapshot that recovery will
persist, including `last_seen` refreshes, so compact current-schema expansion
cannot fail only after other startup files have changed. Exact-limit outputs
remain accepted. The authoritative plan's sampled timestamp is reused by the
live recovery writes, closing decimal-width drift after validation. Issue
`#253` separately owns live persistent-volume corruption
and unavailability qualification for the supported deployment.

The production event-log recovery family is finite: one active 33,554,432-byte
segment plus three canonical 39-digit archives, at most 134,217,728 bytes in
total, with no record larger than 1,048,576 bytes before its newline. Recovery
streams fixed-size chunks, checks a limit-plus-one sentinel independently of
metadata, accepts only complete schema-v2 events, and rejects duplicate event
IDs across the family. Numeric archives that are not exactly 39 ASCII digits,
a fourth archive, symlinks, non-regular family members, invalid complete
records, and unterminated archive tails fail closed. Nonnumeric neighboring
files are not family members.
The active file name is capped at 215 UTF-8 bytes so every canonical suffix
fits the supported Linux component limit. Production excludes every configured
writer from the canonical event- and debug-archive namespaces and compares
existing event-family member identities with all writable targets during both
scans, including hard links with unrelated names.

Production preflights that family, its active-tail repair plan, and complete
pending response/policy contracts without the lease or mutation, then repeats
the authoritative validation under the lease. Any missing expected policy
event that reconciliation would append is size-checked through the production
record serializer during both phases. Those phases also simulate the complete
sorted append/rotation/resolution sequence from the active segment's
post-repair length and apply the writer's checked canonical-suffix successor to
every required rotation. A maximum 39-digit suffix therefore blocks a planned
rotation before mutation but does not block a fitting append. A required
rotation cannot evict the oldest of three archives while any later unresolved
workflow still depends on evidence there. The resulting stream reconstructs
and fully validates only missing bounded bait-security sidecars in both the
pre-lease and authoritative scans and builds one selected response/policy
index for at most 8,192 pending workflows; existing
valid sidecars remain authoritative. A fixed-memory SHA-256 pass verifies the
same ordered membership and bytes before repair/open. This makes startup work
linear in retained family bytes rather than pending sessions times family
bytes. Live appends add payloads only for durable pending workflows and remove
them at resolution. An exactly full active segment remains unrotated when
recovery has no append; any required recovery rotation has already passed the
evidence-retention simulation. The live guard still refuses to prune selected
unresolved evidence. Bare relative paths consistently use the current directory
for archive discovery, sync, and pruning, avoiding a post-rename empty-parent
failure.
Only after validation succeeds may the active tail be repaired, an archive-only
crash window receive a new active file, policy migration/eviction persist,
sidecars replace, or the listener bind. Diagnostics report only aggregate
limits/counts and repair class, never durable IDs or raw records. Live PVC
faults and descriptor-pinned directory hardening remain tracked outside this
source-only control. The process-held writer lease assumes cooperative writers
sharing a stable, operator-controlled storage namespace. An actor able to
rename or unlink the lease path, replace the durable directory or one of its
ancestors, or replace the backing mount while the proxy runs is outside this
lease claim: file locks attach to the opened file object, not permanently to a
replaceable pathname. Such write authority must not be granted to sidecars or
other tenants of the durable volume.

The continuity sidecar MAC authenticates bytes and key provenance; it does not
prove freshness. Restoring an older otherwise valid sidecar together with, or
independently of, PVC state is not detected by schema v2. Strong rollback
detection requires a monotonic commitment outside the PVC and backup rollback
domain. Until such an anchor is supported, backup/restore evidence establishes
only coherent exact-state restoration, not freshness or anti-rollback.

The committed bait-exposure and consumed-proof sidecars are each capped at
4,194,304 bytes and 4,096 records. Reads retain at most one byte beyond the
limit, and writes serialize through the same ceiling before any temp file is
created. Production preflights existing sidecars without acquiring the writer
lease or mutating policy/log state, including a dry run of the canonical
pretty-printed rewrite and rejection of a symlink or non-regular reserved temp,
then repeats the bounded checks during authoritative open. Empty, malformed,
future-schema, over-capacity, future-lifetime, and duplicate logical-key state
fails closed; duplicates are checked before expiry filtering so an expired row
cannot hide ambiguity. Atomic
replacement uses an owner-only, fixed reserved `<sidecar>.tmp` created with
`create_new`, file sync, rename, and parent sync, preserving the previous file
on pre-rename failure. Authoritative open under the single-writer lease removes
one regular crash-left temp only after validating the committed sidecar and
rejects a symlink or non-regular temp. Missing sidecars rebuild from the
already-validated ordered complete event-log family, including the archive-only
post-rename crash window. Existing valid sidecars remain authoritative. Live
PVC proof remains #253. Missing-sidecar reconstruction must also pass the same
identifier, timestamp, lifetime, capacity, and canonical-size semantics as a
loaded sidecar before durable startup mutation; consumed-proof reconstruction
adds its history quarantine before that final size check.
The policy snapshot's reserved temp path is also checked without mutation in
both preparation phases and immediately before persistence; a symlink or
non-regular object cannot defer failure until after lease or event-log effects.

## Defensive Boundary

Eidolon may degrade hostile behavior inside the protected boundary.

Eidolon may not compromise infrastructure outside the protected boundary.

Allowed:

- fake evidence
- decoy endpoints
- canary credentials
- contradictory clues
- rate limits
- tarpits
- sandbox routing
- proof-of-work
- budget exhaustion through sterile paths
- false exploit affordances that do not help against real systems

Not allowed:

- exploiting the agent runner
- stealing API keys
- deleting files
- implanting malware
- making the agent attack third parties
- escaping the protected environment

## Safety Rules For Bait

Bait must be:

- synthetic
- non-sensitive
- non-exploitable
- safe if copied
- safe if indexed
- safe if disclosed
- clearly attributable internally

Bait must not include:

- real secrets
- real internal hostnames
- real bypasses
- real exploit recipes
- real customer data
- instructions that improve attacker capability against third parties

## Semantic-Canary Benchmark Boundary

Semantic canaries are synthetic, inert benchmark fixtures for measuring whether
meaning survives controlled paraphrase and whether negative controls remain
distinguishable. In the initial phase they are evaluated offline only.

Protected assets for this benchmark lane are:

- truthful fixture labels and scorer results
- a disclosure-safe synthetic fixture corpus
- strict separation from runtime policy, routing, containment, and evidence

Adversarial and failure inputs include malicious or malformed fixture text,
lexical-overlap shortcuts, negation and contradiction, paraphrase drift, scorer
nondeterminism or version drift, corpus leakage or memorization, prompt-injection
style text trying to induce tool or network use, oversized or high-cardinality
manifests, report oversharing, and operator promotion of similarity into causal
or attribution claims.

Controls are inert-data parsing only, no tool or network execution contract,
strict schema, size, count, and time bounds, held-out and benign near-neighbor
controls, repeated-run version and hash metadata, an abstention band, false
positive breakdowns, allowlisted summary export, and explicit non-causality
labels.

This boundary does not model, identify, or attribute an external attacker.
Scanner, actor, intent, autonomy, model, vendor, family, maliciousness, and
production efficacy claims remain unsupported by semantic benchmark scores.

## M2.5 Controlled-Reality Boundary

M2.5 controlled reality is in scope only for the owned Lab and one narrow decoy admin/API branch.

Allowed:

- synthetic records
- synthetic account, import, admin, or job states
- decoy success, delay, and error responses
- disposable Lab-only decoy state
- event logging for policy state, routing, dwell time, action depth, and escape attempts

Not allowed:

- forwarding bait-derived writes to the protected upstream
- mutating real target state
- using production services, real secrets, customer data, or internal hostnames
- creating exploit instructions that apply to third-party systems
- claiming autonomous-agent identity from controlled-reality behavior alone
- presenting M2.5 as public-v1 or production-ready

## Claim Boundaries

Do not claim:

```text
AI attacker detected
```

Prefer:

```text
High-confidence bait-derived autonomous recon/action chain observed
```

Eidolon detects behavior, not ontology. It does not need to prove the actor is an LLM.

Semantic-canary benchmark labels, similarity scores, contradiction results, or
action-shape observations are not causal runtime evidence. Keep direct
observations, fixture labels, scorer outputs, derived benchmark evaluations,
and same-session accepted bait proof as separate evidence classes. Ambiguity
means unknown or abstained, never confirmation.
