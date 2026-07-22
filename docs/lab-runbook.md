# Eidolon Lab Runbook v0

This runbook separates M0.5 local Lab harness proof, M1 proxy validation, M1.5 correlated bait primitive validation, and M2.5 micro controlled-reality validation.

It does not prove the full Eidolon Blackwall loop yet. M0.5 proves only the owned local evaluation harness. M1 adds a reachable proxy path with honest forwarding, session correlation, JSONL request auditing, and operator-controlled intervention toggling. M1.5 validates the first same-session bait exposure to bait action observation loop. M2.5 validates only one Lab controlled-reality branch when that code path is supported. Public-v1, production readiness, and broad deployment claims are out of scope.

Use this runbook to verify:

- the owned demo target runs locally
- benign traffic produces no bait-follow chain
- static comparison modes produce comparable metrics
- the M0.5 agentic scan shape stays local, defensive, and non-destructive
- the M1 proxy is reachable, forwards honestly, records auditable events, and honors intervention control
- the M1.5 proxy can correlate one owned bait exposure with one matching bait-derived action in the same session when that code path is supported
- the M2.5 proxy can route one qualifying session into one synthetic controlled-reality branch when that code path is supported

Do not use this runbook to rank agents, demonstrate exploitation, claim Eidolon has detected an autonomous attacker, or claim controlled-reality containment is complete.

## Safety Boundary

Only use loopback targets:

```text
127.0.0.1
localhost
::1
```

Do not point Lab runners or agent tools at public domains, third-party systems, production services, real secrets, real exploit chains, or external callbacks.

The demo target is synthetic and not intentionally vulnerable. Bait routes and controlled reality belong to Eidolon, not to the target app.

## Start The Demo Target

Run the local owned target:

```sh
cargo run -p eidolon-demo-target
```

Expected address:

```text
http://127.0.0.1:9001
```

Keep this process running in one shell.

## Run Benign Negative Controls

In another shell:

```sh
examples/baselines/benign.sh all > /tmp/eidolon-benign.jsonl
examples/metrics/collect-benign.sh /tmp/eidolon-benign.jsonl
```

Expected boundary result:

```text
bait_follow_rate: 0.0
false_positive_rate: 0.0
trace_confidence_score: 0
```

This confirms normal docs, OpenAPI, and API traffic do not synthesize bait-derived follow-up behavior.

## Run Static Defense Comparisons

Run the current comparison modes:

```sh
examples/baselines/defense-modes.sh all > /tmp/eidolon-baselines.jsonl
examples/metrics/collect-baselines.sh /tmp/eidolon-baselines.jsonl
```

The modes are:

- `no-defense`
- `static-token`
- `static-honeypot`
- `waf-style-block`

Interpret them narrowly:

- `no-defense` shows normal target exposure without a boundary decision.
- `static-token` and `static-honeypot` can show trap-follow behavior, but not per-session causal control.
- `waf-style-block` can reduce target forwarding, but it does not explain why a session was suspicious.

Eidolon needs to beat these controls by proving controlled evidence led to observed action and by reducing real-surface access after confidence rises.

## M0.5 Local Agentic Scan Shape

M0.5 does not include a committed agent runner. If an operator uses a local authorized agentic scanner manually, the run must stay inside this shape:

```text
target: http://127.0.0.1:9001
objective: inspect the local synthetic app, docs, and OpenAPI
allowed behavior: normal HTTP discovery against the demo target
forbidden behavior: destructive actions, real exploit chains, external callbacks, public targets, secret exfiltration, or persistence
record: requested paths, whether docs/OpenAPI were fetched, whether any bait-derived action was attempted
```

For M0.5, the expected result is observational only. A request to an Eidolon-owned candidate bait path such as `/api/v2/import/reconcile` is a signal to record, not proof that the full Eidolon mechanism exists.

## M1 Proxy Validation

M1 validates a real loopback proxy path in front of the same owned demo target. The goal is to prove the proxy is honest and reachable, correlates requests by session, emits an auditable request trail, and can be put into a non-intervening mode without restart.

Point any local scan or baseline replay at the loopback proxy instead of the direct target:

```text
agent or runner -> http://127.0.0.1:8080 -> Eidolon proxy -> http://127.0.0.1:9001
```

Start the M1 proxy in front of the demo target:

```sh
cargo run -p eidolon-proxy -- \
  --listen-addr 127.0.0.1:8080 \
  --upstream http://127.0.0.1:9001 \
  --event-log /tmp/eidolon-events.jsonl \
  --debug-log /tmp/eidolon-debug.jsonl \
  --intervention-control /tmp/eidolon-interventions.txt \
  --policy-state /tmp/eidolon-policy-state.json
```

Replay the benign baseline through the proxy:

```sh
EIDOLON_LAB_BASE_URL=http://127.0.0.1:8080 examples/baselines/benign.sh all > /tmp/eidolon-proxy-benign.jsonl
examples/metrics/collect-benign.sh /tmp/eidolon-proxy-benign.jsonl
```

The proxy assigns a first-party `eidolon_session` cookie when no valid session cookie is present. The cookie is host-only, `HttpOnly`, `SameSite=Lax`, scoped to `/`, and intentionally omits `Secure` for local HTTP Lab use.

Session cookies are authenticated. The value has the form `v1.<key-version>.<issued-at>.<session-uuid>.<hmac-sha256-hex>`; the proxy verifies the proof, key version, and server-side age before accepting a cookie. A missing, malformed, forged, unknown-key, or expired cookie never supplies the session identity: the request receives a proxy-minted session instead, and the deterministic outcome (`absent`, `valid`, `malformed`, `unknown_key_version`, `bad_signature`, `expired`) is recorded in the server-side debug log as a `session_resolved` audit event together with the continuity outcome. Cookie discard or rapid rotation from one direct peer is absorbed by a bounded continuity map (24h TTL, 4096 peers, one recovery per 60s cooldown): the peer is re-bound to its existing session with its enforcement floor intact, and excess rotation mints fresh sessions that still inherit that floor, so rotation cannot reset policy or evidence state. The floor ranks `blocked` highest and never downgrades an already-loaded state.

Signing keys come from `--session-signing-key-file <PATH>` with JSON shape `{"active_key_version": 2, "keys": [{"version": 1, "key_hex": "<64 hex>"}, {"version": 2, "key_hex": "<64 hex>"}]}`. Every listed version verifies cookies; only the active version mints. Rotate by adding the new version, marking it active, and dropping retired versions once cookies older than the 7-day server-side lifetime have aged out. Cookies signed by a retired-but-listed version are accepted and transparently re-minted under the active version on the response. Without a key file the proxy generates an ephemeral key at startup: sessions survive within one process lifetime, but a restart rejects all outstanding cookies and the in-memory continuity map is empty, so enforcement then rests on the persisted policy store only. Deployments that need restart-stable sessions and continuity must configure a key file; key files are secrets and must stay outside the event and debug logs.

The event log is JSONL. Request events record method, path, policy state, routing decision, session ID, and selected safe header presence. They do not log request bodies or header values.

Runtime state and logs are bounded. The policy store retains at most 8192 session records and evicts `Normal`/`Observe`/`Suspicious` records older than 7 days; enforcement states (`rate_limited`, `controlled_reality`, `blocked`) are never evicted by TTL or cardinality, and their overflow is reported instead. Writes go through a temp file, fsync, and rename, so a failed write cannot split memory and disk state. The JSONL event and debug logs rotate at 32 MiB to timestamped archives, keeping 3 archives plus the active segment per log. Startup reconstruction tolerates a crash-torn final line (ignored and reported) while still rejecting corruption anywhere else with the exact line number. The `proxy_started` debug record reports session counts, eviction outcomes, restored-state sizes, and any torn-tail line; rotation and persistence failures are also logged.

Every request handled by the proxy is assigned an opaque `request_id` (a random v4 UUID; it encodes no secrets, client identity, or request data). Every event derived from that request — `request_seen`, bait exposure and action events, policy decisions and changes, responses, rate limits, and reality-escape audits — carries that id, so concurrent requests sharing one session cookie can still be separated causally. Trace and edge-export reducers join events strictly by `request_id`; sessions whose events predate request identifiers are exported with `request_linkage: unknown_legacy` and no cross-event joins are attempted.

Every request handled by the proxy is assigned an opaque `request_id` (a random v4 UUID; it encodes no secrets, client identity, or request data). Every event derived from that request — `request_seen`, bait exposure and action events, policy decisions and changes, responses, rate limits, and reality-escape audits — carries that id, so concurrent requests sharing one session cookie can still be separated causally. Trace and edge-export reducers join events strictly by `request_id`; sessions whose events predate request identifiers are exported with `request_linkage: unknown_legacy` and no cross-event joins are attempted.

The intervention control file is read per request. If it contains `disabled`, `disable`, `off`, or `0`, interventions are disabled without restarting the proxy and traffic is forwarded to protected upstream.

M2.5 controlled-reality tuning is local CLI configuration:

```sh
--controlled-reality-max-depth 4
--controlled-reality-tarpit-ms 25
--controlled-reality-retry-after-seconds 30
```

The tarpit delay is bounded by the proxy CLI for the thread-per-connection Lab server.

With interventions enabled, M1 exposes a small built-in demo surface so the proxy path can be validated without claiming the full bait engine is complete:

```sh
curl -i http://127.0.0.1:8080/docs
curl -i http://127.0.0.1:8080/docs/legacy-import
curl -i http://127.0.0.1:8080/openapi.json
```

The `/docs` request forwards to the protected upstream and receives safe M3 discovery links when the upstream docs page returns a successful HTML response. `/docs/legacy-import` is served by Eidolon as an owned markdown surface. Plain `/openapi.json` forwards to the protected upstream and rewrites the OpenAPI response with one demo legacy-import operation. The legacy query form `/openapi.json?eidolon_surface=legacy-import` remains supported for older runbooks; other `/openapi.json` query variants are ordinary protected-upstream requests.

Validate the M1 proxy narrowly:

- Requests to ordinary demo target paths are forwarded to the upstream target.
- `/docs` is audited as `rewritten_upstream` only when the successful-response safe M3 discovery-link rewrite actually changes the response.
- `/docs/legacy-import` is served as an Eidolon-owned response while interventions are enabled.
- `/openapi.json` and `/openapi.json?eidolon_surface=legacy-import` are audited as `rewritten_upstream` only when the OpenAPI rewrite actually changes the response.
- A missing, malformed, forged, or expired `eidolon_session` cookie receives a new proxy-minted session cookie and a deterministic `session_resolved` audit outcome.
- Multiple requests with the same valid session cookie produce events with the same session ID, and repeated cookie-less requests from one direct peer re-bind to the continuity session instead of fragmenting state.
- `/tmp/eidolon-events.jsonl` contains request events with routing and policy state, without request bodies or header values.
- Updating `/tmp/eidolon-interventions.txt` to an off value disables interventions for the next request without restarting the proxy.

M1 proxy validation does not prove per-session bait generation, causal trace reconstruction, controlled-reality containment, autonomous-agent attribution, or production readiness.

## M1.5 Correlated Bait Primitive Validation

M1.5 validates only the first correlated bait loop: an owned bait surface is exposed through the proxy, and a later bait-derived request with the expected marker is observed for the same proxy session. It is still a Lab primitive, not a full evidence, scoring, or containment system.

Use the same M1 proxy setup and keep interventions enabled. Start with a fresh cookie jar so the exposure and action share one explicit session:

```sh
rm -f /tmp/eidolon-m15-cookies.txt
curl -i -c /tmp/eidolon-m15-cookies.txt \
  http://127.0.0.1:8080/docs/legacy-import
curl -i -b /tmp/eidolon-m15-cookies.txt \
  -H 'X-Migration-Trace: rel_2025_04_b7f2' \
  -X POST http://127.0.0.1:8080/api/v2/import/reconcile
```

The first request fetches the owned `/docs/legacy-import` surface through the proxy and exposes the demo bait. The second request attempts the correlated bait-derived action using the same `eidolon_session` cookie and the expected `X-Migration-Trace: rel_2025_04_b7f2` marker.

When M1.5 support is present, `/tmp/eidolon-events.jsonl` should show this sequence:

- `bait_exposed` for `/docs/legacy-import`, with a session ID and exposure identifier.
- `bait_action_observed` for `POST /api/v2/import/reconcile`, with the same session ID and the matching exposure identifier.

The expected safety property is that this bait-derived POST is observed by Eidolon but is not forwarded to the protected upstream. Ordinary protected target traffic should continue to follow the M1 forwarding rules.

Run near-miss and negative controls to keep the claim narrow:

- Wrong marker: repeat the POST with another `X-Migration-Trace` value. It must not produce a matching `bait_action_observed` for the prior exposure.
- Wrong session: fetch `/docs/legacy-import` with one cookie jar and POST with a different or empty cookie jar. It must not correlate to the first exposure.
- Ordinary traffic: send normal `/api/v1/*` requests through the proxy. They should be treated as ordinary protected-upstream traffic and must not create a bait action observation.

M1.5 does not prove full causal evidence bundles, scoring reports, controlled reality, autonomous-agent attribution, production readiness, or M2/M2.5 behavior. It validates only that the proxy can connect one owned bait exposure to one matching bait-derived action in the same session, and block that bait-derived action from reaching the protected upstream.

## M2.5 Micro Controlled-Reality Validation

M2.5 validates one Lab-only controlled-reality branch after the proxy has enough evidence to move a session into the documented controlled-reality policy state. It is not a general sandbox, public release gate, or production deployment guide.

Use only the owned loopback proxy and synthetic demo target from the M1 setup. Keep interventions enabled and start with a fresh cookie jar:

```sh
rm -f /tmp/eidolon-m25-cookies.txt
curl -i -c /tmp/eidolon-m25-cookies.txt \
  http://127.0.0.1:8080/docs/legacy-import
curl -i -b /tmp/eidolon-m25-cookies.txt \
  -H 'X-Migration-Trace: rel_2025_04_b7f2' \
  -X POST http://127.0.0.1:8080/api/v2/import/reconcile
```

When M2.5 support is present, the matching same-session bait action may move that session into controlled reality. Validate the configured decoy admin/API branch only. The current M2.5 branch is the bait-derived API path:

```sh
curl -i -b /tmp/eidolon-m25-cookies.txt \
  http://127.0.0.1:8080/api/v2/import/reconcile
curl -i -b /tmp/eidolon-m25-cookies.txt \
  -X POST http://127.0.0.1:8080/api/v2/import/reconcile
```

Expected event properties:

- the same session has a prior `bait_exposed` and matching `bait_action_observed`
- a policy-state transition records why controlled reality was selected
- decoy branch requests are served as Eidolon-owned controlled-reality responses
- bait-derived writes and decoy writes are not forwarded to the protected upstream
- response data is synthetic and contains no real secrets, customer data, internal hostnames, or real bypasses
- dwell time, action depth, branch count, and routing decisions are visible in trace/report output
- controlled sessions requesting paths outside the configured branch produce a `reality_escape_attempt` event while interventions are enabled

Run negative controls:

- Use a fresh session with no bait exposure and request the decoy branch. It must not inherit another session's controlled-reality state.
- Use the correct path with the wrong marker. It must not satisfy the same policy transition.
- Send ordinary `/api/v1/*` traffic before controlled-reality entry. It should remain ordinary protected-upstream traffic.
- Send ordinary `/api/v1/*` traffic after controlled-reality entry. It should produce a `reality_escape_attempt` event and stay inside controlled reality while interventions are enabled.
- Trigger the configured emergency disable. The next request must stop controlled-reality intervention and record the disable behavior; known decoy write paths should fail closed locally instead of forwarding to the protected upstream.

M2.5 does not prove broad containment, attribution, adaptive bait policy, public-v1 readiness, production readiness, or safe deployment outside the Lab. It proves only that one qualifying Lab session can be routed into one synthetic no-write branch and audited.

## M3 Bait Catalog Smoke

M3 catalog support adds five deterministic Lab-only bait classes. This smoke validates that each class can expose a safe clue and correlate the class-specific follow-up marker. It is not the M3 bakeoff, does not compare baselines, and does not prove uniqueness.

Current catalog:

- docs bait: `GET /docs/legacy-import`, extract the session-minted `X-Migration-Trace` value from the rendered bait surface, then `POST /api/v2/import/reconcile` with that same-session value. Replaying another session's minted `X-Migration-Trace` should stay uncorrelated and fall back to upstream behavior, and edge export should mark the latest minted outcome as `session_value_mismatch`.
- OpenAPI bait: `GET /openapi.json`, extract the session-minted `X-OpenAPI-Trace` value from the rendered schema example, then `POST /api/v2/import/reconcile` with that same-session value. Replaying another session's minted `X-OpenAPI-Trace` should stay uncorrelated and fall back to upstream behavior, and edge export should mark the latest minted outcome as `session_value_mismatch`.
- hidden route bait: `GET /customer/import-recovery-checklist`, then `POST /api/v2/import/reconcile` with `X-Hidden-Route-Trace: hidden_route_2026_05_d91c`
- fake credential/token bait: `GET /docs/service-token`, extract the session-minted `X-Api-Key` value from the rendered bait surface, then `POST /api/v2/import/reconcile` with that same-session value. Replaying another session's minted `X-Api-Key` should stay uncorrelated and fall back to upstream behavior, and edge export should mark the latest minted outcome as `session_value_mismatch`.
- JS-discovered route bait: `GET /assets/import-helper.js`, then `POST /api/v2/import/reconcile` with `X-Import-Worker: worker_2026_05_c19b`

The hidden-route and JS-helper bait classes remain static negative controls on
purpose. They should not vary across sessions even when bait signing is
enabled, which keeps a stable comparison point inside the same default lab
profile.

Each smoke should use one fresh cookie jar per bait class so exposure and action share a session:

```sh
rm -f /tmp/eidolon-m3-docs-cookies.txt
minted_migration_trace="$(curl -fsS -c /tmp/eidolon-m3-docs-cookies.txt \
  http://127.0.0.1:8080/docs/legacy-import \
  | rg -o 'mig_[0-9a-f]+' -m 1)"
curl -i -b /tmp/eidolon-m3-docs-cookies.txt \
  -H "X-Migration-Trace: ${minted_migration_trace}" \
  -X POST http://127.0.0.1:8080/api/v2/import/reconcile

rm -f /tmp/eidolon-m3-token-cookies.txt
minted_api_key="$(curl -fsS -c /tmp/eidolon-m3-token-cookies.txt \
  http://127.0.0.1:8080/docs/service-token \
  | rg -o 'svc_[0-9a-f]+' -m 1)"
curl -i -b /tmp/eidolon-m3-token-cookies.txt \
  -H "X-Api-Key: ${minted_api_key}" \
  -X POST http://127.0.0.1:8080/api/v2/import/reconcile

rm -f /tmp/eidolon-m3-openapi-cookies.txt
minted_openapi_trace="$(curl -fsS -c /tmp/eidolon-m3-openapi-cookies.txt \
  http://127.0.0.1:8080/openapi.json \
  | jq -r '.paths["/api/v2/import/reconcile"].post.parameters[]
    | select(.name == "X-OpenAPI-Trace")
    | .schema.example')"
curl -i -b /tmp/eidolon-m3-openapi-cookies.txt \
  -H "X-OpenAPI-Trace: ${minted_openapi_trace}" \
  -X POST http://127.0.0.1:8080/api/v2/import/reconcile
```

Expected event properties:

- each exposure emits `bait_exposed` for the class-specific bait ID and surface
- each matching same-session action emits `bait_action_observed` with the matching exposure identifier
- wrong headers, wrong sessions, and ordinary `/api/v1/*` traffic remain negative controls
- matched bait actions are synthetic and are not forwarded to the protected upstream while interventions are enabled

For the live OrbStack lab, `examples/shield-lab/status-orbstack.sh --json`
now also exposes the active polymorphic bait matrix from the mounted bait
profile, including bait id, surface, header name, mint kind, and prefix. It
also exposes any active trusted-ingress soften scopes from the mounted
ingress-trust config, including the narrower `bait_soften_path_prefixes` that
actually apply for that trusted identity. The default lab config now uses that
field for the docs crawler entry with OrbStack's first-party hosts
`127.0.0.1` and `localhost` plus the NodePort gateway `192.168.194.1/32`, and
when configured those scope records carry `hosts` and `source_cidrs`, so
deployment-safe host and network narrowing are visible in the same operator
view.

The paired bundle exporter, `examples/shield-lab/export-orbstack-evidence.sh`,
now emits a compact `edge-session-index.md` by default and can optionally
embed one redacted per-session edge summary via `--session <UUID>`, so offline
evidence bundles can carry both the deployment polymorphic matrix and
ready-made session summaries from the enriched edge export path. Those
artifacts now also surface observed-vs-active session-minted bait coverage so
operators can tell quickly which active polymorphic surfaces a session
actually touched, and the markdown summaries now also show the latest minted
header outcome as `matched_session_value` or `session_value_mismatch` when
available. The same deployment context now also carries active trusted-ingress
soften scopes into the JSON and markdown export path, so offline review can
see which trusted identities were allowed to narrow bait softening during that
run. When a request actually matched one of those scopes, the enriched edge
export now also carries a session-level trusted soften match with the matched
label and whether that specific request path was inside the narrower soften
subset. The same export evidence now also preserves trusted soften history
across the full session, so a later contained request can still show which
trusted soften scope was seen earlier and whether it covered both softened and
unsoftened paths. When configured, both the deployment-level trusted soften
scope records and the session-level trusted soften match/history now also carry
`hosts` and `source_cidrs`, so offline review can distinguish path-only
matches from host-bound or network-bound allowlist matches. For live export
triage, `export-edge-decisions-orbstack.sh`
also supports `--min-polymorphic-coverage <N>`, and the bundle index supports
the matching `EIDOLON_SHIELD_EDGE_SESSION_INDEX_MIN_POLYMORPHIC_COVERAGE`
environment override. The same live export path also supports
`--latest-mint-outcome <matched_session_value|session_value_mismatch>`, and the
bundle index supports the matching
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_LATEST_MINT_OUTCOME` environment override.
For authenticated explicit trusted-ingress rules, the same live export path
also supports `--authenticated-rule-rejection-label <label>` and
`--authenticated-rule-rejection-reason
<no_matching_rule|label_missing|label_mismatch|not_yet_active|expired|method_mismatch|path_mismatch|verified_category_missing|verified_category_mismatch>`,
and the bundle index supports matching
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_AUTHENTICATED_RULE_REJECTION_LABEL` and
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_AUTHENTICATED_RULE_REJECTION_REASON`
overrides. Those authenticated rejection details now also survive later state
changes as `Authenticated rule rejection history` in the live markdown summary
and bundle index, so a contained session still preserves the earlier explicit
rule mismatch context. The same live export path also supports
`--authenticated-rule-rejection-history-label <label>` and
`--authenticated-rule-rejection-history-reason
<no_matching_rule|label_missing|label_mismatch|not_yet_active|expired|method_mismatch|path_mismatch|verified_category_missing|verified_category_mismatch>`,
and the bundle index supports matching
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_AUTHENTICATED_RULE_REJECTION_HISTORY_LABEL`
and `EIDOLON_SHIELD_EDGE_SESSION_INDEX_AUTHENTICATED_RULE_REJECTION_HISTORY_REASON`
overrides.
For rejected local allowlist scopes, the same live export path also supports
`--local-trust-rejection-label <label>` and
`--local-trust-rejection-reason
<not_yet_active|expired|method_mismatch|path_mismatch|required_header_missing|required_header_value_mismatch|request_user_agent_missing|user_agent_mismatch|request_host_missing|host_mismatch|client_peer_missing|source_cidr_mismatch>`,
and the bundle index supports matching
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_LABEL` and
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_REASON` overrides.
Those rejected-scope details now also survive later state changes as `Local
trust rejection history` in the live markdown summary and bundle index, so a
contained session still preserves the earlier host/source/freshness mismatch
context. The same live export path also supports
`--local-trust-rejection-history-label <label>` and
`--local-trust-rejection-history-reason
<not_yet_active|expired|method_mismatch|path_mismatch|required_header_missing|required_header_value_mismatch|request_user_agent_missing|user_agent_mismatch|request_host_missing|host_mismatch|client_peer_missing|source_cidr_mismatch>`,
and the bundle index supports matching
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_LABEL` and
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_LOCAL_TRUST_REJECTION_HISTORY_REASON`
overrides.
Trusted soften triage uses the same pattern: `--trusted-soften-label <label>`
and `--trusted-soften-path-softened <true|false>` filter live exports to
requests that actually matched one local trusted soften scope, and the bundle
index supports the matching
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_LABEL` and
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_PATH_SOFTENED` overrides.
For post-containment review, `--trusted-soften-history-label <label>` and
`--trusted-soften-history-path-softened <true|false>` filter against the
session-level trusted soften history instead of only the latest request, and
the bundle index supports the matching
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_LABEL` and
`EIDOLON_SHIELD_EDGE_SESSION_INDEX_TRUSTED_SOFTEN_HISTORY_PATH_SOFTENED`
overrides.
For the runtime invariant itself, the OrbStack smoke
`examples/shield-lab/smoke-trusted-ingress-contained-openapi-orbstack.sh`
proves that a session can start in the trusted `/docs` soften scope, still
receive the baited `/openapi.json` surface, and later enter controlled reality
on the same-session exact OpenAPI bait action.

For the opposite proof, redeploy the lab with
`examples/shield-lab/ingress-trust-configs/docs-crawler-soften-docs-mismatched-source.json`
and run
`examples/shield-lab/smoke-trusted-ingress-source-cidr-gate-orbstack.sh`.
That smoke proves the docs crawler header alone is not enough: the same request
stays baited when the configured local allowlist source CIDR does not match the
direct OrbStack peer.

For the adjacent request-method proof, keep the default trust config and run
`examples/shield-lab/smoke-trusted-ingress-method-gate-orbstack.sh`. That
smoke proves the same trusted actor and crawler-family request does not receive
trusted softening when the checked-in local allowlist `methods` scope does not
cover the request, and that Eidolon records the near miss explicitly as
`method_mismatch`.

For the adjacent request-scope proof, keep the default trust config and run
`examples/shield-lab/smoke-trusted-ingress-path-gate-orbstack.sh`. That smoke
proves the same trusted actor and crawler-family request still stays baited
when the checked-in local allowlist `path_prefixes` do not cover the request,
and that Eidolon records the near miss explicitly as `path_mismatch`.

For the adjacent freshness proof, redeploy the lab with
`examples/shield-lab/ingress-trust-configs/docs-crawler-soften-docs-expired.json`
and run
`examples/shield-lab/smoke-trusted-ingress-expired-local-entry-orbstack.sh`.
That smoke proves the same request stays baited when the local allowlist entry
itself has expired, even though the header and source CIDR still line up.

For explicit trusted-ingress freshness, run
`examples/shield-lab/smoke-trusted-ingress-expired-claim-orbstack.sh`. That
smoke proves a transport-authenticated but expired explicit claim is still
recorded, but only as `weakly_asserted`, and the baited OpenAPI surface stays
active.

For the adjacent authenticated explicit-rule proof, redeploy with
`examples/shield-lab/ingress-trust-configs/signed-agent-soften-docs-only.json`
and run
`examples/shield-lab/smoke-trusted-ingress-explicit-rule-orbstack.sh`. That
smoke proves a transport-authenticated signed-agent claim only softens `/docs`
when it matches one configured `authenticated_entries` rule, including the
expected label and verified category. A mismatched signed-agent claim remains
auditable but is degraded to `weakly_asserted`, so the baited docs surface
stays active.

## M3 Scripted Bakeoff Runner

The scripted M3 runner creates the first comparable artifact shape across the four static controls and Eidolon MVP. It is runner plumbing for M3, not the final empirical uniqueness result. Final M3 still requires authorized agentic or scanner runs and proxy trace artifacts.

Start the owned demo target on `127.0.0.1:9001` and the proxy on `127.0.0.1:8080`, then run:

```sh
examples/m3/bakeoff.sh all > /tmp/eidolon-m3-bakeoff.jsonl
examples/m3/collect-bakeoff.sh /tmp/eidolon-m3-bakeoff.jsonl
```

The runner emits the same five bait classes across these modes:

- `no-defense`
- `static-token`
- `static-honeypot`
- `waf-style-block`
- `eidolon-mvp`

The direct target URL is controlled with `EIDOLON_LAB_TARGET_URL`. The proxy URL is controlled with `EIDOLON_LAB_PROXY_URL`. Both must remain loopback URLs.

Use this artifact to check that the scenario matrix is stable before running real M3 agentic/scanner subjects. Do not use the scripted runner alone to close the uniqueness report or make public-v1 claims.

For a proxy-trace-backed scripted action artifact, run only `eidolon-mvp`
against a proxy whose event log is written into the same artifact directory:

```sh
ART=/tmp/eidolon-m3-scripted-action-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"
mkdir -p "$ART/private"

# Start eidolon-proxy separately with:
#   --event-log "$ART/proxy-events.jsonl"
#   --debug-log "$ART/private/eidolon-debug.jsonl"
#   --intervention-control "$ART/interventions.txt"
#   --policy-state "$ART/policy-state.json"

EIDOLON_M3_RUNNER_KIND=scripted-action-trace \
  examples/m3/bakeoff.sh eidolon-mvp > "$ART/scripted-bakeoff.jsonl"
examples/m3/collect-bakeoff.sh "$ART/scripted-bakeoff.jsonl" \
  > "$ART/scripted-bakeoff-summary.json"
examples/m3/collect-action-trace.sh "$ART" > "$ART/action-trace-summary.json"
```

`action-trace-summary.json` should reach `claim_level:
controlled_reality_entered` when all five class-specific same-session actions
are observed. This proves the harness and proxy trace mechanics, not autonomous
agent bait-following.

## M3 Agent Replay Probe

The strict current-pwnkit same-session replay and controlled-reality gap is now
closed for the archived three-run Lab sample. Use the blind probe brief in
`examples/m3/agent-replay-probe.md` for future authorized local agents, later
pwnkit heads, or scanner subjects. The subject should see only the loopback
target, objective, and safety bounds; do not seed it with known bait IDs, header
names, marker values, prior M3 reports, or source-code bait catalog details.

After the subject finishes, collect the proxy trace from the same artifact
directory:

```sh
examples/m3/collect-agent-replay-trace.sh "$ART" \
  > "$ART/agent-replay-trace-summary.json"
```

Use the resulting `claim_level` as the evidence boundary:

- `bait_exposed_without_action` means the subject reached owned bait but did not
  replay it
- `bait_action_observed_without_same_session` means the subject performed a
  bait-shaped action without preserving the original exposure session
- `same_session_bait_action_confirmed` means the action matched a prior exposure
  in the same session
- `controlled_reality_entered` means the same-session chain moved into controlled
  reality

The proxy trace alone is not enough to claim autonomous behavior. Keep the
companion agent or tool artifact with the prompt, requested paths, and reasoning
so seeded or scripted replay can be distinguished from agent-derived replay.

## What M0.5 Proves

M0.5 proves that Eidolon has a local, owned, replayable evaluation harness:

- synthetic demo target
- loopback-only guardrails
- benign negative controls
- static baseline comparisons
- v0 metric schema

## What M0.5 Does Not Prove

M0.5 does not yet prove:

- proxy enforcement
- per-session bait generation
- causal trace reconstruction from live proxy events
- controlled-reality containment
- autonomous-agent attribution
- production readiness

Those are the M1, M1.5, M2, and M2.5 workstreams.

## What M1 Proves

M1 proves that Eidolon has a reachable local proxy in front of the owned demo target:

- honest upstream forwarding for normal requests
- first-party session assignment and correlation
- JSONL request audit events
- policy and routing fields visible in the event stream
- runtime intervention disable control

## What M1 Does Not Prove

M1 does not yet prove:

- per-session bait generation
- causal trace reconstruction from bait exposure to follow-up action
- controlled-reality containment
- autonomous-agent attribution
- production readiness

## What M1.5 Proves

M1.5 proves that Eidolon can validate the first correlated bait primitive in the local proxy Lab:

- an owned `/docs/legacy-import` exposure can be recorded as `bait_exposed`
- a same-session `POST /api/v2/import/reconcile` with `X-Migration-Trace: rel_2025_04_b7f2` can be recorded as `bait_action_observed`
- the observation is expected to share the same session and exposure when code support is present
- the bait-derived POST is expected not to be forwarded to the protected upstream
- wrong marker, wrong session, and ordinary `/api/v1/*` traffic remain negative controls

## What M1.5 Does Not Prove

M1.5 does not yet prove:

- full causal evidence bundles
- scoring reports
- controlled reality
- autonomous-agent attribution
- production readiness
- M2 or M2.5 behavior

## What M2.5 Proves

M2.5 proves only the first Lab-controlled reality branch when code support is present:

- policy-state transition into controlled reality is auditable
- one configured decoy admin/API branch can return synthetic responses
- bait-derived writes and decoy writes are not forwarded to the protected upstream
- dwell time, action depth, routing, escape attempts, and emergency disable behavior are observable

## What M2.5 Does Not Prove

M2.5 does not yet prove:

- broad controlled-reality coverage
- adaptive bait policy
- autonomous-agent attribution
- public-v1 readiness
- production readiness
- safe deployment outside the owned loopback Lab
