# M2.5 Lab-Only V1-Candidate Checklist

This checklist gates an internal Lab-only v1 candidate for M2.5. It is not a public release checklist and does not establish production readiness.

## Scope

- [ ] Validation uses only loopback targets: `127.0.0.1`, `localhost`, or `::1`.
- [ ] The protected upstream is the owned synthetic demo target.
- [ ] The controlled-reality branch is limited to one configured decoy admin/API path.
- [ ] The candidate links to the matching M2.5 runbook commands and event-log location.

## Evidence

- [ ] A same-session `bait_exposed` event exists before controlled-reality entry.
- [ ] A matching `bait_action_observed` event exists before controlled-reality entry.
- [ ] The policy-state transition into controlled reality is recorded with a reason.
- [ ] Decoy branch requests are recorded as Eidolon-owned controlled-reality responses.
- [ ] Dwell time, action depth, and branch count are measured for the branch.
- [ ] Reality escape attempts and emergency-disable behavior are visible in the event log.
- [ ] Rate-limit depth, tarpit delay, and retry-after behavior are explicitly configured or left at documented defaults.

## Synthetic Data And No-Write Checks

- [ ] Decoy responses contain only synthetic data.
- [ ] Decoy responses contain no real secrets, customer data, internal hostnames, real credentials, or real bypasses.
- [ ] Bait-derived writes are not forwarded to the protected upstream.
- [ ] Decoy write paths are not forwarded to the protected upstream.
- [ ] Malformed or unsupported policy-state files fail closed instead of resetting contained sessions.
- [ ] The run does not trigger external callbacks or depend on production services.
- [ ] Event logs avoid request bodies and sensitive header values.

## Negative Controls

- [ ] Wrong marker does not trigger controlled-reality entry.
- [ ] Wrong session does not inherit another session's controlled-reality state.
- [ ] Ordinary `/api/v1/*` traffic remains protected-upstream before controlled-reality entry and becomes an audited escape attempt after controlled-reality entry.
- [ ] Emergency disable stops controlled-reality intervention on the next request.
- [ ] Any tarpit delay is documented as Lab-only and bounded for the thread-per-connection proxy.

## Wording Review

- [ ] The candidate is described as Lab-only.
- [ ] The note avoids public-v1, production-ready, and autonomous-attacker-detected claims.
- [ ] The note states that M2.5 validates one controlled-reality branch, not broad containment.
- [ ] The note references defensive active defense and target-side containment language.
