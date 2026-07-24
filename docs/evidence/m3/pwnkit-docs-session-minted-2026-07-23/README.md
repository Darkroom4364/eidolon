# M3 Docs-Class Session-Minted Evidence

Lab-only evidence captured on 2026-07-23 against an owned loopback target.

## Scope

- pwnkit: `0.12.0` at
  `de63d9dfd02d283d98a765df1295aab6422534a0`
- evidence track: `local_patched_pwnkit`
- pinned fixture: `pwnkit-de63d9d`
- profile: `docs_session_minted_probe`
- profile SHA-256:
  `7070b6b8678c7002f5cea9fb1c2ee82532ef47718e8f8f6ff697fb834b857a48`
- bait: `rel_2025_04_b7f2`, class `docs`

## Result

Three distinct runs each recorded one request-linked docs exposure, one
accepted same-session action, zero protected-upstream `RequestSeen` events for
that accepted action, and one controlled-reality entry. Run metadata matched
the private profile snapshot, every summary carried the matching canonical
proxy-event stream digest, and those digests were distinct.

`target_runtime_bait_stability.ready_for_stability_claim` is `true`.
`strict_stability.ready_for_stability_claim` is `false`: pwnkit did not retain
a request artifact that could independently correlate the action and
containment. The result is therefore target-runtime evidence, not strict
scanner-internal attribution.

Direct findings were `0/0/0`; Eidolon findings were `0/2/0`; agent errors were
`0/0/0`.

## Disclosure

`runtime-stability-summary.json` contains an explicit allowlist of claim fields.
Raw proxy logs, full URLs, scanner databases, stdout/stderr, auth files, private
paths, and broad packaged summaries are intentionally omitted while issue
`#228` tracks fail-closed evidence packaging.

This does not establish production readiness, upstream-current pwnkit parity,
general docs-class stability, or stability beyond this profile and pwnkit
head. The profile diversifies the lure class but retains the existing
reconcile action path.
