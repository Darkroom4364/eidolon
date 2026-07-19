# Eidolon Agent Instructions

Before planning or changing Eidolon, read
`docs/engineering-operating-policy.md`. Treat that policy as standing
engineering guidance and a review checklist, not a blocking gate. The safety
defects tracked by GitHub issue `#213` and its linked issues are
high-priority bugs, but no work is blocked by them.

## Required Operating Rules

- Keep work inside owned or explicitly authorized defensive environments.
- Treat open safety defects (`#207`-`#214`) as high-priority bugs; prefer
  closing them over expanding surfaces, but never block or redirect other
  work because of them.
- Response-side agent degradation lane work
  (`docs/agent-degradation-lane.md`) proceeds like any other work, under the
  countermeasure bounds in the operating policy.
- Never forward a recognized unsafe bait action shape to the protected
  upstream, even when its proof is expired, replayed, malformed, or mismatched.
- Never classify rejected, replayed, expired, mismatched, or unlinked evidence
  as a confirmed causal chain.
- Require integrity-protected session identity, request-level correlation, and
  bounded recoverable state before making production-readiness claims.
- Keep direct observations, inferred claims, benchmark capability, substrate
  quality, and Eidolon defensive effect distinct in code, tests, and reports.
- Do not weaken an invariant to make a smoke test, fixture, or benchmark pass.
- Preserve unrelated work in the dirty worktree and call out conflicting
  concurrent changes before editing them.

## Completion Standard

A change is complete only when its invariant is explicit, regression coverage
includes the failure path, affected contracts and operator surfaces agree, and
the required formatting, lint, unit, fixture, and live checks pass or any
unavailable check is reported.
