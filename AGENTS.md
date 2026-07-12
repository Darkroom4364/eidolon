# Eidolon Agent Instructions

Before planning or changing Eidolon, read
`docs/engineering-operating-policy.md`. Treat that policy as the default work
order and review standard for every coding session. The active gate is tracked
by GitHub issue `#213`; automated repository enforcement remains tracked by
`#214`.

## Required Operating Rules

- Keep work inside owned or explicitly authorized defensive environments.
- Fix open safety-gate defects before adding policy states, trust variants,
  telemetry, benchmark breadth, export sealing, or execution substrates.
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
