# Contributing to Eidolon

Eidolon accepts defensive research and engineering contributions for owned or
explicitly authorized environments.

Before changing runtime or policy behavior, read
[docs/engineering-operating-policy.md](docs/engineering-operating-policy.md).
The core rules are:

- never forward a recognized unsafe bait action to the protected upstream
- never classify rejected or unlinked evidence as a confirmed causal chain
- keep observed facts separate from inferred claims
- do not include real secrets, exploit payloads, personal data, or third-party
  target data
- keep benchmark capability separate from Eidolon defensive effect

## Workflow

1. Open or reference a focused issue.
2. Branch from current `main`.
3. Keep the change and its tests in one reviewable slice.
4. State the invariant, failure behavior, and affected contracts in the pull
   request.
5. Report any check that could not run and the resulting residual risk.

## Local Checks

Run the checks that apply to your change:

```sh
cargo fmt --check
cargo build --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
git ls-files -z -- '*.sh' | xargs -0 -n1 bash -n
```

Shell and deployment changes should also run their adjacent `test-*.sh`
fixtures. Security-relevant changes need a regression test for the failure
path, not only a happy-path test.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
