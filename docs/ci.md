# CI/CD Checks

Eidolon uses GitHub Actions for repository-local tests and a Foxguard GitHub App
check for external security review.

## Required Checks

Protect `main` with these required checks:

- `Rust`
- `M3 fixtures`
- `Foxguard`

The `Foxguard` workflow job does not run a scanner itself. It waits for a check
run posted by the Foxguard GitHub App on the pull request head commit, falling
back to the workflow commit SHA for push events. This keeps the GitHub App as
the source of truth while making the integration visible and requireable as a
normal Actions check.

## Foxguard App Contract

The default app slug is `foxguard`. If the installed app uses a different slug
or check name, set repository variables in GitHub settings:

- `FOXGUARD_APP_SLUG`
- `FOXGUARD_CHECK_NAME`
- `FOXGUARD_ACCEPTABLE_CONCLUSIONS`
- `FOXGUARD_MAX_WAIT_SECONDS`
- `FOXGUARD_POLL_SECONDS`

By default, the gate accepts only `success` conclusions. If Foxguard uses
additional non-blocking conclusions for clean scans, set
`FOXGUARD_ACCEPTABLE_CONCLUSIONS` to a comma-separated list in the workflow.

Do not store Foxguard private keys or installation tokens in this repository.
The gate reads public repository check runs through the workflow `GITHUB_TOKEN`;
the GitHub App owns scanning, policy, and result publication.

## Repository Settings

After Foxguard is installed and posts its first check, enable the `main`
ruleset or branch protection and require the checks above. A missing Foxguard
App check should block the `Foxguard` job rather than silently passing.
