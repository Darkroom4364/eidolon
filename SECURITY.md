# Security Policy

Eidolon is a defensive active-defense project for owned or authorized web, API, documentation, and developer surfaces.

## Supported Versions

This project is pre-release. Security reports are accepted for the current `main` branch until versioned releases exist.

## Reporting A Vulnerability

Use GitHub private vulnerability reporting for this repository when available.

If private reporting is not available, open a public issue with only a minimal description and request a private disclosure channel. Do not include exploit details, secrets, live target data, or instructions that could enable abuse in a public issue.

Reports should include:

- affected component or document
- impact summary
- safe reproduction steps against local or owned targets
- expected defensive behavior
- any relevant logs with secrets removed

## Defensive Scope

Eidolon accepts reports and contributions that improve defensive evaluation, containment, logging, safety, or reliability.

Do not submit:

- malware
- hack-back techniques
- real exploit chains as bait
- real credentials, customer data, or internal hostnames
- instructions to attack third parties
- code that compromises an attacker's host, tools, files, or accounts

The project may degrade hostile autonomous behavior inside a protected boundary. It must not compromise infrastructure outside that boundary.

For the project safety model, see [docs/safety.md](docs/safety.md) and [docs/threat-model.md](docs/threat-model.md).
