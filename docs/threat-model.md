# Threat Model

## In Scope

Agentwall is designed for:

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

## Out Of Scope For V1

- nation-state operators with strong OPSEC
- malware delivery
- hack-back
- endpoint compromise
- stealing attacker secrets
- corrupting attacker infrastructure
- production deception involving real secrets
- internal enterprise agent governance
- generic MCP gateway enforcement

## Defensive Boundary

Agentwall may degrade hostile behavior inside the protected boundary.

Agentwall may not compromise infrastructure outside the protected boundary.

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

## Claim Boundaries

Do not claim:

```text
AI attacker detected
```

Prefer:

```text
High-confidence bait-derived autonomous recon/action chain observed
```

Agentwall detects behavior, not ontology. It does not need to prove the actor is an LLM.

