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

## Out Of Scope For Lab V1 Candidate

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
