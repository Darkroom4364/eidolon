# Safety And Ethics

Agentwall is defensive active defense.

The project can intentionally degrade hostile autonomous attack loops, but only by controlling surfaces inside the protected boundary.

## Safe Active Defense

Acceptable:

- serving synthetic bait
- serving decoy endpoints
- using canary values
- rate-limiting suspicious sessions
- routing suspicious sessions into a sandbox
- producing trace reports
- evaluating authorized agents in a lab

Not acceptable:

- hack-back
- malware
- compromising the attacker's host
- stealing attacker secrets
- corrupting the attacker's tools
- causing third-party harm
- publishing real exploit chains as bait

## Why The Topic May Trigger Cybersecurity Review

This project discusses terms that overlap with offensive cybersecurity:

- autonomous pentesting
- exploit chains
- reconnaissance
- malicious agents
- pwnkit/XBOW-style systems
- sabotage
- attacker learning resistance

The project intent is defensive, but automated classifiers may flag the topic because the same vocabulary appears in offensive contexts.

## Preferred Wording

Use:

```text
counter-agentic active defense
controlled degradation of autonomous attack loops
target-side containment
causal bait
controlled reality
```

Avoid overusing:

```text
poison
neuter
exploit the model
disable the attacker
AI attack weapon
```

The technical work should stay within the defensive boundary.

