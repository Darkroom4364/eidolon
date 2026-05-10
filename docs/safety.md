# Safety And Ethics

Eidolon is defensive active defense.

The project can intentionally degrade hostile autonomous attack loops, but only by controlling surfaces inside the protected boundary.

## Safe Active Defense

Acceptable:

- serving synthetic bait
- serving synthetic controlled-reality data
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

## Synthetic Data And No-Write Boundary

M2.5 controlled reality is Lab-only and must use synthetic data.

Controlled-reality content must be safe if copied, indexed, logged, or disclosed. It must not contain real secrets, customer data, real internal hostnames, real credentials, real bypasses, or exploit recipes that improve third-party capability.

Controlled-reality paths may record defensive events and disposable Lab state. They must not forward bait-derived writes to the protected upstream, mutate real target state, trigger external callbacks, or depend on production services.

Any emergency disable must return the system to ordinary forwarding or fail-closed Lab behavior according to the local runbook. It must not silently continue controlled-reality intervention.

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
