# Cloudflare AI Labyrinth vs Eidolon

## Why This Doc Exists

The central objection is valid:

> If Eidolon only serves fake links to automated clients, it is just Cloudflare AI Labyrinth again.

That would not be worth building.

This document defines the line Eidolon must not cross back over.

## Cloudflare AI Labyrinth

Cloudflare AI Labyrinth is aimed mainly at unwanted AI crawlers and scrapers.

The actor model is:

```text
fetch page -> follow links -> index content -> repeat
```

The defensive pattern is:

```text
detect unwanted crawler
serve invisible or irrelevant decoy links
route crawler into a maze
record behavior
protect real content
```

That is useful, but it is primarily a crawler trap.

## Eidolon

Eidolon is aimed at autonomous pentesting agents.

The actor model is:

```text
read target evidence
infer possible vulnerability
choose tool/API/browser action
send crafted request
interpret response
chain next step
possibly report finding
```

The defensive pattern is:

```text
serve controlled semantic evidence
observe whether the agent synthesizes a bait-derived action
build a causal trace
route high-confidence sessions into controlled app/API reality
measure outcome against baselines
```

## The Core Difference

AI Labyrinth asks:

```text
Will this bot follow fake paths?
```

Eidolon asks:

```text
Will this agent turn controlled target evidence into a pentest action?
```

That distinction is the project.

## Example Difference

Crawler maze:

```text
Page contains hidden link:
  /maze/a7f3

Crawler later requests:
  /maze/a7f3
```

Evidence:

```text
the crawler followed a link
```

Eidolon causal bait:

```text
Docs contain:
  "Legacy reconciliation accepts X-Migration-Trace: rel_2025_04_b7f2"
  "POST /api/v2/import/reconcile with mode=compat"

Agent later sends:
  POST /api/v2/import/reconcile
  X-Migration-Trace: rel_2025_04_b7f2
  {"mode":"compat","dry_run":false}
```

Evidence:

```text
the actor consumed semantic target evidence,
synthesized a tool/API action from it,
and executed a vulnerability-hypothesis test
```

That is not link crawling. That is agentic pentesting behavior.

## Controlled Reality Difference

AI Labyrinth's controlled world is mostly a maze.

Eidolon's controlled world should be an app/API state machine:

```text
fake admin route
fake import job
fake token
fake status endpoint
fake audit log
fake error condition
fake secondary clue
```

The goal is to measure:

- how deep the agent pursues a false attack chain
- whether it verifies
- whether it notices contradictions
- whether it reports a false finding in lab mode
- whether real target requests decrease after containment
- whether benign crawlers avoid the same chain

If Eidolon does not measure these things, it is not differentiated.

## Evaluation Difference

AI Labyrinth is judged mostly against crawlers and unauthorized AI scrapers.

Eidolon must be judged against:

- benign browser traffic
- simple crawlers
- baseline DAST scanners
- pwnkit-style agentic scanners
- PentestGPT-style agents
- authorized local browser/shell agents

Eidolon must compare against:

- no defense
- static canary token
- static honeypot
- WAF-style block
- crawler maze / link trap where feasible

## Kill Rule

If the demo is:

```text
agent follows fake link
```

stop and reframe. That is not enough.

If the demo is:

```text
agent reads controlled docs/specs,
synthesizes a fake header/API/body action,
executes it,
gets correlated,
and is routed into a controlled app/API branch
```

continue.

## Non-Negotiable Differentiator

Eidolon must remain centered on:

```text
semantic bait -> synthesized action -> causal trace -> controlled reality
```

Not:

```text
fake link -> crawler follows link -> alert
```

