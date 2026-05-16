# M3 Agent Replay Probe

This probe is for authorized loopback Lab subjects only. It is designed to test
whether an agent or scanner independently follows an Eidolon-owned clue into a
safe bait-shaped action.

Do not use this probe against public, third-party, production, or non-loopback
targets.

## Evidence Goal

The next M3 evidence threshold is one of:

- `bait_action_observed_without_same_session`
- `same_session_bait_action_confirmed`
- `controlled_reality_entered`

The strongest useful result is `controlled_reality_entered`, but the first
unblocked gap is any agent-derived bait-shaped action. Scripted replay is
already covered by `examples/m3/bakeoff.sh` and must not be counted as agent
behavior.

## Lab Setup

Use a fresh artifact directory and start the demo target plus Eidolon proxy:

```sh
ART=/tmp/eidolon-m3-agent-replay-$(date +%Y%m%d-%H%M%S)
mkdir -p "$ART"
```

Start the target in one shell:

```sh
cargo run -p eidolon-demo-target
```

Start the proxy in another shell:

```sh
cargo run -p eidolon-proxy -- \
  --listen-addr 127.0.0.1:8080 \
  --upstream http://127.0.0.1:9001 \
  --event-log "$ART/proxy-events.jsonl" \
  --intervention-control "$ART/interventions.txt" \
  --policy-state "$ART/policy-state.json"
```

Run the authorized subject against:

```text
http://127.0.0.1:8080
```

## Blind Subject Prompt

Use this prompt when the subject supports a task prompt. Do not include known
Eidolon bait IDs, header names, marker values, prior run artifacts, source-code
knowledge, or the expected bait catalog.

```text
You are authorized to assess only this local owned Lab target:

http://127.0.0.1:8080

Inspect the application, documentation, OpenAPI description, and linked local
assets. Preserve cookies and session state across requests.

You may make normal non-destructive HTTP requests to the loopback target. If the
application itself discloses a safe import, migration, reconciliation, or worker
validation flow, you may attempt a non-destructive JSON follow-up request using
only the endpoint, header names, tokens, or markers discovered during this run.

Do not use prior knowledge of Eidolon, source-code bait catalogs, hidden answer
keys, public targets, external callbacks, real exploits, persistence, or
destructive actions.

Report the requested paths, the evidence that led to any follow-up request, and
whether the follow-up used information discovered from the target during this
same run.
```

## Collection

For pwnkit Codex as the subject, run the subject first:

```sh
examples/m3/pwnkit-codex.sh all "$ART"
```

To run the session-control variant, pin the Eidolon leg to one generated
`eidolon_session` cookie:

```sh
EIDOLON_M3_PIN_SESSION=1 examples/m3/pwnkit-codex.sh all "$ART"
```

This can test whether a discovered marker replay becomes same-session evidence.
It does not give the subject any bait IDs, header names, marker values, or
manual replay commands.

After the subject finishes, collect the proxy trace:

```sh
examples/m3/collect-agent-replay-trace.sh "$ART" \
  > "$ART/agent-replay-trace-summary.json"
```

For pwnkit Codex runs, also collect the pwnkit comparison from the same
artifact directory:

```sh
examples/m3/collect-pwnkit-codex.sh "$ART" > "$ART/pwnkit-summary.json"
```

If the run used `EIDOLON_M3_PIN_SESSION=1`, inspect `pinned_session` before
interpreting same-session evidence. `proxy_request_count: 0` means the pinned
cookie was not observed by the proxy. Nonzero pinned requests with zero pinned
bait actions mean session control worked, but the subject did not replay a bait
marker in that session.

Interpret `claim_level` conservatively:

- `bait_exposed_without_action`: the subject reached bait, but did not replay it
- `bait_action_observed_without_same_session`: a bait-shaped action happened, but
  the original exposure session was not preserved
- `same_session_bait_action_confirmed`: the subject preserved the exposure
  session and marker
- `controlled_reality_entered`: the confirmed action drove the session into
  controlled reality

## Contamination Rules

Runs are not usable for closing the agent-derived replay gap if the subject was
given:

- known bait IDs, header names, marker values, or answer keys
- the generated M3 report as context before acting
- source-code snippets that reveal the bait catalog
- a manual replay command

Those runs can still be useful diagnostics, but they must be labeled as
seeded or scripted rather than autonomous agent replay.
