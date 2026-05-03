# Landscape Validation - 2026-05-03

## Verdict

Agentwall is not unique at the broad strategy level.

The following areas are already active and crowded:

- cyber deception
- honeypots and canary tokens
- AI bot detection
- WAF / WAAP / bot defense
- MCP and agent firewalls
- autonomous pentesting platforms
- cyber-agent benchmarks and cyber ranges

The differentiated wedge that still survives is narrower:

```text
target-side active defense against autonomous pentesting agents
using causal bait, trace reconstruction, and controlled-reality routing
```

The project should not claim novelty as "active defense" or "deception." Those are established. The claim should be:

```text
agent-aware, target-side, production-adjacent deception and evidence control,
evaluated against modern autonomous pentesting agents rather than humans,
generic malware, or simple crawlers.
```

## Naming Risk

The name `Agentwall` is already crowded.

Observed conflicts:

- [AgentWall](https://agentwall.tech/) for AI browser / paywall protection.
- [Agent Wall](https://agentwall.dev/) for MCP/tool-call firewalling.
- [Agent Wall](https://agent-wall.github.io/agent-wall/) for MCP security.
- `agentwall` packages for coding-agent OS/tool safety.

This does not kill the technical project, but it does mean public naming and positioning need a deliberate decision before a serious launch.

Working internal name can remain Agentwall. Public naming should be revisited.

## Strongest Competitor Classes

### Deception Platforms

Examples:

- [Acalvio 360 Deception / ShadowPlex](https://www.acalvio.com/)
- [CounterCraft](https://www.countercraftsec.com/products/)
- [Fidelis Deception](https://fidelissecurity.com/solutions/deception/)
- [Rapid7 Deception Technology](https://docs.rapid7.com/insightidr/deception-technology/)
- [Thinkst Canarytokens](https://help.canary.tools/hc/en-gb/articles/10905485310109-Canarytoken-Overview-and-Use-Cases)
- [OpenCanary](https://pypi.org/project/opencanary/)

Risk:

They already sell deception, decoys, breadcrumbs, and SOC alerts.

Agentwall must not look like a smaller deception platform.

Differentiation:

- web/API/developer-surface focus
- autonomous pentest-agent behavior focus
- causal trace reconstruction
- session-level controlled-reality routing
- evaluation against agentic scanners, not only human attackers or malware

### AI Bot / Crawler Defense

Examples:

- [Cloudflare AI Labyrinth](https://developers.cloudflare.com/bots/additional-configurations/ai-labyrinth/)
- [Cloudflare Bot Management](https://www.cloudflare.com/products/bot-management/)
- [DataDome Agent Trust](https://datadome.co/products/agent-trust-management/)
- [Akamai Bot Manager](https://www.akamai.com/products/bot-manager)
- [F5 Distributed Cloud Bot Defense](https://www.f5.com/products/distributed-cloud-services/bot-defense-components)

Risk:

They can detect, score, block, challenge, or misroute automated traffic at the edge. Cloudflare AI Labyrinth already uses invisible decoy routes against unauthorized AI crawlers.

Differentiation:

Agentwall should not compete on generic bot detection. It should focus on multi-step pentest-agent reasoning traces:

```text
agent saw decoy docs -> used fake token/header -> called fake API -> continued down decoy state machine
```

### Agent / MCP Firewalls

Examples:

- [PipeLab / Pipelock agent firewall](https://pipelab.org/agent-firewall/)
- [Docker MCP Gateway](https://docs.docker.com/ai/mcp-gateway/)
- [Invariant MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan)
- [Stacklok ToolHive](https://github.com/stacklok/toolhive)
- [agentgateway](https://agentgateway.dev/)
- [Trail of Bits MCP security](https://www.trailofbits.com/mcp/)

Risk:

"Agent firewall" increasingly means protecting the organization that runs agents: egress control, MCP tool governance, prompt-injection filtering, and audit logs.

Differentiation:

Agentwall protects the target being probed by external or unauthorized agents.

```text
agent firewall: protects the agent owner
Agentwall wedge: protects the target from agentic recon and validation loops
```

### AI Agent Canaries / Honeypots

Examples:

- [Canar.ai](https://www.canar.ai/)
- [Palisade LLM Agent Honeypot](https://palisaderesearch.org/blog/llm-honeypot)
- [LLM Agent Honeypot paper](https://huggingface.co/papers/2410.13919)
- [Beelzebub MCP honeypot](https://docs.beelzebub.ai/basics)
- [Kill-Chain Canaries](https://papers.cool/arxiv/2603.28013)

Risk:

Canary tokens and prompt-injection probes are easy to copy. Agent-aware canaries are becoming obvious.

Differentiation:

Agentwall must go beyond "token was touched" into causal chains and controlled routing.

```text
weak: an agent touched a canary
strong: this session consumed bait, synthesized a follow-up action, ignored or handled contradictions, and was diverted
```

### Autonomous Pentesting Platforms

Examples:

- [XBOW](https://xbow.com/)
- [pwnkit](https://docs.pwnkit.com/)
- [Revaizor](https://revaizor.com/)
- [ADCL](https://adcl.io/)
- [Prancer SwarmHack](https://www.prancer.io/)
- [Xalgorix](https://www.xalgorix.com/)
- [PentestGPT](https://github.com/greydgl/pentestgpt)

Risk:

They define the threat model and may eventually add deception-resistance features.

Differentiation:

Agentwall should use these tools as evaluation subjects and publish evidence that its baits change their behavior under authorized lab conditions.

## Academic Signals

Relevant findings:

- [LLM Agents can Autonomously Hack Websites](https://arxiv.org/abs/2402.06664) supports the web/API-first threat model.
- [LLM Agents can Autonomously Exploit One-day Vulnerabilities](https://arxiv.org/abs/2404.08144) shows that vulnerability descriptions and target-provided evidence materially change agent success.
- [Teams of LLM Agents can Exploit Zero-Day Vulnerabilities](https://arxiv.org/abs/2406.01637) suggests multi-agent planning and delegation will matter.
- [Cybench](https://arxiv.org/abs/2408.08926), [CyberGym](https://www.cybergym.io/), [CVE-Bench](https://arxiv.org/abs/2503.17332), and [BountyBench](https://arxiv.org/abs/2505.15216) show cyber-agent evaluation is maturing.
- [Kill-Chain Canaries](https://papers.cool/arxiv/2603.28013) supports stage-level canary tracking rather than binary success/failure.
- [DOLOS](https://iris.unimore.it/handle/11380/1372380), [MITRE Engage](https://www.mitre.org/news-insights/impact-story/mitre-engage-framework-and-community-cyber-deception), and [NIST SP 800-160 Vol. 2 Rev. 1](https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final) show deception and attacker work-factor increase are legitimate but not novel.

Implication:

The roadmap must include a rigorous uniqueness bakeoff. Without metrics, Agentwall will be dismissed as another honeypot.

## Forum And Practitioner Signals

Hacker News and Reddit signal was skeptical but useful.

Recurring objections:

- autonomous pentesting is often seen as fancy vulnerability scanning
- false positives and review burden matter more than flashy demos
- business logic and long attack chains remain hard
- bot/crawler defenses create false positives and accessibility/SEO concerns
- proxy defenses get dismissed if bypasses are not openly acknowledged
- deception/tarpits are accepted only if production-safe and measurable

Implication:

Agentwall should lead with boring evidence:

- false-positive rate
- verified crawler/agent separation
- no SEO/accessibility regression
- time wasted per hostile session
- canary activation rate
- replayable bait-to-action traces
- baseline comparison against static honeypots/canary tokens

## Updated Positioning

Avoid:

```text
AI firewall
AI honeypot
AI pentester blocker
agent firewall
we defeat AI pentesters
Blackwall for everything
```

Prefer:

```text
target-side active defense for autonomous pentesting agents
agent-aware deception and trace reconstruction for web/API targets
controlled reality for AI-driven reconnaissance and exploit validation
```

## Updated Build Strategy

Old risk:

```text
build proxy -> build bait -> build reports -> later validate uniqueness
```

This is backwards.

New strategy:

```text
build evaluation harness early
compare against baselines
measure causal lift
only then harden Shield
```

The fastest uniqueness test:

```text
one proxy
one owned lab target
five correlated bait primitives
one controlled-reality branch
three agent runners / scanner baselines
one metrics table
```

## Go / No-Go Criteria

Continue if Agentwall can show:

- bait-derived action rate is meaningfully higher for agentic scanners than benign crawlers
- false positives remain low under browser, crawler, and baseline DAST traffic
- controlled reality reduces requests to real sensitive surfaces after confidence rises
- causal evidence reports are clearer than raw honeypot alerts
- at least one autonomous agent follows a multi-step bait chain in an owned lab

Kill or reframe if:

- results are indistinguishable from static canary tokens
- benign crawlers trigger the same chains
- agentic scanners ignore all bait without loss of effectiveness
- controlled reality creates unacceptable production safety or SEO/accessibility issues
- reports cannot prove anything stronger than "someone touched a fake route"

