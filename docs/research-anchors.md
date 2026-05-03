# Research Anchors

This file records the systems, papers, and categories that motivated Agentwall.

## Autonomous Pentesting And Vulnerability Research

- Anthropic Project Glasswing / Claude Mythos Preview
- XBOW autonomous pentesting
- pwnkit agentic pentesting framework
- Google Project Naptime / Big Sleep / CodeMender
- DARPA AIxCC cyber reasoning systems
- CyberGym
- EVMbench
- PentestGPT-style scaffolds
- PentAGI / Strix / HexStrike-style agentic security tools

## Agentic Risk And Web-Agent Manipulation

- AgentHarm
- WASP web-agent prompt injection
- OWASP Agentic AI threats and mitigations
- OWASP LLM Top 10
- MCP security benchmark work

## Deception And Canary Baselines

- Thinkst Canarytokens
- OpenCanary
- Tracebit-style canaries
- Acalvio 360 Deception / ShadowPlex
- Cloudflare AI Labyrinth
- DataDome Agent Trust
- Palisade LLM Agent Honeypot
- MITRE Engage / D3FEND
- Kill-Chain Canaries
- agent-aware canary systems such as Canar.ai

## Agent / MCP Firewall Naming Collision

The phrase "agent firewall" and the name "AgentWall" are already used by unrelated projects:

- AgentWall for paywall / AI browser protection
- Agent Wall for MCP/tool-call firewalling
- Agent Wall for coding-agent OS safety
- PipeLab / Pipelock style agent firewalls
- Docker MCP Gateway, ToolHive, agentgateway, Invariant MCP-Scan

Implication:

```text
Do not position Agentwall as a generic agent firewall.
Position it as target-side active defense for autonomous pentesting agents.
```

## Competitive Positioning

Agentwall should not compete head-on as:

- another autonomous pentester
- another WAF
- another enterprise MCP gateway
- another generic honeypot
- another prompt-injection scanner

The intended gap:

```text
target-side active defense against autonomous pentesting agents
through causal bait and trace reconstruction
```

The 2026-05-03 validation tightened this to:

```text
target-side active defense against autonomous pentesting agents
through causal bait, black-box trace reconstruction,
controlled-reality routing, and baseline-measured causal lift
```
