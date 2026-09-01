# AgentTrace — Medium article (ready to publish)

> Copy everything below the line into a new Medium story. The title is the first
> line; the italic line is the subtitle/kicker. Medium tags are listed at the end
> (Medium allows up to 5 tags per story). Extra hashtags are provided for when you
> cross-post to LinkedIn/X.

---

# When Your AI Agent Gets Breached, Can You Prove What It Did?

*Introducing AgentTrace — an open-source, offline forensic tool for reconstructing
AI-agent security incidents.*

AI agents are no longer demos. LLMs wired to tools, memory, retrieval, and other
agents are running in production — reading data, calling APIs, moving money,
touching customer records. And like everything else that touches production, they
get caught up in security incidents.

But investigating an AI-agent incident is not like traditional digital forensics.
I kept running into the same wall, so I built a tool for it. This is the story of
the problem and what AgentTrace does about it.

## Why AI-agent forensics is genuinely different

Three things break the usual DFIR playbook:

**1. The attack vector is natural language.**
When an attacker plants a malicious instruction in a document an agent will
retrieve, that instruction looks *identical* to a legitimate query in every log
most teams collect. There is no binary payload, no CVE signature, no network
packet that lights up. The exploit is a sentence.

**2. The anomaly is the sequence, not any single event.**
Every individual tool call the agent makes is authorized and looks normal.
"Read a file." "Call an API." "Make an HTTP request." Nothing is wrong on its own.
The attack is the *order* — retrieve poisoned content, then access a secret, then
send data out. You cannot see it unless you have the whole chain.

**3. The evidence is scattered and short-lived.**
The pieces live in six or seven different systems: LLM invocation logs, tool
execution traces, MCP server logs, vector-store retrieval logs, OAuth records,
egress logs. Different teams own each one. Different retention windows delete each
one. And the volume is brutal — one documented 2026 incident produced roughly
17,600 agent actions in five days. The team's own postmortem called reconstructing
it by hand "impractical."

Here's the key insight: the industry has mostly solved *recording* agent activity
(OpenTelemetry's GenAI conventions, MCP logging, tamper-evident audit logs). What
nobody had was an automated way to *reconstruct* what actually happened from that
recorded evidence.

That gap is what AgentTrace fills.

## What AgentTrace does

AgentTrace is the **investigation layer** that sits downstream of the recorders.
Point it at your evidence, and it:

- **Ingests 7 evidence sources** into one normalized schema — so a tool call from
  an OTel span and one from an MCP log become comparable.
- **Verifies integrity and chain of custody** — hash-chain verification, gap and
  witness-anchor detection, HMAC-signed manifests, and a tamper-evident custody
  ledger that records every step of the investigation.
- **Reconstructs the causal attack chain** across all those fragmented logs, as a
  timeline plus a provenance-style causal graph.
- **Detects six attack patterns**, each mapped to a **MITRE ATLAS** technique and
  linked to the exact supporting evidence: prompt injection via retrieval,
  exfiltration via tool chaining, OAuth/credential-theft chains, sub-agent
  hijack, memory poisoning, and tool-permission escalation.
- **Builds kill-chain narratives and a 0–100 risk score.**
- **Produces reports** in JSON, Markdown, and self-contained offline HTML (with an
  SVG causal graph), including an **EU AI Act Article 12** record-keeping coverage
  section.
- **Exports portable, signed case bundles** you can carry to an air-gapped machine
  and re-verify.

## Two design choices I won't compromise on

**No AI/ML in the detection path.** Every finding is deterministic and traces back
to concrete evidence. A forensic tool has to be explainable — a model that says "I
think this is an attack" does not survive a review, an audit, or a courtroom.
Ironically, the best tool for investigating AI incidents uses no AI to reach its
conclusions.

**Local-first, zero dependencies.** It runs fully offline on the Python standard
library alone. No cloud, no account, no API key. That matters when the environment
is air-gapped or the network is exactly what's compromised.

## What it looks like in practice

```bash
pip install agenttrace

# What happened? Any known attack patterns?
agenttrace detect logs/*.json logs/*.jsonl

# Is the evidence trustworthy — altered or missing?
agenttrace verify logs/*.jsonl --signing-key "case-key" \
  --case-number "IR-2026-0042" --case-officer "A. Analyst"

# Produce a report for management / legal / a regulator
agenttrace report logs/*.json logs/*.jsonl --html-out report.html
```

On a synthetic multi-source incident, `detect` surfaces things like:

```
[CRITICAL] exfiltration_via_tool_chaining — 25 calls to 'crm_export' in 48s,
           monotonically increasing offsets  (MITRE ATLAS AML.T0057)
[CRITICAL] oauth_credential_theft_chain    — credential access -> rapid egress
[HIGH]     prompt_injection_via_retrieval  — poisoned chunk -> new sensitive tool
```

Each finding links to the exact events behind it, and the HTML report renders the
whole thing as a causal graph: *poisoned document entered context → agent behavior
shifted → credentials accessed → data left the building.*

## Chain of custody, from acquisition to courtroom

Forensic output is only useful if it holds up. So chain of custody is first-class:
every stage — acquisition, verification, analysis, reporting, export, transfer —
is written to a tamper-evident, hash-chained ledger attributed to a case officer,
with tool version and timestamps. Reports and manifests are cryptographically
bound to the exact evidence they were built from. Alter one record and the chain
breaks visibly.

## Try it, break it, improve it

AgentTrace is Apache-2.0, offline, and dependency-free.

**Repo: https://github.com/piyush295/agenttrace**

I'd genuinely value feedback from anyone doing incident response on agentic
systems — especially on the detection heuristics and which additional evidence
sources are worth supporting next.

One important note: AgentTrace is a **defensive** tool. It analyzes evidence you
are authorized to investigate. It is not an attack, exploitation, or surveillance
tool, and it has no capability to access remote systems or accounts.

If you're deploying AI agents and haven't thought about how you'd investigate one
after an incident — that's exactly the gap worth closing before you need it.

---

## Medium tags (pick up to 5)
`Cybersecurity` · `Artificial Intelligence` · `DFIR` · `Incident Response` · `Open Source`

## Hashtags (for LinkedIn / X cross-post)
#AIsecurity #DFIR #IncidentResponse #LLM #AIagents #MITREATLAS #CyberSecurity
#OpenSource #ThreatIntelligence #ChainOfCustody #Forensics #OpenTelemetry
#PromptInjection #BlueTeam #InfoSec
