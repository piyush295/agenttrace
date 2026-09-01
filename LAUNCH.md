# Reconstructing AI-agent security incidents: introducing AgentTrace

*A local-first, open-source DFIR tool for investigating what an AI agent
actually did during a security incident.*

## The problem

AI agents — LLMs wired to tools, memory, retrieval, and other agents — are now
doing real work in production. And they are increasingly involved in security
incidents: a poisoned document steers an agent into calling a tool it never
should have; a compromised credential gets used through a legitimate-looking
tool call; an agent pages a customer database out through an "analytics" endpoint
one row at a time.

Investigating these incidents is genuinely different from traditional DFIR:

- **The attack vector is natural language.** A malicious instruction looks
  identical to a legitimate one in almost every log a company collects. There is
  no binary payload, no CVE signature, no packet that flags the injection.
- **The anomaly is the *sequence*, not any single event.** Each individual tool
  call is authorized and looks normal. The causal chain is the evidence.
- **Evidence is fragmented** across 6–7 systems: LLM invocation logs, tool
  traces, MCP server logs, vector-store retrieval logs, OAuth records, egress
  logs — each owned by a different team, each with a different retention window.
- **Volume defeats manual review.** A documented 2026 incident produced roughly
  17,600 agent actions over five days; the operator's own postmortem called
  reconstructing it by hand "impractical."

The ecosystem has largely solved *recording* (OpenTelemetry GenAI, tamper-evident
audit logs, MCP logging). What is still missing is *reconstruction*: taking that
already-recorded evidence and automatically rebuilding what happened.

## What AgentTrace does

[AgentTrace](https://github.com/piyush295/agenttrace) is the **investigation
layer** that sits downstream of the recorders. It:

1. **Ingests 7 evidence sources** into one normalized schema.
2. **Verifies integrity and chain of custody** — hash chains, gap/witness
   detection, HMAC-signed manifests, and a tamper-evident custody ledger.
3. **Reconstructs the causal attack chain** across fragmented logs (a timeline
   plus a provenance-style causal graph).
4. **Detects 6 attack patterns** — prompt injection via retrieval, exfiltration
   via tool chaining, OAuth/credential theft, sub-agent hijack, memory poisoning,
   tool-permission escalation — each mapped to **MITRE ATLAS** and linked to the
   exact supporting evidence.
5. **Builds kill-chain narratives and risk scores.**
6. **Produces reports** in JSON, Markdown, and self-contained offline HTML (with
   an SVG causal graph), including an **EU AI Act Article 12** coverage section.
7. **Exports portable, signed case bundles** for air-gapped transfer.

Two deliberate design choices:

- **No AI/ML in the detection path.** Every finding is deterministic and traces
  back to concrete evidence. A forensic tool has to be explainable; a model that
  says "I think this is an attack" does not hold up in a review or a courtroom.
- **Local-first, zero dependencies.** It runs fully offline on the standard
  library alone — suitable for air-gapped forensic environments.

## A quick walk-through

```bash
pip install -e .

# 1. What happened? Any known attack patterns?
agenttrace detect logs/*.json logs/*.jsonl

# 2. Is the evidence trustworthy — was anything altered or missing?
agenttrace verify logs/*.jsonl --signing-key "case-key" \
  --case-number "IR-2026-0042" --case-officer "A. Analyst"

# 3. Produce a report for management / legal / a regulator
agenttrace report logs/*.json logs/*.jsonl \
  --html-out report.html --json-out report.json
```

On a synthetic multi-source incident, `detect` surfaces, for example:

```
[CRITICAL] exfiltration_via_tool_chaining — 25 calls to 'crm_export' in 48s,
           monotonically increasing offsets  (MITRE ATLAS AML.T0057)
[CRITICAL] oauth_credential_theft_chain    — credential access → rapid egress
[HIGH]     prompt_injection_via_retrieval  — poisoned chunk → new sensitive tool
```

Each finding links to the exact events behind it, and the HTML report renders the
whole story as a causal graph: *poisoned document entered context → agent
behavior shifted → credentials accessed → data left the building.*

## Chain of custody, everywhere

Because forensic output is only useful if it holds up, chain of custody is
first-class. Every stage — acquisition, verification, analysis, reporting,
export, transfer — is recorded in a tamper-evident, hash-chained custody ledger
attributed to a case officer, with tool version and timestamps. Reports and
manifests are cryptographically bound to the exact evidence they were built from.

## Try it / contribute

- Repo: **https://github.com/piyush295/agenttrace**
- It's Apache-2.0, offline, and dependency-free.
- Feedback, issues, and new collectors/detectors are welcome (see CONTRIBUTING).

**Authorized, defensive use only.** AgentTrace analyzes evidence you are
authorized to investigate; it is not an attack or surveillance tool.
