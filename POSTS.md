# Ready-to-post launch copy

Paste these where relevant. Keep it factual and non-hyperbolic — security
communities dislike marketing spin. Only post to communities whose rules allow
"Show"/self-promotion (check each subreddit's rules first).

---

## Hacker News (Show HN)

**Title:**
Show HN: AgentTrace – open-source forensic reconstruction for AI-agent incidents

**Body:**
I built AgentTrace, a local-first DFIR tool for investigating security incidents
involving AI agents / LLM apps.

The gap it addresses: recording agent activity is fairly solved (OpenTelemetry
GenAI, MCP logging, tamper-evident audit logs), but *reconstructing* what actually
happened across 6–7 fragmented log sources is not. In agent incidents the attack
vector is natural language and the anomaly is the *sequence*, not any single
event — so you need the whole chain stitched back together.

AgentTrace ingests 7 evidence sources into one schema, verifies integrity + chain
of custody, reconstructs the causal attack chain, detects 6 attack patterns
(mapped to MITRE ATLAS, each linked to exact evidence), and produces JSON/Markdown/
offline-HTML reports with an EU AI Act Article 12 coverage section.

Deliberate choices: no AI/ML in the detection path (everything is deterministic
and explainable), zero runtime dependencies, runs fully offline.

Repo (Apache-2.0): https://github.com/piyush295/agenttrace

Feedback welcome — especially from folks doing IR on agentic systems.

---

## Reddit (r/netsec, r/blueteam, r/digitalforensics — check rules first)

**Title:**
AgentTrace: open-source forensic reconstruction for AI-agent security incidents

**Body:**
Sharing a tool I've been building for AI-agent / LLM incident response.

Investigating agent incidents is different from traditional DFIR: the attack
vector is natural language (a malicious prompt looks like a legit one), the
anomaly is the sequence rather than a single event, and evidence is scattered
across LLM logs, tool traces, MCP servers, vector-store retrieval logs, OAuth
records, and egress logs.

AgentTrace ingests those sources, verifies integrity + chain of custody,
reconstructs the causal attack chain, and detects patterns like prompt injection
via retrieval, exfiltration via tool chaining, and credential-theft chains — all
mapped to MITRE ATLAS, each finding linked to the exact evidence. Deterministic
(no ML in the detection path), offline, zero dependencies.

Repo: https://github.com/piyush295/agenttrace

Would love feedback on the detection heuristics and additional evidence sources
worth supporting.

---

## LinkedIn / X

Just open-sourced **AgentTrace** — a local-first DFIR tool for investigating
security incidents involving AI agents.

Recording agent activity is largely solved. *Reconstructing* what happened across
fragmented LLM/tool/MCP/OAuth/egress logs isn't. AgentTrace stitches the causal
attack chain back together, verifies chain of custody, detects attack patterns
(mapped to MITRE ATLAS), and generates court/regulator-ready reports — fully
offline, no ML in the detection path, Apache-2.0.

https://github.com/piyush295/agenttrace

#DFIR #AIsecurity #IncidentResponse #LLM #MITREATLAS
