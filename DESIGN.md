# AgentTrace — Design & Architecture

> The forensic reconstruction layer for AI agent security incidents.

## 1. Problem statement

AI agents (LLM + tools + orchestration) are now involved in a large share of
enterprise security incidents. Investigating these incidents is fundamentally
different from traditional DFIR:

- **The attack vector is natural language.** A malicious prompt is syntactically
  identical to a legitimate one in every log most systems collect. There is no
  binary payload, no CVE signature, no packet that flags the injection.
- **The anomaly is the *sequence*, not any single event.** Each individual tool
  call is authorized and looks normal. The causal chain is the evidence.
- **Evidence is fragmented across 6–7 systems** (LLM invocation logs, tool
  execution traces, MCP server logs, vector-store retrieval logs, orchestration
  traces, OAuth/token records, egress logs), each owned by a different team,
  each with a different retention window.
- **Volume defeats manual review.** A single documented 2026 incident produced
  ~17,600 agent actions over 5 days; the operator's own postmortem called manual
  reconstruction "impractical."

## 2. Market gap (why this tool, and what it is NOT)

The 2026 ecosystem has largely **solved recording**:

- Observability: Langfuse, Opik, MLflow, AgentOps, OpenLIT (debugging, not forensics).
- Tamper-evident recorders: **Halo-record** (hash-chained append-only logs),
  Gryph, AgentLens, ProvenRail, Semantica.
- Standard schema: **OpenTelemetry GenAI semantic conventions** (`gen_ai.*`).

What is **still missing** is *post-incident investigation*: taking already-recorded
(and ideally tamper-evident) evidence and **automatically reconstructing the causal
attack chain**, detecting known attack patterns, and producing a
regulator/court-ready report.

**AgentTrace is a forensic *reconstructor*, not a *recorder*.** It sits downstream
of recorders like Halo-record and OTel. It is their complement, not their competitor.

### Explicit non-goals
- Not a runtime recorder/instrumentation library.
- Not a live monitoring/alerting product.
- **Not an attack, exploitation, surveillance, or covert-monitoring tool.**
- No capability to access systems, accounts, or data the operator is not
  authorized to investigate.

### Authorized-use principle
AgentTrace operates only on evidence the operator is legally authorized to
investigate (their own agent deployments, or incidents they are engaged to
investigate with proper authority). It is a defensive DFIR tool.

## 3. Design principles

1. **Local-first.** Runs fully offline. No evidence leaves the machine. No cloud,
   no account, no API key required to verify or reconstruct.
2. **Standards-aligned.** Ingests OpenTelemetry GenAI spans and the open
   Halo-record format directly; maps everything to one normalized schema.
3. **Evidence integrity is first-class.** Every artifact hashed; chain-of-custody
   metadata recorded; hash-chains verified; missing-record indicators surfaced.
   We distinguish "nothing was edited" from "nothing is missing."
4. **Explainable, not black-box.** Every detected finding links back to the exact
   underlying evidence events. No unexplained ML verdicts.
5. **Pluggable.** New evidence sources are added as collector plugins implementing
   one interface.

## 4. High-level architecture

```
                    ┌──────────────────────────────────────────────┐
   raw evidence     │                 AgentTrace                    │
  (many formats)    │                                               │
  ───────────────►  │  1. INGEST      pluggable collectors ────┐    │
  OTel GenAI spans  │                                          │    │
  Halo-record chain │  2. NORMALIZE   → Unified Forensic Event ◄┘    │
  MCP server logs   │                    (UFE) store                │
  vector store logs │                                               │
  OAuth records     │  3. VERIFY      integrity + chain-of-custody  │
  egress logs       │                                               │
                    │  4. CORRELATE   causal-chain reconstruction   │
                    │                    → timeline + causal graph  │
                    │                                               │
                    │  5. DETECT      attack-pattern detectors      │
                    │                    → IOCs w/ evidence links   │
                    │                                               │
                    │  6. REPORT      JSON + Markdown/HTML          │
                    │                    + EU AI Act Art.12 section │
                    └──────────────────────────────────────────────┘
```

### Pipeline stages
1. **Ingest** — collectors read source-native formats.
2. **Normalize** — map to Unified Forensic Event (UFE) records.
3. **Verify** — hash artifacts, verify Halo-record chains, detect gaps, sign a
   manifest, capture chain-of-custody.
4. **Correlate** — build an ordered timeline and a causal graph linking
   cause → effect across systems (e.g. retrieved chunk → context → tool call → egress).
5. **Detect** — heuristic detectors for known 2026 attack patterns, each emitting
   IOCs with links to supporting UFE events.
6. **Report** — structured JSON + human-readable report, incl. chain-of-custody
   attestation and an EU AI Act Article 12 coverage/readiness section.

## 5. Module layout (Python package)

```
agenttrace/
  __init__.py
  model.py            # UFE schema, EvidenceBundle, enums (Task 2)
  collectors/
    __init__.py       # Collector base class + registry (Task 3)
    otel_genai.py     # OpenTelemetry GenAI spans
    halo_record.py    # Halo-record hash-chain
    jsonl_llm.py      # generic JSONL LLM invocation logs
    mcp.py            # MCP server logs
    vector_store.py   # RAG retrieval logs
    oauth.py          # OAuth grant/token records
    egress.py         # egress network logs
  integrity.py        # hashing, hash-chain verify, gap detection, manifest (Task 4)
  correlate.py        # timeline + causal graph (Task 5)
  detect.py           # attack-pattern detectors (Task 6)
  report.py           # JSON + Markdown/HTML reporting (Task 7)
  cli.py              # command-line interface (Task 9)
tests/                # unit + integration + synthetic datasets (Task 8)
```

## 6. Standards & references informing the design
- OpenTelemetry GenAI semantic conventions (`gen_ai.*` span attributes).
- Halo-record open hash-chained audit format (integrity model + its stated limits).
- W3C PROV-O concepts for provenance (used/generated/wasDerivedFrom) inspiring the causal graph edges.
- EU AI Act Article 12 (record-keeping) for the report's compliance-coverage section.
- OWASP GenAI Incident Response guidance & documented 2026 attack patterns
  (prompt injection via retrieved content; exfiltration via tool-call chaining;
  OAuth/credential theft chains) for the detection layer.

## 7. Incremental roadmap
- **Phase 1 (MVP):** model + collector framework + OTel/Halo/JSONL collectors +
  integrity/chain-of-custody verify + basic timeline + JSON/Markdown report.
- **Phase 2:** full causal-graph correlation + the 3 attack-pattern detectors.
- **Phase 3:** MCP / vector-store / OAuth / egress collectors + Article 12 coverage
  report + HTML output.

Each phase is independently testable against synthetic datasets (Task 8); no live
or third-party system is ever required.
