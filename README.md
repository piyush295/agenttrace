# AgentTrace

**AI agent forensics & incident response — reconstruct, verify, and report on LLM/agent security incidents.**

Local-first · standards-aligned · zero runtime dependencies · defensive DFIR.

AgentTrace is an open-source **digital forensics and incident response (DFIR)**
tool for **AI agents and LLM applications**. It ingests *already-recorded* evidence
(OpenTelemetry GenAI spans, MCP server logs, vector-store retrieval logs, OAuth
records, egress logs, Halo-record hash-chains), verifies its **integrity and chain
of custody**, **reconstructs the causal attack chain**, detects known attack
patterns mapped to **MITRE ATLAS**, and produces a **regulator/court-ready report**
aligned with **EU AI Act Article 12**.

> Keywords: AI agent forensics · LLM incident response · prompt-injection
> investigation · agentic AI security · MITRE ATLAS · chain of custody ·
> OpenTelemetry GenAI · MCP · EU AI Act · DFIR.

### What it does

- 🔌 **Ingests 7 evidence sources** into one normalized schema (OTel GenAI, MCP,
  vector store, OAuth, egress, Halo-record, generic JSONL).
- 🔒 **Verifies integrity & chain of custody** — hash chains, gap/witness
  detection, HMAC-signed manifests, a tamper-evident custody ledger.
- 🕸️ **Reconstructs the causal attack chain** across fragmented logs (timeline +
  provenance graph).
- 🎯 **Detects 6 attack patterns** (prompt injection via retrieval, exfiltration
  via tool chaining, OAuth/credential theft, sub-agent hijack, memory poisoning,
  tool-permission escalation) — each mapped to **MITRE ATLAS** and linked to
  exact evidence.
- 🧭 **Builds kill-chain narratives + risk scores**.
- 📄 **Reports** in JSON, Markdown, and self-contained offline **HTML** (with an
  SVG causal-graph), plus **EU AI Act Article 12** coverage.
- 📦 **Portable signed case bundles** for air-gapped transfer.
- 🚫 **No AI/ML in the detection path** — deterministic and fully explainable.

It is the **investigation layer** that sits downstream of recorders (OpenTelemetry
GenAI, Halo-record, MCP logs). Recording is largely solved; automated
*reconstruction* of what actually happened across 6–7 fragmented log sources is
not. That is the gap AgentTrace fills.

## ⚠️ Authorized use only

AgentTrace is a **defensive** forensic tool. Use it only on evidence you are
legally authorized to investigate (your own agent deployments, or incidents you
are properly engaged to investigate). It is **not** an attack, exploitation, or
surveillance tool, has no capability to access remote systems or accounts, and
runs fully offline.

## Why it exists

- The attack vector in AI-agent incidents is **natural language** — a malicious
  prompt looks identical to a legitimate one in every log. The **sequence** is the
  evidence, not any single event.
- Evidence is scattered across LLM invocation logs, tool traces, MCP server logs,
  vector-store retrieval logs, OAuth records, and egress logs.
- Volume defeats manual review (a documented 2026 incident: ~17,600 agent actions
  in 5 days; the operator called manual reconstruction "impractical").

## Pipeline

```
ingest → normalize (UFE) → verify (integrity + chain of custody)
       → correlate (timeline + causal graph) → detect (attack patterns)
       → report (JSON + Markdown, EU AI Act Art.12 coverage)
```

- **Unified Forensic Event (UFE):** every source is normalized to one schema.
- **Integrity:** verifies Halo-record hash chains, detects sequence/time gaps, and
  supports out-of-band **witness anchors** — distinguishing *"nothing was edited"*
  from *"nothing is missing"*.
- **Correlation:** builds a causal graph with PROV-O-style edges
  (`parent_of`, `followed_by`, `used_data`, `derived_from`).
- **Detection (explainable, evidence-linked):**
  1. prompt injection via retrieved content,
  2. exfiltration via tool-call chaining (monotonic-offset paging),
  3. OAuth / credential-theft chains with anomalous operational velocity.
- **Reporting:** chain-of-custody attestation + EU AI Act Article 12 coverage.

## Install

```bash
pip install agentdfir          # from PyPI (CLI command is `agenttrace`)
# or from source (project root):
pip install -e .
# or run without installing:
python3 -m agenttrace.cli --help
```

Requires Python ≥ 3.10. No third-party runtime dependencies.

## Quickstart

Generate a synthetic incident dataset and run the full pipeline:

```bash
python3 -m tests.synthetic synthetic_data      # writes sample evidence files
agenttrace report synthetic_data/*.json synthetic_data/*.jsonl \
    --signing-key "my-case-key" \
    --title "Synthetic AI Agent Incident" \
    --md-out report.md --json-out report.json --html-out report.html
```

The `--html-out` report is fully self-contained and offline (inline SVG
causal-graph visualization, no external CDN or network access).

### Deterministic by design (no AI/ML in the detection path)

AgentTrace uses **only deterministic heuristics and rule-based correlation** — no
LLM or ML model participates in reaching a finding. This is intentional for a
forensic tool: every finding links back to the exact underlying events, there is
no hallucination or automation-bias risk, and it runs air-gapped with zero
dependencies. Any future AI assistance would be confined to an optional
natural-language *summary* layer on top of the deterministic core, and would
never decide a detection.

Other subcommands:

```bash
agenttrace ingest      <files...>   # normalize evidence to UFE (JSON)
agenttrace verify      <files...>   # integrity + chain of custody + manifest
agenttrace reconstruct <files...>   # timeline + causal graph
agenttrace detect      <files...>   # attack-pattern findings
```

Force a specific collector with `--collector otel_genai|halo_record|jsonl_llm`.

## Supported evidence sources

| Collector      | Source format                                   |
|----------------|-------------------------------------------------|
| `otel_genai`   | OpenTelemetry GenAI spans (`gen_ai.*`)          |
| `halo_record`  | Halo-record hash-chained audit logs (JSONL)     |
| `mcp`          | Model Context Protocol server logs (JSONL)      |
| `vector_store` | RAG vector-store retrieval logs (JSONL)         |
| `oauth`        | OAuth grant / token issuance & use (JSONL)      |
| `egress`       | Egress network logs (JSONL)                     |
| `jsonl_llm`    | Generic JSONL LLM/tool logs (permissive)        |

New sources are added by subclassing `Collector` (see `agenttrace/collectors/`).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

All tests use synthetic data only; no real systems or data are involved.

## Project layout

```
agenttrace/
  model.py         # UFE schema, evidence bundle, redaction
  custody.py       # tamper-evident chain-of-custody ledger
  collectors/      # pluggable ingestion (otel/halo/mcp/vector/oauth/egress/jsonl)
  integrity.py     # hash-chain verify, gap detection, signed manifest
  correlate.py     # timeline + causal graph
  detect.py        # attack-pattern detectors + MITRE ATLAS mapping
  analyze.py       # kill-chain narratives + risk scoring
  bundle.py        # portable signed .tar case bundles
  report.py        # JSON / Markdown / HTML reporting
  cli.py           # command-line interface
tests/             # synthetic dataset generator + test suite
DESIGN.md          # architecture & threat model
```

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, adding collectors/detectors, style.
- [SECURITY.md](SECURITY.md) — responsible disclosure and safe evidence handling.
- [CHANGELOG.md](CHANGELOG.md) — release history.

## Support

AgentTrace is free and open source. If you find it useful and would like to
support development, donations are welcome — entirely at your own discretion.

- **TRON (TRX / USDT–TRC20):** `TYqSCXX8Vu7MXcTXsPPgiKxb4uRHLKTPcC`

> ⚠️ Send only on the **TRON (TRC-20)** network. Always verify the address
> character-for-character before sending. Cryptocurrency transactions are
> irreversible; donate at your own risk. Donations are voluntary and non-refundable.

## License

Apache-2.0. See [LICENSE](LICENSE).
