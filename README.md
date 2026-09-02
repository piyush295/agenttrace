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

### Install on Kali Linux / Debian / Ubuntu

**Option A — apt (GPG-signed repository):**

```bash
# 1. add the signing key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://rakshanex.github.io/apt/agenttrace-archive-keyring.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/agenttrace.gpg

# 2. add the repository (signature-verified, no trusted=yes)
echo "deb [signed-by=/etc/apt/keyrings/agenttrace.gpg] https://rakshanex.github.io/apt ./" \
  | sudo tee /etc/apt/sources.list.d/agenttrace.list

# 3. install
sudo apt update
sudo apt install agentdfir
agenttrace --version
```

Every update is verified against the maintainer's GPG public key, so only the key
holder can publish valid packages.

**Option B — pipx (no repo needed):**

Modern Kali/Debian/Ubuntu ship a PEP 668 "externally managed" Python, so use
**pipx** to install a Python CLI tool cleanly:

```bash
sudo apt update && sudo apt install -y pipx
pipx ensurepath
pipx install agentdfir      # provides the `agenttrace` command
```

Upgrade later with `pipx upgrade agentdfir`.

> Building/hosting the signed apt repo yourself? See
> **[PACKAGING-DEBIAN.md](PACKAGING-DEBIAN.md)**.

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

Other subcommands are documented in the **User Guide** below.

## User Guide

AgentTrace is used as a sequence of commands over your evidence files. A typical
investigation is: **detect → verify → report**, optionally **export** for
hand-off. Every command is offline and reads evidence you provide as file paths.

> The installed command is `agenttrace` (PyPI package `agentdfir`). You can also
> run it as `python3 -m agenttrace.cli` without installing.

### 0. Prepare evidence

Point AgentTrace at logs you are authorized to investigate. Supported formats are
listed in *Supported evidence sources* below. To try it with no real data, generate
a synthetic incident:

```bash
python3 -m tests.synthetic synthetic_data     # creates sample evidence files
```

### 1. `detect` — “what happened? any attack patterns?”

```bash
agenttrace detect <evidence files...>
```
Ingests the evidence, reconstructs the causal chain, and prints detected attack
patterns (each mapped to MITRE ATLAS and linked to the exact evidence events).

Example:
```bash
agenttrace detect synthetic_data/*.json synthetic_data/*.jsonl
```

### 2. `verify` — “is the evidence trustworthy? was it altered or is any missing?”

```bash
agenttrace verify <evidence files...> --signing-key "<your-case-key>" \
    --case-number "IR-2026-0042" --case-officer "A. Analyst"
```
Runs hash-chain verification, sequence/time-gap detection, and produces an
HMAC-signed manifest. Records a chain-of-custody entry attributed to the officer.

### 3. `report` — produce a shareable report

```bash
agenttrace report <evidence files...> \
    --title "Assistant Data Exfiltration - IR-2026-0042" \
    --signing-key "<your-case-key>" \
    --json-out report.json --md-out report.md --html-out report.html
```
Generates JSON, Markdown, and a self-contained offline **HTML** report (with an
SVG causal graph, kill-chain narrative, risk score, and EU AI Act Article 12
coverage). Open `report.html` in any browser — no internet needed.

### 4. `export` / `verify-bundle` — portable, signed case bundles

```bash
# package the whole case into a signed .tar for air-gapped transfer
agenttrace export <evidence files...> --out case.tar --signing-key "<key>"

# on another machine, verify integrity + custody of the bundle
agenttrace verify-bundle case.tar --signing-key "<key>"
```

### 5. `custody` — view/verify the chain-of-custody ledger

```bash
agenttrace custody case.tar
```
Prints and verifies the tamper-evident custody ledger inside a bundle (who did
what, when, with which tool version and evidence hashes).

### Inspection commands

```bash
agenttrace ingest       <files...>   # show normalized events (UFE) as JSON
agenttrace reconstruct  <files...>   # show the timeline + causal graph
```

### Common options

| Option | Applies to | Meaning |
|--------|-----------|---------|
| `--signing-key <str>` | verify, report, export, verify-bundle | HMAC key that seals/verifies the manifest and bundle |
| `--case-number <str>` | all | case number recorded in the custody ledger |
| `--case-officer <str>` | all | investigator name recorded in the custody ledger |
| `--collector <name>` | all | force a collector instead of auto-detecting |
| `--json-out / --md-out / --html-out <path>` | report | write the report to files (otherwise prints Markdown) |
| `--title <str>` | report, export | human-readable case title on the report |
| `--out <path>` | export | output `.tar` path for the portable bundle |

### End-to-end example

```bash
# 1. generate a demo incident
python3 -m tests.synthetic synthetic_data

# 2. detect
agenttrace detect synthetic_data/*.json synthetic_data/*.jsonl

# 3. full report (JSON + Markdown + offline HTML)
agenttrace report synthetic_data/*.json synthetic_data/*.jsonl \
    --title "Synthetic AI Agent Incident" \
    --signing-key "case-2026-001" \
    --case-officer "A. Analyst" --case-number "IR-2026-001" \
    --json-out report.json --md-out report.md --html-out report.html

# 4. package a signed, portable case bundle and verify it
agenttrace export synthetic_data/*.json synthetic_data/*.jsonl \
    --out case.tar --signing-key "case-2026-001"
agenttrace verify-bundle case.tar --signing-key "case-2026-001"
agenttrace custody case.tar
```

Force a specific collector with `--collector otel_genai|halo_record|mcp|vector_store|oauth|egress|jsonl_llm`.

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
