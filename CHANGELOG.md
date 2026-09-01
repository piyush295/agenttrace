# Changelog

All notable changes to AgentTrace are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-09-02

Initial release: a local-first, standards-aligned, zero-dependency forensic
reconstruction tool for AI-agent security incidents.

### Added

**Ingestion**
- Unified Forensic Event (UFE) schema normalizing all sources.
- 7 pluggable collectors: OpenTelemetry GenAI spans, Halo-record hash-chains,
  MCP server logs, vector-store retrieval logs, OAuth grant/token records,
  egress network logs, and a permissive generic JSONL fallback.
- Secret/PII redaction so raw sensitive content never enters normalized events.

**Integrity & chain of custody**
- Hash-chain verification (detects altered/reordered records).
- Sequence-gap and time-gap detection, and witness-anchor verification
  (distinguishes "nothing was edited" from "nothing is missing").
- HMAC-signed evidence manifest bound to an evidence digest.
- First-class, tamper-evident **chain-of-custody ledger** recording every stage
  (acquire, verify, analyze, report, export, transfer) with case officer, host,
  tool version, timestamps, and evidence hashes.

**Analysis**
- Causal-chain reconstruction: per-session timelines + a PROV-O-style causal
  graph (parent_of / followed_by / used_data / derived_from).
- 6 attack-pattern detectors, each mapped to a MITRE ATLAS technique:
  prompt injection via retrieval, exfiltration via tool chaining, OAuth/
  credential theft chain, sub-agent hijack, memory poisoning, tool-permission
  escalation.
- Kill-chain narrative builder and 0–100 risk scoring.

**Reporting & transfer**
- JSON, Markdown, and self-contained offline HTML reports (inline SVG causal
  graph), including an EU AI Act Article 12 record-keeping coverage section.
- Portable, signed `.tar` case bundles for air-gapped transfer, with embedded
  custody ledger and full re-verification on import.

**Interface & quality**
- CLI: `ingest`, `verify`, `reconstruct`, `detect`, `report`, `export`,
  `verify-bundle`, `custody`; `--case-number` / `--case-officer` attribution.
- 32 tests (unit + integration + a 17k-event scale test), all offline.
- Verified to run with network access fully disabled.

### Design principles
- Local-first, zero runtime dependencies (standard library only).
- Deterministic and explainable — no AI/ML in the detection path.
- Defensive, authorized-use only.
