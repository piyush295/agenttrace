# Kali Linux — Tool Submission / Package Request

This document is a ready-to-submit package request for adding **AgentTrace**
(`agentdfir`) to Kali Linux. It follows the information the Kali team asks for
when evaluating a new tool.

> How to file it: open a request on the Kali tools tracker
> (https://gitlab.com/kalilinux/tools/-/issues) or the packages group
> (https://gitlab.com/kalilinux/packages), titled
> **"New tool request: agentdfir (AgentTrace)"**, and paste the sections below.
>
> Honest note: inclusion is at the Kali team's discretion. They favor tools that
> are useful to the security community, actively maintained, and have some
> adoption. A brand-new tool may be asked to mature first. Until then, users can
> install via the signed apt repo or pipx (see README).

---

## Tool information

- **Name:** AgentTrace
- **Package name:** `agentdfir` (installs the `agenttrace` command)
- **Version:** 0.1.0
- **Category:** Forensics / Incident Response (DFIR)
- **Homepage:** https://github.com/rakshanex/agenttrace
- **Source repository:** https://github.com/rakshanex/agenttrace
- **License:** Apache-2.0 (OSI-approved)
- **Author / Maintainer:** Piyush Kumar <mr.piyush295@gmail.com>
- **Programming language:** Python 3 (>= 3.10)
- **Dependencies:** none beyond the Python 3 standard library (zero third-party
  runtime dependencies)
- **Architecture:** all (pure Python)

## What the tool does (one-paragraph description)

AgentTrace is a local-first digital forensics and incident response (DFIR) tool
for AI agents and LLM applications. It ingests already-recorded evidence
(OpenTelemetry GenAI spans, MCP server logs, vector-store retrieval logs, OAuth
records, egress logs, and hash-chained audit logs), verifies integrity and chain
of custody, reconstructs the causal attack chain across those fragmented sources,
detects known attack patterns (each mapped to MITRE ATLAS), and produces
regulator/court-ready reports (JSON, Markdown, offline HTML). It is deterministic
and explainable (no ML in the detection path) and runs fully offline.

## Why it belongs in Kali (community value)

Kali ships strong tooling for traditional DFIR, but AI-agent/LLM incident
response is an emerging gap. AgentTrace gives analysts a dedicated, offline,
standards-aligned way to investigate agentic-AI incidents — a category of attacks
(prompt injection, tool-call exfiltration, credential-theft chains, etc.) that is
growing quickly and is awkward to investigate with existing tools.

## Packaging status

- A Debian packaging tree is provided under `debian/` (control, rules using
  dh/pybuild, changelog, copyright, watch, upstream metadata, manpage).
- The project is also published on PyPI as `agentdfir`, and a GPG-signed apt
  repository is hosted at https://rakshanex.github.io/apt/ .
- Build: `dpkg-buildpackage -us -uc -b` (build-deps: debhelper, dh-python,
  python3-all). A no-debhelper fallback build is documented in PACKAGING-DEBIAN.md.

## How to run / verify

```bash
pip install agentdfir            # or the apt repo above
agenttrace --version
python3 -m tests.synthetic /tmp/demo
agenttrace detect /tmp/demo/*.json /tmp/demo/*.jsonl
```

## Tests

`python3 -m unittest discover -s tests` — a full offline test suite using
synthetic data only (no real systems or data).

## Security / ethics

Defensive, authorized-use only. AgentTrace analyzes evidence the operator is
authorized to investigate; it has no capability to attack, exploit, or access
remote systems, and it runs offline.

## Checklist (Kali/Debian expectations)

- [x] OSI-approved license (Apache-2.0)
- [x] Public source repository
- [x] Builds a `.deb` (debian/ provided)
- [x] No non-free / bundled proprietary code
- [x] Reproducible, offline, no network calls at runtime
- [x] Tests included
- [ ] Demonstrated community adoption (grow this: stars, users, write-ups)
