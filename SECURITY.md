# Security Policy

## Scope & intended use

AgentTrace is a **defensive digital-forensics and incident-response (DFIR)** tool.
It is designed to analyze evidence you are **legally authorized** to investigate
(your own AI-agent deployments, or incidents you are engaged to investigate with
proper authority). It has no capability to access remote systems, accounts, or
data, and it runs fully offline.

It must **not** be used for attack, exploitation, unauthorized access,
surveillance, or covert monitoring.

## Reporting a vulnerability

If you discover a security vulnerability in AgentTrace itself (for example, a
path-traversal in bundle extraction, a way to forge a chain-of-custody signature,
or a parsing crash on malformed evidence), please report it responsibly:

1. **Do not** open a public issue for undisclosed vulnerabilities.
2. Contact the maintainers privately (see repository contact/security advisory).
3. Include reproduction steps and, if possible, a minimal proof of concept using
   **synthetic** data only.

We aim to acknowledge reports promptly and coordinate a fix and disclosure.

## Handling evidence safely

Because this tool processes forensic evidence:

- Raw sensitive content is never stored in normalized events — only redacted
  summaries plus content hashes (see `redact_summary` in `model.py`).
- Integrity and chain-of-custody are verifiable via hash chains and signed
  manifests; report any weakness in these mechanisms as a security issue.
- Treat all ingested evidence as untrusted input.
