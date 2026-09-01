"""AgentTrace — forensic reconstruction for AI agent security incidents.

Local-first, standards-aligned, defensive DFIR tooling. Ingests already-recorded
evidence, verifies integrity/chain-of-custody, reconstructs causal attack chains,
detects known attack patterns, and produces regulator/court-ready reports.

Authorized use only: operate solely on evidence you are legally authorized to
investigate. This is not an attack, exploitation, or surveillance tool.
"""

from .model import (
    EventType,
    Severity,
    UnifiedForensicEvent,
    EvidenceArtifact,
    EvidenceBundle,
    IntegrityFinding,
    make_event_id,
    sha256_hex,
    parse_timestamp,
    to_rfc3339,
    redact_summary,
)

__version__ = "0.1.0"

__all__ = [
    "EventType",
    "Severity",
    "UnifiedForensicEvent",
    "EvidenceArtifact",
    "EvidenceBundle",
    "IntegrityFinding",
    "make_event_id",
    "sha256_hex",
    "parse_timestamp",
    "to_rfc3339",
    "redact_summary",
    "__version__",
]
