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
    "new_case",
    "__version__",
]


def new_case(case_id: str,
             case_number=None,
             case_officer=None,
             acquisition_method=None):
    """Create an EvidenceBundle with an attached custody ledger.

    This is the recommended way to start a case so that chain of custody is
    recorded from the first acquisition onward.
    """
    from .custody import CustodyLedger
    bundle = EvidenceBundle(
        case_id=case_id,
        case_number=case_number,
        case_officer=case_officer,
        acquisition_method=acquisition_method,
    )
    bundle.custody_ledger = CustodyLedger(case_number=case_number)
    return bundle
