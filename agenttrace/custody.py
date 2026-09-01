"""Chain of custody — tamper-evident custody ledger.

Forensic evidence is only defensible if you can show *who* did *what* to *which*
evidence, *when*, and prove the record was not altered. This module provides a
hash-chained, append-only custody ledger that every AgentTrace stage writes to:

    ACQUIRE   evidence ingested (per artifact, with its sha256)
    ACCESS    evidence read/opened for examination
    ANALYZE   correlation / detection run against specific evidence
    REPORT    a report generated, bound to an evidence digest
    EXPORT    a portable case bundle written
    TRANSFER  custody handed from one custodian to another
    RECEIVE   custody received on another machine

Each ledger entry carries: sequence number, RFC3339 timestamp, the action, the
acting case officer + host + tool version, the case number, the evidence ids/
hashes involved, and an optional note. Every entry hashes the previous entry's
hash + its own canonical content, so any alteration or reordering is detectable
(same integrity model used elsewhere in AgentTrace, applied to the custody log).

Fully offline, standard library only.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from . import __version__


GENESIS = "GENESIS"


class CustodyAction(str, Enum):
    ACQUIRE = "acquire"
    ACCESS = "access"
    ANALYZE = "analyze"
    REPORT = "report"
    EXPORT = "export"
    TRANSFER = "transfer"
    RECEIVE = "receive"
    VERIFY = "verify"


def _now() -> str:
    # RFC3339 with microseconds, UTC.
    return datetime.now(timezone.utc).isoformat()


def current_custodian(case_officer: Optional[str] = None) -> str:
    """Identity of who is performing the action (chain of custody).

    Prefers an explicit case_officer; otherwise falls back to the OS user + host.
    """
    if case_officer:
        return case_officer
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return f"{user}@{socket.gethostname()}"


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class CustodyEvent:
    """One immutable custody-ledger entry."""

    seq: int
    timestamp: str
    action: str                    # CustodyAction value
    custodian: str                 # case officer or user@host
    host: str
    tool_version: str
    case_number: Optional[str]
    evidence_ids: list[str] = field(default_factory=list)
    evidence_hashes: list[str] = field(default_factory=list)
    note: Optional[str] = None
    prev_hash: str = GENESIS
    hash: Optional[str] = None

    def _payload(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("hash", None)
        return d

    def compute_hash(self) -> str:
        return hashlib.sha256(
            (str(self.prev_hash) + _canonical(self._payload())).encode("utf-8")
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CustodyLedger:
    """Append-only, hash-chained custody log."""

    case_number: Optional[str] = None
    events: list[CustodyEvent] = field(default_factory=list)

    # -- append ------------------------------------------------------------- #
    def record(self,
               action: CustodyAction,
               custodian: Optional[str] = None,
               evidence_ids: Optional[list[str]] = None,
               evidence_hashes: Optional[list[str]] = None,
               note: Optional[str] = None) -> CustodyEvent:
        prev = self.events[-1].hash if self.events else GENESIS
        ev = CustodyEvent(
            seq=len(self.events),
            timestamp=_now(),
            action=action.value,
            custodian=current_custodian(custodian),
            host=socket.gethostname(),
            tool_version=__version__,
            case_number=self.case_number,
            evidence_ids=list(evidence_ids or []),
            evidence_hashes=list(evidence_hashes or []),
            note=note,
            prev_hash=prev,
        )
        ev.hash = ev.compute_hash()
        self.events.append(ev)
        return ev

    # -- verify ------------------------------------------------------------- #
    def verify(self) -> dict[str, Any]:
        """Verify the custody chain: link continuity + hash recomputation + gaps."""
        issues: list[str] = []
        prev = GENESIS
        for i, ev in enumerate(self.events):
            if ev.seq != i:
                issues.append(f"sequence gap/disorder at index {i} (seq={ev.seq})")
            if ev.prev_hash != prev:
                issues.append(f"broken link at seq {ev.seq}")
            if ev.hash != ev.compute_hash():
                issues.append(f"hash mismatch at seq {ev.seq} (entry altered)")
            prev = ev.hash
        return {"ok": not issues, "event_count": len(self.events),
                "head_hash": self.events[-1].hash if self.events else GENESIS,
                "issues": issues}

    # -- serialization ------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        return {"case_number": self.case_number,
                "event_count": len(self.events),
                "head_hash": self.events[-1].hash if self.events else GENESIS,
                "events": [e.to_dict() for e in self.events]}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CustodyLedger":
        led = cls(case_number=data.get("case_number"))
        for ed in data.get("events", []):
            led.events.append(CustodyEvent(**ed))
        return led
