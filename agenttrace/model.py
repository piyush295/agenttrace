"""AgentTrace core data model.

Defines the Unified Forensic Event (UFE) — a normalized representation that every
evidence source is mapped into — plus supporting types for evidence artifacts,
chain-of-custody, and the signed evidence bundle.

Design notes
------------
* The UFE is deliberately source-agnostic. Collectors translate source-native
  records (OTel GenAI spans, Halo-record entries, MCP logs, etc.) into UFEs so
  that correlation and detection operate on one schema.
* Correlation relies on a small set of "join keys": session_id, trace_id,
  span_id, parent_span_id, and timestamps. Not every source provides all of
  them; correlation degrades gracefully.
* Everything is plain dataclasses + enums (stdlib only) so the package has no
  runtime dependencies — important for a tool meant to run inside sensitive,
  air-gapped forensic environments.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #

class EventType(str, Enum):
    """The kind of agent activity a UFE represents.

    Chosen to align with OpenTelemetry GenAI span operations and the artifact
    categories that matter for AI-agent forensics.
    """

    LLM_INVOCATION = "llm_invocation"        # a model call (prompt/response)
    TOOL_CALL = "tool_call"                  # agent invoked a tool/function
    RETRIEVAL = "retrieval"                  # RAG / vector-store retrieval
    MEMORY_OP = "memory_op"                  # read/write of agent memory
    AGENT_STEP = "agent_step"                # orchestration/reasoning step
    SUBAGENT_SPAWN = "subagent_spawn"        # a sub-agent was created
    APPROVAL = "approval"                    # human/policy approval decision
    OAUTH_GRANT = "oauth_grant"              # OAuth/token issuance or use
    EGRESS = "egress"                        # outbound network request
    DATA_ACCESS = "data_access"              # read/write of a data resource
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #

def parse_timestamp(value: Any) -> Optional[datetime]:
    """Best-effort parse of a timestamp into an aware UTC datetime.

    Accepts: datetime, epoch seconds/millis/nanos (int/float), or RFC3339 /
    ISO-8601 strings (including trailing 'Z' and nanosecond precision).
    Returns None if it cannot be parsed.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # Heuristic on magnitude: ns (~1e18), ms (~1e12), s (~1e9) for 2020s.
        v = float(value)
        if v > 1e17:      # nanoseconds
            v /= 1e9
        elif v > 1e14:    # microseconds
            v /= 1e6
        elif v > 1e11:    # milliseconds
            v /= 1e3
        return datetime.fromtimestamp(v, tz=timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # Normalize trailing Z; trim sub-microsecond precision fromisoformat cannot handle.
        s = s.replace("Z", "+00:00")
        # Trim nanoseconds to microseconds if present: ....123456789+00:00
        if "." in s:
            head, _, tail = s.partition(".")
            frac = tail
            tzpart = ""
            for sign in ("+", "-"):
                if sign in frac:
                    idx = frac.index(sign)
                    frac, tzpart = frac[:idx], frac[idx:]
                    break
            frac = frac[:6]  # microseconds max
            s = f"{head}.{frac}{tzpart}"
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def to_rfc3339(dt: Optional[datetime]) -> Optional[str]:
    """Serialize a datetime to RFC3339 with microsecond precision in UTC."""
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Unified Forensic Event
# --------------------------------------------------------------------------- #

@dataclass
class UnifiedForensicEvent:
    """One normalized forensic event, regardless of originating source.

    Attributes
    ----------
    event_id:
        Stable identifier for this event within a case. If the source does not
        provide one, collectors synthesize a deterministic id (see make_event_id).
    event_type:
        One of EventType.
    timestamp:
        Aware UTC datetime of when the event occurred. May be None if the source
        provided nothing parseable (such events sort last and are flagged).
    source:
        Name of the collector/source that produced this event (e.g. "otel_genai").
    session_id / trace_id / span_id / parent_span_id:
        Correlation join keys. Any may be None depending on the source.
    actor:
        The principal responsible (service account, user, agent name, OAuth app).
    action:
        Short verb/operation string (e.g. "chat", "tool.execute", "http.get").
    target:
        The object acted upon (tool name, resource, URL host, secret name).
    data_refs:
        Identifiers of data touched (document/chunk ids, table names, file paths).
        Used by the correlation engine to link retrieval -> use -> egress.
    attributes:
        Source-specific extra fields, preserved verbatim for evidentiary fidelity.
    content_summary:
        Redacted / summarized content (never raw secrets). For prompts/responses
        we keep a short summary; raw values are referenced via content_hash only.
    content_hash:
        SHA-256 of the original content (if any), for integrity without storing
        sensitive raw data.
    artifact_id:
        Links this event back to the EvidenceArtifact (file) it came from.
    """

    event_id: str
    event_type: EventType
    timestamp: Optional[datetime]
    source: str
    session_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    actor: Optional[str] = None
    action: Optional[str] = None
    target: Optional[str] = None
    data_refs: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    content_summary: Optional[str] = None
    content_hash: Optional[str] = None
    artifact_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["timestamp"] = to_rfc3339(self.timestamp)
        return d


def make_event_id(source: str, *parts: Any) -> str:
    """Deterministic event id from source + salient parts.

    Deterministic ids make ingestion idempotent and make test assertions stable.
    """
    h = hashlib.sha256()
    h.update(source.encode("utf-8"))
    for p in parts:
        h.update(b"\x1f")
        h.update(str(p).encode("utf-8"))
    return f"{source}:{h.hexdigest()[:16]}"


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Evidence artifacts & chain of custody
# --------------------------------------------------------------------------- #

@dataclass
class EvidenceArtifact:
    """A source file/blob that was ingested, with integrity metadata."""

    artifact_id: str
    path: str
    source_type: str            # collector name that handled it
    sha256: str
    size_bytes: int
    collected_at: datetime
    collector_identity: str     # who/what performed collection
    notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["collected_at"] = to_rfc3339(self.collected_at)
        return d


@dataclass
class IntegrityFinding:
    """Result of an integrity/chain-of-custody check on an artifact or chain."""

    artifact_id: Optional[str]
    check: str                  # e.g. "hash_chain", "gap_detection"
    ok: bool
    severity: Severity
    detail: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class EvidenceBundle:
    """The complete normalized case: artifacts + events + integrity results.

    The bundle is what later stages (correlate/detect/report) operate on, and is
    what gets sealed into a signed manifest for chain-of-custody.
    """

    case_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    artifacts: list[EvidenceArtifact] = field(default_factory=list)
    events: list[UnifiedForensicEvent] = field(default_factory=list)
    integrity_findings: list[IntegrityFinding] = field(default_factory=list)

    # -- mutation helpers --------------------------------------------------- #
    def add_artifact(self, artifact: EvidenceArtifact) -> None:
        self.artifacts.append(artifact)

    def add_events(self, events: list[UnifiedForensicEvent]) -> None:
        self.events.extend(events)

    def add_integrity_finding(self, finding: IntegrityFinding) -> None:
        self.integrity_findings.append(finding)

    # -- ordering ----------------------------------------------------------- #
    def sorted_events(self) -> list[UnifiedForensicEvent]:
        """Events in chronological order; undated events sort last, stably."""
        dated = [e for e in self.events if e.timestamp is not None]
        undated = [e for e in self.events if e.timestamp is None]
        dated.sort(key=lambda e: e.timestamp)  # type: ignore[arg-type]
        return dated + undated

    # -- serialization ------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "created_at": to_rfc3339(self.created_at),
            "artifacts": [a.to_dict() for a in self.artifacts],
            "events": [e.to_dict() for e in self.sorted_events()],
            "integrity_findings": [f.to_dict() for f in self.integrity_findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


# --------------------------------------------------------------------------- #
# Redaction helper (used by collectors so raw secrets never enter UFEs)
# --------------------------------------------------------------------------- #

import re as _re

_SECRET_PATTERNS = [
    _re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|authorization)"),
    _re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key id
    _re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT-ish
    _re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # email
]


def redact_summary(text: Any, max_len: int = 200) -> str:
    """Produce a short, redacted, non-sensitive summary of content.

    Raw content is never stored in a UFE; only this summary plus a content_hash.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        try:
            text = json.dumps(text, default=str)
        except Exception:
            text = str(text)
    redacted = text
    for pat in _SECRET_PATTERNS:
        redacted = pat.sub("[REDACTED]", redacted)
    redacted = redacted.replace("\n", " ").strip()
    if len(redacted) > max_len:
        redacted = redacted[:max_len] + "…"
    return redacted
